#!/usr/bin/env python3
"""
native_scanner/webhook.py
=========================
Independent, In-Cluster Kubernetes Admission Controller Webhook.
Pure-Python, Zero-Dependency Validating & Mutating Admission Webhook.

Features:
- ValidatingAdmissionWebhook (/validate): Blocks non-compliant workloads at runtime.
- MutatingAdmissionWebhook (/mutate): RFC 6902 JSONPatch least-privilege auto-remediation.
- Modes: 'enforce' (rejects with 403), 'warn' (returns admission warnings), 'shadow' / 'dry-run'.
- Built-in TLS cert generator with proper SANs.
- Probes: /healthz, /readyz.
- Observability: /metrics (OpenMetrics admission counters).
"""

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import socketserver
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Thread-safe Token Bucket Rate Limiter (Admission Flooding / DoS Defense)
RATE_LIMIT_BUCKET = 200.0  # Max burst tokens
RATE_LIMIT_REFILL_RATE = 100.0  # Tokens refilled per second
RATE_LIMIT_TOKENS = 200.0
RATE_LIMIT_LAST_TIME = time.time()
RATE_LIMIT_LOCK = threading.Lock()


def check_rate_limit() -> bool:
    global RATE_LIMIT_TOKENS, RATE_LIMIT_LAST_TIME
    with RATE_LIMIT_LOCK:
        now = time.time()
        elapsed = now - RATE_LIMIT_LAST_TIME
        RATE_LIMIT_LAST_TIME = now
        RATE_LIMIT_TOKENS = min(RATE_LIMIT_BUCKET, RATE_LIMIT_TOKENS + elapsed * RATE_LIMIT_REFILL_RATE)
        if RATE_LIMIT_TOKENS >= 1.0:
            RATE_LIMIT_TOKENS -= 1.0
            return True
        return False

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """High-concurrency multi-threaded HTTPS server for Kubernetes Admission Reviews."""
    daemon_threads = True

try:
    from . import __version__
except Exception:
    __version__ = "1.0.0"

try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .remediate import remediate_workload_dict
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from remediate import remediate_workload_dict

logger = logging.getLogger("NativeAdmissionWebhook")

METRICS = {
    "admissions_total": 0,
    "admissions_approved_total": 0,
    "admissions_rejected_total": 0,
    "admissions_mutated_total": 0,
    "admissions_shadow_violations_total": 0,
}
METRICS_LOCK = threading.Lock()

MAX_ADMISSION_BODY_BYTES = 8 * 1024 * 1024


def generate_self_signed_cert(
    cert_path: str,
    key_path: str,
    domain: str = "k8s-native-scan-webhook.kube-system.svc",
    valid_days: int = 365,
) -> Tuple[str, str]:
    """Generates self-signed TLS certificates with SANs for Kubernetes API server."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        logger.info(f"Generating self-signed TLS cert for {domain}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kubernetes Native Security Webhook"),
        ])

        san_list = [
            x509.DNSName("localhost"),
            x509.DNSName("k8s-native-scan-webhook"),
            x509.DNSName(domain),
            x509.DNSName(f"{domain}.cluster.local"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        p_cert, p_key = Path(cert_path), Path(key_path)
        p_cert.parent.mkdir(parents=True, exist_ok=True)
        p_key.parent.mkdir(parents=True, exist_ok=True)

        p_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        p_key.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.chmod(p_key, 0o600)
        os.chmod(p_cert, 0o644)
        logger.info(f"Generated TLS certificate at: {cert_path} with 0600 key permissions")
        return cert_path, key_path
    except Exception as e:
        logger.error(f"Cannot generate TLS cert with cryptography: {e}")
        raise


class AdmissionSecurityEngine:
    """Evaluates Kubernetes AdmissionReview requests using pure-Python AST scanner."""

    def __init__(
        self,
        min_score: float = 70.0,
        veto_rules: Optional[Set[str]] = None,
        enforcement_mode: str = "enforce",  # "enforce", "warn", "shadow", "dry-run"
    ):
        self.min_score = min_score
        self.veto_rules = veto_rules or {"V01", "V02", "V09", "V10", "V11", "V45"}
        self.enforcement_mode = enforcement_mode.lower()
        self.scanner = NativeSecurityScanner()

    def evaluate_object(self, obj: Dict[str, Any], name: str) -> Tuple[bool, float, List[str]]:
        """Evaluates Kubernetes object. Returns (allowed, score, violations)."""
        report = self.scanner.scan_dict(obj, source_name=name)
        violations = []

        # Check veto rules
        for f in report.findings:
            if f.vuln_id in self.veto_rules:
                violations.append(f"Veto rule {f.vuln_id} violated: {f.title} ({f.target})")

        # Check compliance score
        if report.compliance_score < self.min_score:
            violations.append(f"Compliance score {report.compliance_score:.1f} is below minimum {self.min_score:.1f}")

        allowed = len(violations) == 0
        return allowed, report.compliance_score, violations

    def generate_mutation_patch(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generates RFC 6902 JSONPatch operations for mutating admission."""
        hardened, changes = remediate_workload_dict(obj)
        if not changes:
            return []

        # If securityContext was added or changed on template/spec
        patches = []
        kind = obj.get("kind", "")
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            spec = hardened.get("spec", {}).get("template", {}).get("spec", {})
            target_path = "/spec/template/spec"
        else:
            spec = hardened.get("spec", {})
            target_path = "/spec"

        # Patch pod-level security context
        if "securityContext" in spec:
            orig_sec = obj.get("spec", {}).get("securityContext") if kind == "Pod" else obj.get("spec", {}).get("template", {}).get("spec", {}).get("securityContext")
            op = "replace" if orig_sec is not None else "add"
            patches.append({
                "op": op,
                "path": f"{target_path}/securityContext",
                "value": spec["securityContext"]
            })

        # Patch container-level security contexts
        containers = spec.get("containers", [])
        for idx, c in enumerate(containers):
            if "securityContext" in c:
                patches.append({
                    "op": "add",
                    "path": f"{target_path}/containers/{idx}/securityContext",
                    "value": c["securityContext"]
                })

        return patches


class AdmissionWebhookHandler(BaseHTTPRequestHandler):
    engine: AdmissionSecurityEngine = AdmissionSecurityEngine()

    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "service": "k8s-native-scan-webhook"}')

        elif self.path == "/metrics":
            with METRICS_LOCK:
                metrics_text = (
                    "# HELP admissions_total Total AdmissionReview requests processed\n"
                    "# TYPE admissions_total counter\n"
                    f"admissions_total {METRICS['admissions_total']}\n"
                    "# HELP admissions_approved_total Total AdmissionReview requests allowed\n"
                    "# TYPE admissions_approved_total counter\n"
                    f"admissions_approved_total {METRICS['admissions_approved_total']}\n"
                    "# HELP admissions_rejected_total Total AdmissionReview requests rejected\n"
                    "# TYPE admissions_rejected_total counter\n"
                    f"admissions_rejected_total {METRICS['admissions_rejected_total']}\n"
                    "# HELP admissions_mutated_total Total AdmissionReview requests mutated\n"
                    "# TYPE admissions_mutated_total counter\n"
                    f"admissions_mutated_total {METRICS['admissions_mutated_total']}\n"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(metrics_text.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not check_rate_limit():
            self.send_response(429)
            self.send_header("Retry-After", "1")
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(b'{"error": "Too Many Requests - Rate Limit Exceeded"}')
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_ADMISSION_BODY_BYTES:
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        try:
            review_req = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        req = review_req.get("request", {})
        uid = req.get("uid", "")
        obj = req.get("object", {})
        name = obj.get("metadata", {}).get("name", "unnamed")

        with METRICS_LOCK:
            METRICS["admissions_total"] += 1

        if self.path == "/validate":
            allowed, score, violations = self.engine.evaluate_object(obj, name)
            is_dry_run = self.engine.enforcement_mode in ("shadow", "dry-run", "warn")

            status_code = 200
            msg = "Workload security policies validated successfully."
            if not allowed:
                if is_dry_run:
                    allowed = True
                    msg = f"[DRY-RUN / SHADOW] Security violations observed: {'; '.join(violations)}"
                    with METRICS_LOCK:
                        METRICS["admissions_shadow_violations_total"] += 1
                        METRICS["admissions_approved_total"] += 1
                else:
                    status_code = 403
                    msg = f"Admission denied by k8s-native-scanner: {'; '.join(violations)}"
                    with METRICS_LOCK:
                        METRICS["admissions_rejected_total"] += 1
            else:
                with METRICS_LOCK:
                    METRICS["admissions_approved_total"] += 1

            review_resp = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": allowed,
                    "status": {
                        "code": status_code,
                        "message": msg,
                    },
                },
            }
            if violations and self.engine.enforcement_mode == "warn":
                review_resp["response"]["warnings"] = violations

            self._send_json(review_resp)

        elif self.path == "/mutate":
            patches = self.engine.generate_mutation_patch(obj)
            with METRICS_LOCK:
                if patches:
                    METRICS["admissions_mutated_total"] += 1
                METRICS["admissions_approved_total"] += 1

            review_resp = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": True,
                },
            }
            if patches:
                patch_bytes = json.dumps(patches).encode("utf-8")
                review_resp["response"]["patchType"] = "JSONPatch"
                review_resp["response"]["patch"] = base64.b64encode(patch_bytes).decode("utf-8")

            self._send_json(review_resp)
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: Dict[str, Any]):
        out = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")


def run_webhook_server(
    port: int = 8443,
    host: str = "0.0.0.0",
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    mode: str = "enforce",
    min_score: float = 70.0,
):
    """Starts the in-cluster HTTPS admission webhook server."""
    AdmissionWebhookHandler.engine = AdmissionSecurityEngine(
        min_score=min_score,
        enforcement_mode=mode,
    )

    if not cert_path or not key_path or not os.path.exists(cert_path) or not os.path.exists(key_path):
        c_path = cert_path or "webhook-cert.pem"
        k_path = key_path or "webhook-key.pem"
        cert_path, key_path = generate_self_signed_cert(c_path, k_path)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Enforce TLS 1.2+ minimum version
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # Modern secure TLS cipher suites
    modern_ciphers = (
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    )
    try:
        context.set_ciphers(modern_ciphers)
    except ssl.SSLError:
        pass

    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server = ThreadedHTTPServer((host, port), AdmissionWebhookHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"\n[✓] Kubernetes Native Admission Webhook listening on https://{host}:{port}/")
    print(f"    Mode: {mode.upper()} | Minimum Score Threshold: {min_score}")
    print(f"    Endpoints: /validate (Validating) | /mutate (Mutating) | /healthz | /metrics")
    print("    Press Ctrl+C to terminate.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping admission webhook...")
        server.server_close()


def generate_webhook_manifests(
    service_name: str = "k8s-native-scan-webhook",
    namespace: str = "kube-system",
    cert_path: Optional[str] = None,
) -> str:
    """Generates turnkey Kubernetes ValidatingWebhookConfiguration & MutatingWebhookConfiguration YAML."""
    ca_bundle_b64 = ""
    if cert_path and Path(cert_path).exists():
        ca_bundle_b64 = base64.b64encode(Path(cert_path).read_bytes()).decode("utf-8")

    return f"""apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: {service_name}-val
webhooks:
  - name: validate.security.k8s.io
    rules:
      - apiGroups: ["", "apps", "batch"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "deployments", "daemonsets", "statefulsets", "jobs"]
        scope: "Namespaced"
    clientConfig:
      service:
        namespace: {namespace}
        name: {service_name}
        path: "/validate"
        port: 8443
      caBundle: "{ca_bundle_b64}"
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 3
    failurePolicy: Fail
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: {service_name}-mut
webhooks:
  - name: mutate.security.k8s.io
    rules:
      - apiGroups: ["", "apps", "batch"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods", "deployments", "daemonsets", "statefulsets", "jobs"]
        scope: "Namespaced"
    clientConfig:
      service:
        namespace: {namespace}
        name: {service_name}
        path: "/mutate"
        port: 8443
      caBundle: "{ca_bundle_b64}"
    admissionReviewVersions: ["v1"]
    sideEffects: None
    timeoutSeconds: 3
    failurePolicy: Ignore
"""

