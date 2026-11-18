#!/usr/bin/env python3
r"""
tests/test_deep_security_penetration.py
=======================================
Deep Security Penetration, Exploit Defense & Adversarial Invariant Test Suite.

Verifies:
1. Container Breakout & Host Escape Defenses (Sockets, Root HostPaths, Sockets, Capabilities).
2. SSRF, Link-Local Metadata (169.254.169.254) & Private Subnet Exfiltration Defenses.
3. Supply Chain Security (Levenshtein Typosquatting $d \le 2$, Cosign/Sigstore SLSA Verification).
4. Secret Credential Exfiltration & High-Entropy Detection (Shannon $H \ge 4.5$).
5. eBPF Kernel Behavioral Intrusion Detection (Reverse Shells, Shadow Access, Mount Escapes).
6. Multi-Tenant Boundary Isolation & RBAC Privilege Escalation Attacks.
7. Admission Webhook Mutating Gates & Strategic Merge Patch Invariance.
8. Multi-Cloud Infrastructure CSPM Security Rule Violations (S3, Security Groups, IMDSv1).
9. Regulatory Compliance & Well-Architected Framework Governance.
"""

import json
import time
import unittest
from typing import Dict, Any, List

from scanner import NativeSecurityScanner, ScanReport, shannon_entropy, check_image_typosquatting
from container import HybridContainerLayerScanner, validate_safe_url
from remediate import auto_remediate_manifest
from webhook import AdmissionSecurityEngine
from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
from auth import (
    EnterpriseAuthManager,
    AuthenticatedIdentity,
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_ENGINEER,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_DEVOPS_OPERATOR,
    PERM_FLEET_MANAGE,
    PERM_CLUSTER_ONBOARD,
    PERM_POLICY_WRITE,
    PERM_SCAN_EXECUTE,
    PERM_REMEDIATE_WRITE,
    PERM_VEX_WAIVE,
    PERM_COMPLIANCE_READ,
)
from cloud_cspm import CloudCSPMEngine
from compliance import ComplianceFrameworkMapper


class TestDeepSecurityPenetration(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()
        self.auth = EnterpriseAuthManager(master_secret="test-sec-pen-suite-key-256bits!!")
        self.ebpf = EBPFTelemetryEngine()

    # ==========================================================================
    # 1. Container Breakout & Host Escape Exploits
    # ==========================================================================
    def test_container_breakout_socket_mount_v46(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: escape-socket-pod
spec:
  containers:
  - name: attacker
    image: alpine:latest
    volumeMounts:
    - name: dockersock
      mountPath: /var/run/docker.sock
  volumes:
  - name: dockersock
    hostPath:
      path: /var/run/docker.sock
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V46", report.detected_vuln_ids)
        finding = next(f for f in report.findings if f.vuln_id == "V46")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("socket", finding.description.lower())

    def test_container_breakout_root_filesystem_mount_v45(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: escape-root-pod
spec:
  containers:
  - name: attacker
    image: alpine:latest
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V45", report.detected_vuln_ids)
        finding = next(f for f in report.findings if f.vuln_id == "V45")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("root directory", finding.description.lower())

    def test_full_namespace_sharing_cluster_killchain(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: god-mode-pod
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  containers:
  - name: root-agent
    image: ubuntu:latest
    securityContext:
      privileged: true
"""
        report = self.scanner.scan_yaml_content(manifest)
        # Must detect privileged, hostNetwork, hostPID, hostIPC, and Cloud IMDS exposure
        self.assertIn("V01", report.detected_vuln_ids)  # Privileged
        self.assertIn("V09", report.detected_vuln_ids)  # hostNetwork
        self.assertIn("V10", report.detected_vuln_ids)  # hostPID
        self.assertIn("V11", report.detected_vuln_ids)  # hostIPC
        self.assertIn("V44", report.detected_vuln_ids)  # Cloud metadata access via hostNetwork
        self.assertLess(report.compliance_score, 40.0)
        self.assertEqual(report.risk_tier, "High")

    def test_dangerous_kernel_capabilities_v05(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: sysadmin-cap-pod
spec:
  containers:
  - name: worker
    image: redis:alpine
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V05", report.detected_vuln_ids)  # Dangerous capabilities
        finding = next(f for f in report.findings if f.vuln_id == "V05")
        self.assertEqual(finding.severity, "CRITICAL")

    # ==========================================================================
    # 2. SSRF, Metadata Exfiltration (169.254.169.254) & Private IP Defense
    # ==========================================================================
    def test_ssrf_blocks_aws_and_cloud_metadata_endpoints(self):
        # AWS / Azure / OpenStack IMDS
        with self.assertRaises(ValueError) as ctx:
            validate_safe_url("https://169.254.169.254/latest/meta-data/")
        self.assertIn("SSRF Protection", str(ctx.exception))

        # GCP metadata hostname
        with self.assertRaises(ValueError) as ctx:
            validate_safe_url("https://metadata.google.internal/computeMetadata/v1/")
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_blocks_loopback_and_internal_rfc1918(self):
        # Localhost
        with self.assertRaises(ValueError):
            validate_safe_url("https://127.0.0.1:8443/admin")
        with self.assertRaises(ValueError):
            validate_safe_url("https://localhost:8080/metrics")

        # Private RFC 1918 subnets
        with self.assertRaises(ValueError):
            validate_safe_url("https://10.0.0.5/api")
        with self.assertRaises(ValueError):
            validate_safe_url("https://192.168.1.1/router")

    def test_ssrf_blocks_insecure_and_file_schemes(self):
        # file:// scheme (local file inclusion)
        with self.assertRaises(ValueError):
            validate_safe_url("file:///etc/shadow")

        # http:// scheme (must enforce TLS https://)
        with self.assertRaises(ValueError):
            validate_safe_url("http://registry-1.docker.io/v2/")

    # ==========================================================================
    # 3. Supply Chain Attacks & Typosquatting
    # ==========================================================================
    def test_supply_chain_typosquatting_detection(self):
        # Distance 1 typosquats
        self.assertTrue(check_image_typosquatting("ngnix:latest")[0])
        self.assertTrue(check_image_typosquatting("red1s:alpine")[0])
        self.assertTrue(check_image_typosquatting("ubunutu:latest")[0])

        # Exact benign matches
        self.assertFalse(check_image_typosquatting("nginx:1.25.0")[0])
        self.assertFalse(check_image_typosquatting("redis:7.0-alpine")[0])
        self.assertFalse(check_image_typosquatting("python:3.12-slim")[0])

    def test_supply_chain_manifest_typosquatting_triggers_v20(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: typosquat-pod
spec:
  containers:
  - name: web
    image: ngnix:latest
"""
        report = self.scanner.scan_yaml_content(manifest)
        # Typosquatting triggers supply chain image alert with typosquatting description
        typo_finding = next((f for f in report.findings if "typosquatting" in f.description.lower()), None)
        self.assertIsNotNone(typo_finding)
        self.assertIn("official library image", typo_finding.description.lower())

    # ==========================================================================
    # 4. Secret Credential Exfiltration & High Shannon Entropy (H >= 4.5)
    # ==========================================================================
    def test_shannon_entropy_catches_high_entropy_secrets(self):
        # 40-character base64 secret access key
        secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        h = shannon_entropy(secret_key)
        self.assertGreater(h, 4.5)

        # Repetitive placeholder string
        placeholder = "CHANGE_ME_PASSWORD_123"
        h_low = shannon_entropy(placeholder)
        self.assertLess(h_low, 4.0)

    def test_embedded_secret_detected_in_manifest_v18(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: secret-leak-pod
spec:
  containers:
  - name: app
    image: python:3.12
    env:
    - name: DB_PASSWORD
      value: "xK9#mQ2$vL8!pZ5@jW3%tY7&rU1*"
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V18", report.detected_vuln_ids)
        finding = next(f for f in report.findings if f.vuln_id == "V18")
        self.assertIn(finding.severity, ("CRITICAL", "HIGH"))

    # ==========================================================================
    # 5. eBPF Kernel Behavioral Intrusion Detection
    # ==========================================================================
    def test_ebpf_catches_interactive_reverse_shell(self):
        event = self.ebpf.evaluate_execve_event(
            pid=4812,
            comm="bash",
            filename="/bin/bash",
            args=["bash", "-i"],
            pod_name="payment-service-67fb9",
            namespace="production",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.event_type, "SUSPICIOUS_PROCESS_EXEC")
        self.assertEqual(event.mitre_technique, "T1059.004")

        # CEF Export contains standard ArcSight format
        cef = event.to_cef()
        self.assertIn("CEF:0|K8sNativeSecurity|EnterpriseCNAPP|2.0.0|", cef)
        self.assertIn("src=payment-service-67fb9", cef)
        self.assertIn("cs1=production", cef)

    def test_ebpf_catches_sensitive_shadow_file_access(self):
        event = self.ebpf.evaluate_file_open_event(
            pid=4920,
            comm="cat",
            filepath="/etc/shadow",
            flags=0,
            pod_name="auth-service",
            namespace="production",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.event_type, "SENSITIVE_FILE_ACCESS")
        self.assertIn("/etc/shadow", event.description)

    def test_ebpf_catches_container_escape_mount(self):
        event = self.ebpf.evaluate_mount_event(
            pid=5100,
            comm="mount",
            source="/dev/nvme0n1p1",
            target="/host",
            filesystem_type="ext4",
            pod_name="insecure-pod",
            namespace="default",
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.event_type, "HOST_MOUNT_ESCAPE")
        self.assertEqual(event.mitre_technique, "T1611")

    # ==========================================================================
    # 6. Multi-Tenant Scoping & 4-Tier RBAC Privilege Escalation
    # ==========================================================================
    def test_rbac_privilege_escalation_blocked(self):
        devops_user = AuthenticatedIdentity(
            subject="junior-dev",
            tenant_id="tenant-marketing",
            roles=[ROLE_DEVOPS_OPERATOR],
        )
        # DevOpsOperator attempting cluster onboarding -> BLOCKED
        allowed, reason = self.auth.authorize(devops_user, PERM_CLUSTER_ONBOARD)
        self.assertFalse(allowed)
        self.assertIn("permission denied", reason)

        # DevOpsOperator attempting fleet policy management -> BLOCKED
        allowed, reason = self.auth.authorize(devops_user, PERM_FLEET_MANAGE)
        self.assertFalse(allowed)

        # DevOpsOperator scanning own tenant -> ALLOWED
        allowed, _ = self.auth.authorize(devops_user, PERM_SCAN_EXECUTE, target_tenant="tenant-marketing")
        self.assertTrue(allowed)

        # DevOpsOperator attempting cross-tenant access to finance -> BLOCKED
        allowed, reason = self.auth.authorize(devops_user, PERM_SCAN_EXECUTE, target_tenant="tenant-finance")
        self.assertFalse(allowed)
        self.assertIn("Multi-tenant violation", reason)

    def test_jwt_signature_tampering_rejected(self):
        token = self.auth.issue_jwt("tenant-acme", "user-1", [ROLE_DEVOPS_OPERATOR])
        parts = token.split(".")
        # Attacker tries to modify signature or claims
        tampered_sig = parts[2][:-4] + "AAAA"
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
        self.assertIsNone(self.auth.verify_jwt(tampered_token))

    # ==========================================================================
    # 7. Admission Webhook Mutating Gate & Remediation Invariance
    # ==========================================================================
    def test_admission_mutating_webhook_security_injection(self):
        engine = AdmissionSecurityEngine()
        raw_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "unhardened-app", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "app", "image": "nginx:1.25.0"}
                ]
            }
        }
        is_allowed, score, violations = engine.evaluate_object(raw_pod, name="unhardened-app")
        # Evaluates object and identifies required security mitigations
        self.assertGreater(len(violations), 0)
        # Generates mutation patch base64
        patch_b64 = engine.generate_mutation_patch(raw_pod)
        self.assertIsNotNone(patch_b64)
        self.assertTrue(len(patch_b64) > 0)

    def test_json_patch_decoding_and_structure(self):
        engine = AdmissionSecurityEngine()
        raw_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "app", "namespace": "prod"},
            "spec": {"containers": [{"name": "c", "image": "redis:alpine"}]}
        }
        patches = engine.generate_mutation_patch(raw_pod)
        self.assertIsInstance(patches, list)
        self.assertTrue(len(patches) > 0)
        self.assertTrue(any("securityContext" in p.get("path", "") for p in patches))

    def test_auto_remediation_invariance(self):
        insecure_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-workload
spec:
  containers:
  - name: web
    image: nginx:latest
    securityContext:
      privileged: true
"""
        before_report = self.scanner.scan_yaml_content(insecure_manifest)
        remediated_yaml, diff = auto_remediate_manifest(insecure_manifest)
        after_report = self.scanner.scan_yaml_content(remediated_yaml)

        # Remediation Invariants:
        # 1. Score after remediation must be strictly higher
        self.assertGreater(after_report.compliance_score, before_report.compliance_score)
        # 2. Privileged V01 must be completely eliminated
        self.assertNotIn("V01", after_report.detected_vuln_ids)
        # 3. Diff must be non-empty and show privileged: false
        self.assertTrue(len(diff) > 0)
        self.assertIn("privileged: false", remediated_yaml)

    # ==========================================================================
    # 8. Multi-Cloud Infrastructure CSPM Security Violations
    # ==========================================================================
    def test_multi_cloud_cspm_catches_open_ingress_and_imds(self):
        engine = CloudCSPMEngine()
        cloud_assets = {
            "aws": {
                "s3_buckets": [{"name": "leaky-bucket", "public_access_block": {"block_public_acls": False, "block_public_policy": False}}],
                "security_groups": [
                    {"id": "sg-open", "ingress_rules": [{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22}]}
                ],
                "ec2_instances": [
                    {"id": "i-vuln", "metadata_options": {"http_tokens": "optional"}}
                ]
            }
        }
        report = engine.evaluate_cloud_inventory(cloud_assets)
        self.assertLess(report.cspm_score, 70.0)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("AWS-S3-01", rule_ids)
        self.assertIn("AWS-SG-01", rule_ids)
        self.assertIn("AWS-EC2-IMDS", rule_ids)

    # ==========================================================================
    # 9. Regulatory Compliance Certification & Well-Architected Framework
    # ==========================================================================
    def test_regulatory_compliance_certification(self):
        # A fully hardened manifest must achieve 100% across all 6 frameworks
        hardened_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fully-hardened-app
  namespace: secure-ns
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            cpu: 100m
            memory: 64Mi
          requests:
            cpu: 25m
            memory: 32Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: hardened-netpol
  namespace: secure-ns
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
"""
        report = self.scanner.scan_yaml_content(hardened_manifest)
        cert = ComplianceFrameworkMapper.evaluate_findings(report.findings, target_name="hardened-app")

        # Must be 100% PASS
        self.assertEqual(cert.overall_status, "PASS")
        self.assertEqual(cert.overall_compliance_score, 100.0)

        # All 6 frameworks must be present and 100% CERTIFIED
        self.assertIn("PCI-DSS-v4.0", cert.frameworks)
        self.assertIn("SOC-2-Type-II", cert.frameworks)
        self.assertIn("HIPAA-Security-Rule", cert.frameworks)
        self.assertIn("ISO-27001-2022", cert.frameworks)
        self.assertIn("NIST-SP-800-190", cert.frameworks)
        self.assertIn("Well-Architected-Framework", cert.frameworks)

        for fw_name, fw_result in cert.frameworks.items():
            self.assertEqual(fw_result.status, "CERTIFIED", f"{fw_name} was not CERTIFIED")
            self.assertEqual(fw_result.compliance_score, 100.0, f"{fw_name} score < 100")


if __name__ == "__main__":
    unittest.main()
