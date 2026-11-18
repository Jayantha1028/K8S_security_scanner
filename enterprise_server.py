#!/usr/bin/env python3
"""
enterprise_server.py
====================
Enterprise Multi-Tenant REST API Server & Built-in Multi-Cluster Console.

Capabilities:
1. Pure-Python Multi-Tenant REST API with zero external runtime dependencies.
2. 4-Tier RBAC & JWT/API-Key Authorization Middleware.
3. Central Fleet Management Endpoints:
   - Cluster Registration & Heartbeat
   - KubeCam Runtime Drift Frame Ingestion
   - Global Threat Index & Heatmap
   - Zero-Trust Fleet Policy Distribution
4. Security Engine Endpoints:
   - On-Demand Workload Scanner (56 Security Rules, 32-D Threat Vector)
   - Auto-Remediation Engine with Unified Diff
   - Contextual Exploitability & OpenVEX Generator
   - Regulatory Compliance Attestation (CIS, NSA, SOC2, PCI-DSS, MITRE)
   - Native eBPF Kernel Telemetry & SIEM Event Streaming (CEF / RFC 5424)
   - Prometheus Metrics Exposition (/metrics)
5. Built-in Embedded HTML5/CSS3 Multi-Cluster Security Portal.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    from .auth import (
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
        PERM_AUDIT_LOGS_READ,
        PERM_TELEMETRY_READ,
    )
    from .fleet import FleetManager, ClusterRecord, FleetPolicy
    from .ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from .scanner import NativeSecurityScanner
    from .remediate import auto_remediate_manifest
    from .vex import ContextualVEXEngine
    from .compliance import ComplianceFrameworkMapper
    from .openapi import get_openapi_spec, get_swagger_ui_html
    from .storage import EnterpriseStorageEngine, TelemetryQueryFilter
    from .notifications import NotificationDispatcher, AlertPayload
except ImportError:
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
        PERM_AUDIT_LOGS_READ,
        PERM_TELEMETRY_READ,
    )
    from fleet import FleetManager, ClusterRecord, FleetPolicy
    from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from scanner import NativeSecurityScanner
    from remediate import auto_remediate_manifest
    from vex import ContextualVEXEngine
    from compliance import ComplianceFrameworkMapper
    from openapi import get_openapi_spec, get_swagger_ui_html
    from storage import EnterpriseStorageEngine, TelemetryQueryFilter
    from notifications import NotificationDispatcher, AlertPayload

logger = logging.getLogger("NativeScanner.EnterpriseServer")


def get_embedded_dashboard_html() -> str:
    """Returns the pure HTML5/CSS3 responsive enterprise fleet console."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kubernetes Native Security | Hyperscale CNAPP Console</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151d2f;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #23314d;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --critical: #dc2626;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    .logo { font-size: 1.4rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }
    .badge-pill { background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid #3b82f6; padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 28px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
    .card h3 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 8px; }
    .card .value { font-size: 2rem; font-weight: 800; }
    .card .sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
    tr:hover { background: rgba(255,255,255,0.02); }
    .status-tag { padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }
    .status-active { background: rgba(16,185,129,0.15); color: var(--success); }
    .status-danger { background: rgba(239,68,68,0.15); color: var(--danger); }
    .section-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    .footer { margin-top: 40px; text-align: center; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); padding-top: 16px; }
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <span>🛡️ Kubernetes Native Security</span>
      <span class="badge-pill">Enterprise CNAPP Fleet</span>
    </div>
    <div>
      <span style="font-size: 0.85rem; color: var(--text-muted); margin-right: 12px;">Active Tenant: <strong>default-tenant</strong></span>
      <button onclick="fetchFleetData()" style="background: var(--accent); color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600;">Refresh Fleet</button>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h3>Global Threat Index</h3>
      <div class="value" id="threatIndex" style="color: var(--success);">0.0</div>
      <div class="sub">Fleet-wide Risk Metric (0 - 100)</div>
    </div>
    <div class="card">
      <h3>Active Clusters</h3>
      <div class="value" id="activeClusters">0 / 0</div>
      <div class="sub">AWS EKS, GCP GKE, Azure AKS</div>
    </div>
    <div class="card">
      <h3>Monitored Pods</h3>
      <div class="value" id="monitoredPods">0</div>
      <div class="sub">Continuous KubeCam & eBPF Telemetry</div>
    </div>
    <div class="card">
      <h3>Critical Findings</h3>
      <div class="value" id="criticalFindings" style="color: var(--critical);">0</div>
      <div class="sub">Fleet-wide Security Deficits</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <div class="section-title">🌐 Multi-Cluster Fleet Matrix</div>
    <table>
      <thead>
        <tr>
          <th>Cluster Name</th>
          <th>Provider / Region</th>
          <th>Kubernetes</th>
          <th>Security Score</th>
          <th>Threat Index</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="clustersBody">
        <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading fleet data...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="section-title">⚡ Real-Time eBPF Kernel Intrusion Stream</div>
    <div id="ebpfStream" style="font-family: monospace; font-size: 0.85rem; background: #070a11; padding: 16px; border-radius: 8px; max-height: 200px; overflow-y: auto; color: #a5b4fc;">
      Waiting for kernel events (execve, sensitive file open, namespace escape)...
    </div>
  </div>

  <div class="footer">
    Kubernetes Native Security Engine 2.0 &bull; Built-in Zero-Trust Fleet Controller &bull; Pure Python Standard Library
  </div>

  <script>
    async function fetchFleetData() {
      try {
        const res = await fetch('/api/v1/fleet/overview');
        if (!res.ok) return;
        const data = await res.json();
        const summary = data.summary || {};
        document.getElementById('threatIndex').innerText = summary.global_threat_index ?? 0.0;
        document.getElementById('threatIndex').style.color = (summary.global_threat_index > 50) ? '#ef4444' : '#10b981';
        document.getElementById('activeClusters').innerText = `${summary.active_clusters ?? 0} / ${summary.total_clusters ?? 0}`;
        document.getElementById('monitoredPods').innerText = summary.total_pods_monitored ?? 0;
        document.getElementById('criticalFindings').innerText = summary.critical_findings_total ?? 0;

        const clusters = data.heatmap?.clusters || [];
        const tbody = document.getElementById('clustersBody');
        if (clusters.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No clusters currently connected. Register via /api/v1/fleet/clusters/register</td></tr>';
        } else {
          tbody.innerHTML = clusters.map(c => `
            <tr>
              <td><strong>${c.name}</strong> <span style="font-size:0.75rem; color:#64748b;">(${c.cluster_id})</span></td>
              <td>${c.cloud_provider.toUpperCase()} &bull; ${c.region}</td>
              <td>v1.28.0</td>
              <td><span style="font-weight:700; color:${c.security_score >= 80 ? '#10b981' : '#f59e0b'}">${c.security_score}%</span></td>
              <td><span style="font-weight:700; color:${c.threat_index > 40 ? '#ef4444' : '#10b981'}">${c.threat_index}</span></td>
              <td><span class="status-tag ${c.status === 'ACTIVE' ? 'status-active' : 'status-danger'}">${c.status}</span></td>
            </tr>
          `).join('');
        }
      } catch (e) {
        console.error('Error fetching fleet data', e);
      }
    }
    fetchFleetData();
    setInterval(fetchFleetData, 5000);
  </script>
</body>
</html>
"""


class EnterpriseAPIHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler implementing RESTful endpoints, RBAC enforcement,
    and enterprise multi-cluster aggregation.
    """

    # Server components injected by EnterpriseServer
    auth_manager: EnterpriseAuthManager
    fleet_manager: FleetManager
    ebpf_engine: EBPFTelemetryEngine
    siem_forwarder: SIEMForwarder
    scanner: NativeSecurityScanner
    vex_engine: ContextualVEXEngine
    storage_engine: Optional[EnterpriseStorageEngine] = None
    notification_dispatcher: Optional[NotificationDispatcher] = None

    def log_message(self, format: str, *args: Any):
        # Silence default stderr logging to keep tests and CLI clean
        logger.debug(f"{self.address_string()} - {format % args}")

    # --------------------------------------------------------------------------
    # CORS & Common Header Helpers
    # --------------------------------------------------------------------------
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Tenant-ID")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, status_code: int, data: Any):
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status_code: int, content: str, content_type: str = "text/plain"):
        payload = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                return {}
            # Safety limit: 10MB
            if content_length > 10 * 1024 * 1024:
                return {}
            raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            return json.loads(raw_body)
        except Exception:
            return {}

    # --------------------------------------------------------------------------
    # Identity & Authorization Middleware
    # --------------------------------------------------------------------------
    def _authenticate_request(self) -> Optional[AuthenticatedIdentity]:
        """Resolves identity from Bearer JWT or X-API-Key header."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            return self.auth_manager.verify_jwt(token)

        api_key = self.headers.get("X-API-Key", "")
        if api_key:
            return self.auth_manager.verify_api_key(api_key)

        return None

    def _authorize(self, required_perm: str) -> Tuple[bool, Optional[AuthenticatedIdentity], str]:
        identity = self._authenticate_request()
        if not identity:
            # Check if dev anonymous mode or missing auth
            return False, None, "Authentication credentials (Bearer token or X-API-Key) required."
        allowed, reason = self.auth_manager.authorize(identity, required_perm)
        return allowed, identity, reason

    # --------------------------------------------------------------------------
    # GET Router
    # --------------------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Health Probe
        if path in ("/healthz", "/readyz"):
            self._send_json(200, {"status": "HEALTHY", "version": "2.0.0"})
            return

        # 2. Embedded Web Dashboard & Swagger UI Documentation
        if path in ("/", "/dashboard", "/console"):
            self._send_text(200, get_embedded_dashboard_html(), "text/html")
            return

        if path in ("/docs", "/swagger"):
            self._send_text(200, get_swagger_ui_html(openapi_url="/api/v1/openapi.json"), "text/html")
            return

        # 2.1 OpenAPI 3.0.3 Specification
        if path == "/api/v1/openapi.json":
            self._send_json(200, get_openapi_spec())
            return

        # 2.2 Storage Engine Health & Stats
        if path == "/api/v1/storage/stats":
            if self.storage_engine:
                self._send_json(200, self.storage_engine.get_stats())
            else:
                self._send_json(200, {"status": "uninitialized"})
            return

        # 3. Prometheus Metrics Exposition
        if path == "/metrics":
            summary = self.fleet_manager.get_fleet_summary()
            metrics_lines = [
                "# HELP k8s_fleet_clusters_total Total registered Kubernetes clusters",
                "# TYPE k8s_fleet_clusters_total gauge",
                f"k8s_fleet_clusters_total {summary.total_clusters}",
                "# HELP k8s_fleet_clusters_active Active reporting clusters",
                "# TYPE k8s_fleet_clusters_active gauge",
                f"k8s_fleet_clusters_active {summary.active_clusters}",
                "# HELP k8s_fleet_threat_index Global fleet threat index (0 - 100)",
                "# TYPE k8s_fleet_threat_index gauge",
                f"k8s_fleet_threat_index {summary.global_threat_index}",
                "# HELP k8s_fleet_security_score Average fleet security score (0 - 100)",
                "# TYPE k8s_fleet_security_score gauge",
                f"k8s_fleet_security_score {summary.average_security_score}",
                "# HELP k8s_fleet_critical_findings Total critical findings across fleet",
                "# TYPE k8s_fleet_critical_findings counter",
                f"k8s_fleet_critical_findings {summary.critical_findings_total}",
            ]
            self._send_text(200, "\n".join(metrics_lines) + "\n", "text/plain; version=0.0.4")
            return

        # 4. Fleet Overview & Heatmap (Open to console / authenticated users)
        if path == "/api/v1/fleet/overview":
            tenant_id = query.get("tenant_id", [None])[0]
            summary = self.fleet_manager.get_fleet_summary(tenant_id)
            heatmap = self.fleet_manager.get_fleet_heatmap(tenant_id)
            self._send_json(200, {"summary": summary.to_dict(), "heatmap": heatmap})
            return

        # 5. List Clusters
        if path == "/api/v1/fleet/clusters":
            tenant_id = query.get("tenant_id", [None])[0]
            clusters = self.fleet_manager.list_clusters(tenant_id)
            self._send_json(200, {"clusters": [c.to_dict() for c in clusters]})
            return

        # 6. Compliance Certificate Attestation
        if path == "/api/v1/compliance/certificate":
            allowed, identity, reason = self._authorize(PERM_COMPLIANCE_READ)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            target = query.get("target", ["fleet-production"])[0]
            cert = ComplianceFrameworkMapper.evaluate_findings([], target_name=target)
            self._send_json(200, cert.to_dict())
            return

        # 7. eBPF Telemetry Events Stream
        if path == "/api/v1/ebpf/events":
            allowed, identity, reason = self._authorize(PERM_TELEMETRY_READ)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            fmt = query.get("format", ["JSON"])[0].upper()
            events = self.ebpf_engine.get_recent_events(limit=50)
            if fmt == "CEF":
                self._send_text(200, "\n".join([e.to_cef() for e in events]), "text/plain")
            elif fmt in ("RFC5424", "SYSLOG"):
                self._send_text(200, "\n".join([e.to_rfc5424_syslog() for e in events]), "text/plain")
            else:
                self._send_json(200, {"events": [e.to_dict() for e in events]})
            return

        self._send_json(404, {"error": f"Endpoint '{path}' not found."})

    # --------------------------------------------------------------------------
    # POST Router
    # --------------------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        # 1. Issue JWT Token (Authentication Gateway)
        if path == "/api/v1/auth/token":
            tenant = body.get("tenant_id", "default-tenant")
            subject = body.get("subject", "devops-engineer")
            roles = body.get("roles", [ROLE_DEVOPS_OPERATOR])
            token = self.auth_manager.issue_jwt(tenant_id=tenant, subject=subject, roles=roles)
            self._send_json(200, {"token": token, "token_type": "Bearer", "expires_in": 3600})
            return

        # 2. Generate API Key (Requires Admin)
        if path == "/api/v1/auth/api-key":
            allowed, identity, reason = self._authorize(PERM_FLEET_MANAGE)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            tenant = body.get("tenant_id", identity.tenant_id if identity else "default-tenant")
            subject = body.get("subject", "service-account")
            roles = body.get("roles", [ROLE_SECURITY_ENGINEER])
            raw_key, record = self.auth_manager.generate_api_key(tenant_id=tenant, subject=subject, roles=roles)
            self._send_json(201, {"api_key": raw_key, "key_id": record.key_id, "expires_at": record.expires_at})
            return

        # 3. Register Cluster
        if path == "/api/v1/fleet/clusters/register":
            allowed, identity, reason = self._authorize(PERM_CLUSTER_ONBOARD)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            cid = body.get("cluster_id") or f"cls-{int(time.time())}"
            name = body.get("name", "kubernetes-cluster")
            tenant = body.get("tenant_id") or (identity.tenant_id if identity else "default-tenant")
            record = self.fleet_manager.register_cluster(
                cluster_id=cid,
                name=name,
                tenant_id=tenant,
                cloud_provider=body.get("cloud_provider", "aws"),
                region=body.get("region", "us-east-1"),
                kubernetes_version=body.get("kubernetes_version", "v1.28.0"),
                node_count=int(body.get("node_count", 3)),
                labels=body.get("labels", {}),
            )
            self._send_json(201, record.to_dict())
            return

        # 4. Heartbeat & Ingest KubeCam Frame
        if path in ("/api/v1/fleet/heartbeat", "/api/v1/fleet/frames/ingest"):
            cid = body.get("cluster_id")
            if not cid:
                self._send_json(400, {"error": "Missing 'cluster_id' parameter."})
                return
            try:
                res = self.fleet_manager.ingest_cluster_frame(cid, body)
                self._send_json(200, res)
            except KeyError as e:
                self._send_json(404, {"error": str(e)})
            return

        # 5. Distribute Fleet Policy
        if path == "/api/v1/fleet/policy/distribute":
            allowed, identity, reason = self._authorize(PERM_POLICY_WRITE)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            tenant = body.get("tenant_id") or (identity.tenant_id if identity else "default-tenant")
            policy_id = body.get("policy_id", "pol-default-zerotrust")
            try:
                res = self.fleet_manager.distribute_fleet_policy(tenant, policy_id)
                self._send_json(200, res)
            except KeyError as e:
                self._send_json(404, {"error": str(e)})
            return

        # 6. On-Demand Manifest Scan
        if path == "/api/v1/scan":
            allowed, identity, reason = self._authorize(PERM_SCAN_EXECUTE)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            manifest_str = body.get("manifest") or body.get("yaml", "")
            if not manifest_str:
                self._send_json(400, {"error": "Missing 'manifest' content in JSON payload."})
                return
            report = self.scanner.scan_yaml_content(manifest_str)
            res_dict = report.to_dict()
            res_dict["security_score"] = report.compliance_score
            self._send_json(200, res_dict)
            return

        # 7. Auto-Remediation
        if path == "/api/v1/remediate":
            allowed, identity, reason = self._authorize(PERM_REMEDIATE_WRITE)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            manifest_str = body.get("manifest") or body.get("yaml", "")
            if not manifest_str:
                self._send_json(400, {"error": "Missing 'manifest' in JSON payload."})
                return
            remediated_yaml, diff = auto_remediate_manifest(manifest_str)
            self._send_json(200, {"remediated_yaml": remediated_yaml, "diff": diff})
            return

        # 8. Contextual VEX Document
        if path == "/api/v1/vex":
            manifest_str = body.get("manifest") or body.get("yaml", "")
            img = body.get("image_name")
            doc = self.vex_engine.generate_vex_for_manifest(manifest_str, image_name=img)
            self._send_json(200, doc.to_dict())
            return

        # 9. Simulate eBPF Event (SIEM integration testing)
        if path == "/api/v1/ebpf/simulate":
            event_type = body.get("event_type", "EXECVE")
            pid = int(body.get("pid", 4120))
            comm = body.get("comm", "sh")
            binary = body.get("binary", "/bin/sh")
            pod = body.get("pod_name", "checkout-service-7f89d")
            ns = body.get("namespace", "production")

            if event_type == "EXECVE":
                evt = self.ebpf_engine.evaluate_execve_event(pid, comm, binary, [comm, "-i"], pod, ns)
            elif event_type == "FILE_OPEN":
                evt = self.ebpf_engine.evaluate_file_open_event(pid, comm, body.get("filepath", "/etc/shadow"), 0, pod, ns)
            else:
                evt = self.ebpf_engine.evaluate_mount_event(pid, comm, "/dev/sda1", "/mnt/host", "ext4", pod, ns)

            if evt:
                self.siem_forwarder.push(evt)
                if self.storage_engine:
                    self.storage_engine.save_telemetry_event(
                        tenant_id=body.get("tenant_id", "default"),
                        cluster_id=body.get("cluster_id", "default"),
                        event_id=evt.event_id,
                        event_type=evt.event_type,
                        severity=evt.severity,
                        pod_name=evt.pod_name,
                        namespace=evt.namespace,
                        comm=evt.comm,
                        description=evt.description,
                        raw_dict=evt.to_dict(),
                    )
                self._send_json(201, {"event": evt.to_dict(), "cef": evt.to_cef()})
            else:
                self._send_json(200, {"status": "BENIGN", "message": "No security violation detected."})
            return

        # 10. Query Historical Telemetry from Persistent Storage
        if path == "/api/v1/telemetry/query":
            allowed, identity, reason = self._authorize(PERM_TELEMETRY_READ)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            if not self.storage_engine:
                self._send_json(500, {"error": "Storage engine uninitialized."})
                return
            qfilter = TelemetryQueryFilter(
                tenant_id=body.get("tenant_id") or (identity.tenant_id if identity else None),
                cluster_id=body.get("cluster_id"),
                min_severity=body.get("min_severity"),
                limit=int(body.get("limit", 100)),
            )
            events = self.storage_engine.query_telemetry_events(qfilter)
            self._send_json(200, {"events": events, "count": len(events)})
            return

        # 11. Dispatch Incident Notification (ChatOps / PagerDuty)
        if path == "/api/v1/notifications/alert":
            allowed, identity, reason = self._authorize(PERM_FLEET_MANAGE)
            if not allowed:
                self._send_json(403, {"error": reason})
                return
            channel = body.get("channel", "slack").lower()
            url = body.get("webhook_url", "")
            alert = AlertPayload(
                title=body.get("title", "Security Alert"),
                severity=body.get("severity", "HIGH"),
                description=body.get("description", ""),
                cluster_id=body.get("cluster_id", "default"),
                namespace=body.get("namespace", "default"),
                workload_name=body.get("workload_name", ""),
                remediation=body.get("remediation", ""),
            )
            try:
                if channel == "slack":
                    ok = NotificationDispatcher.send_slack_alert(url, alert)
                elif channel == "teams":
                    ok = NotificationDispatcher.send_teams_alert(url, alert)
                elif channel == "pagerduty":
                    ok = NotificationDispatcher.send_pagerduty_event(body.get("routing_key", ""), alert)
                else:
                    self._send_json(400, {"error": f"Unsupported channel: {channel}"})
                    return
                self._send_json(200, {"status": "DISPATCHED" if ok else "FAILED"})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        self._send_json(404, {"error": f"Endpoint '{path}' not found."})


class EnterpriseServer:
    """
    Manages the lifecycle of the Enterprise Multi-Tenant CNAPP Server.
    Can be run in a daemon thread (for integration tests/background service)
    or foreground (via CLI).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8443,
        auth_manager: Optional[EnterpriseAuthManager] = None,
        fleet_manager: Optional[FleetManager] = None,
        storage_engine: Optional[EnterpriseStorageEngine] = None,
        notification_dispatcher: Optional[NotificationDispatcher] = None,
    ):
        self.host = host
        self.port = port
        self.auth_manager = auth_manager or EnterpriseAuthManager()
        self.fleet_manager = fleet_manager or FleetManager()
        self.storage_engine = storage_engine or EnterpriseStorageEngine()
        self.notification_dispatcher = notification_dispatcher or NotificationDispatcher()
        self.ebpf_engine = EBPFTelemetryEngine()
        self.siem_forwarder = SIEMForwarder("CEF")
        self.scanner = NativeSecurityScanner()
        self.vex_engine = ContextualVEXEngine()

        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    def start(self, background: bool = True):
        """Starts the enterprise HTTP server."""
        # Setup handler class attributes
        EnterpriseAPIHandler.auth_manager = self.auth_manager
        EnterpriseAPIHandler.fleet_manager = self.fleet_manager
        EnterpriseAPIHandler.ebpf_engine = self.ebpf_engine
        EnterpriseAPIHandler.siem_forwarder = self.siem_forwarder
        EnterpriseAPIHandler.scanner = self.scanner
        EnterpriseAPIHandler.vex_engine = self.vex_engine
        EnterpriseAPIHandler.storage_engine = self.storage_engine
        EnterpriseAPIHandler.notification_dispatcher = self.notification_dispatcher

        # Bind server (allow port reuse)
        class ReusableServer(HTTPServer):
            allow_reuse_address = True

        self._httpd = ReusableServer((self.host, self.port), EnterpriseAPIHandler)
        self._is_running = True
        logger.info(f"Enterprise CNAPP REST Server listening on http://{self.host}:{self.port}")

        if background:
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()
        else:
            try:
                self._httpd.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        """Stops the enterprise HTTP server gracefully."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Enterprise CNAPP REST Server stopped.")

    @property
    def is_running(self) -> bool:
        return self._is_running
