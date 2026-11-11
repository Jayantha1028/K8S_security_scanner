#!/usr/bin/env python3
"""
native_scanner/dashboard.py
===========================
Interactive Web Management Console & Standalone HTML Report Generator.
Zero external runtime dependencies.
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import os
from pathlib import Path
import socketserver
import sys
import threading
from typing import Any, Dict, List, Optional, Union
import urllib.parse

try:
    from . import __version__
except Exception:
    __version__ = "1.0.0"

try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .remediate import auto_remediate_manifest
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from remediate import auto_remediate_manifest

logger = logging.getLogger("NativeDashboard")


HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kubernetes Native Security Audit Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0f172a; color: #f8fafc; font-family: ui-sans-serif, system-ui, sans-serif; }
  </style>
</head>
<body class="p-6 md:p-12 max-w-7xl mx-auto">
  <!-- Header -->
  <header class="flex flex-col md:flex-row justify-between items-start md:items-center pb-8 border-b border-slate-800 gap-4">
    <div>
      <div class="flex items-center gap-3">
        <span class="px-2.5 py-1 text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-full">v__VERSION__</span>
        <h1 class="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
          Kubernetes Native Security Scanner
        </h1>
      </div>
      <p class="text-sm text-slate-400 mt-1">Autonomous AST Manifest Audit & Attack Path DAG Verification</p>
    </div>
    <div class="text-right">
      <span class="text-xs text-slate-500 block">Generated at</span>
      <span class="text-sm font-mono text-slate-300">__GENERATED_AT__</span>
    </div>
  </header>

  <!-- Metrics Overview -->
  <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 my-8">
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Average Compliance</div>
      <div class="text-4xl font-black mt-2 __SCORE_COLOR__">__AVG_SCORE__<span class="text-lg font-normal text-slate-500">/100</span></div>
      <div class="text-xs text-slate-400 mt-2">Posture Score</div>
    </div>
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Workloads Audited</div>
      <div class="text-4xl font-black text-white mt-2">__TOTAL_WORKLOADS__</div>
      <div class="text-xs text-slate-400 mt-2">Manifests analyzed</div>
    </div>
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Findings</div>
      <div class="text-4xl font-black text-rose-400 mt-2">__TOTAL_FINDINGS__</div>
      <div class="text-xs text-slate-400 mt-2">__CRITICAL_COUNT__ Critical | __HIGH_COUNT__ High</div>
    </div>
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Cluster Blast Radius</div>
      <div class="text-4xl font-black text-amber-400 mt-2">__BLAST_RADIUS__<span class="text-lg font-normal text-slate-500">/100</span></div>
      <div class="text-xs text-slate-400 mt-2">Max Kill-Chain Impact</div>
    </div>
  </section>

  <!-- Workload Breakdown -->
  <section class="my-8">
    <h2 class="text-xl font-bold mb-4 text-slate-200">Workload Audit Details</h2>
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse text-sm">
          <thead>
            <tr class="bg-slate-800/60 border-b border-slate-700 text-slate-400 text-xs uppercase font-semibold">
              <th class="p-4">Target Resource</th>
              <th class="p-4">Score</th>
              <th class="p-4">Risk Tier</th>
              <th class="p-4">Findings</th>
              <th class="p-4">Blast Radius</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800 font-mono text-xs">
            __WORKLOAD_ROWS__
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Findings Table -->
  <section class="my-8">
    <h2 class="text-xl font-bold mb-4 text-slate-200">Detailed Security Findings</h2>
    <div class="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse text-sm">
          <thead>
            <tr class="bg-slate-800/60 border-b border-slate-700 text-slate-400 text-xs uppercase font-semibold">
              <th class="p-4">Severity</th>
              <th class="p-4">Rule ID</th>
              <th class="p-4">Title & Target</th>
              <th class="p-4">Remediation Guidance</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            __FINDING_ROWS__
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <footer class="mt-12 pt-6 border-t border-slate-800 text-center text-xs text-slate-500">
    Generated autonomously by Kubernetes Native Security Scanner v__VERSION__ • Pure-Python CNAPP Engine
  </footer>
</body>
</html>
"""


def generate_html_report(
    reports: Union[ScanReport, List[ScanReport]],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Generates an auditor-ready standalone HTML report from scan reports."""
    if isinstance(reports, ScanReport):
        reports = [reports]

    total_workloads = len(reports)
    all_findings = []
    for r in reports:
        all_findings.extend(r.findings)

    avg_score = (sum(r.compliance_score for r in reports) / total_workloads) if total_workloads > 0 else 100.0
    crit_count = sum(1 for f in all_findings if f.severity.upper() == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.severity.upper() == "HIGH")
    max_blast = max((r.blast_radius for r in reports), default=0.0)

    score_color = "text-emerald-400" if avg_score >= 80 else ("text-amber-400" if avg_score >= 50 else "text-rose-400")

    workload_rows = []
    for r in reports:
        risk_color = (
            "bg-rose-500/20 text-rose-400 border border-rose-500/30"
            if r.risk_tier == "High"
            else ("bg-amber-500/20 text-amber-400 border border-amber-500/30" if r.risk_tier == "Medium" else "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30")
        )
        workload_rows.append(f"""
        <tr class="hover:bg-slate-800/40">
          <td class="p-4 text-slate-200 font-medium">{r.manifest_path}</td>
          <td class="p-4 font-bold {score_color}">{r.compliance_score:.1f}</td>
          <td class="p-4"><span class="px-2 py-0.5 rounded text-xs font-semibold {risk_color}">{r.risk_tier}</span></td>
          <td class="p-4 text-slate-300">{len(r.findings)}</td>
          <td class="p-4 text-amber-400">{r.blast_radius:.1f}</td>
        </tr>
        """)

    finding_rows = []
    for f in all_findings:
        sev = f.severity.upper()
        badge_color = (
            "bg-rose-500/20 text-rose-400 border border-rose-500/30"
            if sev == "CRITICAL"
            else ("bg-orange-500/20 text-orange-400 border border-orange-500/30" if sev == "HIGH" else "bg-amber-500/20 text-amber-400 border border-amber-500/30")
        )
        title = getattr(f, "title", getattr(f, "name", "Security Finding"))
        finding_rows.append(f"""
        <tr class="hover:bg-slate-800/40 text-xs">
          <td class="p-4"><span class="px-2 py-0.5 rounded font-bold {badge_color}">{sev}</span></td>
          <td class="p-4 font-mono font-bold text-blue-400">{f.vuln_id}</td>
          <td class="p-4">
            <div class="font-semibold text-slate-200">{title}</div>
            <div class="font-mono text-slate-400 text-xs mt-0.5">{f.target}</div>
            <div class="text-slate-400 text-xs mt-1">{f.description}</div>
          </td>
          <td class="p-4 text-emerald-300 font-mono text-xs">{f.remediation}</td>
        </tr>
        """)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = (
        HTML_REPORT_TEMPLATE
        .replace("__VERSION__", __version__)
        .replace("__GENERATED_AT__", now_str)
        .replace("__AVG_SCORE__", f"{avg_score:.1f}")
        .replace("__SCORE_COLOR__", score_color)
        .replace("__TOTAL_WORKLOADS__", str(total_workloads))
        .replace("__TOTAL_FINDINGS__", str(len(all_findings)))
        .replace("__CRITICAL_COUNT__", str(crit_count))
        .replace("__HIGH_COUNT__", str(high_count))
        .replace("__BLAST_RADIUS__", f"{max_blast:.1f}")
        .replace("__WORKLOAD_ROWS__", "\n".join(workload_rows))
        .replace("__FINDING_ROWS__", "\n".join(finding_rows) if finding_rows else "<tr><td colspan='4' class='p-4 text-center text-slate-500'>No security findings detected. 100% compliant.</td></tr>")
    )

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")

    return html


class ThreadedDashboardServer(socketserver.ThreadingMixIn, HTTPServer):
    """High-concurrency multi-threaded HTTP server for security web console."""
    daemon_threads = True


# Live Web Management Console Handler
class DashboardHttpHandler(BaseHTTPRequestHandler):
    scanner = NativeSecurityScanner()

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;"
        )

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(self._get_console_html().encode("utf-8"))
        elif self.path == "/api/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        else:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 8 * 1024 * 1024:
            self.send_response(413)
            self._send_security_headers()
            self.end_headers()
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if self.path == "/api/scan":
            yaml_str = payload.get("yaml", "")
            report = self.scanner.scan_yaml_content(yaml_str)
            resp = {
                "compliance_score": report.compliance_score,
                "risk_tier": report.risk_tier,
                "blast_radius": report.blast_radius,
                "findings": [
                    {
                        "vuln_id": f.vuln_id,
                        "severity": f.severity,
                        "title": getattr(f, "title", getattr(f, "name", "Finding")),
                        "target": f.target,
                        "description": f.description,
                        "remediation": f.remediation,
                    }
                    for f in report.findings
                ],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif self.path == "/api/remediate":
            yaml_str = payload.get("yaml", "")
            hardened, diff_lines = auto_remediate_manifest(yaml_str)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({
                "hardened_yaml": hardened,
                "changes_count": len(diff_lines),
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()

    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")

    @staticmethod
    def _get_console_html() -> str:
        return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <title>K8s Native Security Management Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body {{ background-color: #0b0f19; color: #f3f4f6; }}</style>
</head>
<body class="p-8 max-w-6xl mx-auto">
  <div class="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
    <h1 class="text-2xl font-bold bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
      Kubernetes Native Security Web Console v{__version__}
    </h1>
    <span class="text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-3 py-1 rounded-full">Server Active</span>
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
    <div>
      <label class="block text-sm font-semibold mb-2">Kubernetes YAML Manifest</label>
      <textarea id="manifestInput" rows="18" class="w-full bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-blue-500" placeholder="Paste Deployment / Pod YAML here..."></textarea>
      <div class="mt-4 flex gap-3">
        <button onclick="scanManifest()" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs rounded-xl shadow-lg transition">Audit Security AST</button>
        <button onclick="remediateManifest()" class="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-lg transition">1-Click Auto-Remediate</button>
      </div>
    </div>

    <div>
      <label class="block text-sm font-semibold mb-2">Real-Time Evaluation Result</label>
      <div id="resultBox" class="w-full bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-y-auto h-[440px] text-slate-400">
        Ready to scan. Paste a manifest on the left and click 'Audit Security AST'.
      </div>
    </div>
  </div>

  <script>
    async function scanManifest() {{
      const yaml = document.getElementById('manifestInput').value;
      const res = await fetch('/api/scan', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ yaml }})
      }});
      const data = await res.json();
      document.getElementById('resultBox').innerHTML = `<pre class="text-emerald-400 font-bold mb-3">Score: ${{data.compliance_score}}/100 | Risk: ${{data.risk_tier}} | Blast Radius: ${{data.blast_radius}}</pre>` +
        data.findings.map(f => `<div class="p-2 mb-2 bg-slate-800/80 rounded border border-slate-700"><span class="text-rose-400 font-bold">[${{f.severity}}] ${{f.vuln_id}}</span>: ${{f.title}}<br/><span class="text-slate-400">${{f.target}}</span><br/><span class="text-blue-300">Fix: ${{f.remediation}}</span></div>`).join('');
    }}

    async function remediateManifest() {{
      const yaml = document.getElementById('manifestInput').value;
      const res = await fetch('/api/remediate', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ yaml }})
      }});
      const data = await res.json();
      document.getElementById('manifestInput').value = data.hardened_yaml;
      document.getElementById('resultBox').innerHTML = `<div class="text-emerald-400 font-bold">Successfully applied least-privilege securityContext hardening. Click 'Audit Security AST' to re-verify score.</div>`;
    }}
  </script>
</body>
</html>
"""


def start_dashboard_server(host: str = "127.0.0.1", port: int = 8080):
    """Spawns the local web console HTTP server."""
    server = ThreadedDashboardServer((host, port), DashboardHttpHandler)
    print(f"\n[✓] Kubernetes Native Security Web Console live at: http://{host}:{port}/")
    print("    Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
        server.server_close()
