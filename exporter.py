#!/usr/bin/env python3
"""
native_scanner/exporter.py
==========================
Zero-Dependency Prometheus & OpenMetrics Exporter for Kubernetes Security Posture.

Translates AST scanner security findings, compliance scores, blast radius indices,
and regulatory frameworks into standard Prometheus OpenMetrics.

Capabilities:
1. Static Textfile Exporter:
   Generates a standard .prom file for Prometheus node_exporter textfile collector
   or CI/CD metric ingestion.
2. Live HTTP Daemon (/metrics):
   Spins up a lightweight threaded HTTP daemon on port 9108 for scraping by
   Prometheus servers and Grafana dashboards.
"""

from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
from pathlib import Path
import socketserver
import sys
import threading
import time
from typing import Any, Dict, List, Optional

try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .compliance import ComplianceFrameworkMapper
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from compliance import ComplianceFrameworkMapper

logger = logging.getLogger("NativeScanner.Exporter")


class ThreadedPrometheusServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class PrometheusMetricsExporter:
    """Generates standard OpenMetrics / Prometheus metrics from Kubernetes scan reports."""

    def __init__(self):
        self.scanner = NativeSecurityScanner()

    def generate_metrics(self, reports: List[ScanReport]) -> str:
        """Converts a collection of ScanReports into OpenMetrics text representation."""
        if not reports:
            return "# No scan reports available\n"

        total_workloads = sum(r.workloads_scanned for r in reports) or len(reports)
        avg_score = sum(r.compliance_score for r in reports) / len(reports)
        max_blast = max((r.blast_radius for r in reports), default=0.0)

        # Findings aggregated by severity and plane
        sev_counts: Counter = Counter()
        plane_counts: Counter = Counter()
        for r in reports:
            for f in r.findings:
                sev_counts[f.severity.upper()] += 1
                plane_counts[f.plane] += 1

        lines = [
            "# HELP k8s_security_cluster_compliance_score Overall Kubernetes security compliance score (0-100)",
            "# TYPE k8s_security_cluster_compliance_score gauge",
            f"k8s_security_cluster_compliance_score {avg_score:.2f}",
            "",
            "# HELP k8s_security_cluster_blast_radius Max lateral exploit kill-chain blast radius (0-100)",
            "# TYPE k8s_security_cluster_blast_radius gauge",
            f"k8s_security_cluster_blast_radius {max_blast:.2f}",
            "",
            "# HELP k8s_security_workloads_total Total count of evaluated Kubernetes workloads",
            "# TYPE k8s_security_workloads_total gauge",
            f"k8s_security_workloads_total {total_workloads}",
            "",
            "# HELP k8s_security_workload_compliance_score Individual workload security posture score",
            "# TYPE k8s_security_workload_compliance_score gauge",
        ]

        for r in reports:
            target = r.manifest_path.replace('"', '\\"')
            lines.append(
                f'k8s_security_workload_compliance_score{{target="{target}",risk_tier="{r.risk_tier}"}} {r.compliance_score:.2f}'
            )

        lines.extend([
            "",
            "# HELP k8s_security_findings_total Total security findings by severity",
            "# TYPE k8s_security_findings_total counter",
        ])
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            lines.append(f'k8s_security_findings_total{{severity="{sev}"}} {sev_counts[sev]}')

        lines.extend([
            "",
            "# HELP k8s_security_plane_findings_total Security findings grouped by defense plane (1-7)",
            "# TYPE k8s_security_plane_findings_total counter",
        ])
        for plane in range(1, 8):
            lines.append(f'k8s_security_plane_findings_total{{plane="{plane}"}} {plane_counts[plane]}')

        # Add regulatory compliance percentage
        try:
            mapper = ComplianceFrameworkMapper()
            all_findings = [f for r in reports for f in r.findings]
            cert = mapper.evaluate(all_findings, avg_score, max_blast, reports[0].manifest_path if reports else "cluster")
            lines.extend([
                "",
                "# HELP k8s_security_framework_compliance_score Regulatory framework pass rate (0-100)",
                "# TYPE k8s_security_framework_compliance_score gauge",
                f'k8s_security_framework_compliance_score{{framework="CIS_v2"}} {cert.cis_k8s_v2_score:.2f}',
                f'k8s_security_framework_compliance_score{{framework="NSA_CISA"}} {cert.nsa_cisa_score:.2f}',
                f'k8s_security_framework_compliance_score{{framework="MITRE_ATTCK"}} {cert.mitre_attack_coverage:.2f}',
            ])
        except Exception:
            pass

        lines.append("")
        return "\n".join(lines)

    def export_to_file(self, reports: List[ScanReport], output_path: str) -> str:
        """Export metrics to a standard .prom file."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        text = self.generate_metrics(reports)
        p.write_text(text, encoding="utf-8")
        return str(p)

    def start_metrics_server(self, target_path: str, port: int = 9108, host: str = "0.0.0.0"):
        """Run continuous HTTP daemon serving /metrics endpoint."""
        scanner = self.scanner
        exporter = self

        class MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/metrics", "/"):
                    p = Path(target_path)
                    if p.is_file():
                        reports = [scanner.scan_file(str(p))]
                    elif p.is_dir():
                        reports = scanner.scan_directory(str(p))
                    else:
                        reports = []

                    output = exporter.generate_metrics(reports).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(output)))
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(output)
                elif self.path == "/healthz":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                logger.debug(f"{self.address_string()} - {format % args}")

        server = ThreadedPrometheusServer((host, port), MetricsHandler)
        print(f"\n[✓] Prometheus Metrics Exporter live at: http://{host}:{port}/metrics")
        print(f"    Target: {target_path} | Scraping interval: On-Demand")
        print("    Press Ctrl+C to terminate.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping metrics server...")
            server.server_close()
