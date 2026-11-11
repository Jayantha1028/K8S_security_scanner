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
from typing import List, Optional

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

        if args.min_score and report.compliance_score < args.min_score:
            print(f"\n[!] Security Gate FAILED: Score {report.compliance_score:.1f} < threshold {args.min_score}")
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

    out_path = Path(args.output) if args.output else target
    out_path.write_text(remediated, encoding="utf-8")
    print(f"[✓] Remediated manifest saved to: {out_path}")
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
    p_ebpf = subparsers.add_parser("ebpf", help="Inspect in-tree eBPF kernel tracepoint status")

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


if __name__ == "__main__":
    main()
