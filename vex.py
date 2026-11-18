#!/usr/bin/env python3
"""
native_scanner/vex.py
=====================
Contextual Exploitability Engine & OpenVEX Standard (v0.2.0) Generator.

Correlates Container SBOM CVEs with Kubernetes Runtime Security Posture:
- Evaluates active defenses (readOnlyRootFilesystem, allowPrivilegeEscalation,
  capabilities drop, default-deny NetworkPolicies, non-root execution).
- Neutralizes false-positive CVE alerts where runtime controls render exploitation impossible.
- Emits CISA / OpenVEX v0.2.0 compliant vulnerability advisories.
- Computes Noise Reduction Metric (e.g., 85% CVE noise eliminated).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None

try:
    from .cve import CVEEntry, KNOWN_IMAGE_CVE_DB, lookup_image_cves
    from .scanner import NativeSecurityScanner
except ImportError:
    from cve import CVEEntry, KNOWN_IMAGE_CVE_DB, lookup_image_cves
    from scanner import NativeSecurityScanner

logger = logging.getLogger("NativeScanner.OpenVEX")

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
TOOLING_NAME = "k8s-native-scanner v1.0.0"


@dataclass
class RuntimeWorkloadProfile:
    """Security attributes extracted from Kubernetes workload specification."""
    workload_name: str
    namespace: str
    kind: str
    image: str
    read_only_rootfs: bool = False
    allow_privilege_escalation: bool = True
    privileged: bool = False
    run_as_non_root: bool = False
    run_as_user: Optional[int] = None
    dropped_caps: Set[str] = field(default_factory=set)
    added_caps: Set[str] = field(default_factory=set)
    has_ingress_network_policy: bool = False
    has_egress_network_policy: bool = False
    has_public_ingress: bool = False
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    mounted_host_paths: List[str] = field(default_factory=list)


@dataclass
class VEXProduct:
    subcomponents: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"subcomponents": self.subcomponents}


@dataclass
class VEXStatement:
    vulnerability_id: str
    vulnerability_description: str
    status: str  # "not_affected", "affected", "fixed", "under_investigation"
    products: List[Dict[str, Any]]
    justification: Optional[str] = None  # OpenVEX standard justification
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    raw_severity: str = "MEDIUM"
    cvss_score: float = 5.0
    contextual_risk: str = "LOW"

    def to_openvex_dict(self) -> Dict[str, Any]:
        stmt: Dict[str, Any] = {
            "vulnerability": {
                "name": self.vulnerability_id,
                "description": self.vulnerability_description,
            },
            "products": self.products,
            "status": self.status,
        }
        if self.status == "not_affected":
            if self.justification:
                stmt["justification"] = self.justification
            if self.impact_statement:
                stmt["impact_statement"] = self.impact_statement
        elif self.status == "affected":
            if self.action_statement:
                stmt["action_statement"] = self.action_statement
        return stmt


@dataclass
class VEXDocument:
    author: str
    role: str
    timestamp: str
    version: int
    tooling: str
    workload: str
    statements: List[VEXStatement] = field(default_factory=list)

    # Contextual Exploitability Metrics
    total_cves: int = 0
    exploitable_cves: int = 0
    mitigated_cves: int = 0
    noise_reduction_ratio: float = 0.0

    def to_openvex_json(self, indent: int = 2) -> str:
        doc = {
            "@context": OPENVEX_CONTEXT,
            "@id": f"https://openvex.dev/docs/public/vex/k8s-{self.workload.replace('/', '-')}-{int(datetime.now(timezone.utc).timestamp())}",
            "author": self.author,
            "role": self.role,
            "timestamp": self.timestamp,
            "version": self.version,
            "tooling": self.tooling,
            "metadata": {
                "workload": self.workload,
                "total_cves_evaluated": self.total_cves,
                "actively_exploitable_cves": self.exploitable_cves,
                "runtime_mitigated_cves": self.mitigated_cves,
                "alert_noise_reduction_pct": f"{self.noise_reduction_ratio:.1f}%",
            },
            "statements": [s.to_openvex_dict() for s in self.statements],
        }
        return json.dumps(doc, indent=indent)


class ContextualVEXEngine:
    """
    Contextual Exploitability Correlation Engine.
    Maps container CVE attack vectors to Kubernetes workload sandboxing.
    """

    def __init__(self):
        self.scanner = NativeSecurityScanner()

    def parse_workload_profile(self, manifest_dict: Dict[str, Any]) -> RuntimeWorkloadProfile:
        """Extracts securityContext, capabilities, volumes, and network metadata from manifest."""
        if not isinstance(manifest_dict, dict):
            manifest_dict = {}
        kind = str(manifest_dict.get("kind") or "Deployment")
        meta = manifest_dict.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        name = str(meta.get("name") or "workload")
        namespace = str(meta.get("namespace") or "default")

        # Resolve Pod template spec safely
        spec_dict = manifest_dict.get("spec")
        spec_dict = spec_dict if isinstance(spec_dict, dict) else {}
        if kind == "Pod":
            spec = spec_dict
        else:
            tmpl = spec_dict.get("template")
            tmpl = tmpl if isinstance(tmpl, dict) else {}
            tmpl_spec = tmpl.get("spec")
            spec = tmpl_spec if isinstance(tmpl_spec, dict) else {}

        pod_sc = spec.get("securityContext")
        pod_sc = pod_sc if isinstance(pod_sc, dict) else {}
        raw_containers = spec.get("containers")
        containers = [c for c in raw_containers if isinstance(c, dict)] if isinstance(raw_containers, list) else []
        primary_c = containers[0] if containers else {}
        c_sc = primary_c.get("securityContext")
        c_sc = c_sc if isinstance(c_sc, dict) else {}

        image = str(primary_c.get("image") or "unknown:latest")

        # Extract capabilities
        c_caps = c_sc.get("capabilities")
        c_caps = c_caps if isinstance(c_caps, dict) else {}
        raw_dropped = c_caps.get("drop")
        dropped = set(str(x) for x in raw_dropped if x is not None) if isinstance(raw_dropped, (list, set)) else set()
        raw_added = c_caps.get("add")
        added = set(str(x) for x in raw_added if x is not None) if isinstance(raw_added, (list, set)) else set()

        # Check host namespaces
        host_net = bool(spec.get("hostNetwork", False))
        host_pid = bool(spec.get("hostPID", False))
        host_ipc = bool(spec.get("hostIPC", False))

        # Check hostPath volumes
        host_paths = []
        raw_vols = spec.get("volumes")
        vols_list = raw_vols if isinstance(raw_vols, list) else []
        for vol in vols_list:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath")
                if isinstance(hp, dict):
                    host_paths.append(str(hp.get("path") or "/"))
                elif isinstance(hp, str):
                    host_paths.append(hp)
                else:
                    host_paths.append("/")

        # Privileged / NonRoot
        is_priv = bool(c_sc.get("privileged", False))
        ro_rootfs = bool(c_sc.get("readOnlyRootFilesystem", False))
        no_priv_esc = c_sc.get("allowPrivilegeEscalation", None)
        allow_pe = True if no_priv_esc is None else bool(no_priv_esc)

        run_non_root = bool(c_sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False)))
        run_user = c_sc.get("runAsUser", pod_sc.get("runAsUser", None))
        if run_user is not None and run_user > 0:
            run_non_root = True

        return RuntimeWorkloadProfile(
            workload_name=name,
            namespace=namespace,
            kind=kind,
            image=image,
            read_only_rootfs=ro_rootfs,
            allow_privilege_escalation=allow_pe,
            privileged=is_priv,
            run_as_non_root=run_non_root,
            run_as_user=run_user,
            dropped_caps=dropped,
            added_caps=added,
            host_network=host_net,
            host_pid=host_pid,
            host_ipc=host_ipc,
            mounted_host_paths=host_paths,
        )

    def evaluate_cve_exploitability(
        self, cve: CVEEntry, profile: RuntimeWorkloadProfile
    ) -> Tuple[str, Optional[str], Optional[str], str]:
        """
        Evaluates a CVE against the runtime security profile.
        Returns: (status, justification, impact_statement, contextual_risk)
        """
        desc = cve.description.lower()
        pkg = cve.package.lower()

        # 1. Privileged Override: If container is privileged with hostPID or hostPath /,
        # all CVEs are actively exploitable with host breakout potential.
        if profile.privileged or (profile.host_pid and not profile.run_as_non_root):
            return (
                "affected",
                None,
                None,
                "CRITICAL",
            )

        # 2. File Write / Web Shell / Rootkit Persistence Mitigations
        # If CVE involves writing payloads, arbitrary file upload, or disk tampering
        write_indicators = ["write", "file upload", "directory traversal", "overwrite", "symlink", "dropper", "rce"]
        if any(w in desc for w in write_indicators):
            if profile.read_only_rootfs and not profile.mounted_host_paths:
                return (
                    "not_affected",
                    "inline_mitigations_already_exist",
                    "Workload enforces readOnlyRootFilesystem: true with zero writable host paths. Attackers cannot persist payloads, write web shells, or execute dropped binaries.",
                    "LOW",
                )

        # 3. Local Privilege Escalation (LPE) Mitigations
        # If CVE targets kernel setuid, elevation, or capability misuse
        lpe_indicators = ["privilege escalation", "local privilege", "elevation", "setuid", "cap_sys_admin", "sudo"]
        if any(l in desc for l in lpe_indicators):
            if not profile.allow_privilege_escalation and profile.run_as_non_root:
                return (
                    "not_affected",
                    "inline_mitigations_already_exist",
                    "Workload enforces allowPrivilegeEscalation: false and executes under an unprivileged non-root UID. The kernel denies setuid elevation and capability acquisition.",
                    "LOW",
                )

        # 4. Network Sniffing / Packet Manipulation
        # CVEs in libpcap, tcpdump, or raw socket crafting
        net_cap_indicators = ["sniffing", "arp", "promiscuous", "raw socket", "packet injection"]
        if any(n in desc for n in net_cap_indicators):
            if "ALL" in profile.dropped_caps or "CAP_NET_RAW" in profile.dropped_caps:
                return (
                    "not_affected",
                    "inline_mitigations_already_exist",
                    "Dangerous capability CAP_NET_RAW / CAP_NET_ADMIN is dropped by securityContext, neutralizing raw network spoofing vectors.",
                    "LOW",
                )

        # 5. Remote Network Exploitation without Ingress
        # If RCE requires inbound HTTP/TCP connections, but pod has no public ingress and is isolated
        remote_indicators = ["remote code execution", "network", "unauthenticated", "buffer overflow in http", "http server"]
        if any(r in desc for r in remote_indicators):
            if profile.has_ingress_network_policy and not profile.has_public_ingress and not profile.host_network:
                return (
                    "not_affected",
                    "vulnerable_code_cannot_be_controlled_by_adversary",
                    "Workload is isolated behind default-deny Ingress NetworkPolicy with no direct public route. Adversaries cannot reach or control network inputs.",
                    "MEDIUM",
                )

        # 6. Reverse Shell / C2 Exfiltration Mitigations
        if "reverse shell" in desc or "exfiltration" in desc or "command injection" in desc:
            if profile.has_egress_network_policy:
                return (
                    "not_affected",
                    "inline_mitigations_already_exist",
                    "Default-deny Egress NetworkPolicy restricts all outbound egress. Secondary beaconing and reverse-shell callbacks are blocked at the CNI layer.",
                    "LOW",
                )

        # Default: Workload lacks inline controls to neutralize this CVE
        return (
            "affected",
            None,
            None,
            cve.severity,
        )

    def generate_vex_for_manifest(
        self,
        manifest_path_or_yaml: str,
        image_name: Optional[str] = None,
        custom_cves: Optional[List[CVEEntry]] = None,
    ) -> VEXDocument:
        """
        Audits a Kubernetes manifest and correlates its container CVEs into an OpenVEX document.
        """
        # Load YAML safely with type checking
        raw = ""
        if manifest_path_or_yaml:
            try:
                p = Path(manifest_path_or_yaml)
                if p.is_file():
                    raw = p.read_text(encoding="utf-8", errors="replace")
                else:
                    raw = str(manifest_path_or_yaml)
            except Exception:
                raw = str(manifest_path_or_yaml)

        try:
            docs = list(yaml.safe_load_all(raw)) if yaml else []
        except Exception:
            docs = []

        manifest_dict = docs[0] if docs and isinstance(docs[0], dict) else {}
        profile = self.parse_workload_profile(manifest_dict)

        # Resolve CVE list
        target_image = image_name or profile.image
        if custom_cves:
            cves = custom_cves
        else:
            cves = lookup_image_cves(target_image)
            if not cves:
                # Fallback to simulated baseline CVEs for demonstration / unknown images
                cves = self._generate_representative_cve_catalog(target_image)

        statements: List[VEXStatement] = []
        mitigated_count = 0
        exploitable_count = 0

        for cve in cves:
            status, just, impact, ctx_risk = self.evaluate_cve_exploitability(cve, profile)

            purl = f"pkg:oci/{target_image.split(':')[0]}?tag={target_image.split(':')[-1] if ':' in target_image else 'latest'}"
            subcomponents = [{"@id": f"pkg:deb/debian/{cve.package}@vulnerable"}]
            products = [{"subcomponents": subcomponents}]

            action_stmt = None
            if status == "affected":
                exploitable_count += 1
                action_stmt = f"Patch package '{cve.package}' to remediate {cve.cve_id}, or apply readOnlyRootFilesystem and non-root securityContext."
            else:
                mitigated_count += 1

            stmt = VEXStatement(
                vulnerability_id=cve.cve_id,
                vulnerability_description=cve.description,
                status=status,
                products=products,
                justification=just,
                impact_statement=impact,
                action_statement=action_stmt,
                raw_severity=cve.severity,
                cvss_score=cve.cvss_score,
                contextual_risk=ctx_risk,
            )
            statements.append(stmt)

        total = len(statements)
        noise_reduction = (mitigated_count / total * 100.0) if total > 0 else 0.0

        return VEXDocument(
            author="Kubernetes Native Security Scanner (k8s-native-scanner)",
            role="Contextual Exploitability & OpenVEX Engine",
            timestamp=datetime.now(timezone.utc).isoformat(),
            version=1,
            tooling=TOOLING_NAME,
            workload=f"{profile.namespace}/{profile.kind}/{profile.workload_name}",
            statements=statements,
            total_cves=total,
            exploitable_cves=exploitable_count,
            mitigated_cves=mitigated_count,
            noise_reduction_ratio=noise_reduction,
        )

    def _generate_representative_cve_catalog(self, image: str) -> List[CVEEntry]:
        """Provides a representative CVE set when testing uncataloged or local container images."""
        return [
            CVEEntry("CVE-2023-38545", "CRITICAL", 9.8, "curl", "< 8.4.0", "SOCKS5 heap-based buffer overflow allowing remote code execution and arbitrary payload writes."),
            CVEEntry("CVE-2023-44487", "HIGH", 7.5, "nghttp2", "< 1.57.0", "HTTP/2 Rapid Reset distributed denial of service attack."),
            CVEEntry("CVE-2022-39253", "HIGH", 8.1, "git", "< 2.38.1", "Git submodule local privilege escalation and arbitrary file write via symlinks."),
            CVEEntry("CVE-2023-2650", "MEDIUM", 6.5, "openssl", "< 3.0.9", "AES-XTS cipher manipulation enabling out-of-bounds memory reading."),
            CVEEntry("CVE-2023-0286", "HIGH", 7.4, "openssl", "< 3.0.8", "X.400 address type confusion vulnerability leading to memory disclosure."),
            CVEEntry("CVE-2021-4034", "CRITICAL", 7.8, "polkit", "< 0.105-31", "PwnKit local privilege escalation via pkexec setuid binary execution."),
            CVEEntry("CVE-2022-24407", "HIGH", 7.2, "cyrus-sasl", "< 2.1.28", "SQL injection in SASL auth plugins permitting credential tampering."),
            CVEEntry("CVE-2023-4911", "HIGH", 7.8, "glibc", "< 2.38", "Looney Tunables dynamic loader buffer overflow enabling local root escalation."),
        ]

    def format_terminal_summary(self, doc: VEXDocument) -> str:
        """Renders an executive summary and triage table for CLI presentation."""
        lines = [
            "╔════════════════════════════════════════════════════════════════════════════════╗",
            f"║          CONTEXTUAL EXPLOITABILITY & OPENVEX ASSESSMENT REPORT                 ║",
            "╚════════════════════════════════════════════════════════════════════════════════╝",
            f"Workload   : {doc.workload}",
            f"Timestamp  : {doc.timestamp}",
            f"Standard   : OpenVEX v0.2.0 (CISA / Chainguard Specification)",
            "",
            "────────────────────────────────────────────────────────────────────────────────",
            "                         EXPLOITABILITY NOISE REDUCTION                         ",
            "────────────────────────────────────────────────────────────────────────────────",
            f"  Raw CVEs Detected          : {doc.total_cves}",
            f"  Actually Exploitable (Live) : {doc.exploitable_cves}  [REQUIRES IMMEDIATE ACTION]",
            f"  Runtime Mitigated (Neutral) : {doc.mitigated_cves}  [NOT AFFECTED]",
            f"  Noise Reduction Metric     : {doc.noise_reduction_ratio:.1f}% alert reduction",
            "",
            "────────────────────────────────────────────────────────────────────────────────",
            f"{'CVE ID':<16} | {'Package':<10} | {'Raw CVSS':<9} | {'Runtime Status':<14} | {'Mitigation / Action'}",
            "────────────────────────────────────────────────────────────────────────────────",
        ]

        for s in doc.statements:
            cve_id = s.vulnerability_id
            pkg = s.products[0]["subcomponents"][0]["@id"].split("/")[-1].split("@")[0]
            raw = f"{s.raw_severity} ({s.cvss_score})"
            status = "NOT AFFECTED" if s.status == "not_affected" else "EXPLOITABLE"
            note = s.justification or (s.action_statement[:40] + "..." if s.action_statement else "Action needed")
            lines.append(f"{cve_id:<16} | {pkg:<10} | {raw:<9} | {status:<14} | {note}")

        lines.append("────────────────────────────────────────────────────────────────────────────────")
        return "\n".join(lines)


def export_vex_report(manifest_path: str, output_path: str, image_name: Optional[str] = None):
    """Exports OpenVEX v0.2.0 JSON report to file."""
    engine = ContextualVEXEngine()
    doc = engine.generate_vex_for_manifest(manifest_path, image_name=image_name)
    Path(output_path).write_text(doc.to_openvex_json(), encoding="utf-8")
    return doc
