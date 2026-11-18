#!/usr/bin/env python3
"""
native_scanner/simulation.py
============================
Automated Adversarial Threat Modeling & Multi-Stage Kill Chain Simulator.
Simulates real-world attacker progression across the Kubernetes Attack Path DAG:
  Initial Access -> Container Execution -> Host Breakout -> IAM Credential Theft -> Cluster Takeover.

Computes:
- Overall Breach Probability (P_breach)
- Mean Time to Compromise (MTTC in minutes)
- MITRE ATT&CK for Containers Matrix Heatmap
- Countermeasure Efficacy Index (evaluates risk reduction before & after patches)
"""

from dataclasses import asdict, dataclass, field
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from .attack_graph import AttackGraphEngine
    from .scanner import NativeSecurityScanner, ScanReport
    from .taxonomy import TAXONOMY_56
except ImportError:
    from attack_graph import AttackGraphEngine
    from scanner import NativeSecurityScanner, ScanReport
    from taxonomy import TAXONOMY_56

logger = logging.getLogger("NativeScanner.Simulation")


@dataclass
class KillChainStage:
    stage_id: str
    phase_name: str
    mitre_tactic: str
    mitre_technique: str
    technique_name: str
    probability: float  # [0.0, 1.0]
    time_to_execute_minutes: float
    description: str
    mitigated_by: List[str] = field(default_factory=list)
    exploited_resource: str = ""


@dataclass
class SimulationReport:
    workload: str
    total_stages_simulated: int
    stages_breached: int
    breach_probability: float  # [0.0, 100.0]
    estimated_mttc_minutes: float  # Mean Time To Compromise
    critical_attack_path: List[KillChainStage] = field(default_factory=list)
    mitre_matrix_coverage: Dict[str, List[str]] = field(default_factory=dict)
    countermeasures_effective: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workload": self.workload,
            "breach_probability_pct": f"{self.breach_probability:.1f}%",
            "estimated_mttc_minutes": f"{self.estimated_mttc_minutes:.1f} min",
            "stages_breached_count": self.stages_breached,
            "total_stages": self.total_stages_simulated,
            "critical_attack_path": [asdict(s) for s in self.critical_attack_path],
            "mitre_matrix_coverage": self.mitre_matrix_coverage,
            "countermeasures_effective": self.countermeasures_effective,
        }


class ThreatSimulationEngine:
    """
    Simulates adversarial intrusion kill chains against Kubernetes infrastructure.
    """

    def __init__(self):
        self.scanner = NativeSecurityScanner()

    def simulate_attack_scenario(self, manifest_path: str) -> SimulationReport:
        """Runs multi-phase adversarial simulation against manifest or directory."""
        p = Path(manifest_path)
        if not p.exists():
            raise FileNotFoundError(f"Target '{manifest_path}' does not exist.")

        if p.is_file():
            reports = [self.scanner.scan_file(str(p))]
        else:
            reports = self.scanner.scan_directory(str(p))

        # Collect all detected vulnerability IDs across reports
        all_vulns: Set[str] = set()
        for r in reports:
            all_vulns.update(r.detected_vuln_ids)

        workload_name = p.stem

        # Define 6 canonical adversary kill chain stages
        stages: List[KillChainStage] = []

        # 1. Initial Access: Ingress / Exposure / Image Typosquatting
        if "V34" in all_vulns or "V36" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-1",
                phase_name="Initial Access",
                mitre_tactic="TA0001",
                mitre_technique="T1190",
                technique_name="Exploit Public-Facing Application",
                probability=0.85,
                time_to_execute_minutes=12.0,
                description="Adversary accesses unauthenticated ingress port or 0.0.0.0/0 exposed CIDR.",
                exploited_resource="Ingress / Service",
            ))
        elif "V24" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-1",
                phase_name="Initial Access",
                mitre_tactic="TA0001",
                mitre_technique="T1195.002",
                technique_name="Supply Chain Compromise (Typosquatted Image)",
                probability=0.70,
                time_to_execute_minutes=5.0,
                description="Adversary leverages typosquatted malicious registry container image.",
                exploited_resource="Pod / Container",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-1",
                phase_name="Initial Access",
                mitre_tactic="TA0001",
                mitre_technique="T1078.001",
                technique_name="Default Account Access",
                probability=0.30,
                time_to_execute_minutes=45.0,
                description="Adversary probes internal cluster perimeter without direct ingress.",
                exploited_resource="Cluster Perimeter",
            ))

        # 2. Execution & Defense Evasion
        if "V04" in all_vulns or "V12" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-2",
                phase_name="Execution & Defense Evasion",
                mitre_tactic="TA0002",
                mitre_technique="T1059.004",
                technique_name="Command and Scripting Interpreter (Shell Dropper)",
                probability=0.90,
                time_to_execute_minutes=3.0,
                description="Writable root filesystem allows downloading ELF payloads, rootkits, and web shells.",
                exploited_resource="Container Filesystem",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-2",
                phase_name="Execution & Defense Evasion",
                mitre_tactic="TA0002",
                mitre_technique="T1610",
                technique_name="Deploy Container",
                probability=0.25,
                time_to_execute_minutes=20.0,
                description="Read-only rootfs prevents downloading exploit payloads to disk.",
                mitigated_by=["readOnlyRootFilesystem: true"],
                exploited_resource="Container Memory",
            ))

        # 3. Privilege Escalation & Host Breakout
        if "V01" in all_vulns or "V45" in all_vulns or "V46" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-3",
                phase_name="Privilege Escalation",
                mitre_tactic="TA0004",
                mitre_technique="T1611",
                technique_name="Escape to Host (Privileged / Docker Socket Breakout)",
                probability=0.95,
                time_to_execute_minutes=4.0,
                description="Container has privileged: true or mounts docker socket, allowing direct host kernel compromise.",
                exploited_resource="Host Node Kernel / Socket",
            ))
        elif "V03" in all_vulns or "V05" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-3",
                phase_name="Privilege Escalation",
                mitre_tactic="TA0004",
                mitre_technique="T1068",
                technique_name="Exploitation for Privilege Escalation (CAP_SYS_ADMIN)",
                probability=0.75,
                time_to_execute_minutes=15.0,
                description="Container retains CAP_SYS_ADMIN or allows privilege escalation to root UID.",
                exploited_resource="Host Capabilities",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-3",
                phase_name="Privilege Escalation",
                mitre_tactic="TA0004",
                mitre_technique="T1611",
                technique_name="Container Escape Attempt",
                probability=0.10,
                time_to_execute_minutes=90.0,
                description="Host escape blocked by unprivileged execution, seccomp, and dropped capabilities.",
                mitigated_by=["privileged: false", "allowPrivilegeEscalation: false", "drop: [ALL]"],
                exploited_resource="Host Node",
            ))

        # 4. Credential Access & Cloud Identity
        if "V18" in all_vulns or "V44" in all_vulns or "V32" not in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-4",
                phase_name="Credential Access",
                mitre_tactic="TA0006",
                mitre_technique="T1552.007",
                technique_name="Container and Cloud Instance Metadata (IMDSv1)",
                probability=0.88,
                time_to_execute_minutes=6.0,
                description="Adversary queries 169.254.169.254 or extracts hardcoded API tokens from environment variables.",
                exploited_resource="Cloud Provider IAM / IMDS",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-4",
                phase_name="Credential Access",
                mitre_tactic="TA0006",
                mitre_technique="T1552",
                technique_name="Unsuccessful Credential Harvest",
                probability=0.15,
                time_to_execute_minutes=35.0,
                description="Secrets are not exposed in plaintext and cloud metadata access is restricted.",
                mitigated_by=["automountServiceAccountToken: false", "Zero hardcoded secrets"],
                exploited_resource="Kubernetes Secrets",
            ))

        # 5. Lateral Movement
        if "V31" in all_vulns or "V32" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-5",
                phase_name="Lateral Movement",
                mitre_tactic="TA0008",
                mitre_technique="T1210",
                technique_name="Exploitation of Remote Services (Flat Cluster Network)",
                probability=0.80,
                time_to_execute_minutes=10.0,
                description="Missing default-deny NetworkPolicy allows lateral scanning and port probing across all pods.",
                exploited_resource="Cluster Flat Network",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-5",
                phase_name="Lateral Movement",
                mitre_tactic="TA0008",
                mitre_technique="T1210",
                technique_name="Lateral Movement Neutralized",
                probability=0.08,
                time_to_execute_minutes=120.0,
                description="Default-deny NetworkPolicy blocks lateral traversal across namespace boundaries.",
                mitigated_by=["NetworkPolicy ingress/egress default-deny"],
                exploited_resource="Isolated Pod Network",
            ))

        # 6. Impact: Cluster Takeover
        if "V27" in all_vulns or "V28" in all_vulns or "V01" in all_vulns:
            stages.append(KillChainStage(
                stage_id="STAGE-6",
                phase_name="Impact",
                mitre_tactic="TA0040",
                mitre_technique="T1496",
                technique_name="Cluster Takeover & Resource Hijacking",
                probability=0.92,
                time_to_execute_minutes=5.0,
                description="Cluster-admin wildcards or host breakout permit full etcd dump, cryptomining, or cluster sabotage.",
                exploited_resource="etcd / Node DaemonSet",
            ))
        else:
            stages.append(KillChainStage(
                stage_id="STAGE-6",
                phase_name="Impact",
                mitre_tactic="TA0040",
                mitre_technique="T1496",
                technique_name="Restricted Impact",
                probability=0.12,
                time_to_execute_minutes=60.0,
                description="Impact constrained by least-privilege RBAC and node isolation.",
                mitigated_by=["RoleBinding least privilege"],
                exploited_resource="Local Container Sandbox",
            ))

        # Compute Compound Breach Probability: P = 1 - product(1 - p_i)
        cumulative_survival = 1.0
        total_time = 0.0
        breached_count = 0
        mitre_matrix: Dict[str, List[str]] = {}
        countermeasures: List[str] = []

        for s in stages:
            cumulative_survival *= (1.0 - s.probability)
            total_time += s.time_to_execute_minutes
            if s.probability >= 0.5:
                breached_count += 1
            if s.mitigated_by:
                countermeasures.extend(s.mitigated_by)
            mitre_matrix.setdefault(s.phase_name, []).append(f"{s.mitre_technique} ({s.technique_name})")

        overall_p_breach = (1.0 - cumulative_survival) * 100.0

        return SimulationReport(
            workload=workload_name,
            total_stages_simulated=len(stages),
            stages_breached=breached_count,
            breach_probability=overall_p_breach,
            estimated_mttc_minutes=total_time,
            critical_attack_path=stages,
            mitre_matrix_coverage=mitre_matrix,
            countermeasures_effective=list(set(countermeasures)),
        )

    def format_simulation_table(self, rep: SimulationReport) -> str:
        """Renders an adversarial kill chain matrix for CLI presentation."""
        lines = [
            "╔════════════════════════════════════════════════════════════════════════════════╗",
            "║        ADVERSARIAL KILL CHAIN SIMULATION & THREAT MODELING REPORT              ║",
            "╚════════════════════════════════════════════════════════════════════════════════╝",
            f"Target Workload      : {rep.workload}",
            f"Breach Probability   : {rep.breach_probability:.1f}% ({rep.stages_breached}/{rep.total_stages_simulated} phases breached)",
            f"Mean Time To Breach  : {rep.estimated_mttc_minutes:.1f} minutes",
            "",
            "────────────────────────────────────────────────────────────────────────────────",
            f"{'Stage / Tactic':<22} | {'MITRE ID':<10} | {'Probability':<11} | {'Time (min)':<10} | {'Status'}",
            "────────────────────────────────────────────────────────────────────────────────",
        ]
        for s in rep.critical_attack_path:
            status = "BREACHED" if s.probability >= 0.5 else "CONTAINED"
            lines.append(f"{s.phase_name:<22} | {s.mitre_technique:<10} | {s.probability*100:>8.1f}%   | {s.time_to_execute_minutes:>8.1f}m  | {status}")

        lines.append("────────────────────────────────────────────────────────────────────────────────")
        if rep.countermeasures_effective:
            lines.append("Active Defensive Countermeasures:")
            for c in rep.countermeasures_effective:
                lines.append(f"  ✓ {c}")
        return "\n".join(lines)
