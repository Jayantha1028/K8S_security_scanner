#!/usr/bin/env python3
"""
compliance_framework_mapper.py
==============================
Regulatory Compliance Framework Mapper & Auditor Certificate Generator.

Maps Kubernetes 56-vulnerability taxonomy findings to major industry compliance frameworks:
  1. PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
  2. SOC 2 Type II (Trust Services Criteria CC6.1 - CC8.1)
  3. HIPAA Security Rule (45 CFR § 164.312 Technical Safeguards)
  4. ISO/IEC 27001:2022 (Annex A.8 Information Security Controls)
  5. NIST SP 800-190 (Application Container Security Guide)

Generates auditor-ready JSON and Markdown Compliance Certificates.
"""

from dataclasses import asdict, dataclass, field
import json
import time
from typing import Any, Dict, List, Set, Tuple


FRAMEWORK_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "PCI-DSS-v4.0": {
        "name": "Payment Card Industry Data Security Standard v4.0",
        "description": "Security standards for organizations handling credit card and payment processing.",
        "controls": {
            "Req-2.2": {
                "name": "System Hardening & Least Functionality",
                "vuln_ids": ["V01", "V02", "V03", "V04", "V08", "V12", "V45"],
                "description": "Configuration standards address all known security vulnerabilities and remove unnecessary functionality."
            },
            "Req-6.4": {
                "name": "Public-Facing Web Applications & Ingress",
                "vuln_ids": ["V10", "V11", "V31"],
                "description": "Public-facing web workloads are protected against known attacks and unrestricted network flow."
            },
            "Req-7.2": {
                "name": "Access Control by Business Need (RBAC)",
                "vuln_ids": ["V33", "V34", "V35", "V36"],
                "description": "Access is restricted to only authorized users, roles, and ServiceAccounts on a need-to-know basis."
            },
            "Req-8.2": {
                "name": "Identification & Cryptographic Secret Protection",
                "vuln_ids": ["V18", "V23", "V32"],
                "description": "Strong authentication management, token automount controls, and zero hardcoded credentials."
            },
        }
    },
    "SOC-2-Type-II": {
        "name": "AICPA SOC 2 Type II Security Criteria",
        "description": "Independent trust services criteria assessing security, confidentiality, and processing integrity.",
        "controls": {
            "CC6.1": {
                "name": "Logical Access Security Controls",
                "vuln_ids": ["V01", "V02", "V32", "V33", "V34"],
                "description": "Restricts logical access to authorized identities to prevent unauthorized escalation."
            },
            "CC6.6": {
                "name": "Boundary Protection & Network Segmentation",
                "vuln_ids": ["V10", "V11", "V31"],
                "description": "Network boundaries are restricted and enforced via default-deny segmentation."
            },
            "CC7.1": {
                "name": "Vulnerability Detection & Container Integrity",
                "vuln_ids": ["V15", "V16", "V17", "V21"],
                "description": "Software dependencies and container images are systematically tracked and patched."
            },
            "CC8.1": {
                "name": "Configuration Integrity & Least Privilege",
                "vuln_ids": ["V03", "V04", "V08", "V12", "V13", "V14"],
                "description": "Workloads are deployed with bounded resources and non-escalating runtime contexts."
            },
        }
    },
    "HIPAA-Security-Rule": {
        "name": "HIPAA Security Rule (45 CFR § 164.312)",
        "description": "Federal technical safeguards protecting Electronic Protected Health Information (ePHI).",
        "controls": {
            "§164.312(a)(1)": {
                "name": "Access Control & Identity Isolation",
                "vuln_ids": ["V01", "V02", "V32", "V33"],
                "description": "Restricted access to computing systems containing protected health information."
            },
            "§164.312(c)(1)": {
                "name": "Workload & File System Integrity",
                "vuln_ids": ["V04", "V45", "V47"],
                "description": "Workload filesystem is protected against unauthorized alteration or host node escape."
            },
            "§164.312(e)(1)": {
                "name": "Transmission Security & Network Exposure",
                "vuln_ids": ["V10", "V31"],
                "description": "Guards against unauthorized network access over open communications networks."
            },
        }
    },
    "ISO-27001-2022": {
        "name": "ISO/IEC 27001:2022 Information Security Management",
        "description": "International standard specification for information security management systems.",
        "controls": {
            "A.8.8": {
                "name": "Management of Technical Vulnerabilities",
                "vuln_ids": ["V15", "V16", "V17", "V21"],
                "description": "Timely identification and remediation of technical vulnerabilities in container workloads."
            },
            "A.8.9": {
                "name": "Configuration Management & Hardening",
                "vuln_ids": ["V01", "V02", "V03", "V08", "V12", "V13", "V14"],
                "description": "Hardened baseline security templates deployed to prevent privilege escalation."
            },
            "A.8.20": {
                "name": "Network Security & Segmentation",
                "vuln_ids": ["V10", "V11", "V31"],
                "description": "Network boundaries, access control lists, and ingress filters protect services."
            },
            "A.8.24": {
                "name": "Use of Cryptography & Key Management",
                "vuln_ids": ["V18", "V23"],
                "description": "Secret protection, API token security, and zero hardcoded plaintext passwords."
            },
        }
    },
    "NIST-SP-800-190": {
        "name": "NIST SP 800-190 Application Container Security Guide",
        "description": "Federal recommendations for securing container images, registries, and runtime hosts.",
        "controls": {
            "Sec-3.1": {
                "name": "Image Vulnerabilities & Embedded Secrets",
                "vuln_ids": ["V15", "V16", "V17", "V18", "V21"],
                "description": "Container images avoid known vulnerabilities, unpinned tags, and exposed keys."
            },
            "Sec-3.3": {
                "name": "Host OS & Container Isolation",
                "vuln_ids": ["V01", "V02", "V05", "V06", "V07", "V45"],
                "description": "Containers prevent host kernel breakout, root UID execution, and kernel capabilities."
            },
            "Sec-3.4": {
                "name": "Runtime Hardware & Isolation Limits",
                "vuln_ids": ["V13", "V14", "V31"],
                "description": "Resource consumption limits and network policies isolate compromised containers."
            },
        }
    }
}


@dataclass
class ControlAuditResult:
    control_id: str
    control_name: str
    description: str
    status: str  # PASSED, FAILED
    tested_vuln_ids: List[str]
    failed_vuln_ids: List[str]
    violation_count: int = 0


@dataclass
class FrameworkAuditResult:
    framework_id: str
    framework_name: str
    compliance_score: float  # 0.0 - 100.0%
    status: str  # CERTIFIED, COMPLIANT, NON_COMPLIANT
    total_controls: int
    passed_controls: int
    failed_controls: int
    controls: List[ControlAuditResult] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["controls"] = [asdict(c) for c in self.controls]
        return d


@dataclass
class ComplianceCertificate:
    audit_target: str
    timestamp: str
    overall_compliance_score: float
    overall_status: str  # PASS, CONDITIONAL, FAIL
    frameworks: Dict[str, FrameworkAuditResult] = field(default_factory=dict)

    def to_dict(self):
        return {
            "audit_target": self.audit_target,
            "timestamp": self.timestamp,
            "overall_compliance_score": self.overall_compliance_score,
            "overall_status": self.overall_status,
            "frameworks": {k: v.to_dict() for k, v in self.frameworks.items()},
        }


class ComplianceFrameworkMapper:
    """
    Evaluates finding vectors against standard regulatory frameworks.
    Produces comprehensive multi-framework compliance audit certifications.
    """

    @classmethod
    def evaluate_findings(cls, findings: List[Any], target_name: str = "cluster") -> ComplianceCertificate:
        """
        Takes a list of Finding objects (or dicts with vuln_id) and maps them to regulatory standards.
        """
        # Collect detected vuln IDs
        detected_ids: Set[str] = set()
        for f in findings:
            v_id = getattr(f, "vuln_id", None) or (f.get("vuln_id") if isinstance(f, dict) else None)
            if v_id:
                detected_ids.add(str(v_id).upper())

        framework_results: Dict[str, FrameworkAuditResult] = {}
        total_scores = []

        for fw_id, fw_def in FRAMEWORK_DEFINITIONS.items():
            ctrl_results: List[ControlAuditResult] = []
            passed_count = 0
            controls_dict = fw_def["controls"]

            for c_id, c_def in controls_dict.items():
                req_vulns = c_def["vuln_ids"]
                failed = [vid for vid in req_vulns if vid in detected_ids]
                is_passed = (len(failed) == 0)
                if is_passed:
                    passed_count += 1

                ctrl_results.append(ControlAuditResult(
                    control_id=c_id,
                    control_name=c_def["name"],
                    description=c_def["description"],
                    status="PASSED" if is_passed else "FAILED",
                    tested_vuln_ids=req_vulns,
                    failed_vuln_ids=failed,
                    violation_count=len(failed),
                ))

            score = round((passed_count / max(1, len(controls_dict))) * 100.0, 1)
            total_scores.append(score)
            status = "CERTIFIED" if score == 100.0 else ("COMPLIANT" if score >= 75.0 else "NON_COMPLIANT")

            framework_results[fw_id] = FrameworkAuditResult(
                framework_id=fw_id,
                framework_name=fw_def["name"],
                compliance_score=score,
                status=status,
                total_controls=len(controls_dict),
                passed_controls=passed_count,
                failed_controls=len(controls_dict) - passed_count,
                controls=ctrl_results,
            )

        mean_score = round(sum(total_scores) / max(1, len(total_scores)), 1)
        overall_status = "PASS" if mean_score >= 85.0 else ("CONDITIONAL" if mean_score >= 60.0 else "FAIL")

        return ComplianceCertificate(
            audit_target=target_name,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            overall_compliance_score=mean_score,
            overall_status=overall_status,
            frameworks=framework_results,
        )

    @classmethod
    def generate_markdown_certificate(cls, cert: ComplianceCertificate) -> str:
        """Renders an auditor-grade Markdown compliance audit certificate."""
        lines = [
            f"# Formal Regulatory Compliance Audit Certificate",
            f"**Audit Target:** `{cert.audit_target}` | **Audit Date:** {cert.timestamp}",
            f"**Overall Compliance Score:** `{cert.overall_compliance_score}%` | **Certification Status:** `{cert.overall_status}`",
            "",
            "---",
            "",
            "## 1. Executive Summary Across Industry Frameworks",
            "",
            "| Regulatory Framework | Standards Authority | Score | Status | Passed Controls |",
            "| :--- | :--- | :---: | :---: | :---: |",
        ]

        for fw in cert.frameworks.values():
            status_badge = "✅ CERTIFIED" if fw.status == "CERTIFIED" else ("⚠️ COMPLIANT" if fw.status == "COMPLIANT" else "❌ NON_COMPLIANT")
            lines.append(f"| **{fw.framework_id}** | {fw.framework_name} | **{fw.compliance_score}%** | {status_badge} | {fw.passed_controls} / {fw.total_controls} |")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Granular Control Verification Matrix",
            "",
        ])

        for fw in cert.frameworks.values():
            lines.append(f"### {fw.framework_name} ({fw.framework_id}) — Score: {fw.compliance_score}%")
            lines.append("")
            lines.append("| Control ID | Control Title | Status | Failed Rules | Description |")
            lines.append("| :--- | :--- | :---: | :---: | :--- |")
            for c in fw.controls:
                c_status = "✅ PASS" if c.status == "PASSED" else "❌ FAIL"
                failed_str = ", ".join(c.failed_vuln_ids) if c.failed_vuln_ids else "None"
                lines.append(f"| `{c.control_id}` | {c.control_name} | {c_status} | `{failed_str}` | {c.description} |")
            lines.append("")

        return "\n".join(lines)


def generate_markdown_certificate(cert: ComplianceCertificate) -> str:
    """Helper to render an auditor-grade Markdown compliance audit certificate."""
    return ComplianceFrameworkMapper.generate_markdown_certificate(cert)

