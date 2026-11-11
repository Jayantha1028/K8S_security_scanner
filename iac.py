#!/usr/bin/env python3
"""
native_scanner/iac.py
=====================
Multi-Format Infrastructure-as-Code (IaC) Security Engine.
Zero-dependency static security auditor for:
1. Dockerfile AST Analysis (CIS Docker Benchmark & NSA Hardening)
2. Terraform HCL Kubernetes Resources (resource "kubernetes_pod", "kubernetes_deployment")

Extends scanner coverage upstream to the build & provisioning pipeline.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IaCFinding:
    rule_id: str
    target: str
    line_number: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    remediation: str

    def to_dict(self):
        return asdict(self)


@dataclass
class IaCScanReport:
    target_path: str
    target_type: str  # "dockerfile" or "terraform"
    findings: List[IaCFinding] = field(default_factory=list)
    compliance_score: float = 100.0

    def to_dict(self):
        return {
            "target_path": self.target_path,
            "target_type": self.target_type,
            "compliance_score": round(self.compliance_score, 1),
            "findings": [f.to_dict() for f in self.findings],
        }


# ==============================================================================
# 1. Pure-Python Dockerfile AST Auditor
# ==============================================================================

class DockerfileScanner:
    """Audits Dockerfiles against CIS Docker Benchmark and container hardening standards."""

    SENSITIVE_FILES_REGEX = re.compile(
        r"(id_rsa|id_dsa|\.pem|\.key|\.env|credentials|secret|passwd|shadow)",
        re.IGNORECASE,
    )
    CURL_BASH_REGEX = re.compile(r"(curl|wget)\s+[^|]+\|\s*(sh|bash)", re.IGNORECASE)
    HARDCODED_SECRET_REGEX = re.compile(
        r"(?i)(?:[a-z0-9_-]*(?:password|secret|token|api_key|access_key)[a-z0-9_-]*)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"
    )

    def scan_content(self, content: str, source_name: str = "Dockerfile") -> IaCScanReport:
        lines = content.splitlines()
        findings: List[IaCFinding] = []

        has_user = False
        has_healthcheck = False
        base_images = []

        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith("#"):
                continue

            # Split instruction and arguments
            parts = line_strip.split(None, 1)
            instruction = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ""

            # D01: FROM base image mutable tag
            if instruction == "FROM":
                img = args.split()[0]
                base_images.append(img)
                if ":" not in img or img.endswith(":latest"):
                    findings.append(IaCFinding(
                        rule_id="D01",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="MEDIUM",
                        title="Mutable Base Image Tag",
                        description=f"Base image '{img}' uses mutable :latest or lacks tag",
                        remediation="Pin base image to specific semantic tag or immutable SHA256 digest",
                    ))

            # D02: USER instruction check
            elif instruction == "USER":
                if args.lower() in ("0", "root"):
                    findings.append(IaCFinding(
                        rule_id="D02",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="HIGH",
                        title="Container Explicitly Runs as Root",
                        description="USER instruction explicitly switches to root (UID 0)",
                        remediation="Configure a non-root user (e.g. USER 10001:10001)",
                    ))
                else:
                    has_user = True

            # D03: HEALTHCHECK instruction
            elif instruction == "HEALTHCHECK":
                has_healthcheck = True

            # D04: Insecure curl | bash in RUN
            elif instruction == "RUN":
                if self.CURL_BASH_REGEX.search(args):
                    findings.append(IaCFinding(
                        rule_id="D03",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="HIGH",
                        title="Insecure Pipe Execution (curl | sh)",
                        description="Remote script piped directly into shell execution without checksum verification",
                        remediation="Download script, verify SHA256 checksum, then execute",
                    ))
                if "sudo" in args.split():
                    findings.append(IaCFinding(
                        rule_id="D04",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="HIGH",
                        title="Sudo In Container Build",
                        description="Sudo package or command should not be used in container images",
                        remediation="Avoid sudo; execute commands directly as root during build then drop privileges",
                    ))

            # D05: Sensitive files added via ADD / COPY
            elif instruction in ("ADD", "COPY"):
                if self.SENSITIVE_FILES_REGEX.search(args):
                    findings.append(IaCFinding(
                        rule_id="D05",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="CRITICAL",
                        title="Sensitive File Included in Image",
                        description=f"Potential private credential or environment key copied: {args}",
                        remediation="Do not bake credentials into images; mount secrets via Kubernetes Secrets at runtime",
                    ))

            # D06: Hardcoded secrets in ENV / ARG
            elif instruction in ("ENV", "ARG"):
                if self.HARDCODED_SECRET_REGEX.search(args):
                    findings.append(IaCFinding(
                        rule_id="D06",
                        target=f"{source_name}:{idx}",
                        line_number=idx,
                        severity="CRITICAL",
                        title="Hardcoded Secret in Build Instruction",
                        description=f"Secret or token assignment detected in {instruction}: {args}",
                        remediation="Use BuildKit secret mounts (--mount=type=secret) or runtime environment variables",
                    ))

        # Check overall Dockerfile requirements
        if not has_user and base_images:
            findings.append(IaCFinding(
                rule_id="D07",
                target=source_name,
                line_number=len(lines),
                severity="HIGH",
                title="Missing USER Instruction (Runs as Root)",
                description="Dockerfile does not specify a non-root USER; container runs as UID 0 by default",
                remediation="Add 'USER 10001:10001' before ENTRYPOINT or CMD",
            ))

        if not has_healthcheck and base_images:
            findings.append(IaCFinding(
                rule_id="D08",
                target=source_name,
                line_number=len(lines),
                severity="LOW",
                title="Missing HEALTHCHECK Instruction",
                description="Dockerfile lacks HEALTHCHECK instruction for container engine health probing",
                remediation="Define HEALTHCHECK instruction or Kubernetes livenessProbe",
            ))

        # Calculate score
        deductions = sum(20 if f.severity == "CRITICAL" else (10 if f.severity == "HIGH" else 5) for f in findings)
        score = max(0.0, 100.0 - deductions)

        return IaCScanReport(
            target_path=source_name,
            target_type="dockerfile",
            findings=findings,
            compliance_score=score,
        )

    def scan_file(self, filepath: str) -> IaCScanReport:
        p = Path(filepath)
        if not p.is_file():
            return IaCScanReport(target_path=filepath, target_type="dockerfile", compliance_score=0.0)
        content = p.read_text(encoding="utf-8", errors="replace")
        return self.scan_content(content, source_name=str(p))


# ==============================================================================
# 2. Pure-Python Terraform HCL Kubernetes Resource Auditor
# ==============================================================================

class TerraformKubernetesScanner:
    """Audits Terraform HCL files defining Kubernetes resources."""

    TF_RESOURCE_REGEX = re.compile(r'resource\s+"kubernetes_(pod|deployment|stateful_set|daemon_set)"\s+"([^"]+)"\s+\{')

    def scan_content(self, content: str, source_name: str = "main.tf") -> IaCScanReport:
        findings: List[IaCFinding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Check privileged flag
            if "privileged" in line and "true" in line.lower():
                findings.append(IaCFinding(
                    rule_id="TF-K8S-01",
                    target=f"{source_name}:{idx}",
                    line_number=idx,
                    severity="CRITICAL",
                    title="Privileged Container in Terraform",
                    description="Terraform manifest enables privileged = true",
                    remediation="Set privileged = false or remove privilege block",
                ))

            # Check host network
            if "host_network" in line and "true" in line.lower():
                findings.append(IaCFinding(
                    rule_id="TF-K8S-02",
                    target=f"{source_name}:{idx}",
                    line_number=idx,
                    severity="HIGH",
                    title="Host Network in Terraform",
                    description="Terraform manifest enables host_network = true",
                    remediation="Set host_network = false",
                ))

            # Check run_as_user = 0
            if "run_as_user" in line and re.search(r"=\s*0\b", line):
                findings.append(IaCFinding(
                    rule_id="TF-K8S-03",
                    target=f"{source_name}:{idx}",
                    line_number=idx,
                    severity="HIGH",
                    title="Root User UID 0 in Terraform",
                    description="Terraform manifest specifies run_as_user = 0",
                    remediation="Specify run_as_user >= 1000 and run_as_non_root = true",
                ))

        deductions = sum(20 if f.severity == "CRITICAL" else 10 for f in findings)
        score = max(0.0, 100.0 - deductions)

        return IaCScanReport(
            target_path=source_name,
            target_type="terraform",
            findings=findings,
            compliance_score=score,
        )

    def scan_file(self, filepath: str) -> IaCScanReport:
        p = Path(filepath)
        if not p.is_file():
            return IaCScanReport(target_path=filepath, target_type="terraform", compliance_score=0.0)
        content = p.read_text(encoding="utf-8", errors="replace")
        return self.scan_content(content, source_name=str(p))
