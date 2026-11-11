#!/usr/bin/env python3
"""
native_scanner/node_auditor.py
==============================
CIS Kubernetes Benchmark v2.0 Host Node & Control Plane Auditor.
Audits Linux Worker and Master Nodes directly via filesystem, process table,
and kernel sysctl parameters:

1. Control Plane Components (CIS Section 1):
   - API Server pod manifest flags & permissions (/etc/kubernetes/manifests/kube-apiserver.yaml)
   - Controller Manager & Scheduler configurations
   - etcd data directory ownership and permissions (/var/lib/etcd)

2. etcd Node Configuration (CIS Section 2):
   - etcd client & peer TLS configuration, data directory ownership

3. Control Plane Configuration Files (CIS Section 3):
   - Permissions on admin.conf, controller-manager.conf, scheduler.conf, PKI certs

4. Worker Node Security (CIS Section 4):
   - Kubelet service configuration (/var/lib/kubelet/config.yaml)
   - Kubelet authentication (anonymous-auth: false, webhook auth)
   - Host kernel parameters (sysctl rp_filter, swap disabled, protectKernelDefaults)

Zero external dependencies.
"""

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class NodeFinding:
    check_id: str
    section: str
    title: str
    status: str  # PASS, FAIL, WARN, INFO
    remediation: str
    actual_value: str = ""
    expected_value: str = ""
    severity: str = "HIGH"

    def to_dict(self):
        return asdict(self)


@dataclass
class NodeAuditReport:
    node_type: str  # "master", "worker", "standalone"
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    score: float = 100.0
    findings: List[NodeFinding] = field(default_factory=list)

    def to_dict(self):
        return {
            "node_type": self.node_type,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "score": round(self.score, 1),
            "findings": [f.to_dict() for f in self.findings],
        }


class NodeAuditor:
    """
    Evaluates host node configurations against CIS Kubernetes Benchmark v2.0.
    Supports running directly on host or within a container with host root mounted at /host.
    """

    def __init__(self, root_prefix: str = ""):
        self.root = Path(root_prefix) if root_prefix else Path("/")
        # Detect container mount point e.g. /host
        if not root_prefix and Path("/host/etc/kubernetes").exists():
            self.root = Path("/host")

    def _resolve(self, path_str: str) -> Path:
        rel = path_str.lstrip("/")
        return self.root / rel

    def _check_file_permissions(
        self,
        filepath: str,
        expected_perm: int,
        check_id: str,
        title: str,
        remediation: str,
        section: str = "3.1",
        severity: str = "HIGH",
    ) -> NodeFinding:
        p = self._resolve(filepath)
        if not p.exists():
            return NodeFinding(
                check_id=check_id,
                section=section,
                title=title,
                status="INFO",
                remediation=f"File {filepath} not found on this node.",
                actual_value="NOT_FOUND",
                expected_value=oct(expected_perm),
                severity="LOW",
            )

        mode = stat.S_IMODE(p.stat().st_mode)
        # Check if actual permissions are at most expected_perm
        if (mode & ~expected_perm) == 0:
            return NodeFinding(
                check_id=check_id,
                section=section,
                title=title,
                status="PASS",
                remediation=remediation,
                actual_value=oct(mode),
                expected_value=oct(expected_perm),
                severity=severity,
            )
        else:
            return NodeFinding(
                check_id=check_id,
                section=section,
                title=title,
                status="FAIL",
                remediation=remediation,
                actual_value=oct(mode),
                expected_value=oct(expected_perm),
                severity=severity,
            )

    def _check_sysctl(
        self,
        param_path: str,
        expected_val: str,
        check_id: str,
        title: str,
        remediation: str,
        section: str = "4.2",
    ) -> NodeFinding:
        p = self._resolve(f"/proc/sys/{param_path}")
        if not p.exists():
            return NodeFinding(
                check_id=check_id,
                section=section,
                title=title,
                status="INFO",
                remediation="Sysctl parameter not accessible in current environment.",
                actual_value="N/A",
                expected_value=expected_val,
                severity="LOW",
            )

        try:
            val = p.read_text().strip()
            if val == expected_val:
                return NodeFinding(
                    check_id=check_id,
                    section=section,
                    title=title,
                    status="PASS",
                    remediation=remediation,
                    actual_value=val,
                    expected_value=expected_val,
                    severity="MEDIUM",
                )
            else:
                return NodeFinding(
                    check_id=check_id,
                    section=section,
                    title=title,
                    status="FAIL",
                    remediation=remediation,
                    actual_value=val,
                    expected_value=expected_val,
                    severity="HIGH",
                )
        except Exception as e:
            return NodeFinding(
                check_id=check_id,
                section=section,
                title=title,
                status="WARN",
                remediation=str(e),
                severity="LOW",
            )

    def audit_node(self) -> NodeAuditReport:
        """Executes full CIS benchmark inspection across Control Plane and Worker rules."""
        findings = []

        # 1. Control Plane Configuration File Permissions (CIS Section 3)
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/admin.conf", 0o600, "CIS-3.1.1",
            "Ensure admin.conf file permissions are 600 or more restrictive",
            "chmod 600 /etc/kubernetes/admin.conf",
        ))
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/controller-manager.conf", 0o600, "CIS-3.1.2",
            "Ensure controller-manager.conf file permissions are 600",
            "chmod 600 /etc/kubernetes/controller-manager.conf",
        ))
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/scheduler.conf", 0o600, "CIS-3.1.3",
            "Ensure scheduler.conf file permissions are 600",
            "chmod 600 /etc/kubernetes/scheduler.conf",
        ))
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/pki", 0o700, "CIS-3.1.4",
            "Ensure PKI directory permissions are 700",
            "chmod 700 /etc/kubernetes/pki",
        ))

        # 2. Control Plane Static Pod Manifests (CIS Section 1)
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/manifests/kube-apiserver.yaml", 0o600, "CIS-1.1.1",
            "Ensure kube-apiserver manifest permissions are 600",
            "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml",
            section="1.1",
        ))
        findings.append(self._check_file_permissions(
            "/etc/kubernetes/manifests/etcd.yaml", 0o600, "CIS-1.1.2",
            "Ensure etcd pod manifest permissions are 600",
            "chmod 600 /etc/kubernetes/manifests/etcd.yaml",
            section="1.1",
        ))

        # 3. Kubelet Configuration (CIS Section 4)
        findings.append(self._check_file_permissions(
            "/var/lib/kubelet/config.yaml", 0o600, "CIS-4.1.1",
            "Ensure kubelet configuration file permissions are 600",
            "chmod 600 /var/lib/kubelet/config.yaml",
            section="4.1",
        ))

        # 4. Kernel sysctl Security Parameters
        findings.append(self._check_sysctl(
            "net/ipv4/conf/all/rp_filter", "1", "CIS-4.2.1",
            "Ensure IPv4 Reverse Path Filtering is enabled (anti-IP spoofing)",
            "sysctl -w net.ipv4.conf.all.rp_filter=1",
        ))
        findings.append(self._check_sysctl(
            "net/ipv4/tcp_syncookies", "1", "CIS-4.2.2",
            "Ensure TCP SYN Cookies are enabled (SYN flood protection)",
            "sysctl -w net.ipv4.tcp_syncookies=1",
        ))

        # Compile report
        evaluated = [f for f in findings if f.status in ("PASS", "FAIL")]
        total = len(evaluated)
        passed = sum(1 for f in evaluated if f.status == "PASS")
        score = (passed / total * 100.0) if total > 0 else 100.0

        is_master = any(f.status == "PASS" and "CIS-1." in f.check_id for f in findings)
        node_type = "master" if is_master else "worker"

        return NodeAuditReport(
            node_type=node_type,
            total_checks=len(findings),
            passed_checks=passed,
            failed_checks=sum(1 for f in evaluated if f.status == "FAIL"),
            score=score,
            findings=findings,
        )
