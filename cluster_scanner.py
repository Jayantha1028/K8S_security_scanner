#!/usr/bin/env python3
"""
native_scanner/cluster_scanner.py
=================================
Live In-Cluster Security Posture & Vulnerability Scanner (CSPM Engine).

Audits live running Kubernetes workloads directly from the Kubernetes Control Plane API
(kube-apiserver) without needing local YAML manifest files.

Capabilities:
1. Dual-Mode Control Plane Ingestion:
   - In-Cluster: Zero-dependency query via ServiceAccount token (/var/run/secrets/kubernetes.io/serviceaccount/)
   - Out-of-Cluster: Uses active kubectl context or ~/.kube/config
2. Pure In-Memory Workload Auditing:
   - Evaluates live objects against the 56-vulnerability security taxonomy
   - Enforces Catastrophic Exploit Vetoes (Privileged, Root UID 0, HostPID, Cluster-Admin)
3. 1-Click Remediation Export:
   - Automatically exports hardened least-privilege YAML manifests for failing workloads
"""

import argparse
from dataclasses import asdict, dataclass, field
import json
import logging
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request
import urllib.error

try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .remediate import remediate_workload_dict
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from remediate import remediate_workload_dict

logger = logging.getLogger("NativeScanner.ClusterScanner")


@dataclass
class WorkloadAuditResult:
    workload_id: str
    namespace: str
    kind: str
    name: str
    compliance_score: float
    risk_tier: str
    veto_triggered: bool
    findings_count: int
    top_findings: List[str] = field(default_factory=list)
    remediated_yaml: Optional[str] = None

    @property
    def has_exploit_veto(self) -> bool:
        return self.veto_triggered

    @property
    def security_score(self) -> float:
        return self.compliance_score

    def to_dict(self):
        d = asdict(self)
        d["has_exploit_veto"] = self.has_exploit_veto
        d["security_score"] = self.security_score
        return d


@dataclass
class LiveClusterReport:
    total_workloads: int = 0
    average_score: float = 100.0
    cluster_risk_tier: str = "Low"
    scan_latency_ms: float = 0.0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    veto_count: int = 0
    namespace_breakdown: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    workload_results: List[WorkloadAuditResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    @property
    def cluster_score(self) -> float:
        return self.average_score

    @property
    def worst_workload_score(self) -> float:
        return min((w.compliance_score for w in self.workload_results), default=100.0)

    @property
    def passed_workloads(self) -> int:
        return self.low_risk_count + self.medium_risk_count

    @property
    def failing_workloads(self) -> int:
        return self.high_risk_count

    @property
    def remediated_count(self) -> int:
        return sum(1 for w in self.workload_results if w.remediated_yaml is not None)

    @property
    def leaderboard(self) -> List[WorkloadAuditResult]:
        return sorted(self.workload_results, key=lambda w: w.compliance_score)

    def to_dict(self):
        d = asdict(self)
        d["cluster_score"] = self.cluster_score
        d["worst_workload_score"] = self.worst_workload_score
        d["passed_workloads"] = self.passed_workloads
        d["failing_workloads"] = self.failing_workloads
        d["remediated_count"] = self.remediated_count
        d["workload_results"] = [w.to_dict() for w in self.workload_results]
        d["leaderboard"] = [w.to_dict() for w in self.leaderboard]
        return d


class LiveClusterScanner:
    """Live In-Cluster & Out-of-Cluster Kubernetes Security Scanner."""

    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.scanner = NativeSecurityScanner()
        self.has_kubectl = shutil.which("kubectl") is not None

    def is_cluster_reachable(self) -> bool:
        """Check if Kubernetes cluster is responding via in-cluster API or kubectl."""
        # 1. In-cluster ServiceAccount probe
        token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        if token_path.exists():
            return True

        # 2. kubectl probe
        if not self.has_kubectl:
            return False
        try:
            cmd = ["kubectl", "version", "--client", "-o", "json"]
            if self.kubeconfig:
                cmd.extend(["--kubeconfig", self.kubeconfig])
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            if res.returncode != 0:
                return False
            res2 = subprocess.run(["kubectl", "get", "ns"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
            return res2.returncode == 0
        except Exception:
            return False

    def _fetch_in_cluster(self, path: str) -> Optional[Dict[str, Any]]:
        """Zero-dependency in-cluster API query using ServiceAccount credentials."""
        token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        if not token_path.exists():
            return None

        token = token_path.read_text().strip()
        url = f"https://kubernetes.default.svc{path}"
        ctx = ssl.create_default_context(cafile=str(ca_path) if ca_path.exists() else None)
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.warning(f"In-cluster API query failed for {path}: {e}")
            return None

    def fetch_live_workloads(
        self,
        namespace: Optional[str] = None,
        resources: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch live Kubernetes objects from kube-apiserver."""
        target_resources = resources or ["pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"]

        # 1. Check in-cluster serviceaccount first if kubectl is not installed
        if not self.has_kubectl and Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists():
            items = []
            ns_prefix = f"/namespaces/{namespace}" if namespace else ""
            endpoints = [
                f"/api/v1{ns_prefix}/pods",
                f"/apis/apps/v1{ns_prefix}/deployments",
                f"/apis/apps/v1{ns_prefix}/daemonsets",
                f"/apis/apps/v1{ns_prefix}/statefulsets",
                f"/apis/batch/v1{ns_prefix}/jobs",
                f"/apis/batch/v1{ns_prefix}/cronjobs",
            ]
            for ep in endpoints:
                data = self._fetch_in_cluster(ep)
                if data and "items" in data:
                    items.extend(data["items"])
            return items

        # 2. Out-of-cluster kubectl fetch
        if not self.has_kubectl:
            logger.error("Neither kubectl nor in-cluster ServiceAccount token is available.")
            return []

        res_str = ",".join(target_resources)
        cmd = ["kubectl", "get", res_str, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if proc.returncode != 0:
            logger.warning(f"kubectl failed to query live cluster: {proc.stderr.strip()[:100]}")
            return []

        try:
            data = json.loads(proc.stdout)
            items = data.get("items", [])
            logger.info(f"Retrieved {len(items)} live workloads from cluster.")
            return items
        except Exception as e:
            logger.error(f"Failed to parse live cluster JSON: {e}")
            return []

    def scan_cluster(
        self,
        namespace: Optional[str] = None,
        remediate_dir: Optional[str] = None,
        mock_objects: Optional[List[Dict[str, Any]]] = None,
        gate_threshold: float = 35.0,
    ) -> LiveClusterReport:
        """Execute full live cluster security posture audit across active workloads."""
        import yaml
        t0 = time.time()
        report = LiveClusterReport()

        if mock_objects is not None:
            workloads = mock_objects
        else:
            workloads = self.fetch_live_workloads(namespace=namespace)

        if not workloads:
            report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
            return report

        valid_workloads = [
            obj for obj in workloads
            if isinstance(obj, dict) and obj.get("kind") in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob")
        ]

        report.total_workloads = len(valid_workloads)
        total_score = 0.0
        rem_path = Path(remediate_dir) if remediate_dir else None
        if rem_path:
            rem_path.mkdir(parents=True, exist_ok=True)

        veto_rules = {"V01", "V02", "V09", "V10", "V11", "V45"}

        for obj in valid_workloads:
            kind = obj.get("kind", "Unknown")
            metadata = obj.get("metadata", {}) or {}
            name = metadata.get("name", "unnamed")
            ns = metadata.get("namespace", namespace or "default")
            target_id = f"{ns}/{kind}/{name}"

            scan_rep = self.scanner.scan_dict(obj, source_name=target_id)
            score = scan_rep.compliance_score
            risk_tier = scan_rep.risk_tier

            triggered_vetoes = sorted(list(veto_rules.intersection(scan_rep.detected_vuln_ids)))
            is_veto = len(triggered_vetoes) > 0

            if is_veto:
                score = min(score, 35.0)
                risk_tier = "High"
                report.veto_count += 1

            if risk_tier == "High":
                report.high_risk_count += 1
            elif risk_tier == "Medium":
                report.medium_risk_count += 1
            else:
                report.low_risk_count += 1

            total_score += score

            # Namespace stats
            if ns not in report.namespace_breakdown:
                report.namespace_breakdown[ns] = {
                    "total_workloads": 0,
                    "scores": [],
                    "high_risk": 0,
                }
            report.namespace_breakdown[ns]["total_workloads"] += 1
            report.namespace_breakdown[ns]["scores"].append(score)
            if risk_tier == "High":
                report.namespace_breakdown[ns]["high_risk"] += 1

            # Auto-remediation if requested or if failing gate
            remediated_yaml_str = None
            if rem_path or score < gate_threshold or is_veto:
                try:
                    hardened, _ = remediate_workload_dict(obj)
                    remediated_yaml_str = yaml.dump(hardened, sort_keys=False)
                    if rem_path:
                        clean_name = f"{ns}_{kind.lower()}_{name}.yaml"
                        (rem_path / clean_name).write_text(remediated_yaml_str, encoding="utf-8")
                except Exception:
                    pass

            top_findings = [f.title for f in scan_rep.findings[:3]]
            report.workload_results.append(WorkloadAuditResult(
                workload_id=target_id,
                namespace=ns,
                kind=kind,
                name=name,
                compliance_score=round(score, 1),
                risk_tier=risk_tier,
                veto_triggered=is_veto,
                findings_count=len(scan_rep.findings),
                top_findings=top_findings,
                remediated_yaml=remediated_yaml_str,
            ))

        if report.total_workloads > 0:
            report.average_score = round(total_score / report.total_workloads, 1)
            for ns, data in report.namespace_breakdown.items():
                data["average_score"] = round(sum(data["scores"]) / len(data["scores"]), 1)
                del data["scores"]

        if report.average_score < 50.0 or report.high_risk_count > report.total_workloads * 0.4:
            report.cluster_risk_tier = "High"
        elif report.average_score < 75.0:
            report.cluster_risk_tier = "Medium"
        else:
            report.cluster_risk_tier = "Low"

        report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
        return report
