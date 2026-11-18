#!/usr/bin/env python3
"""
fleet.py
========
Hyperscale Multi-Cluster Fleet Manager & Central Aggregation Service.

Capabilities:
1. Multi-Cluster Fleet Registry: Real-time management across AWS EKS, GCP GKE, Azure AKS, and Bare-Metal.
2. Continuous KubeCam Telemetry Ingestion: Ingests run-time drift frames and cluster security state.
3. Global Fleet Threat Index (0.0 - 100.0): Mathematical aggregation of multi-cluster risk posture.
4. Multi-Dimensional Threat Heatmap: Grouped by Cloud Provider, Region, Cluster, and Namespace.
5. Fleet Policy Distribution: Synchronizes Zero-Trust baseline security policies across member clusters.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("NativeScanner.Fleet")


@dataclass
class ClusterRecord:
    cluster_id: str
    name: str
    tenant_id: str
    cloud_provider: str = "aws"  # aws, gcp, azure, onprem
    region: str = "us-east-1"
    kubernetes_version: str = "v1.28.0"
    status: str = "ACTIVE"  # ACTIVE, DEGRADED, DISCONNECTED
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_heartbeat: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    node_count: int = 3
    pod_count: int = 0
    threat_index: float = 0.0  # 0.0 (safe) to 100.0 (critical danger)
    security_score: float = 100.0  # 0 to 100
    vulnerabilities_count: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    })
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FleetPolicy:
    policy_id: str
    name: str
    tenant_id: str
    description: str = ""
    min_score_threshold: float = 80.0
    blocked_capabilities: List[str] = field(default_factory=lambda: ["SYS_ADMIN", "NET_ADMIN", "ALL"])
    enforce_non_root: bool = True
    disallow_privileged: bool = True
    require_read_only_root_fs: bool = False
    allowed_registries: List[str] = field(default_factory=lambda: ["*.ecr.aws", "*.gcr.io", "*.azurecr.io", "docker.io/library"])
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FleetDriftSummary:
    total_clusters: int
    active_clusters: int
    total_pods_monitored: int
    global_threat_index: float
    average_security_score: float
    critical_findings_total: int
    high_findings_total: int
    unhealthy_clusters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FleetManager:
    """
    Central Multi-Cluster Aggregation and Fleet Orchestration Service.
    Pure-Python standard library implementation with zero external runtime dependencies.
    """

    def __init__(self, tenant_id: str = "default-tenant"):
        self.default_tenant = tenant_id
        self._clusters: Dict[str, ClusterRecord] = {}
        self._policies: Dict[str, FleetPolicy] = {}
        self._cluster_telemetry_history: Dict[str, List[Dict[str, Any]]] = {}

        # Initialize standard zero-trust fleet baseline policy
        default_policy = FleetPolicy(
            policy_id="pol-default-zerotrust",
            name="Default Zero-Trust Fleet Baseline",
            tenant_id=self.default_tenant,
            description="Enforces non-root, forbids SYS_ADMIN, and mandates securityContext across fleet.",
        )
        self._policies[default_policy.policy_id] = default_policy

    # --------------------------------------------------------------------------
    # 1. Cluster Onboarding & Lifecycle Management
    # --------------------------------------------------------------------------
    def register_cluster(
        self,
        cluster_id: str,
        name: str,
        tenant_id: Optional[str] = None,
        cloud_provider: str = "aws",
        region: str = "us-east-1",
        kubernetes_version: str = "v1.28.0",
        node_count: int = 3,
        labels: Optional[Dict[str, str]] = None,
    ) -> ClusterRecord:
        """Registers or updates a Kubernetes cluster in the global fleet registry."""
        tenant = tenant_id or self.default_tenant
        record = ClusterRecord(
            cluster_id=cluster_id,
            name=name,
            tenant_id=tenant,
            cloud_provider=cloud_provider.lower(),
            region=region,
            kubernetes_version=kubernetes_version,
            node_count=node_count,
            labels=labels or {},
        )
        self._clusters[cluster_id] = record
        if cluster_id not in self._cluster_telemetry_history:
            self._cluster_telemetry_history[cluster_id] = []
        logger.info(f"Registered cluster {cluster_id} ({name}) for tenant {tenant}")
        return record

    def record_heartbeat(
        self,
        cluster_id: str,
        pod_count: Optional[int] = None,
        node_count: Optional[int] = None,
        status: Optional[str] = None,
    ) -> Optional[ClusterRecord]:
        """Records a keep-alive heartbeat from a cluster agent."""
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None
        now_iso = datetime.now(timezone.utc).isoformat()
        cluster.last_heartbeat = now_iso
        if pod_count is not None:
            cluster.pod_count = pod_count
        if node_count is not None:
            cluster.node_count = node_count
        if status:
            cluster.status = status
        else:
            cluster.status = "ACTIVE"
        return cluster

    def get_cluster(self, cluster_id: str) -> Optional[ClusterRecord]:
        return self._clusters.get(cluster_id)

    def list_clusters(self, tenant_id: Optional[str] = None) -> List[ClusterRecord]:
        """Lists clusters, optionally filtered by tenant ID."""
        self._refresh_cluster_liveness()
        if tenant_id:
            return [c for c in self._clusters.values() if c.tenant_id == tenant_id]
        return list(self._clusters.values())

    # --------------------------------------------------------------------------
    # 2. Continuous Telemetry & KubeCam Frame Ingestion
    # --------------------------------------------------------------------------
    def ingest_cluster_frame(self, cluster_id: str, frame_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a KubeCam security frame or runtime scan report from a member cluster.
        Updates security score, vulnerability counts, and computes cluster threat index.
        """
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            raise KeyError(f"Cluster with ID '{cluster_id}' not found in registry.")

        now_iso = datetime.now(timezone.utc).isoformat()
        cluster.last_heartbeat = now_iso
        cluster.status = "ACTIVE"

        # Extract workload metrics
        if "total_workloads" in frame_data:
            cluster.pod_count = int(frame_data.get("total_workloads", cluster.pod_count))
        elif "workloads" in frame_data and isinstance(frame_data["workloads"], list):
            cluster.pod_count = len(frame_data["workloads"])

        # Extract vulnerabilities and scores
        sec_score = float(frame_data.get("security_score", 100.0))
        cluster.security_score = round(max(0.0, min(100.0, sec_score)), 2)

        # Update vulnerability counts
        v_counts = frame_data.get("vulnerabilities_count") or {}
        if not v_counts and "findings" in frame_data:
            findings = frame_data.get("findings", [])
            v_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = str(f.get("severity", "LOW")).upper()
                if sev in v_counts:
                    v_counts[sev] += 1

        cluster.vulnerabilities_count = {
            "CRITICAL": int(v_counts.get("CRITICAL", 0)),
            "HIGH": int(v_counts.get("HIGH", 0)),
            "MEDIUM": int(v_counts.get("MEDIUM", 0)),
            "LOW": int(v_counts.get("LOW", 0)),
        }

        # Calculate Cluster Threat Index (0.0 safe -> 100.0 critical danger)
        # Weighted formula based on Criticals (10x), Highs (4x), and score deficit
        crit = cluster.vulnerabilities_count["CRITICAL"]
        high = cluster.vulnerabilities_count["HIGH"]
        med = cluster.vulnerabilities_count["MEDIUM"]
        score_deficit = 100.0 - cluster.security_score

        raw_threat = (crit * 15.0) + (high * 5.0) + (med * 1.0) + (score_deficit * 0.4)
        cluster.threat_index = round(min(100.0, max(0.0, raw_threat)), 2)

        # Retain history (capped at 50 frames per cluster)
        hist = self._cluster_telemetry_history.setdefault(cluster_id, [])
        hist.append({
            "timestamp": now_iso,
            "threat_index": cluster.threat_index,
            "security_score": cluster.security_score,
            "vulnerabilities": dict(cluster.vulnerabilities_count),
        })
        if len(hist) > 50:
            self._cluster_telemetry_history[cluster_id] = hist[-50:]

        return {
            "status": "INGESTED",
            "cluster_id": cluster_id,
            "threat_index": cluster.threat_index,
            "security_score": cluster.security_score,
            "timestamp": now_iso,
        }

    # --------------------------------------------------------------------------
    # 3. Global Fleet Metrics & Threat Heatmap
    # --------------------------------------------------------------------------
    def get_fleet_summary(self, tenant_id: Optional[str] = None) -> FleetDriftSummary:
        """Calculates global aggregation metrics across the cluster fleet."""
        clusters = self.list_clusters(tenant_id)
        if not clusters:
            return FleetDriftSummary(
                total_clusters=0,
                active_clusters=0,
                total_pods_monitored=0,
                global_threat_index=0.0,
                average_security_score=100.0,
                critical_findings_total=0,
                high_findings_total=0,
                unhealthy_clusters=[],
            )

        active = [c for c in clusters if c.status == "ACTIVE"]
        total_pods = sum(c.pod_count for c in clusters)
        avg_score = sum(c.security_score for c in clusters) / len(clusters)
        crit_total = sum(c.vulnerabilities_count.get("CRITICAL", 0) for c in clusters)
        high_total = sum(c.vulnerabilities_count.get("HIGH", 0) for c in clusters)

        # Global threat index is the weighted average of individual cluster threat indices
        threat_idx = sum(c.threat_index for c in clusters) / len(clusters)

        unhealthy = [c.cluster_id for c in clusters if c.threat_index > 50.0 or c.status != "ACTIVE"]

        return FleetDriftSummary(
            total_clusters=len(clusters),
            active_clusters=len(active),
            total_pods_monitored=total_pods,
            global_threat_index=round(threat_idx, 2),
            average_security_score=round(avg_score, 2),
            critical_findings_total=crit_total,
            high_findings_total=high_total,
            unhealthy_clusters=unhealthy,
        )

    def get_fleet_heatmap(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates a multi-dimensional threat heatmap grouped by:
        1. Cloud Provider (AWS, GCP, Azure, Bare-Metal)
        2. Region
        3. Cluster Threat Breakdown
        """
        clusters = self.list_clusters(tenant_id)

        by_provider: Dict[str, Dict[str, Any]] = {}
        by_region: Dict[str, Dict[str, Any]] = {}
        cluster_cells: List[Dict[str, Any]] = []

        for c in clusters:
            prov = c.cloud_provider
            reg = c.region

            # Provider aggregation
            if prov not in by_provider:
                by_provider[prov] = {"clusters": 0, "critical": 0, "high": 0, "avg_threat": 0.0, "total_threat": 0.0}
            by_provider[prov]["clusters"] += 1
            by_provider[prov]["critical"] += c.vulnerabilities_count.get("CRITICAL", 0)
            by_provider[prov]["high"] += c.vulnerabilities_count.get("HIGH", 0)
            by_provider[prov]["total_threat"] += c.threat_index

            # Region aggregation
            if reg not in by_region:
                by_region[reg] = {"clusters": 0, "critical": 0, "high": 0, "avg_threat": 0.0, "total_threat": 0.0}
            by_region[reg]["clusters"] += 1
            by_region[reg]["critical"] += c.vulnerabilities_count.get("CRITICAL", 0)
            by_region[reg]["high"] += c.vulnerabilities_count.get("HIGH", 0)
            by_region[reg]["total_threat"] += c.threat_index

            # Cluster cell
            cluster_cells.append({
                "cluster_id": c.cluster_id,
                "name": c.name,
                "cloud_provider": c.cloud_provider,
                "region": c.region,
                "threat_index": c.threat_index,
                "security_score": c.security_score,
                "status": c.status,
                "critical": c.vulnerabilities_count.get("CRITICAL", 0),
                "high": c.vulnerabilities_count.get("HIGH", 0),
            })

        for p_info in by_provider.values():
            if p_info["clusters"] > 0:
                p_info["avg_threat"] = round(p_info["total_threat"] / p_info["clusters"], 2)
                p_info.pop("total_threat", None)

        for r_info in by_region.values():
            if r_info["clusters"] > 0:
                r_info["avg_threat"] = round(r_info["total_threat"] / r_info["clusters"], 2)
                r_info.pop("total_threat", None)

        return {
            "by_provider": by_provider,
            "by_region": by_region,
            "clusters": sorted(cluster_cells, key=lambda x: x["threat_index"], reverse=True),
        }

    # --------------------------------------------------------------------------
    # 4. Fleet Policy Distribution
    # --------------------------------------------------------------------------
    def set_fleet_policy(self, policy: FleetPolicy) -> FleetPolicy:
        """Registers or updates a fleet-wide zero-trust policy."""
        policy.updated_at = datetime.now(timezone.utc).isoformat()
        self._policies[policy.policy_id] = policy
        return policy

    def get_fleet_policy(self, policy_id: str) -> Optional[FleetPolicy]:
        return self._policies.get(policy_id)

    def distribute_fleet_policy(self, tenant_id: str, policy_id: str) -> Dict[str, Any]:
        """
        Dispatches a policy to all registered clusters of a tenant.
        Returns distribution status and sync confirmation.
        """
        policy = self._policies.get(policy_id)
        if not policy:
            raise KeyError(f"Policy '{policy_id}' not found.")

        target_clusters = [c for c in self._clusters.values() if c.tenant_id == tenant_id]
        synced_clusters = []
        for c in target_clusters:
            # Stamp cluster metadata with policy deployment
            c.metadata["applied_fleet_policy"] = policy.policy_id
            c.metadata["policy_applied_at"] = datetime.now(timezone.utc).isoformat()
            synced_clusters.append(c.cluster_id)

        return {
            "policy_id": policy.policy_id,
            "tenant_id": tenant_id,
            "status": "DISTRIBUTED",
            "targets_count": len(target_clusters),
            "synced_cluster_ids": synced_clusters,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # --------------------------------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------------------------------
    def _refresh_cluster_liveness(self):
        """Marks clusters DISCONNECTED if no heartbeat received for > 3 minutes."""
        now = datetime.now(timezone.utc)
        for cluster in self._clusters.values():
            try:
                hb_time = datetime.fromisoformat(cluster.last_heartbeat)
                if (now - hb_time) > timedelta(minutes=3):
                    cluster.status = "DISCONNECTED"
            except Exception:
                pass
