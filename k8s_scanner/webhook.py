"""
k8s_scanner.webhook
===================
In-Cluster Validating & Mutating Admission Webhook, Live Cluster Scanner & CRDs.
"""

from webhook import AdmissionSecurityEngine, run_webhook_server, generate_webhook_manifests
from crds import KubernetesCRDManager, SecurityPolicySpec
from cluster_scanner import LiveClusterScanner, LiveClusterReport, WorkloadAuditResult
from gitops import GitOpsRemediator, GitOpsRemediationPlan, WorkloadRemediationDiff
from kubecam import KubeCamEngine, KubeCamFrame, KubeCamFilmstrip, SecurityDriftDelta
from simulation import ThreatSimulationEngine, SimulationReport

__all__ = [
    "AdmissionSecurityEngine",
    "run_webhook_server",
    "generate_webhook_manifests",
    "KubernetesCRDManager",
    "SecurityPolicySpec",
    "LiveClusterScanner",
    "LiveClusterReport",
    "WorkloadAuditResult",
    "GitOpsRemediator",
    "GitOpsRemediationPlan",
    "WorkloadRemediationDiff",
    "KubeCamEngine",
    "KubeCamFrame",
    "KubeCamFilmstrip",
    "SecurityDriftDelta",
    "ThreatSimulationEngine",
    "SimulationReport",
]
