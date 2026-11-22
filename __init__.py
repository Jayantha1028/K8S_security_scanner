r"""
k8s-native-scanner
==================
Independent, High-Performance Kubernetes Security Scanner & Cloud-Native Security Engine.

Features:
- Pure-Python Static AST manifest scanning across 56 vulnerability rules (V01-V56)
- Helm chart and Kustomize overlay direct template rendering
- Cross-Resource Attack Path DAG & heuristic Blast Radius scoring
- Cloud Provider IAM & ServiceAccount privilege correlation (AWS IRSA, GCP Workload Identity, Azure Entra)
- Levenshtein supply chain typosquatting defense ($d \le 2$)
- In-memory deep container layer unpacking, Go/Rust ELF symbol parsing
- CycloneDX v1.5 and SPDX v2.3 SBOM generation
- SARIF v2.1.0 output for GitHub Advanced Security & GitLab CI/CD
- Zero-daemon OCI Registry v2 client
- 15-operator declarative custom policy engine
- Multi-framework regulatory compliance mapper (PCI-DSS 4.0, SOC 2, HIPAA, ISO 27001, NIST)
- Least-privilege automated SecurityContext remediator with capability whitelisting
- Embedded microsecond SQLite CVE intelligence engine with SHA-256 integrity
- In-cluster Kubernetes Validating & Mutating Admission Webhook controller
- Interactive local web console & standalone offline HTML report generator
- Sovereign air-gapped security bundle export and verification
"""

__version__ = "1.0.0"
__author__ = "Kubernetes Native Security Team"
__license__ = "Apache-2.0"

try:
    from .taxonomy import TAXONOMY_56
    from .scanner import (
        NativeSecurityScanner,
        ScanReport,
        Finding,
        shannon_entropy,
        check_image_typosquatting,
        levenshtein_distance,
        FEATURES_17,
        FEATURES_32,
    )
    from .attack_graph import (
        AttackGraphEngine,
        AttackNode,
        AttackEdge,
        KillChainPath,
    )
    from .container import (
        HybridContainerLayerScanner,
        SBOMScanReport,
        InstalledPackage,
        OciRegistryClient,
    )
    from .declarative import (
        DeclarativeRuleEngine,
        DeclarativeRule,
    )
    from .compliance import (
        ComplianceFrameworkMapper,
        ComplianceCertificate,
        generate_markdown_certificate,
        FRAMEWORK_DEFINITIONS,
    )
    from .remediate import (
        auto_remediate_manifest,
        remediate_manifest,
        format_patch_diff,
        remediate_workload_dict,
    )
    from .cve import (
        CVEDatabaseEngine,
        CVEEntry,
        lookup_image_cves,
        summarize_cve_counts,
        KNOWN_IMAGE_CVE_DB,
    )
    from .bundle import StandaloneBundleManager
    from .ebpf_probe import NativeEBPFKernelProbe
    from .sarif import export_sarif_report
    from .dashboard import generate_html_report, start_dashboard_server
    from .webhook import AdmissionSecurityEngine, run_webhook_server, generate_webhook_manifests
    from .version_comparator import LinuxVersionComparator
    from .node_auditor import NodeAuditor, NodeFinding, NodeAuditReport
    from .iac import DockerfileScanner, TerraformKubernetesScanner, IaCFinding, IaCScanReport
    from .cloud_iam import CloudIAMVerifier, CloudIAMFinding
    from .cluster_scanner import LiveClusterScanner, LiveClusterReport, WorkloadAuditResult
    from .gitops import GitOpsRemediator, GitOpsRemediationPlan, WorkloadRemediationDiff
    from .exporter import PrometheusMetricsExporter
    from .agent import SecurityAgent, LLMClient
    from .mcp_server import MCPServer
    from .vex import ContextualVEXEngine, VEXDocument, VEXStatement, export_vex_report
    from .repl import InteractiveCopilotREPL, start_copilot_repl
    from .sigstore import SigstoreVerifier, SignatureVerificationResult
    from .simulation import ThreatSimulationEngine, SimulationReport
    from .kubecam import KubeCamEngine, KubeCamFrame, KubeCamFilmstrip, SecurityDriftDelta
    from .lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport, PhaseResult
    from .auth import (
        EnterpriseAuthManager,
        AuthenticatedIdentity,
        APIKeyRecord,
        ROLE_PLATFORM_ADMIN,
        ROLE_SECURITY_ENGINEER,
        ROLE_COMPLIANCE_AUDITOR,
        ROLE_DEVOPS_OPERATOR,
        PERM_FLEET_MANAGE,
        PERM_CLUSTER_ONBOARD,
        PERM_POLICY_WRITE,
        PERM_SCAN_EXECUTE,
        PERM_REMEDIATE_WRITE,
        PERM_VEX_WAIVE,
        PERM_COMPLIANCE_READ,
        PERM_AUDIT_LOGS_READ,
        PERM_TELEMETRY_READ,
    )
    from .fleet import FleetManager, ClusterRecord, FleetPolicy, FleetDriftSummary
    from .ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from .enterprise_server import EnterpriseServer, EnterpriseAPIHandler
    from .cloud_cspm import CloudCSPMEngine, CloudCSPMReport, CSPMFinding
    from .crds import KubernetesCRDManager, SecurityPolicySpec
    from .storage import EnterpriseStorageEngine, TelemetryQueryFilter
    from .notifications import NotificationDispatcher, AlertPayload
    from .leader_election import LeaderElector, LeaderLease
    from .openapi import get_openapi_spec, get_swagger_ui_html
except ImportError:
    from taxonomy import TAXONOMY_56
    from scanner import (
        NativeSecurityScanner,
        ScanReport,
        Finding,
        shannon_entropy,
        check_image_typosquatting,
        levenshtein_distance,
        FEATURES_17,
        FEATURES_32,
    )
    from attack_graph import (
        AttackGraphEngine,
        AttackNode,
        AttackEdge,
        KillChainPath,
    )
    from container import (
        HybridContainerLayerScanner,
        SBOMScanReport,
        InstalledPackage,
        OciRegistryClient,
    )
    from declarative import (
        DeclarativeRuleEngine,
        DeclarativeRule,
    )
    from compliance import (
        ComplianceFrameworkMapper,
        ComplianceCertificate,
        generate_markdown_certificate,
        FRAMEWORK_DEFINITIONS,
    )
    from remediate import (
        auto_remediate_manifest,
        remediate_manifest,
        format_patch_diff,
        remediate_workload_dict,
    )
    from cve import (
        CVEDatabaseEngine,
        CVEEntry,
        lookup_image_cves,
        summarize_cve_counts,
        KNOWN_IMAGE_CVE_DB,
    )
    from bundle import StandaloneBundleManager
    from ebpf_probe import NativeEBPFKernelProbe
    from sarif import export_sarif_report
    from dashboard import generate_html_report, start_dashboard_server
    from webhook import AdmissionSecurityEngine, run_webhook_server, generate_webhook_manifests
    from version_comparator import LinuxVersionComparator
    from node_auditor import NodeAuditor, NodeFinding, NodeAuditReport
    from iac import DockerfileScanner, TerraformKubernetesScanner, IaCFinding, IaCScanReport
    from cloud_iam import CloudIAMVerifier, CloudIAMFinding
    from cluster_scanner import LiveClusterScanner, LiveClusterReport, WorkloadAuditResult
    from gitops import GitOpsRemediator, GitOpsRemediationPlan, WorkloadRemediationDiff
    from exporter import PrometheusMetricsExporter
    from agent import SecurityAgent, LLMClient
    from mcp_server import MCPServer
    from vex import ContextualVEXEngine, VEXDocument, VEXStatement, export_vex_report
    from repl import InteractiveCopilotREPL, start_copilot_repl
    from sigstore import SigstoreVerifier, SignatureVerificationResult
    from simulation import ThreatSimulationEngine, SimulationReport
    from kubecam import KubeCamEngine, KubeCamFrame, KubeCamFilmstrip, SecurityDriftDelta
    from lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport, PhaseResult
    from auth import (
        EnterpriseAuthManager,
        AuthenticatedIdentity,
        APIKeyRecord,
        ROLE_PLATFORM_ADMIN,
        ROLE_SECURITY_ENGINEER,
        ROLE_COMPLIANCE_AUDITOR,
        ROLE_DEVOPS_OPERATOR,
        PERM_FLEET_MANAGE,
        PERM_CLUSTER_ONBOARD,
        PERM_POLICY_WRITE,
        PERM_SCAN_EXECUTE,
        PERM_REMEDIATE_WRITE,
        PERM_VEX_WAIVE,
        PERM_COMPLIANCE_READ,
        PERM_AUDIT_LOGS_READ,
        PERM_TELEMETRY_READ,
    )
    from fleet import FleetManager, ClusterRecord, FleetPolicy, FleetDriftSummary
    from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
    from enterprise_server import EnterpriseServer, EnterpriseAPIHandler
    from cloud_cspm import CloudCSPMEngine, CloudCSPMReport, CSPMFinding
    from crds import KubernetesCRDManager, SecurityPolicySpec
    from storage import EnterpriseStorageEngine, TelemetryQueryFilter
    from notifications import NotificationDispatcher, AlertPayload
    from leader_election import LeaderElector, LeaderLease
    from openapi import get_openapi_spec, get_swagger_ui_html

KillChain = KillChainPath

__all__ = [
    "NativeSecurityScanner",
    "ScanReport",
    "Finding",
    "shannon_entropy",
    "check_image_typosquatting",
    "levenshtein_distance",
    "TAXONOMY_56",
    "FEATURES_17",
    "FEATURES_32",
    "AttackGraphEngine",
    "AttackNode",
    "AttackEdge",
    "KillChain",
    "HybridContainerLayerScanner",
    "SBOMScanReport",
    "InstalledPackage",
    "OciRegistryClient",
    "DeclarativeRuleEngine",
    "DeclarativeRule",
    "ComplianceFrameworkMapper",
    "ComplianceCertificate",
    "generate_markdown_certificate",
    "FRAMEWORK_DEFINITIONS",
    "auto_remediate_manifest",
    "remediate_manifest",
    "format_patch_diff",
    "remediate_workload_dict",
    "CVEDatabaseEngine",
    "CVEEntry",
    "lookup_image_cves",
    "summarize_cve_counts",
    "KNOWN_IMAGE_CVE_DB",
    "StandaloneBundleManager",
    "NativeEBPFKernelProbe",
    "export_sarif_report",
    "generate_html_report",
    "start_dashboard_server",
    "AdmissionSecurityEngine",
    "run_webhook_server",
    "generate_webhook_manifests",
    "LinuxVersionComparator",
    "NodeAuditor",
    "NodeFinding",
    "NodeAuditReport",
    "DockerfileScanner",
    "TerraformKubernetesScanner",
    "IaCFinding",
    "IaCScanReport",
    "CloudIAMVerifier",
    "CloudIAMFinding",
    "LiveClusterScanner",
    "LiveClusterReport",
    "WorkloadAuditResult",
    "GitOpsRemediator",
    "GitOpsRemediationPlan",
    "WorkloadRemediationDiff",
    "PrometheusMetricsExporter",
    "SecurityAgent",
    "LLMClient",
    "MCPServer",
    "ContextualVEXEngine",
    "VEXDocument",
    "VEXStatement",
    "export_vex_report",
    "InteractiveCopilotREPL",
    "start_copilot_repl",
    "SigstoreVerifier",
    "SignatureVerificationResult",
    "ThreatSimulationEngine",
    "SimulationReport",
    "KubeCamEngine",
    "KubeCamFrame",
    "KubeCamFilmstrip",
    "SecurityDriftDelta",
    "ContainerLifecycleOrchestrator",
    "ContainerLifecycleReport",
    "PhaseResult",
    "EnterpriseAuthManager",
    "AuthenticatedIdentity",
    "APIKeyRecord",
    "ROLE_PLATFORM_ADMIN",
    "ROLE_SECURITY_ENGINEER",
    "ROLE_COMPLIANCE_AUDITOR",
    "ROLE_DEVOPS_OPERATOR",
    "FleetManager",
    "ClusterRecord",
    "FleetPolicy",
    "FleetDriftSummary",
    "EBPFTelemetryEngine",
    "SIEMForwarder",
    "KernelSecurityEvent",
    "EnterpriseServer",
    "EnterpriseAPIHandler",
    "CloudCSPMEngine",
    "CloudCSPMReport",
    "CSPMFinding",
    "KubernetesCRDManager",
    "SecurityPolicySpec",
    "EnterpriseStorageEngine",
    "TelemetryQueryFilter",
    "NotificationDispatcher",
    "AlertPayload",
    "LeaderElector",
    "LeaderLease",
    "get_openapi_spec",
    "get_swagger_ui_html",
]
