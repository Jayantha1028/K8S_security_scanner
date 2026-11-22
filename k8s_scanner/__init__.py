"""
k8s_scanner
===========
Kubernetes Native Security Scanner, Attack Path DAG & Enterprise CNAPP Platform.

Organized Namespaces:
- k8s_scanner.core       : AST Manifest Scanner, Attack Graph DAG, Remediation, Taxonomy, Compliance
- k8s_scanner.container  : Container Layer SBOM, Sigstore Verifier, Contextual VEX, Lifecycle
- k8s_scanner.iac        : Dockerfile AST, Terraform HCL, CIS Node Auditor
- k8s_scanner.cloud      : Multi-Cloud IAM Verifier, Multi-Cloud CSPM Engine
- k8s_scanner.webhook    : In-Cluster Admission Webhook, Kubernetes CRD Manager
- k8s_scanner.enterprise : Identity/RBAC, Fleet Manager, Storage Engine, Notifications, HA Leader Election, REST Server
- k8s_scanner.agent      : Autonomous Security Agent, MCP Server, Copilot REPL
"""

__version__ = "1.0.0"

from . import core
from . import container
from . import iac
from . import cloud
from . import webhook
from . import enterprise
from . import agent

# Top-level direct conveniences
from scanner import NativeSecurityScanner, ScanReport, Finding
from attack_graph import AttackGraphEngine
from remediate import auto_remediate_manifest
from compliance import ComplianceFrameworkMapper

__all__ = [
    "core",
    "container",
    "iac",
    "cloud",
    "webhook",
    "enterprise",
    "agent",
    "NativeSecurityScanner",
    "ScanReport",
    "Finding",
    "AttackGraphEngine",
    "auto_remediate_manifest",
    "ComplianceFrameworkMapper",
]
