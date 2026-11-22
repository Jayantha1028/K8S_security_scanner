"""
k8s_scanner.container
=====================
Container Layer Inspection, SBOM Generation, Sigstore Verification & VEX.
"""

from container import (
    HybridContainerLayerScanner,
    SBOMScanReport,
    InstalledPackage,
    OciRegistryClient,
    validate_safe_url,
)
from sigstore import SigstoreVerifier, SignatureVerificationResult
from vex import ContextualVEXEngine, VEXDocument, VEXStatement, export_vex_report
from lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport, PhaseResult

__all__ = [
    "HybridContainerLayerScanner",
    "SBOMScanReport",
    "InstalledPackage",
    "OciRegistryClient",
    "validate_safe_url",
    "SigstoreVerifier",
    "SignatureVerificationResult",
    "ContextualVEXEngine",
    "VEXDocument",
    "VEXStatement",
    "export_vex_report",
    "ContainerLifecycleOrchestrator",
    "ContainerLifecycleReport",
    "PhaseResult",
]
