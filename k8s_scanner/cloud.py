"""
k8s_scanner.cloud
=================
Multi-Cloud Identity (AWS IRSA, GCP Workload Identity, Azure Entra) & Multi-Cloud CSPM.
"""

from cloud_iam import CloudIAMVerifier, CloudIAMFinding
from cloud_cspm import CloudCSPMEngine, CloudCSPMReport, CSPMFinding

__all__ = [
    "CloudIAMVerifier",
    "CloudIAMFinding",
    "CloudCSPMEngine",
    "CloudCSPMReport",
    "CSPMFinding",
]
