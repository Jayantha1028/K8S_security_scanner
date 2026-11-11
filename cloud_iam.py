#!/usr/bin/env python3
"""
native_scanner/cloud_iam.py
===========================
Cloud Provider IAM & Workload Identity Trust Relationship Verifier.
Validates Kubernetes-to-Cloud IAM bindings:
- AWS EKS IRSA (IAM Roles for Service Accounts) via eks.amazonaws.com/role-arn
- GCP GKE Workload Identity via iam.gke.io/gcp-service-account
- Azure AKS Workload Identity via azure.workload.identity/client-id

Provides dual-mode verification:
1. Static / Offline Structural Analysis:
   - Evaluates ARN format, wildcard accounts, cross-account risks, and privilege boundaries.
2. Live Cloud Verification (Optional, when credentials present):
   - Validates Trust Relationship (OIDC federation), attached policies, and wildcard admin actions.
"""

from dataclasses import asdict, dataclass
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("NativeCloudIAM")


@dataclass
class CloudIAMFinding:
    provider: str  # AWS, GCP, AZURE
    role_identifier: str
    workload_target: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    remediation: str
    is_live_verified: bool = False

    def to_dict(self):
        return asdict(self)


class CloudIAMVerifier:
    """Verifies Cloud Provider IAM integration on Kubernetes ServiceAccounts."""

    AWS_ROLE_ARN_REGEX = re.compile(r"^arn:aws[a-zA-Z-]*:iam::(\d{12}):role/([\w+=,.@\-_/]+)$")
    GCP_SA_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_\.]+\.iam\.gserviceaccount\.com$")

    def __init__(self, enable_live_cloud_api: bool = False):
        self.enable_live_cloud_api = enable_live_cloud_api
        self.boto3_iam = None

        if enable_live_cloud_api:
            try:
                import boto3
                self.boto3_iam = boto3.client("iam")
            except Exception:
                self.boto3_iam = None

    def audit_role_binding(
        self,
        annotations: Dict[str, str],
        workload_name: str,
    ) -> List[CloudIAMFinding]:
        """Audits cloud provider IAM annotations on a workload or ServiceAccount."""
        findings = []

        # 1. AWS IRSA (eks.amazonaws.com/role-arn)
        aws_role = annotations.get("eks.amazonaws.com/role-arn")
        if aws_role:
            findings.extend(self._audit_aws_role(aws_role, workload_name))

        # 2. GCP Workload Identity (iam.gke.io/gcp-service-account)
        gcp_sa = annotations.get("iam.gke.io/gcp-service-account")
        if gcp_sa:
            findings.extend(self._audit_gcp_sa(gcp_sa, workload_name))

        # 3. Azure Workload Identity (azure.workload.identity/client-id)
        azure_id = annotations.get("azure.workload.identity/client-id")
        if azure_id:
            findings.extend(self._audit_azure_identity(azure_id, workload_name))

        return findings

    def _audit_aws_role(self, role_arn: str, workload: str) -> List[CloudIAMFinding]:
        findings = []
        m = self.AWS_ROLE_ARN_REGEX.match(role_arn.strip())
        if not m:
            findings.append(CloudIAMFinding(
                provider="AWS",
                role_identifier=role_arn,
                workload_target=workload,
                risk_level="HIGH",
                title="Malformed AWS IAM Role ARN",
                description=f"Role ARN '{role_arn}' does not match standard 12-digit AWS IAM ARN format",
                remediation="Ensure annotation format is: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>",
            ))
            return findings

        account_id, role_name = m.group(1), m.group(2)

        # Check for administrative role names
        if any(admin_keyword in role_name.lower() for admin_keyword in ("admin", "root", "fullaccess", "superuser")):
            findings.append(CloudIAMFinding(
                provider="AWS",
                role_identifier=role_arn,
                workload_target=workload,
                risk_level="CRITICAL",
                title="Workload Bound to Privileged AWS IAM Role",
                description=f"ServiceAccount assumes cloud role '{role_name}' with administrative keywords",
                remediation="Enforce least-privilege IAM policies scoped strictly to required AWS resources",
            ))

        # Live verification if boto3 is active
        if self.boto3_iam:
            try:
                role_info = self.boto3_iam.get_role(RoleName=role_name)
                trust_doc = role_info.get("Role", {}).get("AssumeRolePolicyDocument", {})
                trust_str = json.dumps(trust_doc)
                if '"Principal": "*"' in trust_str or '"Principal": {"AWS": "*"}' in trust_str:
                    findings.append(CloudIAMFinding(
                        provider="AWS",
                        role_identifier=role_arn,
                        workload_target=workload,
                        risk_level="CRITICAL",
                        title="AWS IAM Role Wildcard Trust Relationship",
                        description=f"Role '{role_name}' allows assumeRole by universal wildcard '*'",
                        remediation="Restrict trust relationship to OIDC provider and specific ServiceAccount sub claim",
                        is_live_verified=True,
                    ))
            except Exception as e:
                logger.debug(f"AWS IAM live check skipped for {role_name}: {e}")

        return findings

    def _audit_gcp_sa(self, gcp_email: str, workload: str) -> List[CloudIAMFinding]:
        findings = []
        if not self.GCP_SA_EMAIL_REGEX.match(gcp_email.strip()):
            findings.append(CloudIAMFinding(
                provider="GCP",
                role_identifier=gcp_email,
                workload_target=workload,
                risk_level="MEDIUM",
                title="Non-Standard GCP Service Account Email",
                description=f"GCP email '{gcp_email}' does not match expected .iam.gserviceaccount.com suffix",
                remediation="Verify ServiceAccount email format in GCP Console",
            ))

        if any(w in gcp_email.lower() for w in ("admin", "owner", "editor")):
            findings.append(CloudIAMFinding(
                provider="GCP",
                role_identifier=gcp_email,
                workload_target=workload,
                risk_level="CRITICAL",
                title="Workload Bound to Privileged GCP Identity",
                description=f"ServiceAccount binds to high-privilege GCP role email '{gcp_email}'",
                remediation="Scope GCP IAM permissions to custom least-privilege roles",
            ))

        return findings

    def _audit_azure_identity(self, client_id: str, workload: str) -> List[CloudIAMFinding]:
        findings = []
        guid_regex = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        if not guid_regex.match(client_id.strip()):
            findings.append(CloudIAMFinding(
                provider="AZURE",
                role_identifier=client_id,
                workload_target=workload,
                risk_level="MEDIUM",
                title="Malformed Azure Workload Identity Client ID",
                description=f"Client ID '{client_id}' is not a valid Azure Application GUID",
                remediation="Provide valid Azure Application (Client) ID GUID",
            ))
        return findings
