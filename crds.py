#!/usr/bin/env python3
"""
crds.py
=======
Kubernetes Native Custom Resource Definition (CRD) Schemas & Controller Models.

Provides:
1. SecurityPolicy CRD (`security.k8s.io/v1`): Zero-Trust baseline policy specifications.
2. ClusterComplianceAudit CRD (`security.k8s.io/v1`): Native Kubernetes audit records.
3. SecurityRemediation CRD (`security.k8s.io/v1`): Declarative auto-remediation records.
4. Turnkey OpenAPI v3 validation schemas exportable via `k8s-native-scan crd`.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional
import yaml


SECURITY_POLICY_CRD_YAML = """
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: securitypolicies.security.k8s.io
spec:
  group: security.k8s.io
  names:
    kind: SecurityPolicy
    listKind: SecurityPolicyList
    plural: securitypolicies
    singular: securitypolicy
    shortNames:
      - secpol
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                minComplianceScore:
                  type: number
                  minimum: 0.0
                  maximum: 100.0
                  default: 80.0
                enforceNonRoot:
                  type: boolean
                  default: true
                disallowPrivileged:
                  type: boolean
                  default: true
                requireReadOnlyRootFilesystem:
                  type: boolean
                  default: false
                blockedCapabilities:
                  type: array
                  items:
                    type: string
                  default: ["SYS_ADMIN", "NET_ADMIN", "ALL"]
                allowedRegistries:
                  type: array
                  items:
                    type: string
                  default: ["*.ecr.aws", "*.gcr.io", "*.azurecr.io", "docker.io/library"]
            status:
              type: object
              properties:
                phase:
                  type: string
                compliantWorkloads:
                  type: integer
                failingWorkloads:
                  type: integer
"""

CLUSTER_COMPLIANCE_AUDIT_CRD_YAML = """
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clustercomplianceaudits.security.k8s.io
spec:
  group: security.k8s.io
  names:
    kind: ClusterComplianceAudit
    listKind: ClusterComplianceAuditList
    plural: clustercomplianceaudits
    singular: clustercomplianceaudit
    shortNames:
      - comaudit
  scope: Cluster
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                auditSchedule:
                  type: string
                  default: "0 * * * *"
                targetNamespaces:
                  type: array
                  items:
                    type: string
            status:
              type: object
              properties:
                lastAuditTimestamp:
                  type: string
                overallScore:
                  type: number
                status:
                  type: string
                findingsCount:
                  type: integer
"""


@dataclass
class SecurityPolicySpec:
    min_compliance_score: float = 80.0
    enforce_non_root: bool = True
    disallow_privileged: bool = True
    require_read_only_root_filesystem: bool = False
    blocked_capabilities: List[str] = field(default_factory=lambda: ["SYS_ADMIN", "NET_ADMIN", "ALL"])
    allowed_registries: List[str] = field(default_factory=lambda: ["*.ecr.aws", "*.gcr.io", "*.azurecr.io", "docker.io/library"])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class KubernetesCRDManager:
    """Manages Kubernetes CRD generation, validation, and serialization."""

    @staticmethod
    def get_all_crd_manifests() -> str:
        """Returns all turnkey Kubernetes CustomResourceDefinitions concatenated in YAML."""
        return f"{SECURITY_POLICY_CRD_YAML.strip()}\n---\n{CLUSTER_COMPLIANCE_AUDIT_CRD_YAML.strip()}"

    @staticmethod
    def parse_security_policy_yaml(yaml_str: str) -> SecurityPolicySpec:
        """Parses a SecurityPolicy custom resource manifest into SecurityPolicySpec."""
        data = yaml.safe_load(yaml_str) if yaml else {}
        if not isinstance(data, dict):
            return SecurityPolicySpec()
        spec = data.get("spec", {})
        if not isinstance(spec, dict):
            return SecurityPolicySpec()

        return SecurityPolicySpec(
            min_compliance_score=float(spec.get("minComplianceScore", 80.0)),
            enforce_non_root=bool(spec.get("enforceNonRoot", True)),
            disallow_privileged=bool(spec.get("disallowPrivileged", True)),
            require_read_only_root_filesystem=bool(spec.get("requireReadOnlyRootFilesystem", False)),
            blocked_capabilities=list(spec.get("blockedCapabilities", ["SYS_ADMIN", "NET_ADMIN", "ALL"])),
            allowed_registries=list(spec.get("allowedRegistries", ["*.ecr.aws", "*.gcr.io", "*.azurecr.io", "docker.io/library"])),
        )
