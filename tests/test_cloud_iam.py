#!/usr/bin/env python3
"""
tests/test_cloud_iam.py
=======================
Unit tests for CloudIAMVerifier across AWS IRSA, GCP Workload Identity, and Azure Entra.
"""

import unittest
from cloud_iam import CloudIAMVerifier


class TestCloudIAMVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = CloudIAMVerifier(enable_live_cloud_api=False)

    def test_aws_irsa_privileged_role(self):
        annotations = {
            "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/SuperAdminRole"
        }
        findings = self.verifier.audit_role_binding(annotations, "workload-app")
        self.assertTrue(any(f.provider == "AWS" and f.risk_level == "CRITICAL" for f in findings))

    def test_aws_irsa_malformed_arn(self):
        annotations = {
            "eks.amazonaws.com/role-arn": "not-an-arn"
        }
        findings = self.verifier.audit_role_binding(annotations, "workload-app")
        self.assertTrue(any("Malformed" in f.title for f in findings))

    def test_gcp_privileged_role(self):
        annotations = {
            "iam.gke.io/gcp-service-account": "cluster-admin@my-project.iam.gserviceaccount.com"
        }
        findings = self.verifier.audit_role_binding(annotations, "workload-app")
        self.assertTrue(any(f.provider == "GCP" and f.risk_level == "CRITICAL" for f in findings))


if __name__ == "__main__":
    unittest.main()
