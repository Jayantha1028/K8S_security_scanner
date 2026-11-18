#!/usr/bin/env python3
"""
tests/test_full_contract_verification.py
========================================
Full-Spectrum Contract & Taxonomy Verification Testing Suite.
Verifies complete schema adherence for all 56 vulnerability rules (V01-V56),
feature vector dimensional invariants (17-D vs 32-D), JSON serialization contracts,
and regulatory framework compliance mappings.
"""

from pathlib import Path
import json
import re
import sys
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from taxonomy import TAXONOMY_56, PLANES
from scanner import (
    NativeSecurityScanner,
    ScanReport,
    Finding,
    FEATURES_17,
    FEATURES_32,
    FEATURE_METADATA_32,
)
from compliance import ComplianceFrameworkMapper


class TestFullContractVerification(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()

    # --------------------------------------------------------------------------
    # 1. 56-Vulnerability Taxonomy Schema Invariants
    # --------------------------------------------------------------------------
    def test_taxonomy_complete_56_rules(self):
        """Validates that exactly 56 vulnerabilities exist and IDs span V01 to V56."""
        self.assertEqual(len(TAXONOMY_56), 56, f"Expected 56 rules, found {len(TAXONOMY_56)}")
        for i in range(1, 57):
            expected_id = f"V{i:02d}"
            self.assertIn(expected_id, TAXONOMY_56, f"Missing vulnerability rule {expected_id}")

    def test_taxonomy_rule_metadata_contract(self):
        """Validates that every single rule conforms to strict enterprise metadata schema."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        id_regex = re.compile(r"^V\d{2}$")
        mitre_regex = re.compile(r"^T\d{4}(?:\.\d{3})?$")

        for vuln_id, meta in TAXONOMY_56.items():
            self.assertTrue(id_regex.match(vuln_id), f"Invalid ID format for {vuln_id}")
            self.assertEqual(meta.get("id"), vuln_id)

            # Plane in [1, 7]
            plane = meta.get("plane")
            self.assertIsInstance(plane, int, f"Plane must be int for {vuln_id}")
            self.assertIn(plane, range(1, 8), f"Plane must be 1..7 for {vuln_id}")
            self.assertIn(plane, PLANES, f"Plane {plane} must exist in PLANES catalog")

            # Severity
            severity = meta.get("severity")
            self.assertIn(severity, valid_severities, f"Invalid severity '{severity}' in {vuln_id}")

            # MITRE technique
            mitre = meta.get("mitre", "")
            self.assertTrue(
                mitre_regex.match(mitre),
                f"Invalid MITRE ATT&CK technique '{mitre}' in {vuln_id}"
            )

            # Title, Description, and Remediation
            name = meta.get("name", "").strip()
            self.assertTrue(len(name) > 3, f"Title too short in {vuln_id}")
            desc = meta.get("description", "").strip()
            self.assertTrue(len(desc) > 10, f"Description too short in {vuln_id}")
            remed = meta.get("remediation", "").strip()
            self.assertTrue(len(remed) > 5, f"Remediation too short in {vuln_id}")

    # --------------------------------------------------------------------------
    # 2. Feature Vector Contract & Dimensional Invariants
    # --------------------------------------------------------------------------
    def test_feature_vector_dimension_invariants(self):
        """Verifies 17-element baseline and 32-element expanded feature contracts."""
        self.assertEqual(len(FEATURES_17), 17)
        self.assertEqual(len(FEATURES_32), 32)

        # Baseline 17 must be strict subset of 32
        for key in FEATURES_17:
            self.assertIn(key, FEATURES_32, f"Baseline feature '{key}' missing from FEATURES_32")

        # FEATURE_METADATA_32 must cover all 32 dimensions
        self.assertEqual(len(FEATURE_METADATA_32), 32)
        for key in FEATURES_32:
            self.assertIn(key, FEATURE_METADATA_32, f"Metadata missing for feature '{key}'")
            meta = FEATURE_METADATA_32[key]
            self.assertIn("dim", meta)
            self.assertIn("category", meta)
            self.assertIn("cis", meta)
            self.assertIn("desc", meta)

    def test_report_ordered_vector_properties(self):
        """Verifies report feature vector extraction preserves order and float typing."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: vector-test-pod
spec:
  containers:
    - name: c
      image: nginx:1.14
      securityContext:
        privileged: true
"""
        report = self.scanner.scan_yaml_content(manifest, "vector.yaml")

        vec_17 = report.feature_vector_17
        self.assertEqual(len(vec_17), 17)
        self.assertTrue(all(isinstance(x, float) for x in vec_17))

        vec_32 = report.feature_vector_32
        self.assertEqual(len(vec_32), 32)
        self.assertTrue(all(isinstance(x, float) for x in vec_32))

        # Privileged flag must be 1.0
        priv_idx_17 = FEATURES_17.index("privileged_count")
        self.assertEqual(vec_17[priv_idx_17], 1.0)
        priv_idx_32 = FEATURES_32.index("privileged_count")
        self.assertEqual(vec_32[priv_idx_32], 1.0)

    # --------------------------------------------------------------------------
    # 3. JSON Serialization Contract
    # --------------------------------------------------------------------------
    def test_scan_report_json_serialization(self):
        """Verifies ScanReport.to_dict() produces 100% valid, loss-free JSON."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: json-test-pod
spec:
  containers:
    - name: c
      image: nginx:latest
"""
        report = self.scanner.scan_yaml_content(manifest, "json_test.yaml")
        rep_dict = report.to_dict()

        # Must serialize cleanly without TypeError (e.g. from sets or objects)
        try:
            serialized = json.dumps(rep_dict, indent=2)
            self.assertTrue(len(serialized) > 50)
            parsed = json.loads(serialized)
            self.assertIn("manifest_path", parsed)
            self.assertIn("compliance_score", parsed)
            self.assertIn("detected_vuln_ids", parsed)
            self.assertIsInstance(parsed["detected_vuln_ids"], list)
        except Exception as e:
            self.fail(f"ScanReport failed JSON serialization contract: {e}")

    # --------------------------------------------------------------------------
    # 4. Multi-Framework Regulatory Compliance Mapping Contract
    # --------------------------------------------------------------------------
    def test_compliance_framework_mappings(self):
        """Verifies auditor-ready mapping across PCI-DSS, SOC 2, HIPAA, ISO 27001, and NIST."""
        findings = [
            Finding("V01", 1, "CRITICAL", "Privileged Container Execution", "pod/c", "Privileged: true", "Remove"),
            Finding("V18", 2, "CRITICAL", "Plaintext Secrets", "pod/c:API_KEY", "Plaintext key", "SecretKeyRef"),
            Finding("V31", 4, "HIGH", "Missing NetworkPolicy", "Namespace", "No policy", "Apply policy"),
        ]
        cert = ComplianceFrameworkMapper.evaluate_findings(findings, target_name="test-deployment.yaml")
        self.assertIsNotNone(cert)
        self.assertEqual(cert.audit_target, "test-deployment.yaml")
        self.assertIsNotNone(cert.overall_compliance_score)

        # Verify framework breakdowns
        frameworks = cert.frameworks
        for fw_key in ("PCI-DSS-v4.0", "SOC-2-Type-II", "HIPAA-Security-Rule", "ISO-27001-2022", "NIST-SP-800-190"):
            self.assertIn(fw_key, frameworks, f"Framework {fw_key} missing from certificate")
            fw_data = frameworks[fw_key]
            self.assertIsNotNone(fw_data.framework_name)
            self.assertIn(fw_data.status, {"COMPLIANT", "NON_COMPLIANT", "AUDIT_REQUIRED"})
            self.assertGreaterEqual(fw_data.compliance_score, 0.0)
            self.assertLessEqual(fw_data.compliance_score, 100.0)


if __name__ == "__main__":
    unittest.main()
