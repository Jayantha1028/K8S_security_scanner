#!/usr/bin/env python3
"""
test_standalone_compliance.py
=============================
Unit tests for the standalone regulatory compliance mapping engine.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
from native_scanner import (
    Finding,
    ComplianceFrameworkMapper,
    generate_markdown_certificate,
)


class TestStandaloneCompliance(unittest.TestCase):
    def test_compliance_evaluation(self):
        findings = [
            Finding(
                vuln_id="V01",
                plane=1,
                severity="CRITICAL",
                title="Privileged Container Execution",
                target="default/Pod/test",
                description="Privileged container detected",
                remediation="Disable privileged mode",
            ),
            Finding(
                vuln_id="V02",
                plane=1,
                severity="HIGH",
                title="Root User Execution",
                target="default/Pod/test",
                description="Root user execution detected",
                remediation="Set runAsNonRoot: true",
            )
        ]

        cert = ComplianceFrameworkMapper.evaluate_findings(findings, "prod-deployment.yaml")
        self.assertIn("PCI-DSS-v4.0", cert.frameworks)
        self.assertIn("SOC-2-Type-II", cert.frameworks)
        self.assertIn("HIPAA-Security-Rule", cert.frameworks)
        self.assertIn("ISO-27001-2022", cert.frameworks)
        self.assertIn("NIST-SP-800-190", cert.frameworks)

        pci = cert.frameworks["PCI-DSS-v4.0"]
        self.assertEqual(pci.failed_controls, 1)
        ctrl_ids = [c.control_id for c in pci.controls]
        self.assertIn("Req-2.2", ctrl_ids)

        cert_md = generate_markdown_certificate(cert)
        self.assertIn("Compliance Audit Certificate", cert_md)
        self.assertIn("PCI-DSS-v4.0", cert_md)


if __name__ == "__main__":
    unittest.main()
