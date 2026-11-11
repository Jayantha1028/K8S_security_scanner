#!/usr/bin/env python3
"""
test_standalone_declarative.py
==============================
Unit tests for the standalone declarative custom rule engine.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
from native_scanner import DeclarativeRuleEngine, DeclarativeRule


class TestStandaloneDeclarative(unittest.TestCase):
    def setUp(self):
        self.engine = DeclarativeRuleEngine()

    def test_custom_operator_evaluation(self):
        rule = DeclarativeRule(
            id="CUSTOM-PORT-RESTRICTION",
            name="Block Insecure Port 22",
            severity="HIGH",
            kinds=["Pod"],
            target="containers",
            field_path="ports.0.containerPort",
            operator="eq",
            expected_value=22,
            message="Direct SSH port 22 exposure is forbidden",
        )
        self.engine.add_rule(rule)

        bad_doc = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ssh-pod"},
            "spec": {
                "containers": [{
                    "name": "sshd",
                    "image": "ubuntu",
                    "ports": [{"containerPort": 22}]
                }]
            }
        }

        findings = self.engine.evaluate_document(bad_doc)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vuln_id"], "CUSTOM-PORT-RESTRICTION")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_clean_doc_no_violations(self):
        rule = DeclarativeRule(
            id="CUSTOM-MUST-HAVE-OWNER",
            name="Enforce Owner Label",
            severity="MEDIUM",
            kinds=["Pod"],
            target="metadata",
            field_path="labels.owner",
            operator="is_null",
            message="Owner label is required",
        )
        self.engine.add_rule(rule)

        good_doc = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "owned-pod", "labels": {"owner": "security-team"}},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        }

        findings = self.engine.evaluate_document(good_doc)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
