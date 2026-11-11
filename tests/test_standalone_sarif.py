#!/usr/bin/env python3
"""
tests/test_standalone_sarif.py
==============================
Unit tests for SARIF v2.1.0 report exporter.
"""

import json
from pathlib import Path
import tempfile
import unittest

from scanner import NativeSecurityScanner
from sarif import export_sarif_report


class TestStandaloneSarif(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()
        self.insecure_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: sarif-test-pod
spec:
  containers:
  - name: test-app
    image: nginx:latest
    securityContext:
      privileged: true
"""

    def test_sarif_export(self):
        report = self.scanner.scan_yaml_content(self.insecure_yaml, source_name="test-manifest.yaml")
        with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False) as f:
            sarif_file = f.name

        try:
            doc = export_sarif_report([report], output_path=sarif_file)
            self.assertEqual(doc["version"], "2.1.0")
            self.assertIn("runs", doc)
            self.assertTrue(len(doc["runs"]) > 0)

            run = doc["runs"][0]
            tool_name = run["tool"]["driver"]["name"]
            self.assertEqual(tool_name, "k8s-native-scanner")

            # Check rules and results
            rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertIn("V01", rule_ids)  # Privileged container

            results = run["results"]
            self.assertTrue(len(results) > 0)
            result_rule_ids = {res["ruleId"] for res in results}
            self.assertIn("V01", result_rule_ids)

            # Check file on disk
            loaded = json.loads(Path(sarif_file).read_text(encoding="utf-8"))
            self.assertEqual(loaded["version"], "2.1.0")
        finally:
            Path(sarif_file).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
