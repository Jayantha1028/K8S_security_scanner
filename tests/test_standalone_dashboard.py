#!/usr/bin/env python3
"""
tests/test_standalone_dashboard.py
==================================
Unit tests for HTML report generator and dashboard logic.
"""

from pathlib import Path
import tempfile
import unittest

from scanner import NativeSecurityScanner
from dashboard import generate_html_report


class TestStandaloneDashboard(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()
        self.yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: demo-pod
spec:
  containers:
  - name: web
    image: nginx:latest
"""

    def test_generate_html_report(self):
        report = self.scanner.scan_yaml_content(self.yaml, source_name="demo-pod.yaml")
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
            html_path = f.name

        try:
            html = generate_html_report([report], output_path=html_path)
            self.assertIn("Kubernetes Native Security Scanner", html)
            self.assertIn("demo-pod.yaml", html)
            self.assertTrue(Path(html_path).exists())
            self.assertGreater(Path(html_path).stat().st_size, 500)
        finally:
            Path(html_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
