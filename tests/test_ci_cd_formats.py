#!/usr/bin/env python3
"""
tests/test_ci_cd_formats.py
===========================
Unit tests for CI/CD reporting outputs (JUnit XML & GitHub Actions Annotations).
"""

import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner
from cli import export_junit_xml, emit_github_actions_annotations


class TestCiCdFormats(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.scanner = NativeSecurityScanner()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_export_junit_xml(self):
        yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
"""
        report = self.scanner.scan_yaml_content(yaml_content, source_name="pod.yaml")
        xml_path = self.td / "junit_results.xml"
        export_junit_xml([report], str(xml_path))

        self.assertTrue(xml_path.exists())
        content = xml_path.read_text(encoding="utf-8")
        self.assertIn("<?xml", content)
        self.assertIn("<testsuites", content)
        self.assertIn("<failure", content)
        self.assertIn("V01", content)

    def test_emit_github_actions_annotations(self):
        yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
"""
        report = self.scanner.scan_yaml_content(yaml_content, source_name="pod.yaml")
        f = io.StringIO()
        with patch("sys.stdout", f):
            emit_github_actions_annotations([report])
        output = f.getvalue()

        self.assertIn("::error file=pod.yaml", output)
        self.assertIn("V01", output)


if __name__ == "__main__":
    unittest.main()
