#!/usr/bin/env python3
"""
test_standalone_cli.py
======================
Unit tests for the standalone CLI entrypoints.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestStandaloneCLI(unittest.TestCase):
    def setUp(self):
        self.cli_path = Path(__file__).resolve().parents[1] / "bin" / "k8s-native-scan"

    def test_cli_version(self):
        res = subprocess.run([str(self.cli_path), "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("k8s-native-scanner v1.0.0", res.stdout)

    def test_cli_scan_manifest(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: cli-test-pod
spec:
  containers:
  - name: c
    image: nginx:1.14
    securityContext:
      privileged: true
""")
            f.flush()
            tmp_p = f.name

        try:
            res = subprocess.run([str(self.cli_path), "scan", tmp_p], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Compliance Score:", res.stdout)
            self.assertIn("V01: Privileged Container Execution", res.stdout)
        finally:
            Path(tmp_p).unlink(missing_ok=True)

    def test_cli_remediate_manifest(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: unhardened-pod
spec:
  containers:
  - name: app
    image: redis:alpine
""")
            f.flush()
            tmp_in = f.name

        tmp_out = tmp_in + ".hardened.yaml"
        try:
            res = subprocess.run([str(self.cli_path), "remediate", tmp_in, "-o", tmp_out, "--diff"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Applied", res.stdout)
            self.assertTrue(Path(tmp_out).exists())
            self.assertIn("readOnlyRootFilesystem", Path(tmp_out).read_text())
        finally:
            Path(tmp_in).unlink(missing_ok=True)
            Path(tmp_out).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
