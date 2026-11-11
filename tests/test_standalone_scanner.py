#!/usr/bin/env python3
"""
test_standalone_scanner.py
==========================
Unit tests for the standalone NativeSecurityScanner engine.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
from native_scanner import (
    NativeSecurityScanner,
    TAXONOMY_56,
    shannon_entropy,
    check_image_typosquatting,
)


class TestStandaloneScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()

    def test_taxonomy_completeness(self):
        self.assertEqual(len(TAXONOMY_56), 56)
        self.assertIn("V01", TAXONOMY_56)
        self.assertIn("V56", TAXONOMY_56)

    def test_privileged_pod_detection(self):
        yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: test-c
    image: nginx:1.14
    securityContext:
      privileged: true
"""
        report = self.scanner.scan_yaml_content(yaml_content, "test.yaml")
        vuln_ids = [f.vuln_id for f in report.findings]
        self.assertIn("V01", vuln_ids)
        self.assertLess(report.compliance_score, 70.0)
        self.assertEqual(report.risk_tier, "High")

    def test_shannon_entropy(self):
        low_entropy = "standard-string"
        high_entropy = "xK9#m$L2@vP8&wQ1"
        self.assertGreater(shannon_entropy(high_entropy), shannon_entropy(low_entropy))
        self.assertGreater(shannon_entropy(high_entropy), 3.5)

    def test_typosquatting_detection(self):
        is_squat, closest, dist = check_image_typosquatting("ng1nx:latest")
        self.assertTrue(is_squat)
        self.assertEqual(closest, "nginx")

        is_squat2, closest2, dist2 = check_image_typosquatting("nginx:latest")
        self.assertFalse(is_squat2)

    def test_hardened_pod_high_score(self):
        yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10001
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: 250m
        memory: 128Mi
      requests:
        cpu: 50m
        memory: 64Mi
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
"""
        report = self.scanner.scan_yaml_content(yaml_content, "secure.yaml")
        self.assertGreaterEqual(report.compliance_score, 80.0)
        self.assertEqual(report.risk_tier, "Low")

    def test_scan_helm_chart_support(self):
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            (p / "Chart.yaml").write_text("apiVersion: v2\nname: test-chart\nversion: 0.1.0")
            tpl = p / "templates"
            tpl.mkdir()
            (tpl / "app.yaml").write_text("""
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: c
    image: nginx:latest
""")
            reports = self.scanner.scan_helm_chart(str(p))
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0].manifest_path, "helm://test-chart")


if __name__ == "__main__":
    unittest.main()
