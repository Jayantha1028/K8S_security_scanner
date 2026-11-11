#!/usr/bin/env python3
"""
tests/test_exporter.py
======================
Unit tests for PrometheusMetricsExporter.
"""

from pathlib import Path
import sys
import tempfile
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner
from exporter import PrometheusMetricsExporter


class TestPrometheusExporter(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.exporter = PrometheusMetricsExporter()
        self.scanner = NativeSecurityScanner()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_generate_metrics(self):
        doc = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
"""
        report = self.scanner.scan_yaml_content(doc, source_name="demo-manifest.yaml")
        metrics_text = self.exporter.generate_metrics([report])

        self.assertIn("k8s_security_cluster_compliance_score", metrics_text)
        self.assertIn("k8s_security_cluster_blast_radius", metrics_text)
        self.assertIn("k8s_security_workloads_total", metrics_text)
        self.assertIn("k8s_security_workload_compliance_score", metrics_text)
        self.assertIn("k8s_security_findings_total", metrics_text)
        self.assertIn("k8s_security_plane_findings_total", metrics_text)

    def test_export_to_file(self):
        doc = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: simple\nspec:\n  containers:\n    - name: c\n      image: busybox\n"
        report = self.scanner.scan_yaml_content(doc, source_name="simple.yaml")
        prom_file = self.td / "metrics.prom"
        self.exporter.export_to_file([report], str(prom_file))

        self.assertTrue(prom_file.exists())
        content = prom_file.read_text(encoding="utf-8")
        self.assertIn("k8s_security_cluster_compliance_score", content)


if __name__ == "__main__":
    unittest.main()
