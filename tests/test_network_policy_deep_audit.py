#!/usr/bin/env python3
"""
tests/test_network_policy_deep_audit.py
=======================================
Unit tests for deep NetworkPolicy security auditing (V31, V32, V34).
"""

from pathlib import Path
import sys
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner


class TestNetworkPolicyAudit(unittest.TestCase):

    def setUp(self):
        self.scanner = NativeSecurityScanner()

    def test_missing_egress_triggers_v32(self):
        # NetworkPolicy only controls Ingress; missing Egress controls
        yaml_content = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend
"""
        report = self.scanner.scan_yaml_content(yaml_content)
        vuln_ids = [f.vuln_id for f in report.findings]
        self.assertIn("V32", vuln_ids)  # Missing Default-Deny Egress
        self.assertNotIn("V31", vuln_ids)

    def test_unrestricted_cidr_triggers_v34(self):
        # NetworkPolicy opens sensitive database port 5432 to 0.0.0.0/0
        yaml_content = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: public-database-ingress
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 5432
"""
        report = self.scanner.scan_yaml_content(yaml_content)
        vuln_ids = [f.vuln_id for f in report.findings]
        self.assertIn("V34", vuln_ids)  # Unrestricted Ingress CIDR on sensitive port

    def test_hardened_network_policy_clean(self):
        # Full zero-trust default-deny NetworkPolicy
        yaml_content = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: secure-ns
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
"""
        report = self.scanner.scan_yaml_content(yaml_content)
        vuln_ids = [f.vuln_id for f in report.findings]
        self.assertNotIn("V31", vuln_ids)
        self.assertNotIn("V32", vuln_ids)
        self.assertNotIn("V34", vuln_ids)


if __name__ == "__main__":
    unittest.main()
