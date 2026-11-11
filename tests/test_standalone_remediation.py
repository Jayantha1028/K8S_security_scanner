#!/usr/bin/env python3
"""
test_standalone_remediation.py
==============================
Unit tests for the standalone least-privilege auto-remediation engine.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
import yaml
from native_scanner import auto_remediate_manifest


class TestStandaloneRemediation(unittest.TestCase):
    def test_auto_remediate_insecure_pod(self):
        vulnerable_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: web
    image: nginx:latest
"""
        remediated_yaml, fixes = auto_remediate_manifest(vulnerable_yaml)
        self.assertGreater(len(fixes), 3)

        doc = yaml.safe_load(remediated_yaml)
        c = doc["spec"]["containers"][0]
        sec = c["securityContext"]
        self.assertFalse(sec["allowPrivilegeEscalation"])
        self.assertTrue(sec["readOnlyRootFilesystem"])
        self.assertEqual(sec["capabilities"]["drop"], ["ALL"])
        self.assertTrue(doc["spec"]["securityContext"]["runAsNonRoot"])

    def test_capability_whitelist_annotation(self):
        annotated_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: net-proxy
  annotations:
    sec.k8s.io/allowed-caps: '["NET_BIND_SERVICE"]'
spec:
  containers:
  - name: proxy
    image: envoy:latest
    securityContext:
      capabilities:
        add:
        - NET_BIND_SERVICE
        - SYS_ADMIN
"""
        remediated_yaml, fixes = auto_remediate_manifest(annotated_yaml)
        doc = yaml.safe_load(remediated_yaml)
        c = doc["spec"]["containers"][0]
        added_caps = c["securityContext"]["capabilities"].get("add", [])
        self.assertIn("NET_BIND_SERVICE", added_caps)
        self.assertNotIn("SYS_ADMIN", added_caps)


if __name__ == "__main__":
    unittest.main()
