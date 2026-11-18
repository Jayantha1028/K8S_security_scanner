#!/usr/bin/env python3
"""
tests/test_vex.py
=================
Unit tests for the Contextual Exploitability Engine & OpenVEX Generator (vex.py).
Verifies runtime security correlation, OpenVEX v0.2.0 schema conformance,
and alert noise reduction calculations.
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from vex import (
    ContextualVEXEngine,
    VEXDocument,
    VEXStatement,
    export_vex_report,
    OPENVEX_CONTEXT,
)
from cve import CVEEntry
from agent import SecurityAgent
from mcp_server import MCPServer


class TestContextualVEXEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ContextualVEXEngine()
        self.temp_dir = tempfile.TemporaryDirectory()

        # Hardened workload with read-only rootfs and dropped caps
        self.hardened_manifest = os.path.join(self.temp_dir.name, "hardened_pod.yaml")
        with open(self.hardened_manifest, "w") as f:
            f.write("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-api
  namespace: prod
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
      - name: api
        image: secure-service:1.0.0
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          privileged: false
          capabilities:
            drop:
            - ALL
""")

        # Vulnerable workload running as privileged root
        self.vulnerable_manifest = os.path.join(self.temp_dir.name, "vulnerable_pod.yaml")
        with open(self.vulnerable_manifest, "w") as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: root-app
    image: legacy-service:latest
    securityContext:
      privileged: true
      readOnlyRootFilesystem: false
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_workload_profile(self):
        doc = self.engine.generate_vex_for_manifest(self.hardened_manifest)
        self.assertEqual(doc.workload, "prod/Deployment/hardened-api")
        self.assertGreaterEqual(doc.total_cves, 1)

    def test_contextual_mitigation_on_hardened_workload(self):
        # Test specific file write RCE CVE
        cve_write = CVEEntry(
            cve_id="CVE-2023-9999",
            severity="CRITICAL",
            cvss_score=9.8,
            package="curl",
            vulnerable_versions="< 1.0",
            description="Arbitrary file write and dropper execution via SOCKS5 buffer overflow.",
        )
        profile = self.engine.parse_workload_profile({
            "kind": "Pod",
            "metadata": {"name": "test", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "securityContext": {
                        "readOnlyRootFilesystem": True,
                        "allowPrivilegeEscalation": False,
                        "runAsNonRoot": True,
                    }
                }]
            }
        })
        status, just, impact, risk = self.engine.evaluate_cve_exploitability(cve_write, profile)
        self.assertEqual(status, "not_affected")
        self.assertEqual(just, "inline_mitigations_already_exist")
        self.assertIn("readOnlyRootFilesystem", impact)
        self.assertEqual(risk, "LOW")

    def test_exploitability_on_privileged_workload(self):
        cve = CVEEntry(
            cve_id="CVE-2023-8888",
            severity="HIGH",
            cvss_score=8.5,
            package="openssl",
            vulnerable_versions="< 1.0",
            description="Memory disclosure and code execution.",
        )
        profile = self.engine.parse_workload_profile({
            "kind": "Pod",
            "metadata": {"name": "test", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "securityContext": {"privileged": True}
                }]
            }
        })
        status, just, impact, risk = self.engine.evaluate_cve_exploitability(cve, profile)
        self.assertEqual(status, "affected")
        self.assertEqual(risk, "CRITICAL")

    def test_noise_reduction_metric(self):
        doc_hardened = self.engine.generate_vex_for_manifest(self.hardened_manifest)
        self.assertGreater(doc_hardened.noise_reduction_ratio, 0.0)
        self.assertGreater(doc_hardened.mitigated_cves, 0)

        doc_vuln = self.engine.generate_vex_for_manifest(self.vulnerable_manifest)
        # Privileged pod should have 0% noise reduction (all CVEs are actively exploitable)
        self.assertEqual(doc_vuln.noise_reduction_ratio, 0.0)
        self.assertEqual(doc_vuln.mitigated_cves, 0)
        self.assertEqual(doc_vuln.exploitable_cves, doc_vuln.total_cves)

    def test_openvex_json_conformance(self):
        doc = self.engine.generate_vex_for_manifest(self.hardened_manifest)
        json_str = doc.to_openvex_json()
        data = json.loads(json_str)

        self.assertEqual(data["@context"], OPENVEX_CONTEXT)
        self.assertIn("author", data)
        self.assertIn("statements", data)
        self.assertGreater(len(data["statements"]), 0)

        first_stmt = data["statements"][0]
        self.assertIn("vulnerability", first_stmt)
        self.assertIn("products", first_stmt)
        self.assertIn("status", first_stmt)
        if first_stmt["status"] == "not_affected":
            self.assertIn("justification", first_stmt)
            self.assertIn("impact_statement", first_stmt)

    def test_export_vex_report(self):
        out_file = os.path.join(self.temp_dir.name, "out.openvex.json")
        doc = export_vex_report(self.hardened_manifest, out_file)
        self.assertTrue(os.path.exists(out_file))
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        self.assertEqual(data["@context"], OPENVEX_CONTEXT)

    def test_terminal_summary_format(self):
        doc = self.engine.generate_vex_for_manifest(self.hardened_manifest)
        summary = self.engine.format_terminal_summary(doc)
        self.assertIn("EXPLOITABILITY NOISE REDUCTION", summary)
        self.assertIn("alert reduction", summary)

    def test_agent_tool_integration(self):
        agent = SecurityAgent()
        res_str = agent.tool_generate_openvex(self.hardened_manifest)
        data = json.loads(res_str)
        self.assertIn("noise_reduction_pct", data)
        self.assertIn("total_cves", data)

    def test_mcp_tool_integration(self):
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "k8s_generate_openvex",
                "arguments": {"target": self.hardened_manifest},
            },
        }
        res = server.handle_request(req)
        content_text = res["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertIn("noise_reduction_pct", data)


if __name__ == "__main__":
    unittest.main()
