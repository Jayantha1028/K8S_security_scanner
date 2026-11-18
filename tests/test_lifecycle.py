#!/usr/bin/env python3
"""
tests/test_lifecycle.py
=======================
Unit tests for End-to-End Container Security Lifecycle Orchestrator (lifecycle.py).
Tests 5-phase evaluation (Build, Artifact, Deploy Gate, Runtime, Post-Run Governance).
"""

import os
import tempfile
import unittest

from lifecycle import ContainerLifecycleOrchestrator, ContainerLifecycleReport, PhaseResult
from agent import SecurityAgent
from repl import InteractiveCopilotREPL


class TestContainerLifecycleOrchestrator(unittest.TestCase):
    def setUp(self):
        self.orchestrator = ContainerLifecycleOrchestrator()
        self.temp_dir = tempfile.TemporaryDirectory()

        # Hardened manifest
        self.hardened_manifest = os.path.join(self.temp_dir.name, "hardened_deployment.yaml")
        with open(self.hardened_manifest, "w") as f:
            f.write("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secured-checkout
  namespace: prod
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
      - name: checkout
        image: checkout@sha256:b45c7e112d8a5629df4f7c8f9b9f7a7d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          privileged: false
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: 500m
            memory: 256Mi
""")

        # Vulnerable manifest
        self.vulnerable_manifest = os.path.join(self.temp_dir.name, "vulnerable_pod.yaml")
        with open(self.vulnerable_manifest, "w") as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: legacy-app
  namespace: default
spec:
  containers:
  - name: root-app
    image: legacy-app:latest
    securityContext:
      privileged: true
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_audit_lifecycle_hardened(self):
        rep = self.orchestrator.audit_lifecycle(self.hardened_manifest)
        self.assertEqual(len(rep.phases), 5)
        self.assertGreaterEqual(rep.overall_lifecycle_score, 70.0)
        self.assertIn(rep.gate_verdict, ("PASSED", "CONDITIONAL_PASS"))
        self.assertIn("NIST_SP_800_190", rep.compliance_mappings)

    def test_audit_lifecycle_vulnerable(self):
        rep = self.orchestrator.audit_lifecycle(self.vulnerable_manifest)
        self.assertEqual(len(rep.phases), 5)
        self.assertEqual(rep.gate_verdict, "FAILED")
        # Pre-deploy phase should fail
        p3 = [p for p in rep.phases if p.phase_number == 3][0]
        self.assertFalse(p3.passed)

    def test_audit_lifecycle_with_dockerfile(self):
        df_path = os.path.join(self.temp_dir.name, "Dockerfile")
        with open(df_path, "w") as f:
            f.write("FROM alpine:3.18\nUSER 10001\nCMD ['sleep', '10']\n")

        rep = self.orchestrator.audit_lifecycle(self.hardened_manifest, dockerfile_path=df_path)
        p1 = [p for p in rep.phases if p.phase_number == 1][0]
        self.assertEqual(p1.phase_name, "Build & Source IaC")
        self.assertTrue(p1.passed)

    def test_format_terminal_summary(self):
        rep = self.orchestrator.audit_lifecycle(self.hardened_manifest)
        summary = self.orchestrator.format_terminal_summary(rep)
        self.assertIn("END-TO-END CONTAINER SECURITY LIFECYCLE AUDIT", summary)
        self.assertIn("Build & Source IaC", summary)
        self.assertIn("Post-Run & Governance", summary)

    def test_repl_lifecycle_slash_command(self):
        agent = SecurityAgent()
        repl = InteractiveCopilotREPL(agent=agent, target=self.hardened_manifest)
        out = repl.handle_slash_command("/lifecycle")
        self.assertIn("LIFECYCLE AUDIT REPORT", out)

    def test_agent_tool_lifecycle(self):
        agent = SecurityAgent()
        res_json = agent.tool_audit_container_lifecycle(self.hardened_manifest)
        self.assertIn("overall_lifecycle_score", res_json)
        self.assertIn("gate_verdict", res_json)


if __name__ == "__main__":
    unittest.main()
