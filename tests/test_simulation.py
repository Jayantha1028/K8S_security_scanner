#!/usr/bin/env python3
"""
tests/test_simulation.py
========================
Unit tests for Adversarial Threat Modeling & Multi-Stage Kill Chain Simulator (simulation.py).
"""

import os
import tempfile
import unittest

from simulation import ThreatSimulationEngine, SimulationReport


class TestThreatSimulationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ThreatSimulationEngine()
        self.temp_dir = tempfile.TemporaryDirectory()

        # Vulnerable workload (privileged + hostPID + docker.sock)
        self.vuln_path = os.path.join(self.temp_dir.name, "critical_app.yaml")
        with open(self.vuln_path, "w") as f:
            f.write("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: billing-engine
  namespace: prod
spec:
  template:
    spec:
      hostPID: true
      containers:
      - name: worker
        image: billing:latest
        securityContext:
          privileged: true
          readOnlyRootFilesystem: false
        volumeMounts:
        - name: sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: sock
        hostPath:
          path: /var/run/docker.sock
""")

        # Hardened workload (restricted, non-root, read-only rootfs)
        self.hardened_path = os.path.join(self.temp_dir.name, "hardened_app.yaml")
        with open(self.hardened_path, "w") as f:
            f.write("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secured-api
  namespace: prod
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
      - name: api
        image: api@sha256:b45c7e112d8a5629df4f7c8f9b9f7a7d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          privileged: false
          capabilities:
            drop:
            - ALL
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_simulation_on_vulnerable_workload(self):
        rep = self.engine.simulate_attack_scenario(self.vuln_path)
        self.assertEqual(rep.workload, "critical_app")
        # Critical pod should have high breach probability (> 80%)
        self.assertGreater(rep.breach_probability, 80.0)
        self.assertGreaterEqual(rep.stages_breached, 3)

        # Check MITRE matrix coverage
        self.assertIn("Privilege Escalation", rep.mitre_matrix_coverage)
        self.assertIn("Impact", rep.mitre_matrix_coverage)

    def test_simulation_on_hardened_workload(self):
        rep = self.engine.simulate_attack_scenario(self.hardened_path)
        self.assertEqual(rep.workload, "hardened_app")
        # Hardened pod should have active countermeasures
        self.assertGreaterEqual(len(rep.countermeasures_effective), 1)

    def test_format_simulation_table(self):
        rep = self.engine.simulate_attack_scenario(self.vuln_path)
        table = self.engine.format_simulation_table(rep)
        self.assertIn("ADVERSARIAL KILL CHAIN SIMULATION", table)
        self.assertIn("Mean Time To Breach", table)
        self.assertIn("BREACHED", table)


if __name__ == "__main__":
    unittest.main()
