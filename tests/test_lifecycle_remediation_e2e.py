#!/usr/bin/env python3
"""
tests/test_lifecycle_remediation_e2e.py
=======================================
End-to-End Invariance, Remediation, and Container Lifecycle Testing Suite.
Verifies mathematical invariance of auto-remediation, contextual VEX exploitability
drift reduction, KubeCam continuous drift detection, and 5-phase lifecycle gates.
"""

from pathlib import Path
import json
import sys
import tempfile
import unittest
import yaml

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner
from remediate import auto_remediate_manifest
from vex import ContextualVEXEngine
from kubecam import KubeCamEngine, KubeCamFrame, WorkloadFrameEntry
from lifecycle import ContainerLifecycleOrchestrator


class TestLifecycleRemediationE2E(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()
        self.vex_engine = ContextualVEXEngine()
        self.kubecam = KubeCamEngine()
        self.lifecycle = ContainerLifecycleOrchestrator()

    # --------------------------------------------------------------------------
    # 1. Remediation Mathematical Invariance
    # --------------------------------------------------------------------------
    def test_remediation_mathematical_invariance(self):
        """
        Tests that remediating an insecure manifest strictly improves compliance score,
        eliminates critical misconfigurations, and produces syntactically valid YAML.
        """
        insecure_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy-app
spec:
  replicas: 2
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: nginx:1.14
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            readOnlyRootFilesystem: false
"""
        # Baseline scan
        report_before = self.scanner.scan_yaml_content(insecure_manifest, "insecure.yaml")
        score_before = report_before.compliance_score
        self.assertLess(score_before, 40.0)
        self.assertIn("V01", report_before.detected_vuln_ids)  # Privileged
        self.assertIn("V02", report_before.detected_vuln_ids)  # Root
        self.assertIn("V03", report_before.detected_vuln_ids)  # Privilege Escalation
        self.assertIn("V04", report_before.detected_vuln_ids)  # Writable Rootfs
        self.assertIn("V09", report_before.detected_vuln_ids)  # hostNetwork

        # Apply automated GitOps remediation
        remediated_yaml, diff = auto_remediate_manifest(insecure_manifest)
        self.assertTrue(len(diff) > 0)
        self.assertTrue(len(remediated_yaml) > 0)

        # Invariance 1: Must be valid YAML
        try:
            docs = list(yaml.safe_load_all(remediated_yaml))
            self.assertEqual(len(docs), 1)
        except Exception as e:
            self.fail(f"Remediated output is not valid YAML: {e}")

        # Invariance 2: Score must strictly improve and reach compliant tier
        report_after = self.scanner.scan_yaml_content(remediated_yaml, "remediated.yaml")
        score_after = report_after.compliance_score
        self.assertGreater(score_after, score_before)
        self.assertGreaterEqual(score_after, 70.0)

        # Invariance 3: Critical isolation misconfigurations must be eliminated
        self.assertNotIn("V01", report_after.detected_vuln_ids)  # Privileged revoked
        self.assertNotIn("V02", report_after.detected_vuln_ids)  # RunAsNonRoot enforced
        self.assertNotIn("V03", report_after.detected_vuln_ids)  # AllowPrivilegeEscalation disabled
        self.assertNotIn("V04", report_after.detected_vuln_ids)  # ReadOnlyRootfs enforced
        self.assertNotIn("V09", report_after.detected_vuln_ids)  # HostNetwork removed
        self.assertNotIn("V12", report_after.detected_vuln_ids)  # RuntimeDefault Seccomp added

    # --------------------------------------------------------------------------
    # 2. Contextual VEX Exploitability Drift Reduction
    # --------------------------------------------------------------------------
    def test_vex_exploitability_drift_reduction(self):
        """
        Verifies that applying runtime defenses flips CVE exploitability from
        'affected' to 'not_affected' with CISA OpenVEX justifications.
        """
        insecure_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-cve-pod
spec:
  containers:
    - name: web
      image: nginx:1.14
      securityContext:
        privileged: true
        readOnlyRootFilesystem: false
"""
        remediated_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: hardened-cve-pod
spec:
  containers:
    - name: web
      image: nginx:1.14
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
  securityContext:
    seccompProfile:
      type: RuntimeDefault
"""
        # Generate VEX for insecure manifest
        doc_insecure = self.vex_engine.generate_vex_for_manifest(insecure_manifest)
        # Generate VEX for hardened manifest
        doc_hardened = self.vex_engine.generate_vex_for_manifest(remediated_manifest)

        # Hardened manifest must achieve significantly higher noise reduction
        self.assertGreaterEqual(doc_hardened.noise_reduction_ratio, doc_insecure.noise_reduction_ratio)
        self.assertGreater(doc_hardened.mitigated_cves, 0)

        # Check for CISA OpenVEX justification
        mitigated_statements = [s for s in doc_hardened.statements if s.status == "not_affected"]
        self.assertTrue(len(mitigated_statements) > 0)
        self.assertEqual(mitigated_statements[0].justification, "inline_mitigations_already_exist")

    # --------------------------------------------------------------------------
    # 3. KubeCam Continuous Assessment & State Drift
    # --------------------------------------------------------------------------
    def test_kubecam_state_drift_lifecycle(self):
        """
        Simulates cluster continuous assessment: baseline -> insecure deployment -> drift remediation.
        """
        # Frame 1: Clean baseline
        frame1 = KubeCamFrame(
            frame_id="frame-001",
            timestamp="2026-11-18T10:00:00Z",
            cluster_version="v1.30.0",
            context_name="prod-cluster",
            total_workloads=1,
            cluster_compliance_score=95.0,
            cluster_blast_radius=5.0,
            workloads={
                "kube-system/coredns": WorkloadFrameEntry(
                    workload_id="Deployment:kube-system/coredns",
                    namespace="kube-system",
                    kind="Deployment",
                    name="coredns",
                    compliance_score=95.0,
                    risk_tier="Low",
                    has_exploit_veto=False,
                    findings_count=0,
                    config_hash="h1",
                    top_findings=[],
                )
            },
            frame_hash="hash-frame-1",
        )

        # Frame 2: Deploying insecure workload (Drift Degraded)
        frame2 = KubeCamFrame(
            frame_id="frame-002",
            timestamp="2026-11-18T10:05:00Z",
            cluster_version="v1.30.0",
            context_name="prod-cluster",
            total_workloads=2,
            cluster_compliance_score=60.0,
            cluster_blast_radius=65.0,
            workloads={
                "kube-system/coredns": WorkloadFrameEntry(
                    workload_id="Deployment:kube-system/coredns",
                    namespace="kube-system",
                    kind="Deployment",
                    name="coredns",
                    compliance_score=95.0,
                    risk_tier="Low",
                    has_exploit_veto=False,
                    findings_count=0,
                    config_hash="h1",
                    top_findings=[],
                ),
                "default/rogue-workload": WorkloadFrameEntry(
                    workload_id="Deployment:default/rogue-workload",
                    namespace="default",
                    kind="Deployment",
                    name="rogue-workload",
                    compliance_score=25.0,
                    risk_tier="High",
                    has_exploit_veto=True,
                    findings_count=5,
                    config_hash="h2",
                    top_findings=["V01 (Privileged Container)", "V46 (Docker Socket Mount)"],
                ),
            },
            frame_hash="hash-frame-2",
        )

        deltas = self.kubecam.diff_frames(frame1, frame2)
        self.assertEqual(len(deltas), 1)
        delta = deltas[0]
        self.assertEqual(delta.workload_id, "default/rogue-workload")
        self.assertEqual(delta.drift_type, "NEW_WORKLOAD")
        self.assertEqual(delta.current_score, 25.0)

    # --------------------------------------------------------------------------
    # 4. 5-Phase Lifecycle Gate Decision Matrix
    # --------------------------------------------------------------------------
    def test_lifecycle_gate_hardened_workload_passed(self):
        """Tests that a fully hardened workload passes all 5 lifecycle evaluation gates."""
        hardened_yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hardened-prod-app
  namespace: production
  annotations:
    cosign.sigstore.dev/verified: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prod
  template:
    metadata:
      labels:
        app: prod
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: gcr.io/distroless/static@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
          imagePullPolicy: Always
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
              cpu: 500m
              memory: 256Mi
            requests:
              cpu: 100m
              memory: 128Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(hardened_yaml)
            tf_path = tf.name

        try:
            report = self.lifecycle.audit_lifecycle(tf_path)
            self.assertEqual(report.gate_verdict, "PASSED")
            self.assertEqual(len(report.phases), 5)
            # Verify Phase 3 (Pre-Deploy & Admission Gate) passed
            p3 = next(p for p in report.phases if "Admission Gate" in p.phase_name)
            self.assertTrue(p3.passed)
        finally:
            Path(tf_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
