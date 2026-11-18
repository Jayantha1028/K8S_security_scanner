#!/usr/bin/env python3
"""
tests/test_fuzz_chaos.py
========================
Fuzz, Chaos, and Adversarial Stress Testing Suite.
Validates that scanners, graph synthesizers, VEX engines, admission webhooks,
and telemetry handlers never crash or hang on malformed, adversarial,
or edge-case inputs.
"""

from pathlib import Path
import json
import random
import string
import sys
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner, ScanReport, shannon_entropy, check_image_typosquatting
from attack_graph import AttackGraphEngine
from vex import ContextualVEXEngine
from kubecam import KubeCamEngine, KubeCamFrame
from webhook import AdmissionSecurityEngine


class TestFuzzAndChaos(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()
        self.attack_graph = AttackGraphEngine()
        self.vex_engine = ContextualVEXEngine()
        self.kubecam = KubeCamEngine()
        self.webhook = AdmissionSecurityEngine()

    # --------------------------------------------------------------------------
    # 1. Scanner Manifest Fuzzing (Type Confusion, Nulls, & Edge Structures)
    # --------------------------------------------------------------------------
    def test_scanner_fuzz_nulls_and_empty_payloads(self):
        """Fuzz scanner with empty strings, whitespace, nulls, and comments."""
        empty_samples = [
            "",
            "   \n\t  \n",
            "---",
            "---\n---",
            "# Only a comment\n",
            "null\n",
            "---\nnull\n---\n",
            "apiVersion: v1\nkind: Pod\nmetadata: null\nspec: null\n",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers: null\n",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers: []\n",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - null\n",
        ]
        for idx, sample in enumerate(empty_samples):
            try:
                rep = self.scanner.scan_yaml_content(sample, f"empty_fuzz_{idx}")
                self.assertIsInstance(rep, ScanReport)
            except Exception as e:
                self.fail(f"Scanner crashed on empty/null sample #{idx}: {e}")

    def test_scanner_fuzz_type_confusion(self):
        """Fuzz scanner with scalar-where-list and list-where-dict type anomalies."""
        anomalous_payloads = [
            # spec as list
            """
apiVersion: v1
kind: Pod
metadata:
  name: list-spec-pod
spec:
  - item1
  - item2
""",
            # command and args as scalar strings rather than lists
            """
apiVersion: v1
kind: Pod
metadata:
  name: scalar-cmd-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      command: "/bin/sh"
      args: "-c echo hello"
""",
            # ports as scalar integer
            """
apiVersion: v1
kind: Pod
metadata:
  name: scalar-ports-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      ports: 8080
""",
            # capabilities.add as integer and string
            """
apiVersion: v1
kind: Pod
metadata:
  name: invalid-caps-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      securityContext:
        capabilities:
          add: 9999
          drop: "NOT_A_LIST"
""",
            # seccompProfile as scalar string
            """
apiVersion: v1
kind: Pod
metadata:
  name: scalar-seccomp-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      securityContext:
        seccompProfile: RuntimeDefault
""",
            # volumeMounts with null mountPath or invalid types
            """
apiVersion: v1
kind: Pod
metadata:
  name: null-mount-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      volumeMounts:
        - name: m1
          mountPath: null
        - name: m2
        - "INVALID_STRING_MOUNT"
""",
            # resources with non-dict limits
            """
apiVersion: v1
kind: Pod
metadata:
  name: invalid-resources-pod
spec:
  containers:
    - name: c1
      image: nginx:latest
      resources:
        limits: 500
        requests: "none"
""",
            # volumes with hostPath as string or null
            """
apiVersion: v1
kind: Pod
metadata:
  name: invalid-hostpath-pod
spec:
  volumes:
    - name: v1
      hostPath: null
    - name: v2
      hostPath: "/etc/passwd"
""",
        ]
        for idx, payload in enumerate(anomalous_payloads):
            try:
                rep = self.scanner.scan_yaml_content(payload, f"type_confusion_{idx}")
                self.assertIsInstance(rep, ScanReport)
            except Exception as e:
                self.fail(f"Scanner crashed on type-confusion payload #{idx}: {e}")

    def test_scanner_fuzz_extreme_integers_and_unicode(self):
        """Fuzz scanner with extreme port numbers, unicode homoglyphs, and giant strings."""
        giant_string = "A" * 50000
        unicode_payload = f"""
apiVersion: v1
kind: Pod
metadata:
  name: "unicode-pod-🚀-\u202e-ltr-rtl"
spec:
  containers:
    - name: "c-\u0430\u0440\u0440"
      image: "myregistry.io/app:1.0"
      ports:
        - containerPort: 999999999
          hostPort: -65535
      env:
        - name: GIANT_VAR
          value: "{giant_string}"
        - name: "VAR-\u0000-NULL"
          value: "normal"
"""
        try:
            rep = self.scanner.scan_yaml_content(unicode_payload, "unicode_fuzz")
            self.assertIsInstance(rep, ScanReport)
            # Null byte injection \u0000 correctly triggers V00 (Malformed YAML AST) syntax guard
            self.assertTrue(any(f.vuln_id == "V00" for f in rep.findings))
            self.assertEqual(rep.compliance_score, 0.0)
        except Exception as e:
            self.fail(f"Scanner crashed on extreme integer/unicode payload: {e}")

    # --------------------------------------------------------------------------
    # 2. Attack Graph Chaos Testing (Cycles, Self-Loops, & Missing References)
    # --------------------------------------------------------------------------
    def test_attack_graph_cyclic_and_malformed_docs(self):
        """Tests that AttackGraph handles cyclic bindings, null metadata, and missing nodes."""
        chaotic_docs = [
            # Binding to itself
            {
                "kind": "RoleBinding",
                "metadata": None,
                "roleRef": {"name": "self-binding-role"},
                "subjects": [{"kind": "ServiceAccount", "name": "sa-1", "namespace": "default"}],
            },
            # Missing spec
            {"kind": "Service", "metadata": {"name": "broken-svc", "namespace": "default"}, "spec": None},
            # Pod referencing non-existent service account
            {
                "kind": "Pod",
                "metadata": {"name": "ghost-sa-pod", "namespace": "default"},
                "spec": {"serviceAccountName": "does-not-exist", "containers": [{"name": "c", "image": "img"}]},
            },
            # Ingress pointing to non-existent service
            {
                "kind": "Ingress",
                "metadata": {"name": "ghost-ing", "namespace": "default"},
                "spec": {
                    "rules": [{
                        "http": {
                            "paths": [{
                                "backend": {"service": {"name": "missing-backend", "port": {"number": 80}}}
                            }]
                        }
                    }]
                },
            },
        ]
        try:
            self.attack_graph.build_from_documents(chaotic_docs)
            blast_radius = self.attack_graph.calculate_cluster_blast_radius()
            self.assertGreaterEqual(blast_radius, 0.0)
            self.assertLessEqual(blast_radius, 100.0)
            mermaid = self.attack_graph.to_mermaid()
            self.assertTrue("TD" in mermaid or "flowchart" in mermaid)
        except Exception as e:
            self.fail(f"AttackGraph crashed on chaotic documents: {e}")

    # --------------------------------------------------------------------------
    # 3. Contextual VEX Fuzzing
    # --------------------------------------------------------------------------
    def test_vex_engine_resilience_to_nil_and_empty_inputs(self):
        """Verifies OpenVEX engine handles None, empty, or corrupt manifests safely."""
        nil_inputs = [None, "", "null", "---", 42, {}]
        for inp in nil_inputs:
            try:
                doc = self.vex_engine.generate_vex_for_manifest(inp)
                self.assertIsInstance(doc.statements, list)
                # Verify OpenVEX JSON export schema
                vex_json = doc.to_openvex_json()
                self.assertIn("@context", vex_json)
                self.assertIn("https://openvex.dev/ns/v0.2.0", vex_json)
            except Exception as e:
                self.fail(f"ContextualVEXEngine crashed on nil/empty input {inp}: {e}")

    # --------------------------------------------------------------------------
    # 4. KubeCam Diffing with Nil / Incomplete Frames
    # --------------------------------------------------------------------------
    def test_kubecam_diff_resilience(self):
        """Verifies KubeCam diffing handles None frames without uncaught exceptions."""
        deltas = self.kubecam.diff_frames(None, None)
        self.assertEqual(deltas, [])

        sample_frame = KubeCamFrame(
            frame_id="frame-001",
            timestamp="2026-11-18T12:00:00Z",
            cluster_version="v1.30.0",
            context_name="test-context",
            total_workloads=0,
            cluster_compliance_score=100.0,
            cluster_blast_radius=0.0,
            workloads={},
            frame_hash="hash001",
        )
        deltas_one_nil = self.kubecam.diff_frames(sample_frame, None)
        self.assertEqual(deltas_one_nil, [])

        deltas_other_nil = self.kubecam.diff_frames(None, sample_frame)
        self.assertEqual(deltas_other_nil, [])

    # --------------------------------------------------------------------------
    # 5. Admission Webhook Fuzzing (Malformed Objects)
    # --------------------------------------------------------------------------
    def test_admission_webhook_fuzzing(self):
        """Tests that validating and mutating webhook engines reject malformed objects safely."""
        malformed_objects = [
            None,
            {},
            {"kind": "UnknownKind"},
            {"kind": "Pod", "spec": None},
            {"kind": "Pod", "spec": {"containers": "NOT_A_LIST"}},
            {"kind": "Deployment", "spec": {"template": "NOT_A_DICT"}},
        ]
        for idx, obj in enumerate(malformed_objects):
            try:
                allowed, score, findings = self.webhook.evaluate_object(obj, f"fuzz-obj-{idx}")
                self.assertIsInstance(allowed, bool)
                self.assertIsInstance(score, (int, float))
                self.assertIsInstance(findings, list)
            except Exception as e:
                self.fail(f"AdmissionWebhook evaluate_object crashed on malformed object {obj}: {e}")

            try:
                patch = self.webhook.generate_mutation_patch(obj)
                self.assertIsInstance(patch, list)
            except Exception as e:
                self.fail(f"AdmissionWebhook generate_mutation_patch crashed on malformed object {obj}: {e}")


if __name__ == "__main__":
    unittest.main()
