#!/usr/bin/env python3
"""
tests/test_standalone_webhook.py
================================
Unit tests for Admission Controller Webhook security engine.
"""

import unittest
from webhook import AdmissionSecurityEngine


class TestStandaloneWebhook(unittest.TestCase):
    def setUp(self):
        self.engine = AdmissionSecurityEngine(min_score=75.0, enforcement_mode="enforce")
        self.insecure_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bad-pod"},
            "spec": {
                "hostNetwork": True,
                "containers": [
                    {
                        "name": "root-box",
                        "image": "redis:latest",
                        "securityContext": {
                            "privileged": True,
                        },
                    }
                ],
            },
        }
        self.secure_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "good-pod"},
            "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": "safe-app",
                        "image": "redis@sha256:4d62b92f7e03ac08fef9b8b0e7741d8e1fb7f12e9ee0c3fa4a34b3f81e33de4e",
                        "imagePullPolicy": "Always",
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "limits": {"cpu": "500m", "memory": "256Mi"}
                        },
                    }
                ],
            },
        }

    def test_veto_rule_rejection(self):
        allowed, score, violations = self.engine.evaluate_object(self.insecure_pod, "bad-pod")
        self.assertFalse(allowed)
        self.assertTrue(any("V01" in v or "V09" in v for v in violations))

    def test_secure_pod_allowed(self):
        allowed, score, violations = self.engine.evaluate_object(self.secure_pod, "good-pod")
        self.assertTrue(allowed)
        self.assertGreaterEqual(score, 75.0)

    def test_mutation_patch_generation(self):
        patches = self.engine.generate_mutation_patch(self.insecure_pod)
        self.assertTrue(len(patches) > 0)
        patch_paths = [p["path"] for p in patches]
        self.assertTrue(any("securityContext" in p for p in patch_paths))


if __name__ == "__main__":
    unittest.main()
