#!/usr/bin/env python3
"""
tests/test_cluster_scanner.py
=============================
Unit tests for LiveClusterScanner (CSPM Engine).
"""

from pathlib import Path
import sys
import tempfile
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from cluster_scanner import LiveClusterScanner, LiveClusterReport, WorkloadAuditResult


class TestClusterScanner(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.scanner = LiveClusterScanner()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_mock_cluster_scan(self):
        mock_objects = [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "secure-app", "namespace": "prod"},
                "spec": {
                    "template": {
                        "spec": {
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [{
                                "name": "app",
                                "image": "nginx:1.25-alpine",
                                "securityContext": {
                                    "readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                                "resources": {
                                    "limits": {"cpu": "200m", "memory": "256Mi"}
                                },
                            }],
                        }
                    }
                }
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "insecure-app", "namespace": "dev"},
                "spec": {
                    "template": {
                        "spec": {
                            "hostNetwork": True,
                            "hostPID": True,
                            "containers": [{
                                "name": "app",
                                "image": "nginx:latest",
                                "securityContext": {"privileged": True},
                            }],
                        }
                    }
                }
            }
        ]

        rem_dir = self.td / "remediated"
        report = self.scanner.scan_cluster(
            mock_objects=mock_objects,
            remediate_dir=str(rem_dir),
            gate_threshold=50.0,
        )

        self.assertEqual(report.total_workloads, 2)
        self.assertGreater(len(report.workload_results), 0)
        self.assertEqual(report.veto_count, 1)  # Insecure app triggers veto

        # Check leaderboard ordering (lowest score first)
        lb = report.leaderboard
        self.assertEqual(lb[0].name, "insecure-app")
        self.assertEqual(lb[1].name, "secure-app")

        # Check auto-remediation export
        self.assertTrue(rem_dir.exists())
        exported_files = list(rem_dir.glob("*.yaml"))
        self.assertGreaterEqual(len(exported_files), 1)

    def test_empty_cluster_scan(self):
        report = self.scanner.scan_cluster(mock_objects=[])
        self.assertEqual(report.total_workloads, 0)
        self.assertEqual(report.cluster_score, 100.0)


if __name__ == "__main__":
    unittest.main()
