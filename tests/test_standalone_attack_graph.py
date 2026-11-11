#!/usr/bin/env python3
"""
test_standalone_attack_graph.py
===============================
Unit tests for the standalone AttackGraphEngine & Blast Radius formula.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
from native_scanner import AttackGraphEngine


class TestStandaloneAttackGraph(unittest.TestCase):
    def setUp(self):
        self.engine = AttackGraphEngine()

    def test_multi_resource_lateral_traversal(self):
        docs = [
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {"name": "public-ingress", "namespace": "default"},
                "spec": {
                    "rules": [{
                        "http": {
                            "paths": [{
                                "backend": {
                                    "service": {"name": "frontend-svc", "port": {"number": 80}}
                                }
                            }]
                        }
                    }]
                }
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "frontend-svc", "namespace": "default"},
                "spec": {
                    "selector": {"app": "frontend"},
                    "ports": [{"port": 80, "targetPort": 8080}]
                }
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "frontend-app", "namespace": "default", "labels": {"app": "frontend"}},
                "spec": {
                    "selector": {"matchLabels": {"app": "frontend"}},
                    "template": {
                        "metadata": {"labels": {"app": "frontend"}},
                        "spec": {
                            "serviceAccountName": "admin-sa",
                            "containers": [{"name": "web", "image": "nginx:1.14"}]
                        }
                    }
                }
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": "cluster-admin"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "admin-binding"},
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [{"kind": "ServiceAccount", "name": "admin-sa", "namespace": "default"}]
            }
        ]

        graph = self.engine.build_from_documents(docs)
        self.assertGreater(len(graph.nodes), 3)
        self.assertGreaterEqual(len(graph.edges), 2)

        chains = graph.find_kill_chains()
        self.assertTrue(len(chains) > 0, "Must identify multi-hop kill chain from Ingress to admin Role")

        blast = graph.calculate_cluster_blast_radius()
        self.assertGreater(blast, 60.0, "Cluster-admin escalation should yield significant blast radius")

        mermaid = graph.to_mermaid()
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("public_ingress", mermaid)

    def test_dynamic_dag_compromise_elevation(self):
        docs = [
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "isolated-pod", "namespace": "prod"},
                "spec": {"containers": [{"name": "app", "image": "alpine:latest"}]}
            }
        ]
        graph = self.engine.build_from_documents(docs)
        base_blast = graph.calculate_cluster_blast_radius()

        # Mark pod as breached via dynamic runtime event
        marked = graph.mark_compromised_node("prod/Pod/isolated-pod", "eBPF shell spawned")
        self.assertTrue(marked)

        runtime_blast = graph.calculate_runtime_dynamic_blast_radius()
        self.assertGreater(runtime_blast, base_blast, "Breach should elevate dynamic blast radius")

    def test_cloud_iam_role_breakout(self):
        docs = [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    "name": "aws-sa",
                    "namespace": "default",
                    "annotations": {
                        "eks.amazonaws.com/role-arn": "arn:aws:iam::111222333444:role/AdminRole"
                    }
                }
            },
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "app-pod", "namespace": "default"},
                "spec": {
                    "serviceAccountName": "aws-sa",
                    "containers": [{"name": "c", "image": "nginx"}]
                }
            }
        ]
        graph = self.engine.build_from_documents(docs)
        cloud_node_id = "CloudIdentity:AWS/arn:aws:iam::111222333444:role/AdminRole"
        self.assertIn(cloud_node_id, graph.nodes)
        self.assertTrue(graph.nodes[cloud_node_id].is_crown_jewel)


if __name__ == "__main__":
    unittest.main()
