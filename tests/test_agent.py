#!/usr/bin/env python3
"""
tests/test_agent.py
===================
Unit tests for the Autonomous Kubernetes Security AI Agent (agent.py).
Verifies provider initialization, tool execution, ReAct loops, and offline fallbacks.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent import SecurityAgent, LLMClient


class TestLLMClient(unittest.TestCase):
    def test_default_local_provider(self):
        with patch.dict(os.environ, {}, clear=True):
            client = LLMClient(provider="auto")
            self.assertEqual(client.provider, "local")
            self.assertEqual(client.model, "heuristic-v1")
            res = client.generate("system", "hello world")
            self.assertIn("Local Expert Reasoner", res)

    def test_explicit_provider_gemini(self):
        client = LLMClient(provider="gemini", api_key="fake-key")
        self.assertEqual(client.provider, "gemini")
        self.assertEqual(client.model, "gemini-1.5-flash")


class TestSecurityAgentTools(unittest.TestCase):
    def setUp(self):
        self.agent = SecurityAgent(llm_client=LLMClient(provider="local"))
        self.temp_dir = tempfile.TemporaryDirectory()

        self.sample_manifest = os.path.join(self.temp_dir.name, "vulnerable_pod.yaml")
        with open(self.sample_manifest, "w") as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_scan_manifest(self):
        res = self.agent.tool_scan_manifest(self.sample_manifest)
        data = json.loads(res)
        self.assertGreaterEqual(data["total_findings"], 1)
        self.assertTrue(any(f["id"] in ("V01", "KS-SEC-001") for r in data["reports"] for f in r["findings"]))

    def test_tool_analyze_attack_graph(self):
        res = self.agent.tool_analyze_attack_graph(self.sample_manifest)
        data = json.loads(res)
        self.assertIn("blast_radius_score", data)
        self.assertIn("nodes", data)

    def test_tool_explain_vulnerability(self):
        res = self.agent.tool_explain_vulnerability("V01")
        data = json.loads(res)
        self.assertEqual(data["id"], "V01")
        self.assertIn("Privileged", data["name"])

    def test_tool_explain_vulnerability_unknown(self):
        res = self.agent.tool_explain_vulnerability("UNKNOWN-999")
        self.assertIn("not found", res)

    def test_tool_generate_gitops_fix(self):
        res = self.agent.tool_generate_gitops_fix(self.sample_manifest)
        data = json.loads(res)
        self.assertGreaterEqual(data["total_workloads"], 1)

    def test_tool_verify_patch_dry_run(self):
        res = self.agent.tool_verify_patch_dry_run(self.sample_manifest)
        data = json.loads(res)
        self.assertTrue(data["modified"])
        self.assertIn("privileged", data["diff_preview"])

    def test_tool_query_cve(self):
        res = self.agent.tool_query_cve("openssl")
        self.assertIsInstance(res, str)

    def test_reason_and_act_deterministic(self):
        res = self.agent.reason_and_act(
            prompt="Audit this pod and tell me if it can escape to the host node.",
            target=self.sample_manifest,
        )
        self.assertEqual(res["status"], "success")
        self.assertIn("Autonomous Security Assessment", res["final_answer"])
        self.assertIn("Cluster Blast Radius Index", res["final_answer"])

    def test_reason_and_act_with_mock_llm_tool_calling(self):
        mock_client = MagicMock()
        mock_client.provider = "gemini"
        mock_client.api_key = "test-key"
        mock_client.generate.side_effect = [
            f'Action: scan_manifest({{"path": "{self.sample_manifest}"}})',
            "Final Answer: The pod runs with privileged: true (V01) allowing host container breakout.",
        ]

        agent = SecurityAgent(llm_client=mock_client)
        res = agent.reason_and_act(prompt="Audit workload", target=self.sample_manifest)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["steps_taken"], 2)
        self.assertIn("host container breakout", res["final_answer"])
        self.assertEqual(len(res["trajectory"]), 1)

    def test_watch_cluster_single_cycle(self):
        with patch.object(self.agent.cluster_scanner, "scan_cluster") as mock_scan:
            mock_scan.return_value = MagicMock(
                workloads_scanned=2,
                findings=[],
                summary={"compliant": True},
            )
            # Should exit cleanly after 1 cycle without hanging
            self.agent.watch_cluster(interval_seconds=1, max_cycles=1)
            mock_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
