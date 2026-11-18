#!/usr/bin/env python3
"""
tests/test_repl.py
==================
Unit tests for the Interactive Multi-Turn AI Copilot REPL (repl.py).
Tests slash commands, multi-turn dialogue memory, and automated remediation triggers.
"""

import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from repl import InteractiveCopilotREPL, Ansi
from agent import SecurityAgent, LLMClient


class TestInteractiveCopilotREPL(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.manifest_path = os.path.join(self.temp_dir.name, "deployment.yaml")
        with open(self.manifest_path, "w") as f:
            f.write("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
""")
        self.agent = SecurityAgent(llm_client=LLMClient(provider="local"))
        self.repl = InteractiveCopilotREPL(agent=self.agent, target=self.manifest_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_banner_display(self):
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            self.repl.display_banner()
        output = captured.getvalue()
        self.assertIn("KUBERNETES NATIVE SECURITY COPILOT", output)
        self.assertIn("Cognitive Brain", output)

    def test_slash_help(self):
        res = self.repl.handle_slash_command("/help")
        self.assertIn("/target", res)
        self.assertIn("/scan", res)
        self.assertIn("/dag", res)
        self.assertIn("/vex", res)
        self.assertIn("/fix", res)

    def test_slash_target(self):
        res = self.repl.handle_slash_command("/target")
        self.assertIn(self.manifest_path, res)

        new_path = os.path.join(self.temp_dir.name, "new.yaml")
        with open(new_path, "w") as f:
            f.write("kind: Pod\n")
        res_update = self.repl.handle_slash_command(f"/target {new_path}")
        self.assertIn("Active target updated", res_update)
        self.assertEqual(self.repl.target, new_path)

    def test_slash_scan(self):
        res = self.repl.handle_slash_command("/scan")
        self.assertIn("Scan Completed", res)
        self.assertIn("Total Findings", res)
        # Verify scan result injected into conversation history
        self.assertTrue(any("User executed /scan" in turn["content"] for turn in self.repl.conversation_history))

    def test_slash_dag(self):
        res = self.repl.handle_slash_command("/dag")
        self.assertIn("Attack Path DAG Analysis", res)
        self.assertIn("Blast Radius Index", res)

    def test_slash_vex(self):
        res = self.repl.handle_slash_command("/vex")
        self.assertIn("CONTEXTUAL EXPLOITABILITY", res)
        self.assertIn("EXPLOITABILITY NOISE REDUCTION", res)

    def test_slash_fix_and_apply(self):
        res_fix = self.repl.handle_slash_command("/fix")
        self.assertIn("Remediation Plan Generated", res_fix)
        self.assertIsNotNone(self.repl.last_remediation_plan)

        res_apply = self.repl.handle_slash_command("/apply")
        self.assertIn("Applied hardening fixes", res_apply)
        self.assertIsNone(self.repl.last_remediation_plan)

    def test_slash_history_and_clear(self):
        self.repl.conversation_history.append({"role": "user", "content": "What is privileged: true?"})
        self.repl.conversation_history.append({"role": "assistant", "content": "It grants full host device access."})

        res_hist = self.repl.handle_slash_command("/history")
        self.assertIn("What is privileged", res_hist)

        res_clear = self.repl.handle_slash_command("/clear")
        self.assertIn("cleared", res_clear)
        self.assertEqual(len(self.repl.conversation_history), 0)

    def test_slash_exit(self):
        res = self.repl.handle_slash_command("/exit")
        self.assertIn("Exiting", res)
        self.assertFalse(self.repl.running)

    def test_multi_turn_conversational_dialogue(self):
        # Turn 1
        res1 = self.repl.handle_input("Is this pod secure against kernel breakouts?")
        self.assertIn("Autonomous Security Assessment", res1)
        self.assertEqual(len(self.repl.conversation_history), 2)

        # Turn 2 (Follow-up)
        res2 = self.repl.handle_input("What is the blast radius score?")
        self.assertIn("Cluster Blast Radius Index", res2)
        self.assertEqual(len(self.repl.conversation_history), 4)

    def test_ansi_color_helper(self):
        # Test Ansi.color without crashing
        formatted = Ansi.color("test", Ansi.GREEN, bold=True)
        self.assertIn("test", formatted)


if __name__ == "__main__":
    unittest.main()
