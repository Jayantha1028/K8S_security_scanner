#!/usr/bin/env python3
"""
tests/test_mcp_server.py
========================
Unit tests for the Model Context Protocol (MCP) Server (mcp_server.py).
Tests protocol lifecycle: initialize, tools/list, tools/call, resources, prompts.
"""

import json
import os
import tempfile
import unittest

from mcp_server import MCPServer


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.server = MCPServer()
        self.temp_dir = tempfile.TemporaryDirectory()

        self.sample_manifest = os.path.join(self.temp_dir.name, "manifest.yaml")
        with open(self.sample_manifest, "w") as f:
            f.write("""
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
""")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialize(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        res = self.server.handle_request(req)
        self.assertEqual(res["id"], 1)
        self.assertEqual(res["result"]["serverInfo"]["name"], "k8s-native-scanner-mcp")
        self.assertIn("tools", res["result"]["capabilities"])

    def test_tools_list(self):
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        res = self.server.handle_request(req)
        tool_names = [t["name"] for t in res["result"]["tools"]]
        self.assertIn("k8s_scan_manifest", tool_names)
        self.assertIn("k8s_analyze_attack_graph", tool_names)
        self.assertIn("k8s_generate_remediation", tool_names)
        self.assertIn("k8s_explain_vulnerability", tool_names)

    def test_tool_call_scan_manifest(self):
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "k8s_scan_manifest",
                "arguments": {"path": self.sample_manifest},
            },
        }
        res = self.server.handle_request(req)
        self.assertEqual(res["id"], 3)
        content_text = res["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertGreaterEqual(data["total_findings"], 1)

    def test_tool_call_explain_vulnerability(self):
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "k8s_explain_vulnerability",
                "arguments": {"vuln_id": "V01"},
            },
        }
        res = self.server.handle_request(req)
        content_text = res["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertEqual(data["id"], "V01")

    def test_resources_list_and_read(self):
        list_req = {"jsonrpc": "2.0", "id": 5, "method": "resources/list"}
        res = self.server.handle_request(list_req)
        uris = [r["uri"] for r in res["result"]["resources"]]
        self.assertIn("k8s://rules/taxonomy", uris)

        read_req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": {"uri": "k8s://rules/taxonomy"},
        }
        read_res = self.server.handle_request(read_req)
        rules_text = read_res["result"]["contents"][0]["text"]
        rules = json.loads(rules_text)
        self.assertIn("V01", rules)

    def test_prompts_list_and_get(self):
        list_req = {"jsonrpc": "2.0", "id": 7, "method": "prompts/list"}
        res = self.server.handle_request(list_req)
        self.assertTrue(len(res["result"]["prompts"]) > 0)

        get_req = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "prompts/get",
            "params": {"name": "k8s_security_triage", "arguments": {"manifest_path": "/tmp/test.yaml"}},
        }
        get_res = self.server.handle_request(get_req)
        msg = get_res["result"]["messages"][0]["content"]["text"]
        self.assertIn("/tmp/test.yaml", msg)


if __name__ == "__main__":
    unittest.main()
