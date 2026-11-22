#!/usr/bin/env python3
"""
native_scanner/mcp_server.py
============================
Model Context Protocol (MCP) Standard Server for Kubernetes Native Security Scanner.
Enables any AI agent (Claude Code, Antigravity, Cursor, LangChain, AutoGen) to
autonomously audit Kubernetes manifests, inspect live clusters, compute attack DAGs,
and execute strategic GitOps remediations via standardized JSON-RPC 2.0 stdio.
"""

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Resilient imports
try:
    from .agent import SecurityAgent
    from .taxonomy import TAXONOMY_56
    from .compliance import ComplianceFrameworkMapper, FRAMEWORK_DEFINITIONS
except ImportError:
    from agent import SecurityAgent
    from taxonomy import TAXONOMY_56
    from compliance import ComplianceFrameworkMapper, FRAMEWORK_DEFINITIONS

VULNERABILITY_TAXONOMY = TAXONOMY_56

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "k8s-native-scanner-mcp"
SERVER_VERSION = "1.0.0"


class MCPServer:
    """Standard JSON-RPC 2.0 Model Context Protocol Server over stdio."""

    def __init__(self):
        self.agent = SecurityAgent()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "k8s_scan_manifest",
                "description": "Scans Kubernetes YAML manifests or directories for 56 security misconfigurations, high-entropy secrets, and typosquatted images.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File or directory path containing Kubernetes YAML manifests.",
                        }
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "k8s_scan_live_cluster",
                "description": "Audits live in-cluster Kubernetes workloads, PodSecurity compliance, and RBAC bindings via K8s API or in-cluster ServiceAccount.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace to audit (default: all namespaces).",
                        }
                    },
                },
            },
            {
                "name": "k8s_analyze_attack_graph",
                "description": "Computes cross-resource exploit kill-chains (Ingress -> Service -> Workload -> RBAC -> Host Kernel) and returns weighted Blast Radius score.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Path to Kubernetes YAML manifest file or directory.",
                        }
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "k8s_generate_remediation",
                "description": "Generates Kustomize strategic merge patches and automated PR markdown for failing workloads.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Path to target manifest file or directory.",
                        },
                        "threshold": {
                            "type": "number",
                            "description": "Policy score threshold (default 70.0).",
                            "default": 70.0,
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "k8s_explain_vulnerability",
                "description": "Retrieves comprehensive threat intelligence for a specific vulnerability rule ID (e.g. KS-SEC-001, KS-SEC-008).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vuln_id": {
                            "type": "string",
                            "description": "Vulnerability rule identifier (e.g. KS-SEC-001).",
                        }
                    },
                    "required": ["vuln_id"],
                },
            },
            {
                "name": "k8s_query_cve",
                "description": "Searches embedded local CVE vulnerability intelligence database for known package or container CVEs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "CVE ID (e.g. CVE-2023-1234) or package name (e.g. openssl).",
                        }
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "k8s_generate_openvex",
                "description": "Correlates container CVEs with Kubernetes runtime defenses (readOnlyRootFilesystem, non-root, NetworkPolicy) and generates CISA OpenVEX v0.2.0 advisory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Path to target manifest file or directory.",
                        },
                        "image": {
                            "type": "string",
                            "description": "Optional container image name to override.",
                        },
                    },
                    "required": ["target"],
                },
            },
        ]

    def get_resource_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "uri": "k8s://rules/taxonomy",
                "name": "Kubernetes 56-Vulnerability Taxonomy",
                "description": "Complete 7-plane Kubernetes security rules and MITRE ATT&CK mapping.",
                "mimeType": "application/json",
            },
            {
                "uri": "k8s://compliance/frameworks",
                "name": "Regulatory Compliance Framework Definitions",
                "description": "PCI-DSS v4.0, SOC 2 Type II, HIPAA, ISO 27001, and NIST SP 800-190 mappings.",
                "mimeType": "application/json",
            },
        ]

    def get_prompt_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "k8s_security_triage",
                "description": "Performs an end-to-end security audit and lateral attack graph triage for a Kubernetes deployment.",
                "arguments": [
                    {
                        "name": "manifest_path",
                        "description": "Path to target YAML manifest",
                        "required": True,
                    }
                ],
            }
        ]

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = req.get("method")
        msg_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                if tool_name == "k8s_scan_manifest":
                    res = self.agent.tool_scan_manifest(args.get("path", "."))
                elif tool_name == "k8s_scan_live_cluster":
                    res = self.agent.tool_scan_cluster(args.get("namespace", ""))
                elif tool_name == "k8s_analyze_attack_graph":
                    res = self.agent.tool_analyze_attack_graph(args.get("target", "."))
                elif tool_name == "k8s_generate_remediation":
                    res = self.agent.tool_generate_gitops_fix(
                        args.get("target", "."), threshold=args.get("threshold", 70.0)
                    )
                elif tool_name == "k8s_explain_vulnerability":
                    res = self.agent.tool_explain_vulnerability(args.get("vuln_id", ""))
                elif tool_name == "k8s_query_cve":
                    res = self.agent.tool_query_cve(args.get("query", ""))
                elif tool_name == "k8s_generate_openvex":
                    res = self.agent.tool_generate_openvex(args.get("target", "."), image=args.get("image", ""))
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32601, "message": f"Method {tool_name} not found"},
                    }

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": str(res)}]},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True},
                }

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"resources": self.get_resource_definitions()},
            }

        elif method == "resources/read":
            uri = params.get("uri")
            if uri == "k8s://rules/taxonomy":
                rules_summary = {
                    k: {
                        "name": r.get("name", ""),
                        "severity": r.get("severity", "MEDIUM"),
                        "description": r.get("description", ""),
                        "plane": r.get("plane", 1),
                    }
                    for k, r in VULNERABILITY_TAXONOMY.items()
                }
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(rules_summary, indent=2),
                            }
                        ]
                    },
                }
            elif uri == "k8s://compliance/frameworks":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(FRAMEWORK_DEFINITIONS, indent=2),
                            }
                        ]
                    },
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": f"Resource not found: {uri}"},
                }

        elif method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"prompts": self.get_prompt_definitions()},
            }

        elif method == "prompts/get":
            pname = params.get("name")
            pargs = params.get("arguments", {})
            if pname == "k8s_security_triage":
                mpath = pargs.get("manifest_path", "./deployment.yaml")
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "description": "Perform comprehensive AST and Attack DAG triage",
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": (
                                        f"Please audit the Kubernetes manifest at '{mpath}'. "
                                        "Call 'k8s_scan_manifest' and 'k8s_analyze_attack_graph' to determine if there "
                                        "are exploitable lateral movement chains, and generate remediation patches."
                                    ),
                                },
                            }
                        ],
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unsupported method: {method}"},
        }

    def run_stdio(self):
        """Standard line-delimited or Content-Length framing JSON-RPC loop over stdio."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                pass
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def run_mcp_server():
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    run_mcp_server()
