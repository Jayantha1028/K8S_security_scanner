#!/usr/bin/env python3
"""
openapi.py
==========
OpenAPI 3.0.3 Specification & Interactive Swagger Documentation Engine.

Capabilities:
1. Generates complete, RFC-compliant OpenAPI 3.0.3 schema covering all REST endpoints.
2. Generates standalone Swagger UI HTML documentation with interactive 'Try it out' console.
3. Supports JSON and YAML serialization formats.
"""

import json
from typing import Any, Dict, Optional


def get_openapi_spec(server_url: str = "http://127.0.0.1:8443") -> Dict[str, Any]:
    """Generates the authoritative OpenAPI 3.0.3 specification for the CNAPP API."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Kubernetes Native Security Scanner & Fleet CNAPP API",
            "version": "2.0.0",
            "description": (
                "Hyperscale Cloud-Native Application Protection Platform (CNAPP) API. "
                "Delivers zero-dependency Kubernetes manifest security auditing, automated remediation, "
                "contextual VEX generation, eBPF runtime threat detection, fleet orchestration, "
                "and regulatory compliance attestation."
            ),
            "contact": {
                "name": "Platform Security Engineering Team",
                "email": "security@platform.enterprise.internal",
            },
            "license": {
                "name": "Apache 2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
            },
        },
        "servers": [
            {
                "url": server_url,
                "description": "Active Cluster CNAPP Controller",
            }
        ],
        "tags": [
            {"name": "Health", "description": "Liveness, readiness, and observability health checks"},
            {"name": "Authentication", "description": "Identity verification, JWT tokens, and API key management"},
            {"name": "Fleet", "description": "Hyperscale multi-cluster onboarding and posture aggregation"},
            {"name": "Scanning", "description": "Manifest vulnerability analysis and security scoring"},
            {"name": "Remediation", "description": "Automated deterministic YAML security patches"},
            {"name": "VEX", "description": "Contextual Vulnerability Exploitability eXchange analysis"},
            {"name": "eBPF Telemetry", "description": "Kernel-level runtime observability and SIEM feeds"},
            {"name": "Compliance", "description": "SOC 2, PCI DSS, HIPAA, NIST, CIS, and WAF attestation"},
            {"name": "Storage", "description": "Persistent telemetry queries and database maintenance"},
            {"name": "Notifications", "description": "ChatOps dispatchers (Slack, Teams, PagerDuty)"},
        ],
        "paths": {
            "/healthz": {
                "get": {
                    "tags": ["Health"],
                    "summary": "Liveness probe",
                    "description": "Returns HTTP 200 if the controller process is alive.",
                    "responses": {
                        "200": {"description": "Service is healthy"}
                    },
                }
            },
            "/readyz": {
                "get": {
                    "tags": ["Health"],
                    "summary": "Readiness probe",
                    "description": "Returns HTTP 200 if the controller is ready to receive requests.",
                    "responses": {
                        "200": {"description": "Service is ready"}
                    },
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["Health"],
                    "summary": "Prometheus metrics",
                    "description": "Prometheus text exposition format (version 0.0.4) for cluster metrics.",
                    "responses": {
                        "200": {"description": "Prometheus exposition stream"}
                    },
                }
            },
            "/api/v1/auth/token": {
                "post": {
                    "tags": ["Authentication"],
                    "summary": "Issue Bearer JWT Token",
                    "description": "Issues a signed RFC 7519 JWT token with role claims for API authentication.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "JWT Token generated successfully",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/TokenResponse"}
                                }
                            },
                        }
                    },
                }
            },
            "/api/v1/auth/api-key": {
                "post": {
                    "tags": ["Authentication"],
                    "summary": "Generate Enterprise API Key",
                    "security": [{"BearerAuth": []}],
                    "description": "Generates a persistent cryptographic API key (requires PLATFORM_ADMIN role).",
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiKeyRequest"}
                            }
                        },
                    },
                    "responses": {
                        "201": {"description": "API key generated successfully"},
                        "403": {"description": "Insufficient permissions"}
                    },
                }
            },
            "/api/v1/scan": {
                "post": {
                    "tags": ["Scanning"],
                    "summary": "Audit Kubernetes Manifest",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "description": "Runs complete static analysis across 32 threat dimensions and outputs score + findings.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Scan audit report completed successfully"},
                        "400": {"description": "Invalid manifest payload"},
                        "403": {"description": "Permission denied"}
                    },
                }
            },
            "/api/v1/remediate": {
                "post": {
                    "tags": ["Remediation"],
                    "summary": "Auto-Remediate Manifest",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "description": "Generates a hardened manifest version with unified diff.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RemediateRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Remediation generated successfully"},
                        "403": {"description": "Permission denied"}
                    },
                }
            },
            "/api/v1/vex": {
                "post": {
                    "tags": ["VEX"],
                    "summary": "Contextual VEX Assessment",
                    "description": "Evaluates CVEs against runtime context (read-only rootfs, non-root, drop ALL) to generate OpenVEX statements.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VexRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "VEX document generated successfully"}
                    },
                }
            },
            "/api/v1/fleet/overview": {
                "get": {
                    "tags": ["Fleet"],
                    "summary": "Global Fleet Posture Overview",
                    "description": "Returns aggregated fleet metrics, cluster count, and global threat index.",
                    "responses": {
                        "200": {"description": "Fleet summary and risk heatmap"}
                    },
                }
            },
            "/api/v1/fleet/clusters": {
                "get": {
                    "tags": ["Fleet"],
                    "summary": "List Registered Clusters",
                    "description": "Lists all onboarded Kubernetes clusters with current status and risk tier.",
                    "responses": {
                        "200": {"description": "List of cluster records"}
                    },
                }
            },
            "/api/v1/compliance/certificate": {
                "get": {
                    "tags": ["Compliance"],
                    "summary": "Generate Regulatory Compliance Certificate",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "description": "Attests compliance across SOC 2, PCI DSS v4.0, HIPAA, NIST 800-53, CIS, and WAF.",
                    "responses": {
                        "200": {"description": "Regulatory attestation certificate"}
                    },
                }
            },
            "/api/v1/ebpf/events": {
                "get": {
                    "tags": ["eBPF Telemetry"],
                    "summary": "Stream Kernel Security Events",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "parameters": [
                        {
                            "name": "format",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["JSON", "CEF", "RFC5424"]},
                            "description": "Telemetry export format (JSON, ArcSight CEF, or RFC 5424 Syslog)",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Recent kernel security telemetry events"}
                    },
                }
            },
            "/api/v1/telemetry/query": {
                "post": {
                    "tags": ["Storage"],
                    "summary": "Query Historical Telemetry Events",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "description": "Queries persisted eBPF runtime events from the storage engine with multi-tenant filtering.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TelemetryQueryRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Filtered telemetry records"}
                    },
                }
            },
            "/api/v1/storage/stats": {
                "get": {
                    "tags": ["Storage"],
                    "summary": "Storage Engine Statistics",
                    "description": "Returns database size, record counts, and WAL mode health.",
                    "responses": {
                        "200": {"description": "Storage statistics"}
                    },
                }
            },
            "/api/v1/notifications/alert": {
                "post": {
                    "tags": ["Notifications"],
                    "summary": "Dispatch Security Alert Card",
                    "security": [{"BearerAuth": []}, {"ApiKeyAuth": []}],
                    "description": "Dispatches security cards to Slack Block Kit, MS Teams Adaptive Cards, or PagerDuty.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AlertDispatchRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Notification dispatched successfully"},
                        "400": {"description": "Failed to dispatch notification or SSRF violation"}
                    },
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "tags": ["Health"],
                    "summary": "OpenAPI 3.0 Specification JSON",
                    "responses": {
                        "200": {"description": "OpenAPI 3.0.3 specification JSON"}
                    },
                }
            },
            "/docs": {
                "get": {
                    "tags": ["Health"],
                    "summary": "Interactive Swagger UI Documentation",
                    "responses": {
                        "200": {"description": "HTML page rendering Swagger UI"}
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "RFC 7519 JWT Bearer Token",
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Enterprise API Key (k8s_sec_...)",
                },
            },
            "schemas": {
                "TokenRequest": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string", "example": "enterprise-corp"},
                        "subject": {"type": "string", "example": "security-engineer@enterprise.com"},
                        "roles": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": ["SECURITY_ENGINEER"],
                        },
                    },
                    "required": ["tenant_id", "subject"],
                },
                "TokenResponse": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string"},
                        "token_type": {"type": "string", "example": "Bearer"},
                        "expires_in": {"type": "integer", "example": 3600},
                    },
                },
                "ApiKeyRequest": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string", "example": "enterprise-corp"},
                        "subject": {"type": "string", "example": "ci-cd-runner"},
                        "roles": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "ScanRequest": {
                    "type": "object",
                    "properties": {
                        "manifest": {
                            "type": "string",
                            "example": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n...",
                        }
                    },
                    "required": ["manifest"],
                },
                "RemediateRequest": {
                    "type": "object",
                    "properties": {
                        "manifest": {"type": "string"}
                    },
                    "required": ["manifest"],
                },
                "VexRequest": {
                    "type": "object",
                    "properties": {
                        "manifest": {"type": "string"},
                        "image_name": {"type": "string", "example": "alpine:3.19"},
                    },
                    "required": ["manifest"],
                },
                "TelemetryQueryRequest": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string"},
                        "cluster_id": {"type": "string"},
                        "min_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
                "AlertDispatchRequest": {
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string", "enum": ["slack", "teams", "pagerduty"]},
                        "webhook_url": {"type": "string", "example": "https://hooks.slack.com/services/..."},
                        "title": {"type": "string", "example": "Container Escape Detected"},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        "cluster_id": {"type": "string", "example": "prod-us-east-1"},
                        "description": {"type": "string", "example": "Suspicious nsenter execution observed."},
                        "workload_name": {"type": "string", "example": "payment-api"},
                        "namespace": {"type": "string", "example": "prod"},
                        "remediation": {"type": "string", "example": "Drop CAP_SYS_ADMIN and enforce read-only rootfs."},
                    },
                    "required": ["channel", "webhook_url", "title", "severity", "cluster_id", "description"],
                },
            },
        },
    }


def get_swagger_ui_html(
    openapi_url: str = "/api/v1/openapi.json",
    title: str = "Kubernetes Native Security CNAPP - Swagger UI",
) -> str:
    """Generates a responsive, modern HTML5 page rendering Swagger UI."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/favicon-32x32.png" sizes="32x32" />
  <style>
    html {{
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }}
    *, *:before, *:after {{
      box-sizing: inherit;
    }}
    body {{
      margin: 0;
      background: #fafafa;
    }}
    .swagger-ui .topbar {{
      background-color: #0b0f19;
      border-bottom: 2px solid #3b82f6;
    }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {{
      window.ui = SwaggerUIBundle({{
        url: "{openapi_url}",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      }});
    }};
  </script>
</body>
</html>
"""
