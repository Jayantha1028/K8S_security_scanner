#!/usr/bin/env python3
"""
native_scanner/sarif.py
=======================
SARIF (Static Analysis Results Interchange Format) v2.1.0 Exporter.
Allows seamless integration into GitHub Advanced Security, GitLab Code Quality,
and standard CI/CD security dashboards.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from . import __version__
except Exception:
    __version__ = "1.0.0"

try:
    from .scanner import Finding, ScanReport
    from .taxonomy import TAXONOMY_56
except ImportError:
    from scanner import Finding, ScanReport
    from taxonomy import TAXONOMY_56

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "note",
}


def finding_to_sarif_rule(vuln_id: str) -> Dict[str, Any]:
    """Extracts SARIF rule descriptor from TAXONOMY_56."""
    tax = TAXONOMY_56.get(vuln_id, {})
    severity = tax.get("severity", "MEDIUM")
    level = SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")

    return {
        "id": vuln_id,
        "name": tax.get("title", f"Rule-{vuln_id}").replace(" ", ""),
        "shortDescription": {
            "text": tax.get("title", f"Kubernetes Security Rule {vuln_id}"),
        },
        "fullDescription": {
            "text": tax.get("description", "Kubernetes security policy failure."),
        },
        "help": {
            "text": f"Remediation: {tax.get('remediation', 'Follow CIS Kubernetes Benchmark guidelines.')}",
            "markdown": (
                f"### Remediation\n{tax.get('remediation', 'N/A')}\n\n"
                f"- **Plane**: Plane {tax.get('plane', 1)}\n"
                f"- **Severity**: {severity}\n"
                f"- **Standards**: CIS Benchmark v2.0, NSA/CISA Kubernetes Hardening"
            ),
        },
        "defaultConfiguration": {
            "level": level,
        },
        "properties": {
            "tags": [
                "security",
                "kubernetes",
                f"plane-{tax.get('plane', 1)}",
                severity.lower(),
            ],
            "precision": "high",
        },
    }


def export_sarif_report(
    reports: Union[ScanReport, List[ScanReport]],
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Converts ScanReport objects to SARIF v2.1.0 document.
    Optionally writes to disk if output_path is provided.
    """
    if isinstance(reports, ScanReport):
        reports = [reports]

    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for report in reports:
        uri = report.manifest_path or "manifest.yaml"
        # Normalize relative uri
        if uri.startswith("./"):
            uri = uri[2:]

        for finding in report.findings:
            vuln_id = finding.vuln_id
            if vuln_id not in rules_map:
                rules_map[vuln_id] = finding_to_sarif_rule(vuln_id)

            level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity.upper(), "warning")
            title = getattr(finding, "title", getattr(finding, "name", "Security Finding"))
            desc = getattr(finding, "description", "")
            remed = getattr(finding, "remediation", "")

            msg = f"[{finding.severity}] {title}: {desc}"
            if remed:
                msg += f" (Fix: {remed})"

            result_entry = {
                "ruleId": vuln_id,
                "ruleIndex": list(rules_map.keys()).index(vuln_id),
                "level": level,
                "message": {
                    "text": msg,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": finding.target or "workload",
                                "kind": "resource",
                            }
                        ],
                    }
                ],
            }
            results.append(result_entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "k8s-native-scanner",
                        "fullName": "Kubernetes Native Security Scanner & Attack DAG Engine",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Jayantha1028/K8S-security-assessment",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc
