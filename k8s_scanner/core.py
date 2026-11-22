"""
k8s_scanner.core
================
Core Manifest Static AST Analysis, Attack Graph DAG & Regulatory Compliance.
"""

from scanner import (
    NativeSecurityScanner,
    ScanReport,
    Finding,
    shannon_entropy,
    check_image_typosquatting,
    levenshtein_distance,
    TAXONOMY_56,
    FEATURES_17,
    FEATURES_32,
)
from attack_graph import AttackGraphEngine, AttackNode, AttackEdge, KillChainPath
from remediate import auto_remediate_manifest, format_patch_diff, remediate_workload_dict
from declarative import DeclarativeRuleEngine, DeclarativeRule
from compliance import ComplianceFrameworkMapper, ComplianceCertificate, generate_markdown_certificate
from cve import CVEDatabaseEngine, CVEEntry, lookup_image_cves
from version_comparator import LinuxVersionComparator
from sarif import export_sarif_report
from bundle import StandaloneBundleManager

__all__ = [
    "NativeSecurityScanner",
    "ScanReport",
    "Finding",
    "shannon_entropy",
    "check_image_typosquatting",
    "levenshtein_distance",
    "TAXONOMY_56",
    "FEATURES_17",
    "FEATURES_32",
    "AttackGraphEngine",
    "AttackNode",
    "AttackEdge",
    "KillChainPath",
    "auto_remediate_manifest",
    "format_patch_diff",
    "remediate_workload_dict",
    "DeclarativeRuleEngine",
    "DeclarativeRule",
    "ComplianceFrameworkMapper",
    "ComplianceCertificate",
    "generate_markdown_certificate",
    "CVEDatabaseEngine",
    "CVEEntry",
    "lookup_image_cves",
    "LinuxVersionComparator",
    "export_sarif_report",
    "StandaloneBundleManager",
]
