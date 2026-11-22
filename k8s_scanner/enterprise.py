"""
k8s_scanner.enterprise
======================
Enterprise Identity/RBAC, Multi-Cluster Fleet, Storage Engine, ChatOps, Leader Election & REST API.
"""

from auth import (
    EnterpriseAuthManager,
    AuthenticatedIdentity,
    APIKeyRecord,
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_ENGINEER,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_DEVOPS_OPERATOR,
    PERM_FLEET_MANAGE,
    PERM_CLUSTER_ONBOARD,
    PERM_POLICY_WRITE,
    PERM_SCAN_EXECUTE,
    PERM_REMEDIATE_WRITE,
    PERM_VEX_WAIVE,
    PERM_COMPLIANCE_READ,
    PERM_AUDIT_LOGS_READ,
    PERM_TELEMETRY_READ,
)
from fleet import FleetManager, ClusterRecord, FleetPolicy, FleetDriftSummary
from storage import EnterpriseStorageEngine, TelemetryQueryFilter
from notifications import NotificationDispatcher, AlertPayload
from leader_election import LeaderElector, LeaderLease
from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent, FalcoBridgeReceiver, get_native_ebpf_c_source
from enterprise_server import EnterpriseServer, EnterpriseAPIHandler
from openapi import get_openapi_spec, get_swagger_ui_html
from exporter import PrometheusMetricsExporter
from dashboard import generate_html_report, start_dashboard_server

__all__ = [
    "EnterpriseAuthManager",
    "AuthenticatedIdentity",
    "APIKeyRecord",
    "ROLE_PLATFORM_ADMIN",
    "ROLE_SECURITY_ENGINEER",
    "ROLE_COMPLIANCE_AUDITOR",
    "ROLE_DEVOPS_OPERATOR",
    "FleetManager",
    "ClusterRecord",
    "FleetPolicy",
    "FleetDriftSummary",
    "EnterpriseStorageEngine",
    "TelemetryQueryFilter",
    "NotificationDispatcher",
    "AlertPayload",
    "LeaderElector",
    "LeaderLease",
    "EBPFTelemetryEngine",
    "SIEMForwarder",
    "KernelSecurityEvent",
    "FalcoBridgeReceiver",
    "get_native_ebpf_c_source",
    "EnterpriseServer",
    "EnterpriseAPIHandler",
    "get_openapi_spec",
    "get_swagger_ui_html",
    "PrometheusMetricsExporter",
    "generate_html_report",
    "start_dashboard_server",
]
