#!/usr/bin/env python3
"""
tests/test_enterprise_readiness.py
==================================
Unit and Integration Test Suite for 100% Enterprise CNAPP Readiness.

Verifies:
1. Enterprise Identity, SAML 2.0, RFC 7519 JWT, API Keys & 4-Tier RBAC (auth.py).
2. Hyperscale Multi-Cluster Fleet Manager & Heatmap Aggregation (fleet.py).
3. eBPF Kernel Telemetry, Cgroups & SIEM Forwarder CEF / RFC 5424 (ebpf.py).
4. Enterprise REST API Server, RBAC Middleware & Dashboard Web Console (enterprise_server.py).
"""

import json
import socket
import time
import unittest
import urllib.error
import urllib.request
from typing import Dict, Any, Optional, Tuple

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
from ebpf import EBPFTelemetryEngine, SIEMForwarder, KernelSecurityEvent
from enterprise_server import EnterpriseServer


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestEnterpriseAuth(unittest.TestCase):
    def setUp(self):
        self.auth = EnterpriseAuthManager(master_secret="test-secret-key-32-bytes-secure!", default_tenant="tenant-alpha")

    def test_jwt_issuance_and_verification(self):
        token = self.auth.issue_jwt(
            tenant_id="tenant-alpha",
            subject="alice",
            roles=[ROLE_SECURITY_ENGINEER],
            allowed_namespaces=["production", "staging"],
            duration_minutes=15,
        )
        self.assertIsInstance(token, str)
        self.assertEqual(token.count("."), 2)

        identity = self.auth.verify_jwt(token)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.subject, "alice")
        self.assertEqual(identity.tenant_id, "tenant-alpha")
        self.assertIn(ROLE_SECURITY_ENGINEER, identity.roles)
        self.assertTrue(identity.can_access_namespace("production"))
        self.assertFalse(identity.can_access_namespace("kube-system"))

    def test_jwt_tampering_rejection(self):
        token = self.auth.issue_jwt(
            tenant_id="tenant-alpha",
            subject="bob",
            roles=[ROLE_DEVOPS_OPERATOR],
        )
        parts = token.split(".")
        # Tamper payload
        tampered_token = f"{parts[0]}.eyJuYW1lIjoidGFtcGVyZWQifQ.{parts[2]}"
        self.assertIsNone(self.auth.verify_jwt(tampered_token))

    def test_api_key_lifecycle(self):
        raw_key, record = self.auth.generate_api_key(
            tenant_id="tenant-alpha",
            subject="ci-service-account",
            roles=[ROLE_DEVOPS_OPERATOR],
            description="GitHub Actions CI Runner",
        )
        self.assertTrue(raw_key.startswith("k8s_sec_live_"))
        self.assertEqual(record.tenant_id, "tenant-alpha")

        # Verify key
        identity = self.auth.verify_api_key(raw_key)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.subject, "ci-service-account")

        # Verify invalid / deactivated key
        self.assertIsNone(self.auth.verify_api_key("k8s_sec_live_invalid_key_hash"))
        record.is_active = False
        self.assertIsNone(self.auth.verify_api_key(raw_key))

    def test_saml_assertion_parsing(self):
        saml_xml = """<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:Subject>
                <saml2:NameID>sec-auditor@enterprise.com</saml2:NameID>
            </saml2:Subject>
            <saml2:AttributeStatement>
                <saml2:Attribute Name="email"><saml2:AttributeValue>sec-auditor@enterprise.com</saml2:AttributeValue></saml2:Attribute>
                <saml2:Attribute Name="groups"><saml2:AttributeValue>Corporate-Security-Admins</saml2:AttributeValue></saml2:Attribute>
            </saml2:AttributeStatement>
        </saml2:Assertion>"""

        identity = self.auth.parse_saml_assertion(saml_xml, tenant_id="corp-tenant")
        self.assertIsNotNone(identity)
        self.assertEqual(identity.subject, "sec-auditor@enterprise.com")
        self.assertIn(ROLE_PLATFORM_ADMIN, identity.roles)

    def test_rbac_matrix_authorization(self):
        devops_id = AuthenticatedIdentity(subject="dev", tenant_id="t1", roles=[ROLE_DEVOPS_OPERATOR])
        sec_id = AuthenticatedIdentity(subject="sec", tenant_id="t1", roles=[ROLE_SECURITY_ENGINEER])
        admin_id = AuthenticatedIdentity(subject="admin", tenant_id="t1", roles=[ROLE_PLATFORM_ADMIN])
        auditor_id = AuthenticatedIdentity(subject="audit", tenant_id="t1", roles=[ROLE_COMPLIANCE_AUDITOR])

        # DevOps can scan & remediate, but cannot manage fleet or waive VEX
        self.assertTrue(self.auth.authorize(devops_id, PERM_SCAN_EXECUTE)[0])
        self.assertTrue(self.auth.authorize(devops_id, PERM_REMEDIATE_WRITE)[0])
        self.assertFalse(self.auth.authorize(devops_id, PERM_FLEET_MANAGE)[0])
        self.assertFalse(self.auth.authorize(devops_id, PERM_VEX_WAIVE)[0])

        # Security Engineer can waive VEX and read telemetry
        self.assertTrue(self.auth.authorize(sec_id, PERM_VEX_WAIVE)[0])
        self.assertTrue(self.auth.authorize(sec_id, PERM_TELEMETRY_READ)[0])

        # Compliance Auditor can read compliance and audit logs only
        self.assertTrue(self.auth.authorize(auditor_id, PERM_COMPLIANCE_READ)[0])
        self.assertFalse(self.auth.authorize(auditor_id, PERM_REMEDIATE_WRITE)[0])

        # Platform Admin can cross tenant boundaries and manage fleet
        self.assertTrue(self.auth.authorize(admin_id, PERM_FLEET_MANAGE)[0])
        self.assertTrue(self.auth.authorize(admin_id, PERM_SCAN_EXECUTE, target_tenant="other-tenant")[0])
        self.assertFalse(self.auth.authorize(devops_id, PERM_SCAN_EXECUTE, target_tenant="other-tenant")[0])


class TestFleetManager(unittest.TestCase):
    def setUp(self):
        self.fleet = FleetManager(tenant_id="tenant-prod")

    def test_cluster_onboarding_and_heartbeat(self):
        c1 = self.fleet.register_cluster(
            cluster_id="cls-eks-us-east-1",
            name="EKS Production East",
            cloud_provider="aws",
            region="us-east-1",
            node_count=10,
        )
        self.assertEqual(c1.cluster_id, "cls-eks-us-east-1")
        self.assertEqual(c1.status, "ACTIVE")

        # Heartbeat
        updated = self.fleet.record_heartbeat("cls-eks-us-east-1", pod_count=45)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.pod_count, 45)

    def test_frame_ingestion_and_threat_index(self):
        self.fleet.register_cluster("cls-gke-prod", "GKE EU Prod", cloud_provider="gcp", region="europe-west1")
        frame_data = {
            "total_workloads": 25,
            "security_score": 65.0,
            "vulnerabilities_count": {
                "CRITICAL": 2,
                "HIGH": 4,
                "MEDIUM": 5,
                "LOW": 10,
            }
        }
        res = self.fleet.ingest_cluster_frame("cls-gke-prod", frame_data)
        self.assertEqual(res["status"], "INGESTED")

        cluster = self.fleet.get_cluster("cls-gke-prod")
        self.assertEqual(cluster.vulnerabilities_count["CRITICAL"], 2)
        self.assertGreater(cluster.threat_index, 30.0)

        # Fleet summary and heatmap
        summary = self.fleet.get_fleet_summary("tenant-prod")
        self.assertEqual(summary.total_clusters, 1)
        self.assertEqual(summary.critical_findings_total, 2)
        self.assertEqual(summary.total_pods_monitored, 25)

        heatmap = self.fleet.get_fleet_heatmap("tenant-prod")
        self.assertIn("gcp", heatmap["by_provider"])
        self.assertEqual(heatmap["by_provider"]["gcp"]["clusters"], 1)

    def test_fleet_policy_distribution(self):
        self.fleet.register_cluster("cls-aks-1", "AKS Prod", cloud_provider="azure", region="eastus")
        self.fleet.register_cluster("cls-aks-2", "AKS Staging", cloud_provider="azure", region="westus")

        policy = FleetPolicy(
            policy_id="pol-zero-trust-strict",
            name="Strict Zero Trust",
            tenant_id="tenant-prod",
            disallow_privileged=True,
            enforce_non_root=True,
        )
        self.fleet.set_fleet_policy(policy)
        dist_res = self.fleet.distribute_fleet_policy("tenant-prod", "pol-zero-trust-strict")

        self.assertEqual(dist_res["targets_count"], 2)
        self.assertIn("cls-aks-1", dist_res["synced_cluster_ids"])
        self.assertIn("cls-aks-2", dist_res["synced_cluster_ids"])


class TestEBPFTelemetry(unittest.TestCase):
    def setUp(self):
        self.engine = EBPFTelemetryEngine(node_name="node-worker-01")
        self.siem = SIEMForwarder("CEF")

    def test_cgroup_resolution(self):
        cgroup_v2 = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod9a8b7c6d_1234_5678_90ab_cdef01234567.slice/cri-containerd-a1b2c3d4e5f60718293a4b5c.scope"
        res = self.engine.parse_proc_cgroup(cgroup_v2)
        self.assertEqual(res["pod_uid"], "9a8b7c6d-1234-5678-90ab-cdef01234567")
        self.assertEqual(res["container_id"], "a1b2c3d4e5f6")

    def test_execve_anomaly_detection(self):
        # Interactive shell invocation
        evt = self.engine.evaluate_execve_event(
            pid=5120,
            comm="bash",
            filename="/bin/bash",
            args=["bash", "-i"],
            pod_name="auth-service-59bd7",
            namespace="production",
        )
        self.assertIsNotNone(evt)
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(evt.event_type, "SUSPICIOUS_PROCESS_EXEC")
        self.assertEqual(evt.mitre_technique, "T1059.004")

        # Benign binary execution
        benign = self.engine.evaluate_execve_event(
            pid=5121,
            comm="node",
            filename="/usr/local/bin/node",
            args=["node", "server.js"],
        )
        self.assertIsNone(benign)

    def test_sensitive_file_and_mount_escape(self):
        file_evt = self.engine.evaluate_file_open_event(
            pid=5200,
            comm="cat",
            filepath="/etc/shadow",
            flags=0,
            pod_name="api-gateway",
            namespace="production",
        )
        self.assertIsNotNone(file_evt)
        self.assertEqual(file_evt.severity, "CRITICAL")
        self.assertEqual(file_evt.event_type, "SENSITIVE_FILE_ACCESS")

        mount_evt = self.engine.evaluate_mount_event(
            pid=5300,
            comm="mount",
            source="/dev/sda1",
            target="/host",
            filesystem_type="ext4",
        )
        self.assertIsNotNone(mount_evt)
        self.assertEqual(mount_evt.event_type, "HOST_MOUNT_ESCAPE")

    def test_siem_forwarder_cef_and_syslog(self):
        evt = KernelSecurityEvent(
            event_id="evt-001",
            timestamp="2026-11-18T00:00:00Z",
            event_type="SUSPICIOUS_PROCESS_EXEC",
            severity="CRITICAL",
            pid=4100,
            comm="nmap",
            pod_name="recon-pod",
            namespace="prod",
            container_id="112233445566",
            description="Network scanner execution",
            mitre_technique="T1046",
        )
        cef_str = evt.to_cef()
        self.assertTrue(cef_str.startswith("CEF:0|K8sNativeSecurity|EnterpriseCNAPP|2.0.0|SUSPICIOUS_PROCESS_EXEC|"))
        self.assertIn("cs3=T1046", cef_str)
        self.assertIn("src=recon-pod", cef_str)

        syslog_str = evt.to_rfc5424_syslog()
        self.assertTrue(syslog_str.startswith("<10>1 2026-11-18T00:00:00Z"))
        self.assertIn('pod="recon-pod"', syslog_str)

        # SIEM Forwarder buffer & flush
        self.siem.push(evt)
        flushed = self.siem.flush()
        self.assertEqual(len(flushed), 1)
        self.assertEqual(len(self.siem.flush()), 0)


class TestEnterpriseServerE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = find_free_port()
        cls.auth_mgr = EnterpriseAuthManager(master_secret="server-test-secret-key-32-bytes!!")
        cls.fleet_mgr = FleetManager()
        cls.server = EnterpriseServer(host="127.0.0.1", port=cls.port, auth_manager=cls.auth_mgr, fleet_manager=cls.fleet_mgr)
        cls.server.start(background=True)
        time.sleep(0.01)  # Socket is already bound synchronously

        # Pre-generate tokens
        cls.admin_token = cls.auth_mgr.issue_jwt("default-tenant", "superadmin", [ROLE_PLATFORM_ADMIN])
        cls.devops_token = cls.auth_mgr.issue_jwt("default-tenant", "developer", [ROLE_DEVOPS_OPERATOR])

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _request(self, method: str, path: str, data: Optional[Dict[str, Any]] = None, token: Optional[str] = None) -> Tuple[int, Any]:
        url = f"http://127.0.0.1:{self.port}{path}"
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = json.dumps(data).encode("utf-8") if data else None

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
                ct = resp.headers.get("Content-Type", "")
                raw = resp.read().decode("utf-8")
                if "application/json" in ct:
                    return status, json.loads(raw)
                return status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw

    def test_health_metrics_and_dashboard_endpoints(self):
        status, health = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "HEALTHY")

        status, metrics = self._request("GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertIn("k8s_fleet_threat_index", metrics)

        status, html = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Hyperscale CNAPP Console", html)

    def test_auth_token_issuance_api(self):
        status, res = self._request("POST", "/api/v1/auth/token", {
            "tenant_id": "tenant-corp",
            "subject": "service-bot",
            "roles": [ROLE_SECURITY_ENGINEER],
        })
        self.assertEqual(status, 200)
        self.assertIn("token", res)
        self.assertEqual(res["token_type"], "Bearer")

    def test_cluster_registration_and_rbac(self):
        # DevOps operator lacks cluster:onboard permission -> 403
        status, res = self._request(
            "POST",
            "/api/v1/fleet/clusters/register",
            {"cluster_id": "c-unauthorized", "name": "Test Cluster"},
            token=self.devops_token,
        )
        self.assertEqual(status, 403)

        # Platform Admin can register cluster -> 201
        status, res = self._request(
            "POST",
            "/api/v1/fleet/clusters/register",
            {
                "cluster_id": "cls-eks-prod-e2e",
                "name": "EKS Prod E2E",
                "cloud_provider": "aws",
                "region": "us-east-1",
            },
            token=self.admin_token,
        )
        self.assertEqual(status, 201)
        self.assertEqual(res["cluster_id"], "cls-eks-prod-e2e")

        # Ingest KubeCam Frame
        status, frame_res = self._request("POST", "/api/v1/fleet/heartbeat", {
            "cluster_id": "cls-eks-prod-e2e",
            "security_score": 85.0,
            "vulnerabilities_count": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 5},
            "total_workloads": 12,
        })
        self.assertEqual(status, 200)
        self.assertEqual(frame_res["status"], "INGESTED")

        # Verify in fleet overview
        status, overview = self._request("GET", "/api/v1/fleet/overview")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(overview["summary"]["total_clusters"], 1)

    def test_on_demand_scan_and_remediation_api(self):
        manifest_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
"""
        # Scan workload
        status, scan_res = self._request(
            "POST",
            "/api/v1/scan",
            {"manifest": manifest_yaml},
            token=self.devops_token,
        )
        self.assertEqual(status, 200)
        self.assertLess(scan_res["security_score"], 80.0)
        self.assertGreaterEqual(len(scan_res["findings"]), 1)

        # Auto-Remediate workload
        status, rem_res = self._request(
            "POST",
            "/api/v1/remediate",
            {"manifest": manifest_yaml},
            token=self.devops_token,
        )
        self.assertEqual(status, 200)
        self.assertIn("privileged: false", rem_res["remediated_yaml"])
        self.assertTrue(len(rem_res["diff"]) > 0)

    def test_openvex_and_compliance_api(self):
        manifest_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
spec:
  containers:
  - name: app
    image: python:3.9
    securityContext:
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      allowPrivilegeEscalation: false
"""
        # Contextual OpenVEX
        status, vex_res = self._request("POST", "/api/v1/vex", {"manifest": manifest_yaml})
        self.assertEqual(status, 200)
        self.assertIn("statements", vex_res)
        self.assertGreaterEqual(vex_res["mitigated_cves"], 0)

        # Compliance Attestation Certificate
        status, cert = self._request("GET", "/api/v1/compliance/certificate?target=fleet-e2e", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(cert["audit_target"], "fleet-e2e")
        self.assertIn("SOC-2-Type-II", cert["frameworks"])
        self.assertIn("PCI-DSS-v4.0", cert["frameworks"])

    def test_ebpf_simulation_and_event_streaming(self):
        # Simulate an event
        status, sim_res = self._request("POST", "/api/v1/ebpf/simulate", {
            "event_type": "EXECVE",
            "comm": "sh",
            "binary": "/bin/sh",
            "pod_name": "checkout-svc-49af",
            "namespace": "production",
        })
        self.assertEqual(status, 201)
        self.assertEqual(sim_res["event"]["event_type"], "SUSPICIOUS_PROCESS_EXEC")
        self.assertTrue(sim_res["cef"].startswith("CEF:0|K8sNativeSecurity|"))

        # Retrieve eBPF telemetry events in CEF format
        status, cef_stream = self._request("GET", "/api/v1/ebpf/events?format=CEF", token=self.admin_token)
        self.assertEqual(status, 200)
        self.assertIn("CEF:0", cef_stream)


if __name__ == "__main__":
    unittest.main()
