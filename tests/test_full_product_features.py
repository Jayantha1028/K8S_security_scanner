#!/usr/bin/env python3
"""
tests/test_full_product_features.py
===================================
Comprehensive Unit and Integration Tests for Enterprise Full-Product Features:
1. Persistent Telemetry & Scan Storage (SQLite WAL mode & retention pruning).
2. ChatOps & Incident Notification Dispatcher (Slack, Teams, PagerDuty + SSRF guard).
3. Kubernetes Distributed Leader Election (Active-Passive Lease coordination).
4. OpenAPI 3.0.3 Specification & Swagger UI Interactive Documentation.
5. Enterprise Server REST API integrations.
6. CLI Subcommand execution.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error

from storage import EnterpriseStorageEngine, TelemetryQueryFilter
from notifications import NotificationDispatcher, AlertPayload
from leader_election import LeaderElector, LeaderLease
from openapi import get_openapi_spec, get_swagger_ui_html
from enterprise_server import EnterpriseServer
from auth import EnterpriseAuthManager, ROLE_SECURITY_ENGINEER, ROLE_PLATFORM_ADMIN


class TestEnterpriseStorageEngine(unittest.TestCase):
    """Verifies SQLite WAL persistence, indexing, querying, and retention pruning."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_telemetry.db")
        self.storage = EnterpriseStorageEngine(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schema_initialization_and_wal_mode(self):
        """Verifies relational tables and WAL mode are initialized."""
        with self.storage._get_connection() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")

            # Check tables exist
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            self.assertIn("scan_records", tables)
            self.assertIn("telemetry_events", tables)
            self.assertIn("compliance_certificates", tables)

    def test_scan_record_persistence_and_stats(self):
        """Verifies saving and counting scan records."""
        rec_id = self.storage.save_scan_record(
            tenant_id="tenant-alpha",
            cluster_id="cls-prod-01",
            target_name="payment-deployment.yaml",
            compliance_score=94.5,
            risk_tier="LOW",
            findings=[{"rule_id": "V01", "severity": "MEDIUM", "title": "Missing runAsNonRoot"}],
        )
        self.assertGreater(rec_id, 0)

        stats = self.storage.get_stats()
        self.assertEqual(stats["scan_records_count"], 1)
        self.assertEqual(stats["backend"], "sqlite_wal")

    def test_telemetry_event_upsert_and_filtering(self):
        """Verifies telemetry event persistence and multi-dimensional query filtering."""
        # Insert 3 events
        self.storage.save_telemetry_event(
            tenant_id="tenant-alpha",
            cluster_id="cls-prod-01",
            event_id="evt-001",
            event_type="EXECVE",
            severity="CRITICAL",
            pod_name="api-gateway-1",
            namespace="production",
            comm="nsenter",
            description="Container escape attempt detected",
            raw_dict={"pid": 4122, "binary": "/usr/bin/nsenter"},
        )
        self.storage.save_telemetry_event(
            tenant_id="tenant-alpha",
            cluster_id="cls-prod-01",
            event_id="evt-002",
            event_type="FILE_OPEN",
            severity="MEDIUM",
            pod_name="redis-cache-1",
            namespace="production",
            comm="cat",
            description="Read access to /etc/hosts",
            raw_dict={"pid": 3011},
        )
        self.storage.save_telemetry_event(
            tenant_id="tenant-beta",
            cluster_id="cls-dev-01",
            event_id="evt-003",
            event_type="EXECVE",
            severity="CRITICAL",
            pod_name="dev-runner",
            namespace="dev",
            comm="bash",
            description="Interactive shell",
            raw_dict={"pid": 5555},
        )

        # Filter by tenant-alpha
        q1 = TelemetryQueryFilter(tenant_id="tenant-alpha")
        res1 = self.storage.query_telemetry_events(q1)
        self.assertEqual(len(res1), 2)

        # Filter by severity CRITICAL
        q2 = TelemetryQueryFilter(min_severity="CRITICAL")
        res2 = self.storage.query_telemetry_events(q2)
        self.assertEqual(len(res2), 2)

        # Filter by tenant-alpha AND severity CRITICAL
        q3 = TelemetryQueryFilter(tenant_id="tenant-alpha", min_severity="CRITICAL")
        res3 = self.storage.query_telemetry_events(q3)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0]["event_id"], "evt-001")

    def test_compliance_certificate_persistence(self):
        """Verifies saving compliance certificates."""
        cert_id = self.storage.save_compliance_certificate(
            tenant_id="tenant-corp",
            target_name="fleet-us-east-1",
            overall_score=99.2,
            status="CERTIFIED",
            certificate_dict={"frameworks": ["SOC-2-Type-II", "PCI-DSS-v4.0"]},
        )
        self.assertGreater(cert_id, 0)
        stats = self.storage.get_stats()
        self.assertEqual(stats["compliance_certificates_count"], 1)

    def test_retention_pruning(self):
        """Verifies automated retention cutoff pruning."""
        # Insert record with an old timestamp (100 days ago)
        old_time = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        with self.storage._get_connection() as conn:
            conn.execute(
                "INSERT INTO scan_records (tenant_id, cluster_id, target_name, compliance_score, risk_tier, findings_count, findings_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("t1", "c1", "old.yaml", 80.0, "LOW", 0, "[]", old_time),
            )
            conn.execute(
                "INSERT INTO telemetry_events (tenant_id, cluster_id, event_id, event_type, severity, pod_name, namespace, comm, description, raw_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("t1", "c1", "old-evt", "EXECVE", "LOW", "p1", "n1", "c", "d", "{}", old_time),
            )

        self.assertEqual(self.storage.get_stats()["scan_records_count"], 1)
        self.assertEqual(self.storage.get_stats()["telemetry_events_count"], 1)

        # Prune keeping 90 days
        pruned = self.storage.prune_retention(days_to_keep=90)
        self.assertEqual(pruned, 2)
        self.assertEqual(self.storage.get_stats()["scan_records_count"], 0)
        self.assertEqual(self.storage.get_stats()["telemetry_events_count"], 0)


class TestNotificationDispatcher(unittest.TestCase):
    """Verifies ChatOps and incident notification formatting and SSRF safety."""

    def test_slack_block_kit_structure(self):
        """Verifies Block Kit structure without sending external HTTP requests."""
        alert = AlertPayload(
            title="Container Breakout Attempt",
            severity="CRITICAL",
            description="Process executed nsenter with SYS_ADMIN capability.",
            cluster_id="prod-aws-east",
            namespace="finance",
            workload_name="transaction-processor",
            remediation="Drop CAP_SYS_ADMIN and enforce read-only root filesystem.",
        )
        # Mock _post_json to verify the constructed payload
        sent_payload = []
        original_post = NotificationDispatcher._post_json
        try:
            NotificationDispatcher._post_json = lambda url, data, timeout=5: sent_payload.append(data) or True
            ok = NotificationDispatcher.send_slack_alert("https://hooks.slack.com/services/T00/B00/X00", alert)
            self.assertTrue(ok)
            self.assertEqual(len(sent_payload), 1)
            p = sent_payload[0]
            self.assertIn("Container Breakout Attempt", p["text"])
            self.assertEqual(p["attachments"][0]["color"], "#dc2626")  # Critical red
            blocks = p["attachments"][0]["blocks"]
            self.assertEqual(blocks[0]["type"], "header")
            # Verify fields
            fields = blocks[1]["fields"]
            field_texts = [f["text"] for f in fields]
            self.assertTrue(any("CRITICAL" in t for t in field_texts))
            self.assertTrue(any("prod-aws-east" in t for t in field_texts))
            self.assertTrue(any("transaction-processor" in t for t in field_texts))
        finally:
            NotificationDispatcher._post_json = original_post

    def test_teams_adaptive_card_structure(self):
        """Verifies MS Teams Adaptive Card structure."""
        alert = AlertPayload(
            title="Typosquatted Image Detected",
            severity="HIGH",
            description="Image 'ngnix:latest' mimics canonical 'nginx:latest'.",
            cluster_id="staging-cluster",
            namespace="web",
            workload_name="frontend",
            remediation="Pin trusted digest sha256:...",
        )
        sent_payload = []
        original_post = NotificationDispatcher._post_json
        try:
            NotificationDispatcher._post_json = lambda url, data, timeout=5: sent_payload.append(data) or True
            ok = NotificationDispatcher.send_teams_alert("https://outlook.office.com/webhook/...", alert)
            self.assertTrue(ok)
            self.assertEqual(len(sent_payload), 1)
            card = sent_payload[0]
            self.assertEqual(card["@type"], "MessageCard")
            self.assertIn("Typosquatted Image Detected", card["title"])
            self.assertEqual(card["sections"][0]["facts"][0]["name"], "Cluster")
        finally:
            NotificationDispatcher._post_json = original_post

    def test_pagerduty_events_v2_structure(self):
        """Verifies PagerDuty Events API v2 payload structure."""
        alert = AlertPayload(
            title="Kernel PrivEsc Exploit",
            severity="CRITICAL",
            description="eBPF detected unauthorized mount in container cgroup.",
            cluster_id="prod-us-west-2",
            namespace="production",
            workload_name="auth-service",
            remediation="Quarantine node immediately.",
        )
        sent_payload = []
        original_post = NotificationDispatcher._post_json
        try:
            NotificationDispatcher._post_json = lambda url, data, timeout=5: sent_payload.append(data) or True
            ok = NotificationDispatcher.send_pagerduty_event("pd-test-key-12345", alert)
            self.assertTrue(ok)
            self.assertEqual(len(sent_payload), 1)
            pd = sent_payload[0]
            self.assertEqual(pd["routing_key"], "pd-test-key-12345")
            self.assertEqual(pd["event_action"], "trigger")
            self.assertEqual(pd["payload"]["severity"], "critical")
            self.assertEqual(pd["payload"]["source"], "prod-us-west-2")
        finally:
            NotificationDispatcher._post_json = original_post

    def test_ssrf_protection_on_webhooks(self):
        """Verifies SSRF attacks targeting AWS IMDS or internal IPs are blocked."""
        alert = AlertPayload(
            title="Test",
            severity="LOW",
            description="Test",
            cluster_id="test",
        )
        # IMDS attempt
        with self.assertRaises(ValueError):
            NotificationDispatcher.send_slack_alert("http://169.254.169.254/latest/meta-data/", alert)

        # Loopback attempt
        with self.assertRaises(ValueError):
            NotificationDispatcher.send_teams_alert("http://127.0.0.1:8080/internal-admin", alert)


class TestLeaderElectionEngine(unittest.TestCase):
    """Verifies Kubernetes distributed lease election protocol."""

    def test_single_candidate_acquire_and_renew(self):
        """Verifies a single candidate acquires and renews the distributed lease."""
        elector = LeaderElector(candidate_id="replica-pod-1", lease_duration=2, renew_interval=1)
        acquired = elector.try_acquire_or_renew()
        self.assertTrue(acquired)
        self.assertTrue(elector.is_leader)
        self.assertEqual(elector.current_lease.holder_identity, "replica-pod-1")

        # Renewing should succeed
        renewed = elector.try_acquire_or_renew()
        self.assertTrue(renewed)
        self.assertTrue(elector.is_leader)

        # Step down
        elector.step_down()
        self.assertFalse(elector.is_leader)

    def test_multi_replica_failover_and_takeover(self):
        """Verifies secondary candidate cannot preempt active leader until expiration."""
        leader1 = LeaderElector(candidate_id="replica-pod-1", lease_duration=10)
        leader2 = LeaderElector(candidate_id="replica-pod-2", lease_duration=10)

        # Replica 1 acquires
        self.assertTrue(leader1.try_acquire_or_renew())
        self.assertTrue(leader1.is_leader)

        # Share current lease state with replica 2
        leader2.current_lease = leader1.current_lease

        # Replica 2 attempts acquire while lease is active -> MUST FAIL
        self.assertFalse(leader2.try_acquire_or_renew())
        self.assertFalse(leader2.is_leader)

        # Force expiration of lease 1
        expired_time = (datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat()
        leader2.current_lease.renew_time = expired_time

        # Replica 2 attempts acquire now that lease expired -> MUST SUCCEED
        self.assertTrue(leader2.try_acquire_or_renew())
        self.assertTrue(leader2.is_leader)
        self.assertEqual(leader2.current_lease.holder_identity, "replica-pod-2")


class TestOpenAPIAndSwagger(unittest.TestCase):
    """Verifies OpenAPI 3.0.3 schema specification and Swagger UI rendering."""

    def test_openapi_spec_structure(self):
        """Verifies OpenAPI specification conforms to 3.0.3."""
        spec = get_openapi_spec(server_url="http://10.0.0.1:8443")
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertEqual(spec["info"]["title"], "Kubernetes Native Security Scanner & Fleet CNAPP API")
        self.assertEqual(spec["servers"][0]["url"], "http://10.0.0.1:8443")

        # Verify key paths
        paths = spec["paths"]
        expected_endpoints = [
            "/healthz",
            "/readyz",
            "/metrics",
            "/api/v1/auth/token",
            "/api/v1/auth/api-key",
            "/api/v1/scan",
            "/api/v1/remediate",
            "/api/v1/vex",
            "/api/v1/fleet/overview",
            "/api/v1/fleet/clusters",
            "/api/v1/compliance/certificate",
            "/api/v1/ebpf/events",
            "/api/v1/telemetry/query",
            "/api/v1/storage/stats",
            "/api/v1/notifications/alert",
            "/api/v1/openapi.json",
            "/docs",
        ]
        for ep in expected_endpoints:
            self.assertIn(ep, paths, f"Endpoint {ep} missing in OpenAPI specification.")

        # Verify security schemes
        schemes = spec["components"]["securitySchemes"]
        self.assertIn("BearerAuth", schemes)
        self.assertIn("ApiKeyAuth", schemes)

    def test_swagger_ui_html_rendering(self):
        """Verifies HTML output contains Swagger UI bundle references."""
        html = get_swagger_ui_html(openapi_url="/api/v1/openapi.json", title="CNAPP API Docs")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<title>CNAPP API Docs</title>", html)
        self.assertIn("swagger-ui-bundle.js", html)
        self.assertIn("/api/v1/openapi.json", html)


class TestEnterpriseServerProductIntegration(unittest.TestCase):
    """Verifies live REST API integration for storage, docs, and openapi."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.temp_dir.name, "server_telemetry.db")
        cls.storage = EnterpriseStorageEngine(db_path=cls.db_path)

        cls.auth_mgr = EnterpriseAuthManager()
        cls.port = 18443
        cls.server = EnterpriseServer(
            host="127.0.0.1",
            port=cls.port,
            auth_manager=cls.auth_mgr,
            storage_engine=cls.storage,
        )
        cls.server.start(background=True)
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.temp_dir.cleanup()

    def _get(self, path: str, headers: dict = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()

    def _post_json(self, path: str, data: dict, headers: dict = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        body = json.dumps(data).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, headers=hdrs)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_openapi_endpoint(self):
        """GET /api/v1/openapi.json returns valid 3.0.3 schema."""
        status, body = self._get("/api/v1/openapi.json")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["openapi"], "3.0.3")
        self.assertIn("/api/v1/scan", data["paths"])

    def test_swagger_ui_endpoint(self):
        """GET /docs returns Swagger UI HTML."""
        status, body = self._get("/docs")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("swagger-ui", text)

    def test_storage_stats_endpoint(self):
        """GET /api/v1/storage/stats returns DB status."""
        status, body = self._get("/api/v1/storage/stats")
        self.assertEqual(status, 200)
        stats = json.loads(body.decode("utf-8"))
        self.assertEqual(stats["backend"], "sqlite_wal")

    def test_telemetry_query_api_with_auth(self):
        """POST /api/v1/telemetry/query queries persisted telemetry."""
        # Issue JWT
        token = self.auth_mgr.issue_jwt(
            tenant_id="tenant-test",
            subject="tester",
            roles=[ROLE_SECURITY_ENGINEER],
        )

        # Save an event to storage directly
        self.storage.save_telemetry_event(
            tenant_id="tenant-test",
            cluster_id="cls-demo",
            event_id="evt-server-1",
            event_type="EXECVE",
            severity="CRITICAL",
            pod_name="api",
            namespace="prod",
            comm="cat",
            description="test description",
            raw_dict={"foo": "bar"},
        )

        # Query via REST API
        status, res = self._post_json(
            "/api/v1/telemetry/query",
            {"tenant_id": "tenant-test", "limit": 10},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["events"][0]["event_id"], "evt-server-1")


if __name__ == "__main__":
    unittest.main()
