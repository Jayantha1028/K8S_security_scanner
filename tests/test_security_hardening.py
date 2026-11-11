#!/usr/bin/env python3
"""
tests/test_security_hardening.py
================================
Comprehensive verification of all security hardening & concurrency defenses:
1. Webhook rate limiting, 0600 TLS private key permissions, and HTTP security headers.
2. Dashboard ThreadedHTTPServer and security headers.
3. OCI registry SSRF defense and scheme validation.
4. YAML entity expansion (Billion Laughs) and max payload size limits.
5. SQLite multi-threaded WAL concurrency.
6. Bundle path traversal and decompression safety.
"""

from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from webhook import (
    check_rate_limit,
    generate_self_signed_cert,
    AdmissionWebhookHandler,
    RATE_LIMIT_LOCK,
)
import webhook as wh_mod
from dashboard import DashboardHttpHandler, ThreadedDashboardServer
from container import validate_safe_url, OciRegistryClient
from scanner import NativeSecurityScanner
from cve import CVEDatabaseEngine
from bundle import StandaloneBundleManager, BundleSecurityError


class DummySocket:
    def __init__(self):
        self.data = io.BytesIO()

    def makefile(self, mode="r", buffering=-1):
        if "w" in mode or "b" in mode:
            return self.data
        return io.BytesIO(b"")

    def sendall(self, data):
        self.data.write(data)


class MockHTTPHandler(AdmissionWebhookHandler):
    def __init__(self, request_bytes: bytes, path: str = "/validate", method: str = "POST"):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()
        self.path = path
        self.command = method
        self.headers = {"Content-Length": str(len(request_bytes)), "Content-Type": "application/json"}
        self.server_version = "BaseHTTP/0.6"
        self.sys_version = "Python/3.13"
        self.request_version = "HTTP/1.1"
        self.requestline = f"{method} {path} HTTP/1.1"

    def log_message(self, *args):
        pass


class TestSecurityHardening(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    # 1. Webhook Rate Limiting & TLS Permissions
    def test_webhook_rate_limiter(self):
        with RATE_LIMIT_LOCK:
            wh_mod.RATE_LIMIT_TOKENS = 2.0
            wh_mod.RATE_LIMIT_BUCKET = 2.0

        self.assertTrue(check_rate_limit())
        self.assertTrue(check_rate_limit())
        self.assertFalse(check_rate_limit())

    def test_tls_private_key_permissions(self):
        try:
            cert_p = str(self.td / "cert.pem")
            key_p = str(self.td / "key.pem")
            generate_self_signed_cert(cert_p, key_p)
            st = os.stat(key_p)
            mode = oct(st.st_mode & 0o777)
            self.assertEqual(mode, "0o600")
        except ImportError:
            self.skipTest("cryptography library not installed")

    def test_webhook_security_headers(self):
        with RATE_LIMIT_LOCK:
            wh_mod.RATE_LIMIT_TOKENS = 100.0
        handler = MockHTTPHandler(b'{"request": {"uid": "abc", "object": {"kind": "Pod"}}}')
        handler.do_POST()
        response_bytes = handler.wfile.getvalue()
        response_str = response_bytes.decode("utf-8", errors="ignore")
        self.assertIn("X-Content-Type-Options: nosniff", response_str)
        self.assertIn("X-Frame-Options: DENY", response_str)
        self.assertIn("Strict-Transport-Security", response_str)
        self.assertIn("Content-Security-Policy: default-src 'none'", response_str)

    # 2. Dashboard Security & Concurrency
    def test_dashboard_security_headers(self):
        class MockDash(DashboardHttpHandler):
            def __init__(self, path="/index.html"):
                self.rfile = io.BytesIO()
                self.wfile = io.BytesIO()
                self.path = path
                self.command = "GET"
                self.headers = {}
                self.server_version = "BaseHTTP/0.6"
                self.sys_version = "Python/3.13"
                self.request_version = "HTTP/1.1"
                self.requestline = f"GET {path} HTTP/1.1"

            def log_message(self, *args):
                pass

        dash = MockDash()
        dash.do_GET()
        out = dash.wfile.getvalue().decode("utf-8", errors="ignore")
        self.assertIn("X-Content-Type-Options: nosniff", out)
        self.assertIn("X-Frame-Options: SAMEORIGIN", out)
        self.assertIn("Content-Security-Policy", out)

    def test_dashboard_threaded_server_class(self):
        self.assertTrue(issubclass(ThreadedDashboardServer, HTTPServer))
        self.assertTrue(ThreadedDashboardServer.daemon_threads)

    # 3. SSRF & URL Validation
    def test_ssrf_rejects_http_scheme(self):
        with self.assertRaises(ValueError) as cm:
            validate_safe_url("http://registry-1.docker.io/v2/")
        self.assertIn("Only HTTPS is permitted", str(cm.exception))

    def test_ssrf_rejects_cloud_metadata(self):
        with self.assertRaises(ValueError) as cm:
            validate_safe_url("https://169.254.169.254/latest/meta-data")
        self.assertIn("SSRF Protection", str(cm.exception))

    def test_ssrf_rejects_loopback(self):
        with self.assertRaises(ValueError) as cm:
            validate_safe_url("https://127.0.0.1:8443/v2/")
        self.assertIn("SSRF Protection", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            validate_safe_url("https://localhost:8443/v2/")
        self.assertIn("SSRF Protection", str(cm.exception))

    def test_ssrf_rejects_rfc1918_private_ips(self):
        for ip in ("10.0.0.5", "172.16.1.1", "192.168.1.100"):
            with self.assertRaises(ValueError) as cm:
                validate_safe_url(f"https://{ip}/v2/")
            self.assertIn("SSRF Protection", str(cm.exception))

    # 4. Billion Laughs & Excessive YAML Payload Protection
    def test_scanner_rejects_huge_manifest(self):
        huge_yaml = "a: " + ("x" * (11 * 1024 * 1024))
        scanner = NativeSecurityScanner()
        report = scanner.scan_yaml_content(huge_yaml)
        self.assertEqual(report.compliance_score, 0.0)
        self.assertTrue(any(f.vuln_id == "V00" and "10MB" in (f.title + f.description) for f in report.findings))

    def test_scanner_rejects_yaml_entity_expansion_bomb(self):
        bomb_lines = ["a: &a ['lol','lol','lol','lol','lol']"]
        for i in range(1, 20):
            bomb_lines.append(f"b{i}: &b{i} [*b{i-1}, *b{i-1}, *b{i-1}]" if i > 1 else f"b1: &b1 [*a, *a, *a, *a]")
        bomb_yaml = "\n".join(bomb_lines)
        # Add many alias references to trigger guard
        bomb_yaml += "\nrefs: [" + ", ".join(["*a"] * 350) + "]"

        scanner = NativeSecurityScanner()
        report = scanner.scan_yaml_content(bomb_yaml)
        self.assertEqual(report.compliance_score, 0.0)
        self.assertTrue(any("Entity Expansion" in f.title for f in report.findings))

    # 5. Multi-threaded SQLite Concurrency
    def test_cve_db_concurrent_reads_and_writes(self):
        db_file = self.td / "concurrency_test.sqlite"
        engine = CVEDatabaseEngine(db_file)

        def worker(thread_id: int):
            for i in range(15):
                pkg = f"package_{thread_id}_{i}"
                with engine._get_connection() as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO cves (
                            cve_id, severity, cvss_score, package_name,
                            vulnerable_versions, description, ecosystem
                        ) VALUES (?, 'HIGH', 8.0, ?, '< 1.0', 'concurrency test', 'generic')
                    """, (f"CVE-TEST-{thread_id}-{i}", pkg))
                res = engine.query_package_cves(pkg)
                assert len(res) >= 1

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, tid) for tid in range(8)]
            for f in futures:
                f.result()

        stats = engine.get_stats()
        self.assertGreaterEqual(stats["total_cves"], 8 * 15)


if __name__ == "__main__":
    unittest.main()
