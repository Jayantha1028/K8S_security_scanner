#!/usr/bin/env python3
"""
tests/test_accuracy_performance.py
==================================
Unit tests verifying detection accuracy enhancements (false positive suppression)
and microsecond latency optimizations in the NativeSecurityScanner engine.
"""

from pathlib import Path
import sys
import time
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import (
    NativeSecurityScanner,
    is_likely_false_positive_secret,
    shannon_entropy,
    levenshtein_distance,
    check_image_typosquatting,
)


class TestAccuracyAndPerformance(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()

    # --------------------------------------------------------------------------
    # 1. Detection Accuracy: False Positive Secret Suppression
    # --------------------------------------------------------------------------
    def test_false_positive_secret_filter(self):
        """Verifies that non-secret strings are accurately identified as benign."""
        benign_samples = [
            "https://kubernetes.default.svc.cluster.local:443",
            "http://elasticsearch.logging.svc:9200",
            "postgres://user:pass@db.internal:5432/mydb",
            "$(POD_IP):$(POD_PORT)",
            "$(POD_NAME).$(POD_NAMESPACE).svc.cluster.local",
            "{{ .Values.database.url }}",
            "{{ include \"common.names.fullname\" . }}",
            "123e4567-e89b-12d3-a456-426614174000",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "4a3b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "CHANGE_ME",
            "replace_me_with_production_key",
            "dummy_placeholder_token",
            "<redacted>",
            "/var/log/application/audit-trail.log",
            "application/vnd.docker.distribution.manifest.v2+json",
            "------------------------------------",
            "====================================",
        ]
        for sample in benign_samples:
            self.assertTrue(
                is_likely_false_positive_secret(sample),
                f"Expected '{sample}' to be filtered as likely false positive secret"
            )

    def test_real_secrets_not_filtered(self):
        """Verifies that actual high-confidence secret credentials are NOT filtered."""
        real_secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_123456789012345678901234567890123456",
            "xK9#m$L2@vP8&wQ1",
            "U19#qK!z8L*wM4$p0X&r",
        ]
        for sec in real_secrets:
            self.assertFalse(
                is_likely_false_positive_secret(sec),
                f"Expected real secret '{sec}' NOT to be filtered as false positive"
            )

    def test_manifest_secret_scanning_accuracy(self):
        """
        Tests that an environment variable containing an internal URL, Helm parameter,
        or UUID is NOT falsely flagged as V18 (Plaintext Secret).
        """
        manifest_with_urls = """
apiVersion: v1
kind: Pod
metadata:
  name: web-app
spec:
  containers:
    - name: api
      image: myregistry.io/app:1.0.0@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
      env:
        - name: SERVICE_ENDPOINT
          value: "https://kubernetes.default.svc.cluster.local:443"
        - name: DOWNWARD_API_PORT
          value: "$(POD_IP):$(POD_PORT)"
        - name: HELM_PARAM
          value: "{{ .Values.database.url }}"
        - name: CORRELATION_ID
          value: "4a3b2c1d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
        - name: PLACEHOLDER_VAR
          value: "CHANGE_ME"
"""
        report = self.scanner.scan_yaml_content(manifest_with_urls)
        # Verify NO V18 findings exist for the benign environment variables
        v18_findings = [f for f in report.findings if f.vuln_id == "V18"]
        self.assertEqual(
            len(v18_findings), 0,
            f"Expected zero V18 false positive findings, but found: {[f.target + ': ' + f.description for f in v18_findings]}"
        )

    def test_manifest_real_secret_detected(self):
        """Tests that genuine secret credentials in manifests continue to trigger V18."""
        manifest_with_secrets = """
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-app
spec:
  containers:
    - name: api
      image: myregistry.io/app:1.0.0
      env:
        - name: AWS_ACCESS_KEY_ID
          value: "AKIAIOSFODNN7EXAMPLE"
        - name: RND_API_TOKEN
          value: "xK9#m$L2@vP8&wQ1-prod-key"
"""
        report = self.scanner.scan_yaml_content(manifest_with_secrets)
        v18_findings = [f for f in report.findings if f.vuln_id == "V18"]
        self.assertGreaterEqual(len(v18_findings), 2)
        vuln_ids = report.detected_vuln_ids
        self.assertIn("V18", vuln_ids)

    # --------------------------------------------------------------------------
    # 2. HostPath Accuracy: Distinguishing Sockets (V46), Root (V45), & Safe Certs
    # --------------------------------------------------------------------------
    def test_hostpath_socket_detection_v46(self):
        """Tests that container runtime socket mounts map to V46 with CRITICAL severity."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: socket-pod
spec:
  containers:
    - name: runner
      image: docker:20.10
      volumeMounts:
        - name: sock
          mountPath: /var/run/docker.sock
  volumes:
    - name: sock
      hostPath:
        path: /var/run/docker.sock
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V46", report.detected_vuln_ids)
        socket_finding = next(f for f in report.findings if f.vuln_id == "V46")
        self.assertEqual(socket_finding.severity, "CRITICAL")
        self.assertIn("docker.sock", socket_finding.description)

    def test_hostpath_root_detection_v45(self):
        """Tests that root filesystem mounts map to V45."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: root-escape-pod
spec:
  containers:
    - name: app
      image: alpine:latest
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V45", report.detected_vuln_ids)

    def test_hostpath_safe_certs_read_only(self):
        """Tests that benign read-only CA certificates do not falsely trigger root escape."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: cert-pod
spec:
  containers:
    - name: app
      image: alpine:latest
      volumeMounts:
        - name: ca-certs
          mountPath: /etc/ssl/certs
          readOnly: true
  volumes:
    - name: ca-certs
      hostPath:
        path: /etc/ssl/certs
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertNotIn("V45", report.detected_vuln_ids)
        self.assertNotIn("V46", report.detected_vuln_ids)
        self.assertNotIn("V47", report.detected_vuln_ids)

    # --------------------------------------------------------------------------
    # 3. Supply Chain Image Digest Pinning
    # --------------------------------------------------------------------------
    def test_digest_pinned_image_bypasses_mutable_tag_alert(self):
        """Verifies that an image with an immutable @sha256 digest is NOT flagged as V15."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: pinned-pod
spec:
  containers:
    - name: app
      image: myregistry.io/app@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertNotIn("V15", report.detected_vuln_ids)
        self.assertNotIn("V19", report.detected_vuln_ids)

    # --------------------------------------------------------------------------
    # 4. Latency & Performance Verification
    # --------------------------------------------------------------------------
    def test_shannon_entropy_mathematical_precision(self):
        """Verifies exact Shannon entropy calculation across edge cases."""
        # Single char or empty -> 0.0
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaa"), 0.0)
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

        # Uniform distribution of 16 distinct chars -> log2(16) = 4.0
        exact_16 = "abcdefghijklmnop"
        self.assertAlmostEqual(shannon_entropy(exact_16), 4.0, places=5)

        # Random cryptographic token
        high_rand = "xK9#m$L2@vP8&wQ1"
        self.assertGreater(shannon_entropy(high_rand), 3.8)

    def test_caching_speedup(self):
        """Verifies that LRU caching delivers sub-millisecond execution on repeated queries."""
        image = "ng1nx:latest"
        # Prime the cache
        check_image_typosquatting(image)

        # Execute 5,000 cached evaluations
        t0 = time.perf_counter()
        for _ in range(5000):
            check_image_typosquatting(image)
        t1 = time.perf_counter()

        elapsed = t1 - t0
        self.assertLess(elapsed, 0.05, f"Expected 5,000 cached checks in <0.05s, got {elapsed:.4f}s")

    def test_scan_throughput(self):
        """Verifies high throughput scanning of Kubernetes manifests."""
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: benchmark-pod
spec:
  containers:
    - name: app
      image: nginx:1.21.6
      resources:
        limits:
          cpu: 500m
          memory: 256Mi
"""
        t0 = time.perf_counter()
        iterations = 100
        for _ in range(iterations):
            self.scanner.scan_yaml_content(manifest)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        rate = iterations / elapsed
        self.assertGreater(rate, 200, f"Expected > 200 manifests/sec, achieved {rate:.1f} manifests/sec")


if __name__ == "__main__":
    unittest.main()
