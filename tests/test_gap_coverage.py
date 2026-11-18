#!/usr/bin/env python3
"""
tests/test_gap_coverage.py
==========================
Verifies the 6 architectural enhancements bridging previous tool gaps:
1. Rust Cargo.lock & Python poetry.lock package parsers (container.py).
2. Multi-Cloud Infrastructure CSPM evaluation (cloud_cspm.py).
3. Kubernetes Native CustomResourceDefinition schemas (crds.py).
4. Native C eBPF CO-RE code generation & Falco Bridge ingestion (ebpf.py).
"""

import unittest
from container import HybridContainerLayerScanner
from cloud_cspm import CloudCSPMEngine, CloudCSPMReport
from crds import KubernetesCRDManager, SecurityPolicySpec
from ebpf import EBPFTelemetryEngine, FalcoBridgeReceiver, get_native_ebpf_c_source


class TestGapCoverage(unittest.TestCase):
    def test_cargo_and_poetry_lock_parsers(self):
        # 1. Rust Cargo.lock
        cargo_content = """
[[package]]
name = "tokio"
version = "1.28.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.160"
"""
        cargo_pkgs = HybridContainerLayerScanner._parse_cargo_lock(cargo_content)
        self.assertEqual(len(cargo_pkgs), 2)
        self.assertEqual(cargo_pkgs[0].name, "tokio")
        self.assertEqual(cargo_pkgs[0].version, "1.28.0")
        self.assertEqual(cargo_pkgs[0].package_type, "cargo")

        # 2. Python poetry.lock
        poetry_content = """
[[package]]
name = "fastapi"
version = "0.100.0"

[[package]]
name = "uvicorn"
version = "0.22.0"
"""
        poetry_pkgs = HybridContainerLayerScanner._parse_poetry_lock(poetry_content)
        self.assertEqual(len(poetry_pkgs), 2)
        self.assertEqual(poetry_pkgs[0].name, "fastapi")
        self.assertEqual(poetry_pkgs[0].version, "0.100.0")
        self.assertEqual(poetry_pkgs[0].package_type, "pypi")

    def test_multi_cloud_cspm_engine(self):
        engine = CloudCSPMEngine()
        inventory = {
            "aws": {
                "s3_buckets": [
                    {"name": "public-data-bucket", "public_access_block": {"block_public_acls": False}},
                    {"name": "secure-bucket", "public_access_block": {"block_public_acls": True, "block_public_policy": True}, "encryption": {"enabled": True}},
                ],
                "security_groups": [
                    {
                        "id": "sg-open-ssh",
                        "ingress_rules": [{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22}],
                    }
                ],
                "ec2_instances": [
                    {"id": "i-legacy-imds", "metadata_options": {"http_tokens": "optional"}}
                ]
            },
            "gcp": {
                "storage_buckets": [
                    {"name": "gcs-unhardened", "uniform_bucket_level_access": {"enabled": False}}
                ],
                "firewall_rules": [
                    {"name": "fw-allow-all", "source_ranges": ["0.0.0.0/0"], "allowed": [{"ports": ["22"]}]}
                ]
            }
        }

        report = engine.evaluate_cloud_inventory(inventory)
        self.assertIsInstance(report, CloudCSPMReport)
        self.assertLess(report.cspm_score, 80.0)
        self.assertIn(report.risk_tier, ["High", "Critical"])
        self.assertGreaterEqual(len(report.findings), 4)

        # Check specific findings
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("AWS-S3-01", rule_ids)
        self.assertIn("AWS-SG-01", rule_ids)
        self.assertIn("AWS-EC2-IMDS", rule_ids)
        self.assertIn("GCP-FW-01", rule_ids)

    def test_crd_schemas_and_parser(self):
        all_crds = KubernetesCRDManager.get_all_crd_manifests()
        self.assertIn("securitypolicies.security.k8s.io", all_crds)
        self.assertIn("clustercomplianceaudits.security.k8s.io", all_crds)

        policy_yaml = """
apiVersion: security.k8s.io/v1
kind: SecurityPolicy
metadata:
  name: prod-strict-policy
spec:
  minComplianceScore: 85.0
  enforceNonRoot: true
  disallowPrivileged: true
  requireReadOnlyRootFilesystem: true
  blockedCapabilities: ["SYS_ADMIN", "ALL"]
"""
        spec = KubernetesCRDManager.parse_security_policy_yaml(policy_yaml)
        self.assertEqual(spec.min_compliance_score, 85.0)
        self.assertTrue(spec.enforce_non_root)
        self.assertTrue(spec.require_read_only_root_filesystem)
        self.assertIn("SYS_ADMIN", spec.blocked_capabilities)

    def test_ebpf_c_source_and_falco_bridge(self):
        # 1. Native C source code generation
        c_source = get_native_ebpf_c_source()
        self.assertIn("SEC(\"tracepoint/syscalls/sys_enter_execve\")", c_source)
        self.assertIn("BPF_MAP_TYPE_RINGBUF", c_source)

        # 2. Falco Bridge event ingestion
        engine = EBPFTelemetryEngine()
        bridge = FalcoBridgeReceiver(engine)
        falco_payload = {
            "output": "14:10:00.123456 Notice Terminal shell in container (user=root pod=api-7b89 ns=prod)",
            "priority": "Critical",
            "rule": "Terminal shell in container",
            "output_fields": {
                "proc.name": "bash",
                "proc.pid": 5890,
                "k8s.pod.name": "api-7b89",
                "k8s.ns.name": "prod",
                "container.id": "a1b2c3d4e5f67890",
            }
        }
        event = bridge.parse_falco_alert(falco_payload)
        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.pod_name, "api-7b89")
        self.assertEqual(len(engine.get_recent_events()), 1)


if __name__ == "__main__":
    unittest.main()
