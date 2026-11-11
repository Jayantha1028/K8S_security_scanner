#!/usr/bin/env python3
"""
tests/test_node_auditor.py
==========================
Unit tests for CIS Kubernetes Node & Control Plane Auditor.
"""

from pathlib import Path
import tempfile
import unittest

from node_auditor import NodeAuditor


class TestNodeAuditor(unittest.TestCase):
    def test_node_auditor_mock_root(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)

            # Create mock /etc/kubernetes/admin.conf with strict 600 permissions
            k8s_dir = tmp_root / "etc" / "kubernetes"
            k8s_dir.mkdir(parents=True, exist_ok=True)
            admin_conf = k8s_dir / "admin.conf"
            admin_conf.write_text("apiVersion: v1\nkind: Config\n")
            admin_conf.chmod(0o600)

            # Create insecure controller-manager.conf with 644
            cm_conf = k8s_dir / "controller-manager.conf"
            cm_conf.write_text("apiVersion: v1\nkind: Config\n")
            cm_conf.chmod(0o644)

            auditor = NodeAuditor(root_prefix=str(tmp_root))
            report = auditor.audit_node()

            self.assertGreater(report.total_checks, 0)
            finding_ids = {f.check_id: f.status for f in report.findings}
            self.assertEqual(finding_ids.get("CIS-3.1.1"), "PASS")
            self.assertEqual(finding_ids.get("CIS-3.1.2"), "FAIL")


if __name__ == "__main__":
    unittest.main()
