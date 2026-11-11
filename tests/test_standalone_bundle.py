#!/usr/bin/env python3
"""
test_standalone_bundle.py
=========================
Unit tests for the standalone air-gapped sovereign bundle manager and CLI.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import sqlite3
import subprocess
import tempfile
import unittest

from native_scanner import StandaloneBundleManager


class TestStandaloneBundle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.td = Path(self.temp_dir.name)

        # Create dummy rule and cve db
        self.rules_dir = self.td / "rules"
        self.rules_dir.mkdir()
        (self.rules_dir / "custom.yaml").write_text("id: CR-01\nname: TestRule\n", encoding="utf-8")

        self.db_path = self.td / "test.sqlite"
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute("CREATE TABLE test (val TEXT)")
        c.execute("INSERT INTO test VALUES ('ok')")
        conn.commit()
        conn.close()

        self.mgr = StandaloneBundleManager(base_dir=self.td)
        self.cli_path = _PKG_DIR / "bin" / "k8s-native-scan"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_export_and_verify(self):
        out_tar = self.td / "bundle.tar.gz"
        manifest = self.mgr.export_rules_and_data(
            output_path=out_tar,
            rules_dir=self.rules_dir,
            cve_db_path=self.db_path,
        )
        self.assertTrue(out_tar.exists())
        self.assertEqual(manifest["file_count"], 2)

        valid, msg, mf = self.mgr.verify_bundle(out_tar)
        self.assertTrue(valid)
        self.assertIn("rules/custom.yaml", mf["checksums"])
        self.assertIn("data/cve_database.sqlite", mf["checksums"])

    def test_02_import_bundle(self):
        out_tar = self.td / "bundle.tar.gz"
        self.mgr.export_rules_and_data(
            output_path=out_tar,
            rules_dir=self.rules_dir,
            cve_db_path=self.db_path,
        )

        dest = self.td / "extracted"
        res = self.mgr.import_bundle(out_tar, target_dir=dest)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue((dest / "rules" / "custom.yaml").exists())
        self.assertTrue((dest / "data" / "cve_database.sqlite").exists())

    def test_03_cli_bundle_workflow(self):
        out_tar = self.td / "cli_bundle.tar.gz"
        # CLI Export
        res_exp = subprocess.run(
            [str(self.cli_path), "bundle", "export", str(out_tar), "-r", str(self.rules_dir), "--cve-db", str(self.db_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_exp.returncode, 0)
        self.assertTrue(out_tar.exists())

        # CLI Verify
        res_ver = subprocess.run(
            [str(self.cli_path), "bundle", "verify", str(out_tar)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_ver.returncode, 0)
        self.assertIn("100% Verified", res_ver.stdout)

        # CLI Import
        import_dest = self.td / "cli_imported"
        res_imp = subprocess.run(
            [str(self.cli_path), "bundle", "import", str(out_tar), "-d", str(import_dest)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_imp.returncode, 0)
        self.assertTrue((import_dest / "rules" / "custom.yaml").exists())


if __name__ == "__main__":
    unittest.main()
