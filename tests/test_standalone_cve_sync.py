#!/usr/bin/env python3
"""
tests/test_standalone_cve_sync.py
=================================
Unit tests for deep historical CVE scale and embedded SQLite database engine.
"""

import unittest
from cve import CVEDatabaseEngine, lookup_image_cves


class TestStandaloneCVESync(unittest.TestCase):
    def setUp(self):
        self.engine = CVEDatabaseEngine()

    def test_database_stats_and_scale(self):
        stats = self.engine.get_stats()
        self.assertGreater(stats["total_cves"], 300)
        self.assertIn("CRITICAL", stats["by_severity"])
        self.assertIn("HIGH", stats["by_severity"])
        self.assertTrue(len(stats["sha256"]) == 64)

    def test_package_cve_query(self):
        cves = self.engine.query_package_cves("util-linux")
        self.assertGreater(len(cves), 0)
        cve_ids = {c.cve_id for c in cves}
        self.assertIn("CVE-2016-2779", cve_ids)

    def test_extended_image_catalog(self):
        nginx_cves = lookup_image_cves("nginx:1.14")
        self.assertGreater(len(nginx_cves), 100)
        debian_cves = lookup_image_cves("debian:9")
        self.assertGreater(len(debian_cves), 100)


if __name__ == "__main__":
    unittest.main()
