#!/usr/bin/env python3
"""
tests/test_version_comparator.py
================================
Unit tests for LinuxVersionComparator across Debian, RPM, and Alpine formats.
"""

import unittest
from version_comparator import (
    compare_debian_versions,
    compare_rpm_versions,
    compare_apk_versions,
    LinuxVersionComparator,
)


class TestVersionComparator(unittest.TestCase):
    def test_debian_epoch_and_revision(self):
        # 1:1.0 is greater than 2.0 without epoch
        self.assertEqual(compare_debian_versions("1:1.0", "2.0"), 1)
        # Upstream equal, revision differs
        self.assertEqual(compare_debian_versions("1.1.1f-1ubuntu2", "1.1.1f-1ubuntu2.19"), -1)
        # Tilde sorts before empty string
        self.assertEqual(compare_debian_versions("1.0~rc1", "1.0"), -1)
        # Digits compared numerically
        self.assertEqual(compare_debian_versions("1.10", "1.2"), 1)

    def test_rpmvercmp(self):
        # Alpha segments vs numeric segments
        self.assertEqual(compare_rpm_versions("1.2.3", "1.2.4"), -1)
        self.assertEqual(compare_rpm_versions("2.0-1.el8", "2.0-2.el8"), -1)
        self.assertEqual(compare_rpm_versions("1:2.0-1", "3.0-1"), 1)  # Epoch wins

    def test_apk_version_comparison(self):
        self.assertEqual(compare_apk_versions("1.2.3_rc1", "1.2.3"), -1)
        self.assertEqual(compare_apk_versions("1.2.3-r1", "1.2.3-r2"), -1)
        self.assertEqual(compare_apk_versions("1.2.3_p1", "1.2.3"), 1)

    def test_is_vulnerable(self):
        # Installed 1.1.1f-1ubuntu2 < Fixed 1.1.1f-1ubuntu2.19 -> True (vulnerable)
        self.assertTrue(LinuxVersionComparator.is_vulnerable(
            "1.1.1f-1ubuntu2", "1.1.1f-1ubuntu2.19", "ubuntu"
        ))
        # Installed is newer than fixed -> False (patched)
        self.assertFalse(LinuxVersionComparator.is_vulnerable(
            "1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.19", "ubuntu"
        ))


if __name__ == "__main__":
    unittest.main()
