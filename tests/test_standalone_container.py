#!/usr/bin/env python3
"""
test_standalone_container.py
============================
Unit tests for standalone container layer unpacking, SBOM & CycloneDX/SPDX generation.
"""

import sys
from pathlib import Path
_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import unittest
from io import BytesIO
import json
import tarfile
from native_scanner import HybridContainerLayerScanner, SBOMScanReport, InstalledPackage


class TestStandaloneContainerScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = HybridContainerLayerScanner()

    def test_mock_dpkg_unpacking(self):
        tar_buf = BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            # Add manifest.json
            manifest_data = json.dumps([{"Config": "config.json", "Layers": ["layer1.tar"]}]).encode("utf-8")
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(manifest_data)
            tar.addfile(ti, BytesIO(manifest_data))

            # Add layer1.tar containing /var/lib/dpkg/status
            sub_buf = BytesIO()
            with tarfile.open(fileobj=sub_buf, mode="w") as sub_tar:
                dpkg_status = b"""Package: openssl
Status: install ok installed
Version: 1.1.1n-0+deb10u3
Architecture: amd64

Package: curl
Status: install ok installed
Version: 7.64.0-4+deb10u2
Architecture: amd64
"""
                sub_ti = tarfile.TarInfo("var/lib/dpkg/status")
                sub_ti.size = len(dpkg_status)
                sub_tar.addfile(sub_ti, BytesIO(dpkg_status))

            sub_bytes = sub_buf.getvalue()
            layer_ti = tarfile.TarInfo("layer1.tar")
            layer_ti.size = len(sub_bytes)
            tar.addfile(layer_ti, BytesIO(sub_bytes))

        report = self.scanner.scan_tar_bytes(tar_buf.getvalue(), "mock-debian:latest")
        self.assertEqual(report.os_distro, "debian/ubuntu")
        self.assertGreaterEqual(len(report.packages), 2)
        pkg_names = [p.name for p in report.packages]
        self.assertIn("openssl", pkg_names)
        self.assertIn("curl", pkg_names)

        # Verify CycloneDX v1.5 export
        cdx = report.to_cyclonedx()
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.5")
        self.assertGreaterEqual(len(cdx["components"]), 2)

        # Verify SPDX v2.3 export
        spdx = report.to_spdx()
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertGreaterEqual(len(spdx["packages"]), 2)


if __name__ == "__main__":
    unittest.main()
