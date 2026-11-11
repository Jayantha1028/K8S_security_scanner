#!/usr/bin/env python3
"""
container_layer_scanner.py
===========================
Hybrid Container Layer & Deep OS Package Scanner.

Unpacks container image layers and parses in-container package manager databases
to generate a complete Software Bill of Materials (SBOM) and match exact package CVEs.

Operational Modes:
1. Docker Daemon Integration (Live Stream):
   When the Docker daemon is active, runs `docker save <image>` and streams stdout
   directly into an in-memory tarball reader without persisting gigabyte archives to disk.

2. Pure-Python Layer Unpacker (OCI / Docker Tarball Engine):
   Inspects container tarballs (exported or streamed), reads manifest.json, and sequentially
   inspects layer archives in memory:
   - Debian / Ubuntu : /var/lib/dpkg/status
   - Alpine Linux    : /lib/apk/db/installed
   - RedHat / CentOS : /var/lib/rpm/Packages or rpmdb.sqlite
   - Language files  : requirements.txt, package-lock.json

3. Trivy Engine Delegation:
   When Trivy is installed, delegates deep multi-ecosystem analysis and parses JSON results.

4. Air-Gapped / Offline Fallback:
   When neither Docker nor tarballs are reachable, falls back to native image metadata
   and known CVE catalog mappings so CI/CD pipelines never block.
"""

import argparse
from io import BytesIO
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("NativeContainerScanner")

try:
    from .cve import CVEEntry, lookup_image_cves
except ImportError:
    from cve import CVEEntry, lookup_image_cves


@dataclass
class InstalledPackage:
    name: str
    version: str
    architecture: str = "amd64"
    package_type: str = "os"  # os, python, node, go
    layer_index: int = 0
    license: str = "unknown"

    def to_dict(self):
        return asdict(self)


@dataclass
class SBOMScanReport:
    image_name: str
    os_distro: str = "unknown"
    execution_mode: str = "PURE_PYTHON_OCI"
    scan_latency_ms: float = 0.0
    total_packages: int = 0
    packages: List[InstalledPackage] = field(default_factory=list)
    critical_cves: List[CVEEntry] = field(default_factory=list)
    high_cves: List[CVEEntry] = field(default_factory=list)
    medium_cves: List[CVEEntry] = field(default_factory=list)
    total_cves: int = 0
    layers_inspected: int = 0

    def to_dict(self):
        d = asdict(self)
        d["packages"] = [p.to_dict() for p in self.packages]
        d["critical_cves"] = [c.to_dict() for c in self.critical_cves]
        d["high_cves"] = [c.to_dict() for c in self.high_cves]
        d["medium_cves"] = [c.to_dict() for c in self.medium_cves]
        return d

    def to_cyclonedx(self) -> Dict[str, Any]:
        """Export SBOM in standard CycloneDX v1.5 JSON specification."""
        components = []
        for pkg in self.packages:
            if pkg.package_type == "node":
                purl_type = "npm"
            elif pkg.package_type == "python":
                purl_type = "pypi"
            elif pkg.package_type == "java":
                purl_type = "maven"
            elif pkg.package_type == "go":
                purl_type = "golang"
            elif pkg.package_type == "rust":
                purl_type = "cargo"
            elif pkg.package_type == "rpm" or "rhel" in self.os_distro or "centos" in self.os_distro or "fedora" in self.os_distro:
                purl_type = "rpm"
            elif "debian" in self.os_distro or "ubuntu" in self.os_distro:
                purl_type = "deb"
            elif "alpine" in self.os_distro:
                purl_type = "apk"
            else:
                purl_type = "generic"

            comp: Dict[str, Any] = {
                "type": "library" if pkg.package_type != "os" else "operating-system",
                "name": pkg.name,
                "version": pkg.version,
                "purl": f"pkg:{purl_type}/{pkg.name}@{pkg.version}?arch={pkg.architecture}",
            }
            if pkg.license and pkg.license != "unknown":
                comp["licenses"] = [{"license": {"name": pkg.license}}]
            components.append(comp)

        vulns = []
        for cve in (self.critical_cves + self.high_cves + self.medium_cves):
            vulns.append({
                "id": cve.cve_id,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"},
                "ratings": [{
                    "score": cve.cvss_score,
                    "severity": cve.severity.lower(),
                    "method": "CVSSv3",
                }],
                "description": cve.description,
                "affects": [{"ref": f"pkg:generic/{cve.package}@{cve.vulnerable_versions}"}],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{os.urandom(16).hex()}",
            "version": 1,
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tools": [{
                    "vendor": "Kubernetes ML Security Platform",
                    "name": "HybridContainerLayerScanner",
                    "version": "2.0.0",
                }],
                "component": {
                    "type": "container",
                    "name": self.image_name,
                    "properties": [
                        {"name": "k8s-sec:os_distro", "value": self.os_distro},
                        {"name": "k8s-sec:layers_inspected", "value": str(self.layers_inspected)},
                    ]
                }
            },
            "components": components,
            "vulnerabilities": vulns,
        }

    def to_spdx(self) -> Dict[str, Any]:
        """Export SBOM in standard SPDX v2.3 JSON specification."""
        spdx_pkgs = []
        for idx, pkg in enumerate(self.packages, start=1):
            spdx_pkgs.append({
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": pkg.license if pkg.license != "unknown" else "NOASSERTION",
                "licenseDeclared": pkg.license if pkg.license != "unknown" else "NOASSERTION",
                "copyrightText": "NOASSERTION",
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"SBOM-{self.image_name.replace('/', '_').replace(':', '_')}",
            "documentNamespace": f"https://spdx.org/spdxdocs/{self.image_name}-{os.urandom(6).hex()}",
            "creationInfo": {
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "creators": ["Tool: Kubernetes ML Security Platform - HybridContainerLayerScanner-2.0.0"],
            },
            "packages": spdx_pkgs,
        }


class HybridContainerLayerScanner:
    """
    Hybrid Deep Container Layer & OS Package Unpacker.
    Combines Docker daemon streaming, Trivy CLI delegation, and Pure-Python OCI tarball parsing.
    """

    def __init__(self, trivy_bin: Optional[str] = None):
        self.trivy_bin = trivy_bin or shutil.which("trivy") or "/opt/homebrew/bin/trivy"
        self.has_trivy = os.path.isfile(self.trivy_bin) and os.access(self.trivy_bin, os.X_OK)
        self.has_docker = self._check_docker_daemon()

    @staticmethod
    def _check_docker_daemon() -> bool:
        """Verify if Docker CLI exists and the daemon socket responds."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _is_image_in_docker(self, image: str) -> bool:
        """Verify if an image is locally available in the Docker daemon."""
        if not self.has_docker or not image or image.startswith("-"):
            return False
        try:
            res = subprocess.run(
                ["docker", "image", "inspect", "--", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return res.returncode == 0
        except Exception:
            return False

    def scan_image(self, image: str, use_trivy_if_available: bool = True) -> SBOMScanReport:
        """
        Deep scan an image by name:
        1. If image exists in local Docker daemon, stream 'docker save' into Python layer unpacker.
        2. If Trivy is available and preferred, delegates to Trivy JSON.
        3. Fallback to native intelligence catalog.
        """
        t0 = time.time()
        report = SBOMScanReport(image_name=image)

        # 1. Live Docker Daemon Stream Unpacking (zero network if locally present)
        if self.has_docker and self._is_image_in_docker(image):
            try:
                docker_report = self._scan_via_docker_stream(image)
                if docker_report:
                    docker_report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
                    return docker_report
            except Exception:
                pass

        # 2. Trivy Engine Delegation
        if use_trivy_if_available and self.has_trivy:
            try:
                trivy_report = self._scan_with_trivy(image)
                if trivy_report:
                    trivy_report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
                    return trivy_report
            except Exception:
                pass  # Fallback to docker stream or native catalog

        # 3. Live Docker Daemon Stream Unpacking (attempt pull or stream if docker active)
        if self.has_docker:
            try:
                docker_report = self._scan_via_docker_stream(image)
                if docker_report:
                    docker_report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
                    return docker_report
            except Exception:
                pass

        # 4. Offline Intelligence Catalog Fallback
        report.execution_mode = "OFFLINE_CATALOG_FALLBACK"
        cves = lookup_image_cves(image)
        for c in cves:
            if c.severity == "CRITICAL":
                report.critical_cves.append(c)
            elif c.severity == "HIGH":
                report.high_cves.append(c)
            elif c.severity == "MEDIUM":
                report.medium_cves.append(c)
        report.total_cves = len(cves)
        report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
        return report

    def scan_tarball(self, tar_path: str) -> SBOMScanReport:
        """Unpack a local OCI / Docker tarball archive from disk."""
        t0 = time.time()
        p = Path(tar_path)
        if not p.is_file():
            raise FileNotFoundError(f"Tarball not found: {tar_path}")

        with tarfile.open(p, "r:*") as tf:
            report = self._unpack_tarfile(tf, source_name=p.name)

        report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
        return report

    def scan_tar_bytes(self, tar_bytes: bytes, source_name: str = "in_memory_image.tar") -> SBOMScanReport:
        """Unpack an in-memory tarball bytes object."""
        t0 = time.time()
        bio = BytesIO(tar_bytes)
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            report = self._unpack_tarfile(tf, source_name=source_name)
        report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
        return report

    def _scan_via_docker_stream(self, image: str) -> Optional[SBOMScanReport]:
        """Stream 'docker save' directly into in-memory BytesIO without saving to disk."""
        if not image or image.startswith("-"):
            logger.warning(f"Refusing to stream container image with leading hyphen/invalid name: {image}")
            return None
        cmd = ["docker", "save", "--", image]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            data, _ = proc.communicate(timeout=60)
            if proc.returncode != 0:
                return None
            report = self.scan_tar_bytes(data, source_name=image)
            report.execution_mode = "DOCKER_STREAM"
            return report
        except Exception:
            proc.kill()
            return None

    def _scan_with_trivy(self, image: str) -> Optional[SBOMScanReport]:
        """Execute Trivy image scanner and parse JSON output."""
        if not image or image.startswith("-"):
            logger.warning(f"Refusing to scan container image with leading hyphen/invalid name: {image}")
            return None
        cmd = [self.trivy_bin, "image", "--format", "json", "--quiet", "--timeout", "5s", "--", image]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=6)
        if res.returncode != 0:
            return None

        data = json.loads(res.stdout)
        report = SBOMScanReport(image_name=image, execution_mode="TRIVY_CLI_ENGINE")
        results = data.get("Results", [])

        packages_seen: Set[Tuple[str, str]] = set()

        for target in results:
            target_class = target.get("Class", "")
            target_type = target.get("Type", "")
            vulns = target.get("Vulnerabilities") or []
            pkgs = target.get("Packages") or []

            # Extract packages
            for p in pkgs:
                name = p.get("Name", "")
                ver = p.get("Version", "")
                if (name, ver) not in packages_seen:
                    packages_seen.add((name, ver))
                    report.packages.append(InstalledPackage(
                        name=name,
                        version=ver,
                        package_type=target_type or target_class,
                        license=p.get("License", "unknown")
                    ))

            # Extract CVEs
            for v in vulns:
                cve_id = v.get("VulnerabilityID", "")
                severity = v.get("Severity", "UNKNOWN").upper()
                score = float(v.get("CVSS", {}).get("nvd", {}).get("V3Score", 7.0) or 7.0)
                entry = CVEEntry(
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=score,
                    package=v.get("PkgName", ""),
                    vulnerable_versions=v.get("InstalledVersion", ""),
                    description=v.get("Title") or v.get("Description", "")[:120],
                )
                if severity == "CRITICAL":
                    report.critical_cves.append(entry)
                elif severity == "HIGH":
                    report.high_cves.append(entry)
                elif severity == "MEDIUM":
                    report.medium_cves.append(entry)

        report.total_packages = len(report.packages)
        report.total_cves = len(report.critical_cves) + len(report.high_cves) + len(report.medium_cves)
        return report

    def _unpack_tarfile(self, tf: tarfile.TarFile, source_name: str) -> SBOMScanReport:
        """
        Pure-Python layer-by-layer unpacker.
        Inspects manifest.json, examines layer archives, and extracts package manager records.
        """
        report = SBOMScanReport(image_name=source_name, execution_mode="PURE_PYTHON_OCI")
        manifest_data = None

        # Look for manifest.json
        for member in tf:
            if member.name == "manifest.json":
                f = tf.extractfile(member)
                if f:
                    manifest_data = json.loads(f.read().decode("utf-8"))
                break

        layer_paths = []
        if manifest_data and len(manifest_data) > 0:
            layer_paths = manifest_data[0].get("Layers", [])
        else:
            # Fallback for un-manifested layers
            layer_paths = [m.name for m in tf.getmembers() if m.name.endswith(".tar") or "/layer.tar" in m.name]

        report.layers_inspected = len(layer_paths)
        packages_dict: Dict[str, InstalledPackage] = {}

        for idx, layer_path in enumerate(layer_paths):
            try:
                layer_member = tf.getmember(layer_path)
            except KeyError:
                continue

            layer_file = tf.extractfile(layer_member)
            if not layer_file:
                continue

            try:
                with tarfile.open(fileobj=layer_file, mode="r:*") as layer_tf:
                    for item in layer_tf.getmembers():
                        # A. Debian / Ubuntu Package DB
                        if item.name.endswith("var/lib/dpkg/status"):
                            content = layer_tf.extractfile(item).read().decode("utf-8", errors="replace")
                            report.os_distro = "debian/ubuntu"
                            for pkg in self._parse_dpkg_status(content, layer_idx=idx):
                                packages_dict[pkg.name] = pkg

                        # B. Alpine Linux Package DB
                        elif item.name.endswith("lib/apk/db/installed"):
                            content = layer_tf.extractfile(item).read().decode("utf-8", errors="replace")
                            report.os_distro = "alpine"
                            for pkg in self._parse_apk_installed(content, layer_idx=idx):
                                packages_dict[pkg.name] = pkg

                        # C. Python requirements or site-packages
                        elif item.name.endswith("requirements.txt") or item.name.endswith("Pipfile.lock"):
                            content = layer_tf.extractfile(item).read().decode("utf-8", errors="replace")
                            for pkg in self._parse_requirements_txt(content, layer_idx=idx):
                                packages_dict[pkg.name] = pkg

                        # D. Statically linked Go/Rust ELF Binaries (.go.buildinfo / Cargo Auditable)
                        elif item.isfile() and (
                            item.name.startswith("bin/") or "/bin/" in item.name or
                            item.name.startswith("usr/bin/") or "/usr/bin/" in item.name or
                            item.name.startswith("usr/local/bin/") or "/usr/local/bin/" in item.name or
                            item.name.startswith("app/") or "/app/" in item.name or
                            not "." in Path(item.name).name
                        ):
                            extracted = layer_tf.extractfile(item)
                            if extracted:
                                header = extracted.read(4)
                                if header == b"\x7fELF":
                                    rest = extracted.read(30 * 1024 * 1024)
                                    elf_data = header + rest
                                    elf_pkgs = self._parse_elf_symbols(elf_data, binary_name=Path(item.name).name, layer_idx=idx)
                                    if elf_pkgs:
                                        if not report.os_distro or report.os_distro == "unknown":
                                            report.os_distro = "distroless/static-elf"
                                        for pkg in elf_pkgs:
                                            packages_dict[pkg.name] = pkg

                        # E. RedHat / CentOS / Fedora / Amazon Linux Package DB
                        elif item.name.endswith("var/lib/rpm/rpmdb.sqlite") or item.name.endswith("var/lib/rpm/Packages"):
                            rpm_f = layer_tf.extractfile(item)
                            if rpm_f:
                                rpm_bytes = rpm_f.read()
                                report.os_distro = "rhel/centos/fedora"
                                for pkg in self._parse_rpm_db(rpm_bytes, filename=Path(item.name).name, layer_idx=idx):
                                    packages_dict[pkg.name] = pkg

                        elif item.name.endswith("etc/redhat-release") or item.name.endswith("etc/centos-release") or item.name.endswith("etc/fedora-release"):
                            report.os_distro = "rhel/centos/fedora"

                        # F. Node.js Package Lockfiles
                        elif item.name.endswith("package-lock.json"):
                            lock_f = layer_tf.extractfile(item)
                            if lock_f:
                                content = lock_f.read().decode("utf-8", errors="replace")
                                for pkg in self._parse_package_lock_json(content, layer_idx=idx):
                                    packages_dict[pkg.name] = pkg

                        # G. Java JAR archives & pom.xml
                        elif item.name.endswith(".jar") or item.name.endswith(".war"):
                            extracted_jar = layer_tf.extractfile(item)
                            if extracted_jar:
                                jar_bytes = extracted_jar.read()
                                for pkg in self._parse_java_archive(jar_bytes, jar_name=Path(item.name).name, layer_idx=idx):
                                    packages_dict[pkg.name] = pkg

                        elif item.name.endswith("pom.xml") and not item.name.startswith("META-INF"):
                            pom_f = layer_tf.extractfile(item)
                            if pom_f:
                                content = pom_f.read().decode("utf-8", errors="replace")
                                for pkg in self._parse_java_pom_xml(content, layer_idx=idx):
                                    packages_dict[pkg.name] = pkg
            except Exception:
                continue

        report.packages = list(packages_dict.values())
        report.total_packages = len(report.packages)

        # Match packages against CVE knowledge catalog
        self._correlate_cves(report)
        return report

    @staticmethod
    def _parse_dpkg_status(content: str, layer_idx: int) -> List[InstalledPackage]:
        packages = []
        for block in content.split("\n\n"):
            pkg_m = re.search(r"^Package: (.+)$", block, re.M)
            ver_m = re.search(r"^Version: (.+)$", block, re.M)
            arch_m = re.search(r"^Architecture: (.+)$", block, re.M)
            status_m = re.search(r"^Status: (.+)$", block, re.M)

            if pkg_m and ver_m:
                status = status_m.group(1) if status_m else "installed"
                if "installed" in status:
                    packages.append(InstalledPackage(
                        name=pkg_m.group(1).strip(),
                        version=ver_m.group(1).strip(),
                        architecture=arch_m.group(1).strip() if arch_m else "amd64",
                        package_type="deb",
                        layer_index=layer_idx
                    ))
        return packages

    @staticmethod
    def _parse_apk_installed(content: str, layer_idx: int) -> List[InstalledPackage]:
        packages = []
        for block in content.split("\n\n"):
            lines = block.splitlines()
            name, ver, lic = None, None, "unknown"
            for line in lines:
                if line.startswith("P:"):
                    name = line[2:].strip()
                elif line.startswith("V:"):
                    ver = line[2:].strip()
                elif line.startswith("L:"):
                    lic = line[2:].strip()
            if name and ver:
                packages.append(InstalledPackage(
                    name=name,
                    version=ver,
                    architecture="musl",
                    package_type="apk",
                    layer_index=layer_idx,
                    license=lic
                ))
        return packages

    @staticmethod
    def _parse_requirements_txt(content: str, layer_idx: int) -> List[InstalledPackage]:
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.match(r"^([A-Za-z0-9_-]+)==([A-Za-z0-9._-]+)", line)
                if m:
                    packages.append(InstalledPackage(
                        name=m.group(1),
                        version=m.group(2),
                        package_type="python",
                        layer_index=layer_idx
                    ))
        return packages

    @staticmethod
    def _parse_rpm_db(data: bytes, filename: str = "rpmdb.sqlite", layer_idx: int = 0) -> List[InstalledPackage]:
        packages = []
        if not data:
            return packages

        # Case 1: Modern RPM SQLite database (Fedora, RHEL 8+, Amazon Linux 2023)
        if b"SQLite format 3" in data[:16]:
            try:
                con = sqlite3.connect(":memory:")
                con.deserialize(data)
                cur = con.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row[0] for row in cur.fetchall()}
                if "Packages" in tables:
                    try:
                        cur.execute("SELECT name, version, release, arch FROM Packages")
                        for name, ver, rel, arch in cur.fetchall():
                            full_ver = f"{ver}-{rel}" if rel else str(ver)
                            packages.append(InstalledPackage(
                                name=str(name),
                                version=str(full_ver),
                                architecture=str(arch) if arch else "amd64",
                                package_type="rpm",
                                layer_index=layer_idx
                            ))
                    except Exception:
                        pass
                con.close()
            except Exception:
                pass

        # Case 2: Legacy RPM Berkeley DB or binary string fallback
        if not packages:
            matches = re.findall(rb'([a-zA-Z0-9_\-\+]+)-([0-9]+(?:\.[0-9a-zA-Z_\-]+)+)-([0-9]+(?:\.[0-9a-zA-Z_\-]+)*)\.([a-zA-Z0-9_]+)', data)
            seen_rpm = set()
            for name_b, ver_b, rel_b, arch_b in matches[:500]:
                try:
                    name = name_b.decode("utf-8", errors="ignore")
                    ver = f"{ver_b.decode('utf-8')}-{rel_b.decode('utf-8')}"
                    arch = arch_b.decode("utf-8", errors="ignore")
                    if arch in ("x86_64", "noarch", "aarch64", "i686", "arm64", "amd64") and len(name) > 1 and name not in seen_rpm:
                        seen_rpm.add(name)
                        packages.append(InstalledPackage(
                            name=name,
                            version=ver,
                            architecture=arch,
                            package_type="rpm",
                            layer_index=layer_idx
                        ))
                except Exception:
                    continue

        return packages

    @staticmethod
    def _parse_package_lock_json(content: str, layer_idx: int = 0) -> List[InstalledPackage]:
        packages = []
        try:
            data = json.loads(content)
        except Exception:
            return packages

        seen = set()
        # npm lockfile v2 / v3
        if "packages" in data and isinstance(data["packages"], dict):
            for path, info in data["packages"].items():
                if not path or not isinstance(info, dict):
                    continue
                name = info.get("name")
                if not name:
                    parts = path.split("node_modules/")
                    if len(parts) > 1 and parts[-1]:
                        name = parts[-1]
                version = info.get("version", "")
                if name and version and name not in seen:
                    seen.add(name)
                    packages.append(InstalledPackage(
                        name=name,
                        version=version,
                        package_type="node",
                        layer_index=layer_idx,
                        license=info.get("license", "unknown")
                    ))

        # npm lockfile v1
        if not packages and "dependencies" in data and isinstance(data["dependencies"], dict):
            for name, info in data["dependencies"].items():
                if isinstance(info, dict):
                    ver = info.get("version", "")
                    if ver and name not in seen:
                        seen.add(name)
                        packages.append(InstalledPackage(
                            name=name,
                            version=ver,
                            package_type="node",
                            layer_index=layer_idx
                        ))

        return packages

    @staticmethod
    def _parse_java_archive(data: bytes, jar_name: str = "app.jar", layer_idx: int = 0) -> List[InstalledPackage]:
        packages = []
        if not data or len(data) < 30:
            return packages
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for zname in zf.namelist():
                    try:
                        info = zf.getinfo(zname)
                        if info.file_size > 10 * 1024 * 1024:
                            continue  # Decompression bomb guard
                    except Exception:
                        continue
                    if zname.endswith("pom.properties"):
                        try:
                            prop_text = zf.read(zname).decode("utf-8", errors="replace")
                            group, artifact, version = "", "", ""
                            for line in prop_text.splitlines():
                                line = line.strip()
                                if line.startswith("groupId="):
                                    group = line.split("=", 1)[1].strip()
                                elif line.startswith("artifactId="):
                                    artifact = line.split("=", 1)[1].strip()
                                elif line.startswith("version="):
                                    version = line.split("=", 1)[1].strip()
                            if artifact and version:
                                full_name = f"{group}:{artifact}" if group else artifact
                                packages.append(InstalledPackage(
                                    name=full_name,
                                    version=version,
                                    package_type="java",
                                    layer_index=layer_idx
                                ))
                        except Exception:
                            pass
        except Exception:
            pass
        return packages

    @staticmethod
    def _parse_java_pom_xml(content: str, layer_idx: int = 0) -> List[InstalledPackage]:
        packages = []
        art_m = re.search(r"<artifactId>([^<]+)</artifactId>", content)
        ver_m = re.search(r"<version>([^<]+)</version>", content)
        grp_m = re.search(r"<groupId>([^<]+)</groupId>", content)
        if art_m and ver_m:
            grp = grp_m.group(1).strip() if grp_m else ""
            art = art_m.group(1).strip()
            ver = ver_m.group(1).strip()
            name = f"{grp}:{art}" if grp else art
            packages.append(InstalledPackage(
                name=name,
                version=ver,
                package_type="java",
                layer_index=layer_idx
            ))
        return packages

    @classmethod
    def _parse_elf_symbols(cls, data: bytes, binary_name: str = "binary", layer_idx: int = 0) -> List[InstalledPackage]:
        """
        Parses statically linked Go and Rust ELF binaries in distroless/scratch containers:
        1. Go ELF binaries: parses .go.buildinfo section and embedded module dependencies
           (path, mod, dep, build flags) and Go compiler runtime version.
        2. Rust ELF binaries: parses cargo-auditable dependency JSON tables and rustc versions.
        """
        packages: List[InstalledPackage] = []
        if not data or len(data) < 16 or not data.startswith(b"\x7fELF"):
            return packages

        # Determine architecture from ELF header byte 18-19 (e_machine)
        arch = "amd64"
        if len(data) >= 20:
            machine = int.from_bytes(data[18:20], byteorder="little")
            if machine == 0x3E:   # EM_X86_64
                arch = "amd64"
            elif machine == 0xB7: # EM_AARCH64
                arch = "arm64"
            elif machine == 0x03: # EM_386
                arch = "386"
            elif machine == 0x28: # EM_ARM
                arch = "arm"

        # --- A. Go Build Info (.go.buildinfo) Module Parsing ---
        has_go_magic = b"\xff Go buildinf:" in data or b"Go buildinf:" in data
        go_mod_match = re.search(rb'(path\t[^\x00]+)', data)
        if go_mod_match or has_go_magic:
            raw_text = ""
            if go_mod_match:
                raw_text = go_mod_match.group(1).decode("utf-8", errors="ignore")
            else:
                dep_matches = re.findall(rb'(?:mod|dep)\t[^\n\x00]+', data)
                if dep_matches:
                    raw_text = "\n".join(m.decode("utf-8", errors="ignore") for m in dep_matches)

            for line in raw_text.splitlines():
                line = line.strip()
                if line.startswith("dep\t"):
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        packages.append(InstalledPackage(
                            name=parts[1].strip(),
                            version=parts[2].strip(),
                            architecture=arch,
                            package_type="go-module",
                            layer_index=layer_idx,
                            license="unknown"
                        ))
                elif line.startswith("mod\t"):
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        packages.append(InstalledPackage(
                            name=parts[1].strip(),
                            version=parts[2].strip(),
                            architecture=arch,
                            package_type="go-module",
                            layer_index=layer_idx,
                            license="unknown"
                        ))

            # Detect Go compiler version (e.g. go1.22.1)
            go_ver_match = re.search(rb'(go1\.[0-9]+(?:\.[0-9]+)?)', data)
            if go_ver_match:
                packages.append(InstalledPackage(
                    name="golang",
                    version=go_ver_match.group(1).decode("utf-8", errors="ignore"),
                    architecture=arch,
                    package_type="go-runtime",
                    layer_index=layer_idx
                ))

        # --- B. Rust Cargo-Auditable Parsing ---
        cargo_match = re.search(rb'(\{"packages":\s*\[.*?\]\})', data, re.DOTALL)
        if cargo_match:
            try:
                cargo_data = json.loads(cargo_match.group(1).decode("utf-8", errors="ignore"))
                for p in cargo_data.get("packages", []):
                    p_name = p.get("name")
                    p_ver = p.get("version")
                    if p_name and p_ver:
                        packages.append(InstalledPackage(
                            name=p_name,
                            version=str(p_ver),
                            architecture=arch,
                            package_type="rust-crate",
                            layer_index=layer_idx,
                            license=p.get("license", "unknown")
                        ))
            except Exception:
                pass

        # Detect rustc compiler version (e.g. rustc 1.77.0)
        rustc_match = re.search(rb'(rustc\s+1\.[0-9]+(?:\.[0-9]+)?)', data)
        if rustc_match:
            parts = rustc_match.group(1).decode("utf-8", errors="ignore").split()
            if len(parts) == 2:
                packages.append(InstalledPackage(
                    name="rustc",
                    version=parts[1],
                    architecture=arch,
                    package_type="rust-runtime",
                    layer_index=layer_idx
                ))

        # Standalone native ELF executable fallback
        if not packages and data.startswith(b"\x7fELF"):
            packages.append(InstalledPackage(
                name=binary_name,
                version="static-elf",
                architecture=arch,
                package_type="static-binary",
                layer_index=layer_idx
            ))

        return packages

    @staticmethod
    def _correlate_cves(report: SBOMScanReport):
        """Match unpacked packages against CVE knowledge database & SQLite cache."""
        seen_cves = set()
        cves = lookup_image_cves(report.image_name)

        # Also query embedded SQLite CVE database for exact package matches
        try:
            try:
                from .cve import CVEDatabaseEngine
            except ImportError:
                try:
                    from cve import CVEDatabaseEngine
                except ImportError:
                    from scanners.cve_sync_engine import CVEDatabaseEngine
            db_engine = CVEDatabaseEngine()
            for p in report.packages:
                if hasattr(db_engine, "check_package_vulnerability"):
                    extra_cves = db_engine.check_package_vulnerability(p.name, p.version, report.os_distro)
                else:
                    extra_cves = db_engine.query_package_cves(p.name)
                cves.extend(extra_cves)
        except Exception:
            pass

        for cve in cves:
            if cve.cve_id in seen_cves:
                continue
            # Check if vulnerable package is actually present in unpacked SBOM
            is_present = any(p.name.lower() == cve.package.lower() for p in report.packages) or (report.total_packages == 0)
            if is_present:
                seen_cves.add(cve.cve_id)
                if cve.severity == "CRITICAL":
                    report.critical_cves.append(cve)
                elif cve.severity == "HIGH":
                    report.high_cves.append(cve)
                elif cve.severity == "MEDIUM":
                    report.medium_cves.append(cve)

        report.total_cves = len(report.critical_cves) + len(report.high_cves) + len(report.medium_cves)


def print_sbom_report(report: SBOMScanReport):
    print("=" * 85)
    print("      DEEP CONTAINER IMAGE LAYER & OS PACKAGE UNPACKING AUDIT")
    print("=" * 85)
    print(f"Target Image      : {report.image_name}")
    print(f"Execution Engine  : {report.execution_mode} ({report.scan_latency_ms:.1f} ms)")
    print(f"Operating System  : {report.os_distro.upper()} | Layers Inspected: {report.layers_inspected}")
    print(f"Discovered Packages: {report.total_packages} (SBOM Entries)")
    print(f"Vulnerabilities   : {len(report.critical_cves)} Critical | {len(report.high_cves)} High | {len(report.medium_cves)} Medium")
    print("-" * 85)

    if report.packages:
        print("SAMPLE UNPACKED SOFTWARE BILL OF MATERIALS (SBOM):")
        print(f"{'Package Name':<28} | {'Installed Version':<18} | {'Type':<8} | {'Layer'}")
        print("-" * 85)
        for p in report.packages[:8]:
            print(f"{p.name:<28} | {p.version:<18} | {p.package_type:<8} | Layer {p.layer_index}")
        if len(report.packages) > 8:
            print(f"... [{len(report.packages) - 8} additional packages cataloged]")

    if report.critical_cves or report.high_cves:
        print("\nDEEP MATCHED VULNERABILITIES:")
        print(f"{'CVE Identifier':<18} | {'Severity':<10} | {'Package':<16} | {'Description'}")
        print("-" * 85)
        for c in (report.critical_cves + report.high_cves)[:5]:
            print(f"{c.cve_id:<18} | {c.severity:<10} | {c.package:<16} | {c.description[:35]}")
    print("=" * 85 + "\n")


def validate_safe_url(url: str, allow_private: bool = False) -> None:
    """
    Validates URL to defend against Server-Side Request Forgery (SSRF).
    Enforces HTTPS scheme and rejects requests targeting RFC 1918 private IPs,
    loopback addresses, link-local metadata endpoints (e.g. AWS/GCP/Azure 169.254.169.254),
    and internal domain names.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"SSRF Protection: Insecure scheme '{parsed.scheme}'. Only HTTPS is permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("SSRF Protection: Missing or invalid hostname in URL.")

    lowered_host = hostname.lower()
    blocked_hosts = {
        "localhost", "metadata.google.internal", "instance-data",
        "metadata.packet.net", "169.254.169.254", "metadata"
    }
    if not allow_private and lowered_host in blocked_hosts:
        raise ValueError(f"SSRF Protection: Restricted host '{hostname}' is blocked.")

    # Check direct IP literals
    try:
        ip = ipaddress.ip_address(lowered_host)
        if not allow_private and (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or str(ip) == "169.254.169.254"
        ):
            raise ValueError(f"SSRF Protection: Direct IP '{ip}' is in a private/restricted range.")
    except ValueError as ve:
        if "SSRF Protection" in str(ve):
            raise
        # Host is a domain name, resolve via DNS
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip_str = sockaddr[0]
                resolved_ip = ipaddress.ip_address(ip_str)
                if not allow_private and (
                    resolved_ip.is_loopback
                    or resolved_ip.is_private
                    or resolved_ip.is_link_local
                    or resolved_ip.is_reserved
                    or resolved_ip.is_multicast
                    or str(resolved_ip) == "169.254.169.254"
                ):
                    raise ValueError(
                        f"SSRF Protection: Host '{hostname}' resolves to private/restricted IP '{ip_str}'."
                    )
        except socket.gaierror:
            pass


class OciRegistryClient:
    """
    Pure-Python OCI / Docker Registry v2 Client.
    Fetches image manifests and configuration metadata directly over HTTPS
    without requiring a running Docker daemon.
    """

    @staticmethod
    def parse_image_reference(image: str) -> Tuple[str, str, str]:
        """
        Parses image reference into (registry, repository, tag_or_digest).
        e.g. 'quay.io/coreos/etcd:v3.5.0' -> ('quay.io', 'coreos/etcd', 'v3.5.0')
        e.g. 'nginx:1.21' -> ('registry-1.docker.io', 'library/nginx', '1.21')
        """
        tag = "latest"
        digest = None
        if "@" in image:
            image, digest = image.split("@", 1)
        if ":" in image:
            image, tag = image.split(":", 1)

        parts = image.split("/")
        if len(parts) == 1:
            registry = "registry-1.docker.io"
            repo = f"library/{parts[0]}"
        elif "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
            registry = parts[0]
            repo = "/".join(parts[1:])
        else:
            registry = "registry-1.docker.io"
            repo = "/".join(parts)

        ref = digest if digest else tag
        return registry, repo, ref

    def fetch_manifest(self, image: str, timeout: int = 5, allow_private: bool = False) -> Dict[str, Any]:
        """Fetch OCI v2 or Docker v2 manifest from registry over HTTPS with SSRF protection."""
        registry, repo, ref = self.parse_image_reference(image)
        url = f"https://{registry}/v2/{repo}/manifests/{ref}"
        validate_safe_url(url, allow_private=allow_private)

        headers = {
            "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
        }

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 401 and "Www-Authenticate" in e.headers:
                auth_header = e.headers["Www-Authenticate"]
                token = self._fetch_bearer_token(auth_header, repo, timeout=timeout, allow_private=allow_private)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    auth_req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(auth_req, timeout=timeout) as resp2:
                        return json.loads(resp2.read().decode("utf-8"))
            raise e

    @staticmethod
    def _fetch_bearer_token(auth_header: str, repo: str, timeout: int = 5, allow_private: bool = False) -> Optional[str]:
        """Fetch bearer token from OAuth2 / Token service with SSRF validation."""
        realm_m = re.search(r'realm="([^"]+)"', auth_header)
        service_m = re.search(r'service="([^"]+)"', auth_header)
        if not realm_m:
            return None
        realm = realm_m.group(1)
        params = {"scope": f"repository:{repo}:pull"}
        if service_m:
            params["service"] = service_m.group(1)
        token_url = f"{realm}?{urllib.parse.urlencode(params)}"
        validate_safe_url(token_url, allow_private=allow_private)
        try:
            req = urllib.request.Request(token_url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("token") or data.get("access_token")
        except Exception:
            return None


def main():
    parser = argparse.ArgumentParser(description="Hybrid Deep Container Layer & OS Package Scanner")
    parser.add_argument("--image", default="nginx:1.14.2", help="Container image name to scan")
    parser.add_argument("--tarball", default=None, help="Local OCI/Docker image tarball archive")
    parser.add_argument("--output", default=None, help="Save SBOM and vulnerability report as JSON")
    parser.add_argument("--cyclonedx", default=None, help="Export CycloneDX v1.5 JSON SBOM to file")
    parser.add_argument("--spdx", default=None, help="Export SPDX v2.3 JSON SBOM to file")
    args = parser.parse_args()

    scanner = HybridContainerLayerScanner()

    if args.tarball:
        report = scanner.scan_tarball(args.tarball)
    else:
        report = scanner.scan_image(args.image)

    print_sbom_report(report)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"✓ Deep SBOM report saved to: {out_p}")

    if args.cyclonedx:
        cdx_p = Path(args.cyclonedx)
        cdx_p.parent.mkdir(parents=True, exist_ok=True)
        cdx_p.write_text(json.dumps(report.to_cyclonedx(), indent=2))
        print(f"✓ CycloneDX v1.5 JSON SBOM saved to: {cdx_p}")

    if args.spdx:
        spdx_p = Path(args.spdx)
        spdx_p.parent.mkdir(parents=True, exist_ok=True)
        spdx_p.write_text(json.dumps(report.to_spdx(), indent=2))
        print(f"✓ SPDX v2.3 JSON SBOM saved to: {spdx_p}")


if __name__ == "__main__":
    main()
