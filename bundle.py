#!/usr/bin/env python3
"""
native_scanner/bundle.py
========================
Standalone Air-Gapped Sovereign Security Bundle Manager for k8s-native-scanner.
Zero external dependencies, pure standard library implementation.
"""

from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import shutil
import tarfile
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("NativeAirgapBundle")

BUNDLE_SPEC_VERSION = "1.0.0"
MAX_MEMBER_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB max per single file
MAX_TOTAL_EXTRACT_BYTES = 500 * 1024 * 1024  # 500 MB max bundle decompression (Zip/Tar bomb guard)


class BundleSecurityError(Exception):
    """Raised when bundle archive violates path traversal or cryptographic integrity."""
    pass


def compute_file_sha256(filepath: Path) -> str:
    if not filepath.exists() or not filepath.is_file():
        return ""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StandaloneBundleManager:
    """Zero-dependency Air-Gapped Bundle Exporter and Importer for native scanner."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir).resolve() if base_dir else Path.cwd()

    def export_rules_and_data(
        self,
        output_path: Path,
        rules_dir: Optional[Path] = None,
        cve_db_path: Optional[Path] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Exports standalone declarative rules and offline threat databases."""
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        files_to_pack: List[Tuple[Path, str]] = []
        checksums: Dict[str, str] = {}

        if rules_dir and Path(rules_dir).exists():
            for r in Path(rules_dir).glob("*.yaml"):
                rel_path = f"rules/{r.name}"
                files_to_pack.append((r, rel_path))
                checksums[rel_path] = compute_file_sha256(r)

        if cve_db_path and Path(cve_db_path).exists():
            rel_path = "data/cve_database.sqlite"
            files_to_pack.append((Path(cve_db_path), rel_path))
            checksums[rel_path] = compute_file_sha256(Path(cve_db_path))

        manifest = {
            "bundle_spec_version": BUNDLE_SPEC_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "generator": "k8s-native-scanner-bundle/1.0",
            "file_count": len(files_to_pack),
            "checksums": checksums,
            "metadata": custom_metadata or {},
        }

        with tarfile.open(output_path, "w:gz") as tar:
            manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name="bundle_manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = int(datetime.now(timezone.utc).timestamp())
            tar.addfile(info, BytesIO(manifest_bytes))

            for src, rel in files_to_pack:
                tar.add(str(src), arcname=rel)

        manifest["bundle_path"] = str(output_path)
        manifest["bundle_size_kb"] = round(output_path.stat().st_size / 1024, 2)
        manifest["bundle_sha256"] = compute_file_sha256(output_path)
        return manifest

    def verify_bundle(self, bundle_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
        """Verifies tar integrity and SHA256 checksums."""
        bundle_path = Path(bundle_path).resolve()
        if not bundle_path.exists():
            return False, f"File {bundle_path} does not exist", {}

        try:
            with tarfile.open(bundle_path, "r:*") as tar:
                try:
                    manifest_member = tar.getmember("bundle_manifest.json")
                except KeyError:
                    return False, "Missing bundle_manifest.json", {}

                mf = tar.extractfile(manifest_member)
                if not mf:
                    return False, "Cannot read manifest", {}

                manifest = json.loads(mf.read().decode("utf-8"))
                checksums = manifest.get("checksums", {})

                for member in tar.getmembers():
                    if member.name == "bundle_manifest.json" or member.isdir():
                        continue
                    if ".." in Path(member.name).parts or member.name.startswith("/"):
                        return False, f"Malicious path traversal: {member.name}", {}
                    if member.name not in checksums:
                        return False, f"Untracked member: {member.name}", {}

                    f = tar.extractfile(member)
                    if not f:
                        return False, f"Cannot extract member: {member.name}", {}
                    if compute_bytes_sha256(f.read()) != checksums[member.name]:
                        return False, f"Checksum mismatch on {member.name}", {}

            return True, "Bundle verified successfully", manifest
        except Exception as e:
            return False, str(e), {}

    def import_bundle(self, bundle_path: Path, target_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Safely imports bundle files into destination directory with Tar Bomb and Path Traversal defense."""
        dest = Path(target_dir).resolve() if target_dir else self.base_dir
        valid, msg, manifest = self.verify_bundle(bundle_path)
        if not valid:
            raise ValueError(f"Bundle verification failed: {msg}")

        imported = []
        total_extracted_bytes = 0

        with tarfile.open(bundle_path, "r:*") as tar:
            for member in tar.getmembers():
                if member.name == "bundle_manifest.json" or member.isdir():
                    continue

                # Block symlink / hardlink attacks
                if member.issym() or member.islnk():
                    raise BundleSecurityError(f"Symlinks/hardlinks not permitted in sovereign bundle: {member.name}")

                # Tar Bomb protection
                if member.size > MAX_MEMBER_SIZE_BYTES:
                    raise BundleSecurityError(f"Bundle member {member.name} exceeds max size ({member.size} > {MAX_MEMBER_SIZE_BYTES})")
                total_extracted_bytes += member.size
                if total_extracted_bytes > MAX_TOTAL_EXTRACT_BYTES:
                    raise BundleSecurityError(f"Total extracted bytes exceed decompression limit ({MAX_TOTAL_EXTRACT_BYTES} bytes)")

                out_path = (dest / member.name).resolve()
                if not out_path.is_relative_to(dest):
                    raise BundleSecurityError(f"Path traversal blocked: {member.name}")

                out_path.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(out_path.parent, 0o700)

                with open(out_path, "wb") as f_out:
                    shutil.copyfileobj(tar.extractfile(member), f_out)
                os.chmod(out_path, 0o600)
                imported.append(str(out_path))

        return {
            "status": "SUCCESS",
            "imported_files": imported,
            "manifest": manifest,
        }
