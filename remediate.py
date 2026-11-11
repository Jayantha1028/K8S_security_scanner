#!/usr/bin/env python3
"""
auto_remediate.py
=================
Automated Kubernetes Security Remediation Engine.

Applies NSA/CISA and CIS Benchmark v2.0 hardening rules across any Kubernetes workload:
- Pod
- Deployment
- DaemonSet
- StatefulSet
- Job / CronJob

Functions:
- remediate_workload_dict: In-memory dictionary hardening (used by Admission Controller)
- remediate_yaml_string: In-memory YAML string hardening (used by Web Console & CLI)
- remediate_manifest: File-based hardening with optional unified diff
"""

import argparse
import copy
import difflib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml


def _get_pod_spec(workload_dict: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Retrieve the mutable pod spec dictionary and path prefix based on workload kind."""
    kind = workload_dict.get("kind", "")
    if kind == "Pod":
        return workload_dict.setdefault("spec", {}), "spec"
    elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"):
        spec = workload_dict.setdefault("spec", {})
        template = spec.setdefault("template", {})
        return template.setdefault("spec", {}), "spec.template.spec"
    elif kind == "CronJob":
        spec = workload_dict.setdefault("spec", {})
        job_template = spec.setdefault("jobTemplate", {})
        j_spec = job_template.setdefault("spec", {})
        template = j_spec.setdefault("template", {})
        return template.setdefault("spec", {}), "spec.jobTemplate.spec.template.spec"
    return None, ""


def remediate_workload_dict(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Apply least-privilege security context fixes to a Kubernetes workload dictionary in memory.
    Features:
    - Eliminates host namespaces (hostNetwork, hostPID, hostIPC)
    - Enforces Pod-level runAsNonRoot (UID 10001) & RuntimeDefault seccompProfile
    - Disables privileged containers & allowPrivilegeEscalation
    - Enforces readOnlyRootFilesystem with Safe Volume Padding (ephemeral scratchpads)
    - Respects Workload Capability Whitelist Annotations (sec.k8s.io/allowed-caps)
    - Enforces CPU & Memory ceilings to prevent noisy neighbor DoS
    Returns: (hardened_dict, list_of_changes_applied)
    """
    if not isinstance(data, dict):
        return data, []

    hardened = copy.deepcopy(data)
    pod_spec, prefix = _get_pod_spec(hardened)
    if pod_spec is None:
        return data, []

    changes_applied = []

    # 0. Capability Whitelist Annotation Extraction
    top_annotations = hardened.get("metadata", {}).get("annotations", {}) or {}
    template_annotations = {}
    if "spec" in hardened and isinstance(hardened["spec"], dict):
        template_annotations = hardened["spec"].get("template", {}).get("metadata", {}).get("annotations", {}) or {}

    def _extract_whitelist(ann: Dict[str, Any], container_name: str) -> Optional[Set[str]]:
        for key in (
            f"sec.k8s.io/allowed-caps.{container_name}",
            f"security.k8s.io/allowed-capabilities.{container_name}",
            "sec.k8s.io/allowed-caps",
            "security.k8s.io/allowed-capabilities",
            "k8s-sec.io/allowed-capabilities",
        ):
            if key in ann:
                val = ann[key]
                if isinstance(val, str):
                    try:
                        parsed = json.loads(val)
                        if isinstance(parsed, list):
                            return {str(c).strip().upper() for c in parsed if str(c).strip()}
                    except Exception:
                        pass
                    return {c.strip().upper() for c in re.split(r"[,\s]+", val) if c.strip()}
                elif isinstance(val, list):
                    return {str(c).strip().upper() for c in val if str(c).strip()}
        return None

    # 1. Eliminate host namespaces
    if pod_spec.pop("hostNetwork", None):
        changes_applied.append("Disabled hostNetwork")
    if pod_spec.pop("hostPID", None):
        changes_applied.append("Disabled hostPID")
    if pod_spec.pop("hostIPC", None):
        changes_applied.append("Disabled hostIPC")

    # 2. Pod-level security context
    pod_sec = pod_spec.setdefault("securityContext", {})
    if not pod_sec.get("runAsNonRoot"):
        pod_sec["runAsNonRoot"] = True
        pod_sec["runAsUser"] = 10001
        pod_sec["runAsGroup"] = 10001
        changes_applied.append("Enforced runAsNonRoot (UID 10001)")

    if "seccompProfile" not in pod_sec:
        pod_sec["seccompProfile"] = {"type": "RuntimeDefault"}
        changes_applied.append("Applied RuntimeDefault seccomp profile")

    # 3. Container-level hardening & Safe Volume Padding
    containers = pod_spec.get("containers", [])
    needed_volumes: Dict[str, Dict[str, Any]] = {}

    pad_enabled = (
        top_annotations.get("sec.k8s.io/safe-volume-padding", "true").lower() != "false"
        and template_annotations.get("sec.k8s.io/safe-volume-padding", "true").lower() != "false"
    )

    for c in containers:
        c_name = c.get("name", "container")
        c_sec = c.setdefault("securityContext", {})
        if c_sec.get("privileged"):
            c_sec["privileged"] = False
            changes_applied.append(f"Revoked privileged container access on '{c_name}'")
        if c_sec.get("allowPrivilegeEscalation") is not False:
            c_sec["allowPrivilegeEscalation"] = False
            changes_applied.append(f"Disabled allowPrivilegeEscalation on '{c_name}'")

        was_readonly = c_sec.get("readOnlyRootFilesystem", False)
        if not was_readonly:
            c_sec["readOnlyRootFilesystem"] = True
            changes_applied.append(f"Enforced readOnlyRootFilesystem on '{c_name}'")

        # Safe Volume Padding: ensure scratchpads exist without duplicate mountPaths
        if pad_enabled:
            volume_mounts = c.setdefault("volumeMounts", [])
            existing_mount_paths = {
                str(m.get("mountPath", "")).rstrip("/")
                for m in volume_mounts if isinstance(m, dict) and m.get("mountPath")
            }
            target_padding = [
                ("/tmp", "tmp-storage"),
                ("/var/run", "var-run"),
            ]
            for m_path, v_name in target_padding:
                if m_path.rstrip("/") not in existing_mount_paths:
                    volume_mounts.append({"name": v_name, "mountPath": m_path})
                    existing_mount_paths.add(m_path.rstrip("/"))
                    needed_volumes[v_name] = {"name": v_name, "emptyDir": {}}

        # Capability handling with Workload Whitelist Support
        caps = c_sec.setdefault("capabilities", {})
        whitelist = _extract_whitelist(template_annotations, c_name) or _extract_whitelist(top_annotations, c_name)

        has_any_whitelist = any(
            k.startswith("sec.k8s.io/allowed-caps") or k.startswith("security.k8s.io/allowed-capabilities")
            for k in list(top_annotations.keys()) + list(template_annotations.keys())
        )
        if whitelist is None and has_any_whitelist:
            whitelist = set()

        existing_add = caps.get("add", [])
        if whitelist is not None:
            # Whitelist mode: preserve whitelisted capabilities, drop dangerous capabilities
            allowed_add = [c_item for c_item in existing_add if c_item.upper() in whitelist]
            dropped_add = [c_item for c_item in existing_add if c_item.upper() not in whitelist]
            caps["drop"] = ["ALL"]
            if allowed_add:
                caps["add"] = sorted(list(set(allowed_add)))
                changes_applied.append(
                    f"Preserved whitelisted capability(ies) {', '.join(caps['add'])} on '{c_name}' via sec.k8s.io/allowed-caps"
                )
            else:
                caps.pop("add", None)
            if dropped_add:
                changes_applied.append(f"Dropped unwhitelisted capability(ies) {', '.join(dropped_add)} on '{c_name}'")
            changes_applied.append(f"Dropped ALL Linux capabilities on '{c_name}'")
        else:
            # Default least-privilege mode: drop ALL, remove NET_ADMIN / unneeded additions
            caps["drop"] = ["ALL"]
            if "NET_ADMIN" in caps.get("add", []):
                caps["add"].remove("NET_ADMIN")
                changes_applied.append(f"Removed risky capability NET_ADMIN on '{c_name}'")
            if not caps.get("add"):
                caps.pop("add", None)
            changes_applied.append(f"Dropped ALL Linux capabilities on '{c_name}'")

        # Clean hostPort if present
        for port in c.get("ports", []):
            if "hostPort" in port:
                port.pop("hostPort")
                changes_applied.append(f"Removed hostPort binding on '{c_name}'")

        # Ensure resource limits exist
        res = c.setdefault("resources", {})
        if "limits" not in res:
            res["limits"] = {"cpu": "250m", "memory": "128Mi"}
            res["requests"] = {"cpu": "50m", "memory": "64Mi"}
            changes_applied.append(f"Configured CPU & memory resource limits on '{c_name}'")

    # Safe volume registration without duplicates
    if needed_volumes:
        vols = pod_spec.setdefault("volumes", [])
        existing_vol_names = {v.get("name") for v in vols if isinstance(v, dict)}
        for v_name, v_def in needed_volumes.items():
            if v_name not in existing_vol_names:
                vols.append(v_def)
                existing_vol_names.add(v_name)

    return hardened, changes_applied


def remediate_yaml_string(yaml_text: str) -> Tuple[str, List[str]]:
    """Harden raw YAML string in-memory without writing to disk."""
    if len(yaml_text.encode("utf-8", errors="ignore")) > 10 * 1024 * 1024:
        return yaml_text, ["Error: YAML manifest exceeds maximum 10MB safety limit"]
    try:
        data = yaml.safe_load(yaml_text)
    except Exception:
        return yaml_text, []

    hardened_dict, changes = remediate_workload_dict(data)
    new_yaml = yaml.dump(hardened_dict, sort_keys=False)
    return new_yaml, changes


def format_patch_diff(original_text: str, remediated_text: str, filename: str = "manifest.yaml") -> str:
    """Format unified diff between original and remediated manifest."""
    diff = difflib.unified_diff(
        original_text.splitlines(keepends=True),
        remediated_text.splitlines(keepends=True),
        fromfile=f"original/{filename}",
        tofile=f"remediated/{filename}",
    )
    return "".join(diff)


# Convenience alias for in-memory auto remediation
auto_remediate_manifest = remediate_yaml_string


def remediate_manifest(manifest_path: str, output_path: Optional[str] = None, show_diff: bool = True):
    """File-based CLI wrapper with unified diff output."""
    path = Path(manifest_path)
    if not path.is_file():
        raise SystemExit(f"File not found: {manifest_path}")

    raw_text = path.read_text(encoding="utf-8")
    new_yaml, changes_applied = remediate_yaml_string(raw_text)

    if not changes_applied:
        print(f"Skipping {manifest_path}: No applicable workload spec found for auto-remediation.")
        return

    print(f"\n=======================================================")
    print(f"   AUTO-REMEDIATION REPORT: {path.name}")
    print(f"=======================================================")
    print(f"Applied {len(changes_applied)} Security Fixes:")
    for change in sorted(set(changes_applied)):
        print(f"  ✓ {change}")

    if show_diff:
        print("\nUnified Hardening Diff:")
        diff = difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            new_yaml.splitlines(keepends=True),
            fromfile=f"original/{path.name}",
            tofile=f"remediated/{path.name}",
        )
        sys.stdout.writelines(diff)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(new_yaml, encoding="utf-8")
        print(f"\nRemediated manifest written to: {out_p}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Kubernetes Security Remediation Engine")
    parser.add_argument("manifest", help="Path to input YAML manifest")
    parser.add_argument("--output", "-o", default=None, help="Path to write remediated YAML")
    parser.add_argument("--diff", action="store_true", default=True, help="Display unified diff")
    args = parser.parse_args()

    remediate_manifest(args.manifest, output_path=args.output, show_diff=args.diff)
