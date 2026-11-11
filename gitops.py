#!/usr/bin/env python3
"""
native_scanner/gitops.py
========================
Shift-Left GitOps Auto-Remediation PR Bot & Kustomize Strategic Patch Overlay Generator.

Eliminates the "GitOps Configuration Drift War" where mutating admission webhooks alter
live objects in etcd, triggering ArgoCD and Flux reconciliation fighting loops.

Key Features:
1. Shift-Left Manifest Hardening:
   - Scans Git repositories or manifest trees.
   - Calculates unified diffs and score enhancements (e.g. 13.2 -> 88.0).
2. GitOps PR / MR Formatter:
   - Formats complete GitHub Pull Request and GitLab Merge Request Markdown bodies
     with executive scorecards, CIS control citations, and collapsible diffs.
3. Kustomize Strategic Merge Patch Overlay Export:
   - Exports non-destructive `kustomization.yaml` with strategic merge patches
     so developers can adopt least-privilege security without altering upstream vendor charts.
"""

from dataclasses import asdict, dataclass, field
import difflib
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import yaml

try:
    from .scanner import NativeSecurityScanner, ScanReport
    from .remediate import remediate_workload_dict
except ImportError:
    from scanner import NativeSecurityScanner, ScanReport
    from remediate import remediate_workload_dict

logger = logging.getLogger("NativeScanner.GitOps")


@dataclass
class WorkloadRemediationDiff:
    """Remediation details and diff for a single Kubernetes workload manifest."""
    file_path: str
    workload_id: str
    namespace: str
    kind: str
    name: str
    before_score: float
    after_score: float
    score_delta: float
    before_risk_tier: str
    after_risk_tier: str
    patches_applied: List[str]
    unified_diff: str
    hardened_yaml: str
    strategic_patch_yaml: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GitOpsRemediationPlan:
    """Full remediation plan across a repository or directory tree."""
    target_path: str
    total_files_analyzed: int = 0
    failing_manifests_count: int = 0
    workload_diffs: List[WorkloadRemediationDiff] = field(default_factory=list)
    pr_title: str = ""
    pr_body_markdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["workload_diffs"] = [w.to_dict() for w in self.workload_diffs]
        return d


class GitOpsRemediator:
    """Automated GitOps Remediation Engine for Kubernetes infrastructure repositories."""

    def __init__(self, threshold: float = 70.0):
        self.threshold = threshold
        self.scanner = NativeSecurityScanner()

    def plan_remediation(self, target_path: str) -> GitOpsRemediationPlan:
        """Scan a manifest file or directory tree and compute a complete remediation plan."""
        target = Path(target_path)
        plan = GitOpsRemediationPlan(target_path=str(target))

        if target.is_file():
            yaml_files = [target]
        elif target.is_dir():
            yaml_files = sorted(list(target.rglob("*.yaml")) + list(target.rglob("*.yml")))
        else:
            logger.warning(f"Target path does not exist: {target_path}")
            return plan

        plan.total_files_analyzed = len(yaml_files)
        veto_rules = {"V01", "V02", "V09", "V10", "V11", "V45"}

        for yf in yaml_files:
            try:
                content = yf.read_text(encoding="utf-8")
            except Exception:
                continue

            report = self.scanner.scan_yaml_content(content, source_name=str(yf))
            has_veto = len(veto_rules.intersection(report.detected_vuln_ids)) > 0

            # Only remediate if workload fails threshold or triggers an exploit veto
            if report.compliance_score >= self.threshold and not has_veto:
                continue

            try:
                docs = list(yaml.safe_load_all(content))
            except Exception:
                continue

            hardened_docs = []
            applied_patches_summary = []
            strategic_patches = []

            for doc in docs:
                if not isinstance(doc, dict):
                    hardened_docs.append(doc)
                    continue

                kind = doc.get("kind", "")
                if kind not in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"):
                    hardened_docs.append(doc)
                    continue

                hardened_doc, patches = remediate_workload_dict(doc)
                hardened_docs.append(hardened_doc)
                applied_patches_summary.extend(patches)

                strategic_patch = self._extract_strategic_patch(hardened_doc)
                strategic_patches.append(strategic_patch)

            if not applied_patches_summary:
                continue

            hardened_yaml_str = yaml.dump_all(hardened_docs, sort_keys=False)
            h_report = self.scanner.scan_yaml_content(hardened_yaml_str, source_name=str(yf))

            diff_lines = list(difflib.unified_diff(
                content.splitlines(keepends=True),
                hardened_yaml_str.splitlines(keepends=True),
                fromfile=f"a/{yf.name}",
                tofile=f"b/{yf.name}",
            ))
            unified_diff_str = "".join(diff_lines)

            meta = docs[0].get("metadata", {}) if docs and isinstance(docs[0], dict) else {}
            w_name = meta.get("name", yf.stem)
            w_ns = meta.get("namespace", "default")
            w_kind = docs[0].get("kind", "Deployment") if docs and isinstance(docs[0], dict) else "Deployment"

            w_diff = WorkloadRemediationDiff(
                file_path=str(yf),
                workload_id=f"{w_ns}/{w_kind}/{w_name}",
                namespace=w_ns,
                kind=w_kind,
                name=w_name,
                before_score=round(report.compliance_score, 1),
                after_score=round(h_report.compliance_score, 1),
                score_delta=round(h_report.compliance_score - report.compliance_score, 1),
                before_risk_tier=report.risk_tier,
                after_risk_tier=h_report.risk_tier,
                patches_applied=applied_patches_summary,
                unified_diff=unified_diff_str,
                hardened_yaml=hardened_yaml_str,
                strategic_patch_yaml=yaml.dump_all(strategic_patches, sort_keys=False),
            )
            plan.workload_diffs.append(w_diff)

        plan.failing_manifests_count = len(plan.workload_diffs)
        plan.pr_title = f"security(gitops): remediate {plan.failing_manifests_count} non-compliant workload(s) to least-privilege"
        plan.pr_body_markdown = self._format_pr_body(plan)
        return plan

    @staticmethod
    def _extract_strategic_patch(doc: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a minimal Kustomize strategic merge patch dictionary."""
        kind = doc.get("kind", "Deployment")
        patch: Dict[str, Any] = {
            "apiVersion": doc.get("apiVersion", "apps/v1"),
            "kind": kind,
            "metadata": {
                "name": doc.get("metadata", {}).get("name", "unnamed"),
            }
        }
        if "namespace" in doc.get("metadata", {}):
            patch["metadata"]["namespace"] = doc["metadata"]["namespace"]

        spec = doc.get("spec", {})
        if kind == "Pod":
            target_spec = spec
            patch_target = patch.setdefault("spec", {})
        else:
            target_spec = spec.get("template", {}).get("spec", {})
            patch_target = patch.setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})

        if "securityContext" in target_spec:
            patch_target["securityContext"] = target_spec["securityContext"]

        patch_containers = []
        for c in target_spec.get("containers", []):
            c_patch: Dict[str, Any] = {"name": c.get("name", "main")}
            if "securityContext" in c:
                c_patch["securityContext"] = c["securityContext"]
            if "resources" in c:
                c_patch["resources"] = c["resources"]
            patch_containers.append(c_patch)

        if patch_containers:
            patch_target["containers"] = patch_containers

        return patch

    def export_kustomize_overlay(self, plan: GitOpsRemediationPlan, output_dir: str) -> List[str]:
        """Export non-destructive Kustomize overlay directory with strategic merge patches."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        created_files = []

        patches_files = []
        for diff in plan.workload_diffs:
            clean_name = f"patch-{diff.kind.lower()}-{diff.name.replace(':', '_')}.yaml"
            patch_path = out / clean_name
            patch_path.write_text(diff.strategic_patch_yaml, encoding="utf-8")
            patches_files.append(clean_name)
            created_files.append(str(patch_path))

        # Generate kustomization.yaml
        kust = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": [f"../../{Path(d.file_path).name}" for d in plan.workload_diffs],
            "patchesStrategicMerge": patches_files,
        }
        kust_path = out / "kustomization.yaml"
        kust_path.write_text(yaml.dump(kust, sort_keys=False), encoding="utf-8")
        created_files.append(str(kust_path))
        return created_files

    def apply_in_place(self, plan: GitOpsRemediationPlan) -> int:
        """Apply hardened manifests directly in-place across target files."""
        modified = 0
        for diff in plan.workload_diffs:
            p = Path(diff.file_path)
            if p.exists():
                p.write_text(diff.hardened_yaml, encoding="utf-8")
                modified += 1
        return modified

    def _format_pr_body(self, plan: GitOpsRemediationPlan) -> str:
        """Format an executive-grade GitHub PR / GitLab MR Markdown body."""
        avg_before = sum(d.before_score for d in plan.workload_diffs) / max(1, len(plan.workload_diffs))
        avg_after = sum(d.after_score for d in plan.workload_diffs) / max(1, len(plan.workload_diffs))

        md = [
            "## 🛡️ Autonomous Kubernetes Security Posture Remediation",
            "",
            "This Pull Request applies automated, least-privilege security controls conforming to **CIS Kubernetes Benchmark v2.0** and **NSA/CISA Pod Security Standards**.",
            "",
            "### 📊 Posture Enhancement Summary",
            f"- **Workloads Hardened:** `{plan.failing_manifests_count}` / `{plan.total_files_analyzed}`",
            f"- **Fleet Average Score:** `{avg_before:.1f}/100` ➔ **`{avg_after:.1f}/100`** (+{avg_after - avg_before:.1f} pts)",
            "",
            "| Workload | Namespace | Before | After | Delta | Risk Tier |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for d in plan.workload_diffs:
            md.append(f"| `{d.kind}/{d.name}` | `{d.namespace}` | `{d.before_score}` | **`{d.after_score}`** | `+{d.score_delta}` | `{d.before_risk_tier}` ➔ `{d.after_risk_tier}` |")

        md.extend([
            "",
            "### 🔍 Detailed Diffs",
        ])

        for d in plan.workload_diffs:
            md.extend([
                f"<details><summary><b>{d.workload_id} ({d.file_path})</b></summary>",
                "",
                "```diff",
                d.unified_diff.strip(),
                "```",
                "</details>",
                "",
            ])

        md.extend([
            "---",
            "*Generated autonomously by [k8s-native-scanner](https://github.com/k8s-native-scanner).* Non-destructive least-privilege overlay.",
        ])

        return "\n".join(md)
