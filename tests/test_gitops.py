#!/usr/bin/env python3
"""
tests/test_gitops.py
====================
Unit tests for Shift-Left GitOpsRemediator and Kustomize Overlay Generator.
"""

from pathlib import Path
import sys
import tempfile
import unittest
import yaml

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from gitops import GitOpsRemediator, GitOpsRemediationPlan


class TestGitOps(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.remediator = GitOpsRemediator(threshold=70.0)

        # Write weak deployment
        self.weak_deploy = self.td / "weak-deploy.yaml"
        self.weak_deploy.write_text(yaml.dump({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "sample-api", "namespace": "staging"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{
                            "name": "web",
                            "image": "nginx:latest",
                            "securityContext": {
                                "privileged": True,
                            }
                        }]
                    }
                }
            }
        }), encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_plan_remediation(self):
        plan = self.remediator.plan_remediation(str(self.td))
        self.assertEqual(plan.total_files_analyzed, 1)
        self.assertEqual(plan.failing_manifests_count, 1)

        diff = plan.workload_diffs[0]
        self.assertLess(diff.before_score, 50.0)
        self.assertGreater(diff.after_score, diff.before_score)
        self.assertGreater(diff.score_delta, 0.0)
        self.assertIn("security(gitops):", plan.pr_title)
        self.assertIn("## 🛡️ Autonomous Kubernetes Security Posture Remediation", plan.pr_body_markdown)

    def test_export_kustomize_overlay(self):
        plan = self.remediator.plan_remediation(str(self.td))
        out_dir = self.td / "kustomize_overlay"
        files = self.remediator.export_kustomize_overlay(plan, str(out_dir))

        self.assertTrue((out_dir / "kustomization.yaml").exists())
        kust_data = yaml.safe_load((out_dir / "kustomization.yaml").read_text(encoding="utf-8"))
        self.assertIn("patchesStrategicMerge", kust_data)
        self.assertGreaterEqual(len(kust_data["patchesStrategicMerge"]), 1)

        # Verify patch file contains hardened securityContext
        patch_file = out_dir / kust_data["patchesStrategicMerge"][0]
        self.assertTrue(patch_file.exists())
        patch_content = patch_file.read_text(encoding="utf-8")
        self.assertIn("securityContext", patch_content)

    def test_apply_in_place(self):
        plan = self.remediator.plan_remediation(str(self.td))
        mod_count = self.remediator.apply_in_place(plan)
        self.assertEqual(mod_count, 1)

        # Re-read and re-scan: score should now be high
        re_plan = self.remediator.plan_remediation(str(self.td))
        self.assertEqual(re_plan.failing_manifests_count, 0)


if __name__ == "__main__":
    unittest.main()
