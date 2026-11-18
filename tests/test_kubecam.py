#!/usr/bin/env python3
"""
tests/test_kubecam.py
=====================
Unit tests for KubeCam: Cluster Continuous Assessment Monitor & Kubescape Bridge (kubecam.py).
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from kubecam import (
    KubeCamEngine,
    KubeCamFrame,
    KubeCamFilmstrip,
    WorkloadFrameEntry,
    SecurityDriftDelta,
)
from cluster_scanner import LiveClusterReport, WorkloadAuditResult


class TestKubeCamEngine(unittest.TestCase):
    def setUp(self):
        self.engine = KubeCamEngine()

    def test_capture_frame_mocked(self):
        mock_audit = WorkloadAuditResult(
            workload_id="default/Deployment/payment-api",
            namespace="default",
            kind="Deployment",
            name="payment-api",
            compliance_score=75.0,
            risk_tier="MEDIUM",
            veto_triggered=False,
            findings_count=2,
            top_findings=["[V04] Writable Root Filesystem", "[V12] Missing Seccomp Profile"],
        )
        mock_rep = LiveClusterReport(
            total_workloads=1,
            average_score=75.0,
            workload_results=[mock_audit],
        )

        with patch.object(self.engine.cluster_scanner, "scan_cluster", return_value=mock_rep):
            frame = self.engine.capture_frame(frame_id=1, namespace="default")
            self.assertEqual(frame.frame_id, 1)
            self.assertEqual(frame.total_workloads, 1)
            self.assertEqual(frame.cluster_compliance_score, 75.0)
            self.assertIn("default/Deployment/payment-api", frame.workloads)
            self.assertTrue(len(frame.frame_hash) > 0)

    def test_diff_frames_drift_detection(self):
        # Frame 1: Baseline compliant workload
        entry_v1 = WorkloadFrameEntry(
            workload_id="prod/Deployment/auth-service",
            namespace="prod",
            kind="Deployment",
            name="auth-service",
            compliance_score=95.0,
            risk_tier="MINIMAL",
            has_exploit_veto=False,
            findings_count=0,
            config_hash="hash-v1",
            top_findings=[],
        )
        frame1 = KubeCamFrame(
            frame_id=1,
            timestamp="2026-11-18T10:00:00Z",
            cluster_version="v1.28",
            context_name="prod",
            total_workloads=1,
            cluster_compliance_score=95.0,
            cluster_blast_radius=5.0,
            workloads={"prod/Deployment/auth-service": entry_v1},
        )

        # Frame 2: Security drift! Someone added privileged: true and degraded compliance score
        entry_v2 = WorkloadFrameEntry(
            workload_id="prod/Deployment/auth-service",
            namespace="prod",
            kind="Deployment",
            name="auth-service",
            compliance_score=40.0,
            risk_tier="CRITICAL",
            has_exploit_veto=True,
            findings_count=3,
            config_hash="hash-v2",
            top_findings=["[V01] Privileged Container Execution"],
        )
        # Also deployed a new rogue workload
        entry_rogue = WorkloadFrameEntry(
            workload_id="prod/Pod/miner",
            namespace="prod",
            kind="Pod",
            name="miner",
            compliance_score=20.0,
            risk_tier="CRITICAL",
            has_exploit_veto=True,
            findings_count=5,
            config_hash="hash-miner",
            top_findings=["[V55] Crypto Mining Outbound"],
        )

        frame2 = KubeCamFrame(
            frame_id=2,
            timestamp="2026-11-18T10:15:00Z",
            cluster_version="v1.28",
            context_name="prod",
            total_workloads=2,
            cluster_compliance_score=30.0,
            cluster_blast_radius=70.0,
            workloads={
                "prod/Deployment/auth-service": entry_v2,
                "prod/Pod/miner": entry_rogue,
            },
        )

        deltas = self.engine.diff_frames(frame1, frame2)
        self.assertEqual(len(deltas), 2)

        types = {d.drift_type for d in deltas}
        self.assertIn("POSTURE_DEGRADED", types)
        self.assertIn("NEW_WORKLOAD", types)

        degraded = [d for d in deltas if d.drift_type == "POSTURE_DEGRADED"][0]
        self.assertEqual(degraded.previous_score, 95.0)
        self.assertEqual(degraded.current_score, 40.0)
        self.assertEqual(degraded.score_delta, -55.0)
        self.assertIn("[V01] Privileged Container Execution", degraded.new_findings)

    def test_record_time_lapse(self):
        mock_rep = LiveClusterReport(
            total_workloads=1,
            average_score=100.0,
            workload_results=[],
        )
        with patch.object(self.engine.cluster_scanner, "scan_cluster", return_value=mock_rep):
            filmstrip = self.engine.record_time_lapse(interval_seconds=0, total_frames=2)
            self.assertEqual(filmstrip.frames_recorded, 2)
            self.assertEqual(len(filmstrip.frames), 2)

    def test_export_kubescape_format(self):
        entry = WorkloadFrameEntry(
            workload_id="default/Deployment/app",
            namespace="default",
            kind="Deployment",
            name="app",
            compliance_score=60.0,
            risk_tier="HIGH",
            has_exploit_veto=True,
            findings_count=1,
            config_hash="hash-123",
            top_findings=["[V01] Privileged Container Execution"],
        )
        frame = KubeCamFrame(
            frame_id=1,
            timestamp="2026-11-18T11:00:00Z",
            cluster_version="v1.28",
            context_name="production-cluster",
            total_workloads=1,
            cluster_compliance_score=60.0,
            cluster_blast_radius=40.0,
            workloads={"default/Deployment/app": entry},
        )

        kubescape_doc = self.engine.export_kubescape_format(frame)
        self.assertEqual(kubescape_doc["frameworkName"], "AllControls")
        self.assertEqual(kubescape_doc["clusterRiskScore"], 40.0)
        self.assertEqual(len(kubescape_doc["controls"]), 1)
        self.assertEqual(kubescape_doc["controls"][0]["controlID"], "C-V01")

    def test_format_filmstrip_summary(self):
        filmstrip = KubeCamFilmstrip(
            session_id="test-session-001",
            start_time="2026-11-18T10:00:00Z",
            end_time="2026-11-18T10:10:00Z",
            frames_recorded=1,
            total_drifts_detected=0,
            frames=[
                KubeCamFrame(
                    frame_id=1,
                    timestamp="2026-11-18T10:00:00Z",
                    cluster_version="v1.28",
                    context_name="prod",
                    total_workloads=5,
                    cluster_compliance_score=88.5,
                    cluster_blast_radius=11.5,
                    frame_hash="abcdef123456",
                )
            ],
            drift_events=[],
        )
        summary = self.engine.format_filmstrip_summary(filmstrip)
        self.assertIn("KUBECAM: CONTINUOUS CLUSTER AUDIT CAMERA", summary)
        self.assertIn("test-session-001", summary)
        self.assertIn("88.5%", summary)


if __name__ == "__main__":
    unittest.main()
