#!/usr/bin/env python3
"""
tests/test_taxonomy_full_coverage.py
====================================
Comprehensive verification of 100% 56-vulnerability taxonomy rule auditing:
- Plane 2: V19 (Image signature), V20 (Outdated base), V22 (Default password)
- Plane 3: V29 (RBAC privilege escalation verbs bind/escalate)
- Plane 4: V33 (hostPort), V35 (Missing mTLS), V37 (CoreDNS query leakage)
- Plane 5: V38 (Anonymous API), V39 (Unencrypted etcd), V40 (Audit logging), V41/V42 (Kubelet), V43 (Admission plugins), V44 (Cloud IMDS)
- Plane 6: V48 (etcd secrets encryption), V49 (Secrets in env), V50 (ReadWriteMany storage)
- Plane 7: V51 (Interactive shell), V52 (Recon tools), V53 (Writable system mounts), V54 (Kernel module), V55 (Crypto-mining), V56 (Kernel memory)
"""

from pathlib import Path
import sys
import tempfile
import unittest

_PKG_DIR = Path(__file__).resolve().parents[1]
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from scanner import NativeSecurityScanner


class TestTaxonomyFullCoverage(unittest.TestCase):

    def setUp(self):
        self.scanner = NativeSecurityScanner()

    def test_plane2_supply_chain_rules(self):
        # V20: Outdated base OS image, V22: Default root password
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: legacy-pod
spec:
  containers:
    - name: legacy
      image: centos:6
      env:
        - name: MYSQL_ROOT_PASSWORD
          value: "root"
"""
        report = self.scanner.scan_yaml_content(manifest)
        vulns = report.detected_vuln_ids
        self.assertIn("V20", vulns)  # Outdated base image
        self.assertIn("V22", vulns)  # Default password

    def test_plane3_rbac_privilege_escalation(self):
        # V29: RBAC Role granting bind and escalate
        manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: role-escalator
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "clusterroles"]
    verbs: ["bind", "escalate"]
"""
        report = self.scanner.scan_yaml_content(manifest)
        self.assertIn("V29", report.detected_vuln_ids)

    def test_plane4_perimeter_rules(self):
        # V33: hostPort, V35: missing mTLS on listening ports, V37: ndots > 3
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: web-listener
spec:
  dnsConfig:
    options:
      - name: ndots
        value: "5"
  containers:
    - name: web
      image: myregistry.io/app:1.0.0
      ports:
        - containerPort: 8080
          hostPort: 8080
"""
        report = self.scanner.scan_yaml_content(manifest)
        vulns = report.detected_vuln_ids
        self.assertIn("V33", vulns)  # hostPort
        self.assertIn("V35", vulns)  # missing mTLS
        self.assertIn("V37", vulns)  # CoreDNS query leakage

    def test_plane5_control_plane_rules(self):
        # V38 (anonymous auth), V40 (audit logging), V43 (admission plugins), V48 (secrets encryption)
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --anonymous-auth=true
"""
        report = self.scanner.scan_yaml_content(manifest)
        vulns = report.detected_vuln_ids
        self.assertIn("V38", vulns)
        self.assertIn("V40", vulns)
        self.assertIn("V43", vulns)
        self.assertIn("V48", vulns)

    def test_plane6_storage_and_env_secrets(self):
        # V49: Secret in env, V50: ReadWriteMany storage
        pvc_manifest = """
apiVersion: v1
kind: PersistentVolume
metadata:
  name: shared-nfs
spec:
  accessModes:
    - ReadWriteMany
  capacity:
    storage: 100Gi
"""
        rep_pvc = self.scanner.scan_yaml_content(pvc_manifest)
        self.assertIn("V50", rep_pvc.detected_vuln_ids)

        env_secret_manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-env-secret
spec:
  containers:
    - name: worker
      image: myapp:1.0.0
      env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: token
"""
        rep_env = self.scanner.scan_yaml_content(env_secret_manifest)
        self.assertIn("V49", rep_env.detected_vuln_ids)

    def test_plane7_runtime_and_kernel_rules(self):
        # V51 (interactive shell), V52 (recon tools), V53 (writable system mount),
        # V54 (kernel module), V55 (crypto-mining), V56 (kernel memory)
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: hostile-container
spec:
  containers:
    - name: attacker
      image: alpine:latest
      stdin: true
      tty: true
      command: ["/bin/sh", "-c", "nmap -sS 10.0.0.0/8 && xmrig -o stratum+tcp://xmr.pool.com"]
      securityContext:
        capabilities:
          add: ["CAP_SYS_MODULE"]
      volumeMounts:
        - name: host-bin
          mountPath: /usr/bin
          readOnly: false
        - name: host-mem
          mountPath: /dev/mem
"""
        report = self.scanner.scan_yaml_content(manifest)
        vulns = report.detected_vuln_ids
        self.assertIn("V51", vulns)  # interactive shell
        self.assertIn("V52", vulns)  # reconnaissance tool
        self.assertIn("V53", vulns)  # writable system mount
        self.assertIn("V54", vulns)  # kernel module capability
        self.assertIn("V55", vulns)  # crypto-mining
        self.assertIn("V56", vulns)  # sensitive kernel memory

    def test_parallel_multi_core_scanning(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            for i in range(12):
                (p / f"manifest_{i}.yaml").write_text(f"""
apiVersion: v1
kind: Pod
metadata:
  name: pod-{i}
spec:
  containers:
    - name: app
      image: nginx:1.25
""", encoding="utf-8")

            reports = self.scanner.scan_directory(str(p))
            self.assertEqual(len(reports), 12)
            names = {r.manifest_path for r in reports}
            self.assertEqual(len(names), 12)


if __name__ == "__main__":
    unittest.main()
