# Kubernetes Native Security Scanner (`k8s-native-scanner`)

```
========================================================================================
       HIGH-PERFORMANCE PURE-PYTHON KUBERNETES SECURITY SCANNER & ATTACK DAG ENGINE
========================================================================================
Standard    : CIS Kubernetes Benchmark v2.0, NSA/CISA Hardening, MITRE ATT&CK, NIST SP 800-190
Footprint   : Zero External Binaries | Pure Python 3.9+ | Sub-5ms Execution | ~18MB RAM
Interoper   : SARIF v2.1.0, JUnit XML, OpenMetrics, CycloneDX v1.5, SPDX v2.3, Mermaid DAG
Integrations: Live Cluster CSPM, Shift-Left GitOps, Prometheus Metrics, Admission Webhook, Web Console
Full Scope  : Manifest AST + Container SBOM + Node CIS Benchmark + Dockerfile & Terraform IaC
```

`k8s-native-scanner` is an enterprise-grade, standalone Cloud-Native Application Protection Platform (CNAPP) scanner engineered for high-velocity CI/CD security gates, in-cluster admission webhooks, container layer SBOM extraction, host node CIS compliance, and multi-framework regulatory auditing.

---

## Key Capabilities

1. **Pure-Python AST Manifest Scanner (56-Vulnerability Taxonomy)**:
   - Audits OpenAPI syntax trees across 8 security planes (Isolation, Identity, Network, Storage, Secrets, Supply Chain, Reliability, Runtime).
   - Ingests standard YAML manifests, Helm charts (`Chart.yaml`), and Kustomize overlays.
   - High-entropy cryptographic secret identification (Shannon entropy $H > 3.8$ bits/char).
   - Supply chain typosquatting defense using bounded Levenshtein distance ($d \le 2$).

2. **Cross-Resource Attack Path Directed Acyclic Graph (DAG)**:
   - Correlates decoupled YAML resources (`Ingress` $\to$ `Service` $\to$ `Workload` $\to$ `ServiceAccount` $\to$ `RBAC` $\to$ `Secret` / Host Kernel).
   - **NetworkPolicy Reachability Engine**: Evaluates active ingress/egress network segmentation rules, pruning or discounting lateral reachability edges.
   - Correlates Cloud Provider IAM Identities (**AWS IRSA**, **GCP Workload Identity**, **Azure Entra ID**).
   - Calculates closed-form cluster-wide Blast Radius ($\mathcal{B} \in [0.0, 100.0]$).
   - Exports interactive Mermaid DAGs and exploit kill-chains.

3. **In-Cluster Admission Controller Webhook (`/validate` & `/mutate`)**:
   - Zero-dependency in-cluster multi-threaded HTTPS server with automatic self-signed TLS certificate generation.
   - Enforcing, warn, shadow, and dry-run observation modes with Catastrophic Exploit Veto.
   - Real-time RFC 6902 JSONPatch mutations injecting least-privilege securityContext.
   - Turnkey Kubernetes `ValidatingWebhookConfiguration` & `MutatingWebhookConfiguration` YAML generator (`webhook --generate-config`).
   - Built-in `/healthz`, `/readyz`, and `/metrics` (OpenMetrics counters).

4. **Multi-Format IaC Security Scanner (`scan-iac`)**:
   - **Dockerfile AST Auditor**: Detects root execution, insecure `curl | bash` pipelines, missing `HEALTHCHECK`, sensitive file copies (`.env`, `id_rsa`), and hardcoded credentials.
   - **Terraform Kubernetes Auditor**: Audits `.tf` HCL files defining `kubernetes_pod` or `kubernetes_deployment` resources.

5. **CIS Kubernetes Benchmark Host Node & Control Plane Auditor (`node-audit`)**:
   - Audits master and worker Linux nodes against CIS Benchmark v2.0 directly via filesystem permissions (`admin.conf`, `pki/`, `kube-apiserver.yaml`, `kubelet/config.yaml`) and kernel sysctl parameters (`rp_filter`, `tcp_syncookies`).

6. **Precision Linux Distro Version Comparator (`version_comparator`)**:
   - Native Debian/Ubuntu epoch (`epoch:upstream-revision`), RPM (`epoch:version-release`), and Alpine APK semantic version comparison.
   - Drastically eliminates false positives caused by enterprise backported security patches.

7. **Multi-Cloud IAM Reality Verifier (`cloud_iam`)**:
   - Syntactic and structural validation of AWS IAM Role ARNs, GCP ServiceAccount emails, and Azure Application IDs.
   - Flags administrative wildcard credentials and open trust relationships.

8. **Enterprise Portability & CI/CD Tooling**:
   - **SARIF v2.1.0 Exporter**: Directly integrates into GitHub Advanced Security Code Scanning tabs.
   - **Interactive Web Management Console**: Local web UI for live testing and 1-click remediation.
   - **Standalone Offline HTML Reports**: Executive reports with dark mode and metrics.
   - **Air-Gapped Sovereign Security Bundles**: Cryptographically verified `.tar.gz` bundles for air-gapped / SCIF / FedRAMP environments.

---

## Quickstart & CLI Guide

### 1. Installation

```bash
# Editable install
pip install -e .

# Or run directly via wrapper
./bin/k8s-native-scan --help
```

### 2. Manifest Scanning & Security Gates

```bash
# Scan a single manifest
k8s-native-scan scan manifests/deployment.yaml

# Scan a directory recursively with SARIF and HTML report export
k8s-native-scan scan manifests/ --sarif results.sarif --html report.html --mermaid attack_graph.mmd

# CI/CD Gate: Fail pipeline if compliance score is below threshold (0-100)
k8s-native-scan scan manifests/ --min-score 85.0
```

### 3. Multi-Format IaC Scanning (Dockerfile & Terraform)

```bash
# Audit a Dockerfile
k8s-native-scan scan-iac Dockerfile

# Audit Terraform Kubernetes infrastructure
k8s-native-scan scan-iac main.tf
```

### 4. CIS Kubernetes Host Node & Control Plane Audit

```bash
# Run directly on host Linux node or inside DaemonSet container
k8s-native-scan node-audit

# Run with custom host root mount (e.g. /host)
k8s-native-scan node-audit --root /host --json
```

### 5. Automated Least-Privilege Remediation

```bash
# Preview least-privilege patches as unified diff
k8s-native-scan remediate manifests/insecure.yaml --diff

# Apply fixes in-place
k8s-native-scan remediate manifests/insecure.yaml --write
```

### 6. In-Cluster Admission Webhook & Turnkey YAML Generation

```bash
# Generate Kubernetes Validating/Mutating Webhook YAML manifests
k8s-native-scan webhook --generate-config -o webhook-deployment.yaml

# Start HTTPS webhook in Enforcing mode on port 8443
k8s-native-scan webhook --port 8443 --mode enforce --min-score 75.0
```

### 7. Deep Historical CVE Threat Intelligence & Delta Sync

```bash
# Query embedded SQLite database statistics & SHA-256 integrity hash
k8s-native-scan cve

# Look up historical CVEs affecting a specific container package
k8s-native-scan cve --lookup util-linux

# Synchronize live CVE deltas from OSV.dev (aggregating NVD, GHSA, Debian, Alpine)
k8s-native-scan cve --sync
```

### 8. Air-Gapped Sovereign Bundle Management

```bash
# Export sovereign threat bundle
k8s-native-scan bundle export bundle.tar.gz

# Cryptographically verify bundle integrity
k8s-native-scan bundle verify bundle.tar.gz
```

### 9. Live In-Cluster Security Posture Audit (CSPM Engine)

```bash
# Audit running cluster workloads (auto-detects in-cluster ServiceAccount or kubectl)
k8s-native-scan cluster

# Audit specific namespace and export auto-remediated least-privilege manifests
k8s-native-scan cluster -n production --remediate-out ./remediated-manifests -o cluster-audit.json
```

### 10. Shift-Left GitOps PR Bot & Kustomize Overlay Generator

```bash
# Calculate GitOps remediation plan with unified diffs and score deltas
k8s-native-scan gitops manifests/

# Export non-destructive Kustomize strategic merge patch overlays
k8s-native-scan gitops manifests/ --kustomize-out overlays/hardened --pr-body-out pr_description.md

# Pre-commit hook & CI/CD gate: fail with exit code 1 if any workload is non-compliant
k8s-native-scan gitops manifests/ --ci-check --threshold 75.0
```

### 11. Prometheus Metrics Exporter & OpenMetrics Daemon

```bash
# Export static OpenMetrics .prom textfile
k8s-native-scan export-metrics manifests/ -o /var/lib/node_exporter/textfile_collector/k8s_security.prom

# Run live Prometheus HTTP daemon on port 9108 (/metrics)
k8s-native-scan export-metrics manifests/ --serve --port 9108
```

### 12. Interactive Web Management Console

```bash
# Launch local web console on port 8080
k8s-native-scan dashboard --port 8080
```

---

## Automated Test Suite

Run the full enterprise test suite (70 tests covering all modules):

```bash
make test
# or
python3 -m unittest discover tests
```
