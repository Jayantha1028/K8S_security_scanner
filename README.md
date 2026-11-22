# Kubernetes Native Security Scanner (`k8s-native-scanner`)

[![CI](https://github.com/Jayantha1028/K8S_security_scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Jayantha1028/K8S_security_scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-223%20Passing-brightgreen)](https://github.com/Jayantha1028/K8S_security_scanner/actions)
[![Benchmark](https://img.shields.io/badge/AST%20Scan%20p50-0.68ms-brightgreen)](benchmarks/)

```
========================================================================================
       HIGH-PERFORMANCE PURE-PYTHON KUBERNETES SECURITY SCANNER & ATTACK DAG ENGINE
========================================================================================
Standard    : CIS Kubernetes Benchmark v2.0, NSA/CISA Hardening, MITRE ATT&CK, NIST SP 800-190
Footprint   : Zero External Binaries | Pure Python 3.9+ | Sub-Millisecond Execution | <4MB RAM
Interoper   : SARIF v2.1.0, JUnit XML, OpenMetrics, CycloneDX v1.5, SPDX v2.3, Mermaid DAG
Integrations: Live Cluster CSPM, Shift-Left GitOps, Prometheus Metrics, Admission Webhook, Web Console
Full Scope  : Manifest AST + Container SBOM + Node CIS Benchmark + Dockerfile & Terraform IaC
========================================================================================
```

`k8s-native-scanner` is an enterprise-grade, standalone Cloud-Native Application Protection Platform (CNAPP) scanner engineered for high-velocity CI/CD security gates, in-cluster admission webhooks, container layer SBOM extraction, host node CIS compliance, and multi-framework regulatory auditing.

---

## 🏛️ Two-Tier Modular Architecture

To guarantee auditability, trust, and performance, `k8s-native-scanner` strictly decouples its core scanning engine from enterprise extensions:

- **Tier 1: Lean Core Engine** (`scanner.py`, `attack_graph.py`, `remediate.py`, `container.py`, `compliance.py`, `declarative.py`, `iac.py`):
  - Completely zero-binary, pure-Python standard library + PyYAML.
  - Sub-millisecond manifest AST analysis across 56 vulnerability rules.
  - Generates cross-resource lateral exploit attack graphs (DAG) and blast radius indices.
  - Zero network egress during scanning.

- **Tier 2: In-Cluster & Enterprise Extensions** (`webhook.py`, `auth.py`, `fleet.py`, `storage.py`, `notifications.py`, `leader_election.py`, `enterprise_server.py`):
  - Optional in-cluster HTTPS admission webhook (`/validate`, `/mutate`).
  - RFC 7519 JWT identity and 4-tier RBAC management.
  - Multi-cluster fleet manager and KubeCam telemetry aggregator.
  - SQLite WAL persistent store with retention pruning.
  - ChatOps incident dispatchers (Slack Block Kit, Teams, PagerDuty).

📖 *For detailed subsystem interactions and data flow diagrams, see [ARCHITECTURE.md](ARCHITECTURE.md).*

---

## ⚡ Measured Performance Benchmarks

All performance claims are continuously verified with reproducible micro-benchmarks in [`benchmarks/run_benchmarks.py`](benchmarks/run_benchmarks.py).

Run the benchmark suite locally:
```bash
python3 cli.py benchmark --markdown
```

### Measured Benchmark Results (Sample Size: 300 Iterations)

| Benchmark Metric | Measured Value | Specification Target | Status |
| :--- | :---: | :---: | :---: |
| **Engine Cold-Start Time** | `0.001 ms` | `< 10.0 ms` | ✅ Verified |
| **Single Workload AST Scan (p50)** | `0.68 ms` | `< 3.0 ms` | ✅ Verified |
| **Single Workload AST Scan (p99)** | `0.92 ms` | `< 5.0 ms` | ✅ Verified |
| **Multi-Resource Manifest Scan (p50)** | `0.81 ms` | `< 6.0 ms` | ✅ Verified |
| **Attack Path DAG Computation** | `0.12 ms` | `< 2.0 ms` | ✅ Verified |
| **Scan Throughput** | `~1,200 manifests/sec` | `> 500 / sec` | ✅ Verified |
| **Peak Process RAM Consumption** | `3.23 MB` | `< 20.0 MB` | ✅ Verified |
| **Taxonomy Rule Coverage** | `56 / 56 Rules (100%)` | `V01 - V56` | ✅ Verified |

---

## 🔒 Cryptographic Primitives & Security Audit

Given this product verifies manifests, issues API keys, and signs tokens, cryptographic logic adheres to vetted principles:

1. **Safe Manifest Ingestion**:
   - Manifest parsing strictly uses `yaml.safe_load` / `yaml.safe_load_all` (or C-accelerated `CSafeLoader`).
   - Standard Python `yaml.load` is prohibited to prevent arbitrary code execution vulnerabilities.
2. **Timing-Safe Key & Token Verification**:
   - Master secrets are generated using OS CSPRNG (`secrets.token_bytes(32)`).
   - Signatures and API key hashes are compared strictly with `hmac.compare_digest()` to eliminate side-channel timing attacks.
3. **Algorithm Confusion Defense**:
   - RFC 7519 JWT verification validates token headers to enforce `alg: "HS256"`.
   - Tokens specifying `alg: "none"`, asymmetric keys (`RS256`), or malformed structures are rejected immediately.
4. **Outbound SSRF Protection**:
   - Webhooks and incident notification URLs (Slack, Teams, PagerDuty) pass through `validate_safe_url()`.
   - Blocks AWS/GCP IMDS (`169.254.169.254`), loopbacks, and RFC1918 private subnets.
5. **TLS Webhook Encryption**:
   - In-cluster admission webhooks support self-signed TLS generation via Python's standard `cryptography` x509 builder.
   - Enforces TLS 1.2+ minimum with modern ECDHE cipher suites and sets `0600` permissions on private keys.

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

### 13. Performance Micro-Benchmarks

```bash
# Execute local micro-benchmarks across 300 iterations
k8s-native-scan benchmark --markdown
```

---

## Automated Test Suite

Run the full enterprise test suite (223 tests covering all modules, executing in < 3.0s):

```bash
python3 -m unittest discover tests -v
```

---

## Contributing & Security

We welcome community contributions, bug reports, and rule improvements.
- Please review [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, test execution, and code standards.
- Detailed architecture and subsystem diagrams are documented in [ARCHITECTURE.md](ARCHITECTURE.md).
- To report a security vulnerability, please refer to our disclosure policy in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
