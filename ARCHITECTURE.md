# System Architecture & Technical Specifications

This document outlines the architecture, data flows, and security boundaries of `k8s-native-scanner`.

---

## 1. Architectural Philosophy: Two-Tier Modular Design

The codebase is organized into two explicit functional tiers:
1. **Tier 1: Core Security Engine (Lightweight, Zero-Binary, Pure-Python)**
2. **Tier 2: In-Cluster & Enterprise Extensions (Decoupled, Modular, Opt-In)**

```mermaid
graph TD
    subgraph "Tier 1: Core Security Engine (Zero Dependencies)"
        AST[Manifest & AST Parser<br/><code>scanner.py</code>] --> TAX[56-Rule Taxonomy<br/><code>taxonomy.py</code>]
        AST --> DAG[Attack Path DAG Engine<br/><code>attack_graph.py</code>]
        AST --> REM[Least-Privilege Remediator<br/><code>remediate.py</code>]
        AST --> DEC[15-Operator Rule Engine<br/><code>declarative.py</code>]
        AST --> CMP[Compliance Framework Mapper<br/><code>compliance.py</code>]
        CONT[Container Layer SBOM<br/><code>container.py</code>] --> CVE[Embedded SQLite CVE DB<br/><code>cve.py</code>]
        IAC[Dockerfile & Terraform<br/><code>iac.py</code>] --> AST
    end

    subgraph "Tier 2: In-Cluster & Enterprise Extensions"
        WH[Admission Webhook<br/><code>webhook.py</code>] -.-> AST
        CRD[Kubernetes CRD Manager<br/><code>crds.py</code>] -.-> AST
        SRV[Enterprise REST Server<br/><code>enterprise_server.py</code>] --> AUTH[JWT & RBAC Auth<br/><code>auth.py</code>]
        SRV --> FLEET[Fleet Manager<br/><code>fleet.py</code>]
        SRV --> STOR[Telemetry Storage (WAL)<br/><code>storage.py</code>]
        SRV --> NOTIF[ChatOps Dispatcher<br/><code>notifications.py</code>]
        SRV --> HA[Leader Election (Lease)<br/><code>leader_election.py</code>]
        SRV --> OAPI[OpenAPI 3.0 & Swagger<br/><code>openapi.py</code>]
        EBPF[eBPF Kernel Telemetry<br/><code>ebpf.py</code>] --> STOR
    end
```

---

## 2. Tier 1: Core Security Engine Components

All Tier 1 components operate with standard Python 3.9+ libraries plus `PyYAML` and produce zero network calls during local scanning:

| Module | Primary Responsibility | Key Interfaces |
| :--- | :--- | :--- |
| [`scanner.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/scanner.py) | AST manifest auditing, Shannon entropy secrets analysis, typosquatting defense. | `NativeSecurityScanner`, `ScanReport`, `Finding` |
| [`taxonomy.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/taxonomy.py) | Authoritative 56-vulnerability taxonomy mapped across 8 security planes. | `TAXONOMY_56`, `PLANES` |
| [`attack_graph.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/attack_graph.py) | Cross-resource lateral exploit DAG construction and heuristic Blast Radius scoring. | `AttackGraphEngine`, `KillChainPath` |
| [`remediate.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/remediate.py) | Deterministic least-privilege securityContext auto-patching and diff generation. | `auto_remediate_manifest`, `format_patch_diff` |
| [`compliance.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/compliance.py) | Multi-framework regulatory auditor (PCI DSS, SOC 2, HIPAA, ISO 27001, NIST, WAF). | `ComplianceFrameworkMapper`, `ComplianceCertificate` |
| [`container.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/container.py) | In-memory OCI tarball unpacking, ELF symbol inspection, CycloneDX & SPDX SBOM generation. | `HybridContainerLayerScanner`, `SBOMScanReport` |
| [`declarative.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/declarative.py) | 15-operator declarative policy engine (regex, semver, cidr, glob, set operations). | `DeclarativeRuleEngine`, `DeclarativeRule` |
| [`iac.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/iac.py) | IaC parsing for Dockerfiles and Terraform Kubernetes HCL resources. | `DockerfileScanner`, `TerraformKubernetesScanner` |
| [`cve.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/cve.py) | Microsecond embedded SQLite vulnerability lookup with SHA-256 integrity checks. | `CVEDatabaseEngine`, `lookup_image_cves` |

---

## 3. Tier 2: Enterprise & In-Cluster Extensions

Tier 2 modules build upon the core engine to enable cluster runtime enforcement, fleet orchestration, and persistent auditing:

| Module | Primary Responsibility | Key Interfaces |
| :--- | :--- | :--- |
| [`auth.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/auth.py) | RFC 7519 HMAC-SHA256 JWT tokens, constant-time API keys, SAML 2.0 parser, 4-tier RBAC. | `EnterpriseAuthManager`, `AuthenticatedIdentity` |
| [`fleet.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/fleet.py) | Multi-cluster onboarding, KubeCam frame stream aggregation, global threat index (0-100). | `FleetManager`, `ClusterRecord`, `FleetPolicy` |
| [`storage.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/storage.py) | High-throughput SQLite persistence in Write-Ahead Logging (WAL) mode with partition pruning. | `EnterpriseStorageEngine`, `TelemetryQueryFilter` |
| [`notifications.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/notifications.py) | ChatOps incident dispatcher (Slack Block Kit, Teams Cards, PagerDuty Events v2) with SSRF guard. | `NotificationDispatcher`, `AlertPayload` |
| [`leader_election.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/leader_election.py) | Kubernetes Lease distributed lock protocol (`coordination.k8s.io`) for multi-replica HA. | `LeaderElector`, `LeaderLease` |
| [`ebpf.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/ebpf.py) | Kernel security event classifier, cgroup container attribution, and ArcSight CEF / RFC 5424 Syslog feeds (ingests from Falco, Tetragon, or out-of-process BPF probes). | `EBPFTelemetryEngine`, `SIEMForwarder` |
| [`enterprise_server.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/enterprise_server.py) | Multi-tenant REST API server, RBAC middleware, Prometheus `/metrics`, embedded web console. | `EnterpriseServer`, `EnterpriseAPIHandler` |
| [`openapi.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/openapi.py) | OpenAPI 3.0.3 specification generator and standalone interactive Swagger UI page. | `get_openapi_spec`, `get_swagger_ui_html` |
| [`webhook.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/webhook.py) | In-cluster HTTPS validating & mutating webhook controller with dynamic SAN TLS generation. | `AdmissionSecurityEngine`, `run_webhook_server` |

---

## 4. Cryptographic Primitives & Security Audit

Given the security-critical nature of identity issuance and manifest ingestion, the implementation adheres strictly to the following standards:

### 1. Ingestion Safety (YAML & JSON)
- **Zero Unsafe Deserialization**: All manifest parsing uses `yaml.safe_load`, `yaml.safe_load_all`, or `CSafeLoader`. Standard Python `yaml.load` is strictly prohibited.
- **Resource Limits**: Incoming webhook request bodies and REST payloads are bounded to 10 MB maximum to prevent memory exhaustion (DoS).

### 2. Token & Secret Cryptography ([`auth.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/auth.py))
- **Entropy Generation**: Master secrets and API keys are generated via `secrets.token_bytes(32)` (256-bit cryptographically secure pseudorandom number generator backed by OS CSPRNG `/dev/urandom`).
- **Timing-Attack Resistance**: API key hashes and JWT signatures are verified using `hmac.compare_digest()`, guaranteeing constant-time comparison to prevent side-channel timing attacks.
- **Algorithm Confusion Prevention**: During JWT verification:
  1. The header is decoded and validated as a JSON object.
  2. The `alg` claim is explicitly verified to match `"HS256"`.
  3. Tokens with `alg: "none"`, asymmetric keys (`RS256`, `ES256`), or missing headers are rejected before signature verification.
- **Clock Skew & Expiration**: Strict check of `exp` and `nbf` claims with bounded 30-second clock skew compensation.

### 3. Outbound SSRF Protection ([`notifications.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/notifications.py) & [`container.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/container.py))
- All outbound HTTP dispatchers (Slack, Teams, PagerDuty, Registry Webhooks) pass destination URLs through `validate_safe_url()`.
- Explicitly blocks:
  - AWS/GCP Instance Metadata Service (`169.254.169.254`).
  - Loopback interfaces (`127.0.0.0/8`, `::1`).
  - Private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Link-local and multicast ranges.

### 4. TLS & Webhook Certificates ([`webhook.py`](file:///Users/jayanthanayak/Side_task/native_K8S_scanner/webhook.py))
- Automatic TLS certificate generation uses Python's standard `cryptography` x509 builder.
- Generated private keys enforce `0600` permissions (`os.chmod(key_path, 0o600)`).
- Webhook HTTPS servers enforce **TLS 1.2+** with modern ECDHE cipher suites.

---

## 5. Performance Invariants & Benchmarks

The core engine is tested to sustain:
- **Cold-Start Time**: `< 10.0 ms` (measured: `< 0.01 ms`).
- **Workload Scan Latency**: `< 3.0 ms` p50 (measured: `~0.68 ms`).
- **Attack Path DAG Computation**: `< 2.0 ms` p50 (measured: `~0.12 ms`).
- **Memory Consumption**: `< 20 MB` peak (measured: `~3.2 MB` peak traced).
- **Throughput**: `> 1,000` manifests per second per core.

Reproducible benchmarks can be executed at any time via:
```bash
python3 cli.py benchmark --markdown
# or
python3 benchmarks/run_benchmarks.py --markdown
```
