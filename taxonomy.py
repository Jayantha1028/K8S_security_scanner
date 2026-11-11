"""
vulnerability_taxonomy_56.py
============================
Defines the 56-point Kubernetes Security Vulnerability Taxonomy across 7 operational planes.
Provides vulnerability metadata, detection signatures, MITRE ATT&CK & CIS/NSA references,
and an automated scanning engine that maps Kubernetes manifests, RBAC policies, and telemetry.
"""

from typing import Dict, Any, List, Optional
import os
import yaml

# The 7 Operational Defense Planes
PLANES = {
    1: "Pod Security & Kernel Capabilities",
    2: "Supply Chain & Container Images",
    3: "Identity, RBAC & Service Accounts",
    4: "Network Perimeter & Ingress",
    5: "Control Plane, Infrastructure & etcd",
    6: "Volumes, Host Storage & Secrets Management",
    7: "Runtime Kernel Telemetry & Exploitation Signals"
}

# The 56 Vulnerabilities Definition
TAXONOMY_56: Dict[str, Dict[str, Any]] = {
    # ---------------- Plane 1: Pod Security & Kernel Capabilities ----------------
    "V01": {
        "id": "V01",
        "plane": 1,
        "name": "Privileged Container Execution",
        "severity": "CRITICAL",
        "standard": "CIS 5.2.1 / C-0057",
        "mitre": "T1611",
        "description": "Container executes with privileged: true, giving direct kernel access to all host devices.",
        "remediation": "Set securityContext.privileged: false"
    },
    "V02": {
        "id": "V02",
        "plane": 1,
        "name": "Root User Execution (UID 0)",
        "severity": "HIGH",
        "standard": "CIS 5.2.6 / C-0013",
        "mitre": "T1611",
        "description": "Container runs as UID 0 (root), facilitating kernel exploit escalation.",
        "remediation": "Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser"
    },
    "V03": {
        "id": "V03",
        "plane": 1,
        "name": "Privilege Escalation Allowed",
        "severity": "HIGH",
        "standard": "CIS 5.2.5 / C-0016",
        "mitre": "T1548",
        "description": "Container allows setuid binaries to elevate process privileges.",
        "remediation": "Set securityContext.allowPrivilegeEscalation: false"
    },
    "V04": {
        "id": "V04",
        "plane": 1,
        "name": "Writable Root Filesystem",
        "severity": "MEDIUM",
        "standard": "CIS 5.2.12 / C-0017",
        "mitre": "T1222",
        "description": "Container root filesystem is writable, allowing malware or rootkit downloads.",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true and use emptyDir for temporary writes"
    },
    "V05": {
        "id": "V05",
        "plane": 1,
        "name": "Dangerous Capability CAP_SYS_ADMIN Added",
        "severity": "CRITICAL",
        "standard": "MITRE T1611 / C-0046",
        "mitre": "T1611",
        "description": "Grants virtual root permissions including mounting filesystems and ptrace.",
        "remediation": "Remove CAP_SYS_ADMIN from capabilities.add"
    },
    "V06": {
        "id": "V06",
        "plane": 1,
        "name": "Dangerous Capabilities CAP_NET_ADMIN/RAW Added",
        "severity": "HIGH",
        "standard": "MITRE T1040 / C-0046",
        "mitre": "T1040",
        "description": "Enables raw packet sniffing, ARP spoofing, and routing table manipulation.",
        "remediation": "Remove CAP_NET_ADMIN and CAP_NET_RAW from capabilities.add"
    },
    "V07": {
        "id": "V07",
        "plane": 1,
        "name": "Dangerous Capability CAP_SYS_PTRACE Added",
        "severity": "HIGH",
        "standard": "MITRE T1055 / C-0046",
        "mitre": "T1055",
        "description": "Allows debugging and inspecting memory of other host or container processes.",
        "remediation": "Remove CAP_SYS_PTRACE from capabilities.add"
    },
    "V08": {
        "id": "V08",
        "plane": 1,
        "name": "Capabilities Not Dropped (Missing drop: ALL)",
        "severity": "MEDIUM",
        "standard": "CIS 5.2.7 / C-0046",
        "mitre": "T1611",
        "description": "Container retains default Linux capabilities rather than starting minimal.",
        "remediation": "Add securityContext.capabilities.drop: ['ALL']"
    },
    "V09": {
        "id": "V09",
        "plane": 1,
        "name": "Host Network Namespace Sharing (hostNetwork: true)",
        "severity": "HIGH",
        "standard": "CIS 5.2.4 / C-0041",
        "mitre": "T1611",
        "description": "Shares the host node's network namespace, bypassing network isolation.",
        "remediation": "Set spec.hostNetwork: false"
    },
    "V10": {
        "id": "V10",
        "plane": 1,
        "name": "Host PID Namespace Sharing (hostPID: true)",
        "severity": "CRITICAL",
        "standard": "CIS 5.2.2 / C-0042",
        "mitre": "T1611",
        "description": "Shares host process namespace; container can inspect or kill host OS processes.",
        "remediation": "Set spec.hostPID: false"
    },
    "V11": {
        "id": "V11",
        "plane": 1,
        "name": "Host IPC Namespace Sharing (hostIPC: true)",
        "severity": "HIGH",
        "standard": "CIS 5.2.3 / C-0043",
        "mitre": "T1611",
        "description": "Shares host Inter-Process Communication, permitting shared memory inspection.",
        "remediation": "Set spec.hostIPC: false"
    },
    "V12": {
        "id": "V12",
        "plane": 1,
        "name": "Missing Seccomp Profile",
        "severity": "MEDIUM",
        "standard": "CIS 5.7.2 / C-0030",
        "mitre": "T1059",
        "description": "Container issues system calls without seccomp filtering.",
        "remediation": "Set securityContext.seccompProfile.type: RuntimeDefault"
    },
    "V13": {
        "id": "V13",
        "plane": 1,
        "name": "Missing CPU Resource Limit",
        "severity": "LOW",
        "standard": "CIS 5.2.13 / C-0009",
        "mitre": "T1496",
        "description": "Containers without CPU quotas can starve other workloads on the node.",
        "remediation": "Define resources.limits.cpu"
    },
    "V14": {
        "id": "V14",
        "plane": 1,
        "name": "Missing Memory Resource Limit",
        "severity": "MEDIUM",
        "standard": "CIS 5.2.14 / C-0009",
        "mitre": "T1496",
        "description": "Containers without memory limits can trigger node-wide OOM panics.",
        "remediation": "Define resources.limits.memory"
    },

    # ---------------- Plane 2: Supply Chain & Container Images ----------------
    "V15": {
        "id": "V15",
        "plane": 2,
        "name": "Floating or Untagged Image Tag (:latest)",
        "severity": "MEDIUM",
        "standard": "NSA Ch. 2 / C-0019",
        "mitre": "T1525",
        "description": "Image uses mutable tag like :latest or no tag, breaking reproducibility.",
        "remediation": "Pin container image tags or use immutable SHA256 digests"
    },
    "V16": {
        "id": "V16",
        "plane": 2,
        "name": "Critical Severity Image CVE (CVSS >= 9.0)",
        "severity": "CRITICAL",
        "standard": "NIST SP 800-190",
        "mitre": "T1190",
        "description": "Known remote code execution vulnerability in container packages.",
        "remediation": "Patch image base layers or update vulnerable dependencies"
    },
    "V17": {
        "id": "V17",
        "plane": 2,
        "name": "High Severity Image CVE (CVSS 7.0 - 8.9)",
        "severity": "HIGH",
        "standard": "NIST SP 800-190",
        "mitre": "T1190",
        "description": "High-severity vulnerabilities enabling privilege escalation or DoS.",
        "remediation": "Update package dependencies or rebuild on patched base image"
    },
    "V18": {
        "id": "V18",
        "plane": 2,
        "name": "Plaintext Secrets Hardcoded in Manifests/Images",
        "severity": "CRITICAL",
        "standard": "MITRE T1552 / Trivy",
        "mitre": "T1552",
        "description": "API tokens, private keys, or passwords embedded in YAML or image layers.",
        "remediation": "Use Kubernetes Secret references or external secret stores (Vault)"
    },
    "V19": {
        "id": "V19",
        "plane": 2,
        "name": "Unverified Image Signature (Missing Cosign/Notary)",
        "severity": "HIGH",
        "standard": "NSA Ch. 2",
        "mitre": "T1525",
        "description": "Image provenance and digital cryptographic signature are not validated.",
        "remediation": "Enforce signature admission verification with Cosign or Kyverno"
    },
    "V20": {
        "id": "V20",
        "plane": 2,
        "name": "Outdated / Heavyweight Base OS Image",
        "severity": "LOW",
        "standard": "CIS 5.4.1",
        "mitre": "T1059",
        "description": "Using bloated OS distributions containing package managers (apt, curl).",
        "remediation": "Migrate to minimal distroless or Alpine base images"
    },
    "V21": {
        "id": "V21",
        "plane": 2,
        "name": "Risky ImagePullPolicy (IfNotPresent with mutable tags)",
        "severity": "MEDIUM",
        "standard": "NSA Ch. 2",
        "mitre": "T1525",
        "description": "Node image cache poisoning risk when using mutable tags without Always.",
        "remediation": "Set imagePullPolicy: Always when using mutable tags"
    },
    "V22": {
        "id": "V22",
        "plane": 2,
        "name": "Default or Hardcoded Root Password Configured",
        "severity": "HIGH",
        "standard": "MITRE T1078",
        "mitre": "T1078",
        "description": "Environment variables configure root credentials directly in workload specs.",
        "remediation": "Inject credentials via secretKeyRef instead of plaintext literals"
    },

    # ---------------- Plane 3: Identity, RBAC & Service Accounts ----------------
    "V23": {
        "id": "V23",
        "plane": 3,
        "name": "Unnecessary Service Account Token Auto-Mount",
        "severity": "MEDIUM",
        "standard": "CIS 5.1.5 / C-0034",
        "mitre": "T1078.004",
        "description": "API server token is mounted automatically even when pod does not use it.",
        "remediation": "Set automountServiceAccountToken: false"
    },
    "V24": {
        "id": "V24",
        "plane": 3,
        "name": "Wildcard Resource Access in RBAC (resources: ['*'])",
        "severity": "CRITICAL",
        "standard": "CIS 5.1.3 / C-0021",
        "mitre": "T1078",
        "description": "Grants access to all current and future API resources in the cluster.",
        "remediation": "Explicitly enumerate required resources (e.g. pods, deployments)"
    },
    "V25": {
        "id": "V25",
        "plane": 3,
        "name": "Wildcard Verb Access in RBAC (verbs: ['*'])",
        "severity": "CRITICAL",
        "standard": "CIS 5.1.3 / C-0021",
        "mitre": "T1078",
        "description": "Grants blanket operations (get, list, delete, escalate, patch).",
        "remediation": "Scope verbs strictly to least-privilege operations (get, list)"
    },
    "V26": {
        "id": "V26",
        "plane": 3,
        "name": "Cluster-Admin Privileges Bound to Workload",
        "severity": "CRITICAL",
        "standard": "CIS 5.1.1 / C-0035",
        "mitre": "T1078",
        "description": "ClusterRoleBinding links application ServiceAccount to cluster-admin.",
        "remediation": "Use namespaced Roles with scoped permissions"
    },
    "V27": {
        "id": "V27",
        "plane": 3,
        "name": "RBAC Permission to Exec into Pods (pods/exec)",
        "severity": "HIGH",
        "standard": "MITRE T1609",
        "mitre": "T1609",
        "description": "Allows executing arbitrary shell commands inside any running container.",
        "remediation": "Restrict pods/exec verb strictly to designated administrative roles"
    },
    "V28": {
        "id": "V28",
        "plane": 3,
        "name": "RBAC Permission to Read/List Secrets",
        "severity": "CRITICAL",
        "standard": "MITRE T1552.007",
        "mitre": "T1552",
        "description": "Allows retrieving sensitive cryptographic keys and cluster credentials.",
        "remediation": "Remove get/list/watch on secrets for regular workload service accounts"
    },
    "V29": {
        "id": "V29",
        "plane": 3,
        "name": "RBAC Privilege Escalation Verbs (bind / escalate)",
        "severity": "CRITICAL",
        "standard": "CIS 5.1.4",
        "mitre": "T1548",
        "description": "Allows binding permissions higher than the caller's existing rights.",
        "remediation": "Remove bind and escalate verbs from custom roles"
    },
    "V30": {
        "id": "V30",
        "plane": 3,
        "name": "Default Service Account Assigned Permissions",
        "severity": "MEDIUM",
        "standard": "CIS 5.1.5",
        "mitre": "T1078.004",
        "description": "Assigning RBAC roles to the default service account leaks rights to all pods.",
        "remediation": "Create dedicated, uniquely named ServiceAccounts per application"
    },

    # ---------------- Plane 4: Network Perimeter & Ingress ----------------
    "V31": {
        "id": "V31",
        "plane": 4,
        "name": "Missing Default-Deny Ingress NetworkPolicy",
        "severity": "HIGH",
        "standard": "CIS 5.3.2 / C-0066",
        "mitre": "T1210",
        "description": "Namespace lacks default-deny ingress policy; any pod can probe any other.",
        "remediation": "Deploy a default-deny ingress NetworkPolicy in every tenant namespace"
    },
    "V32": {
        "id": "V32",
        "plane": 4,
        "name": "Missing Default-Deny Egress NetworkPolicy",
        "severity": "HIGH",
        "standard": "NSA Ch. 3 / C-0066",
        "mitre": "T1071",
        "description": "Compromised pods can establish unrestricted outbound connections to C2.",
        "remediation": "Deploy a default-deny egress NetworkPolicy and allow only verified CIDRs"
    },
    "V33": {
        "id": "V33",
        "plane": 4,
        "name": "Direct hostPort Allocation",
        "severity": "HIGH",
        "standard": "CIS 5.2.10",
        "mitre": "T1046",
        "description": "Exposes ports directly on host node IP, bypassing cluster NetworkPolicies.",
        "remediation": "Use ClusterIP Services with Ingress controllers instead of hostPort"
    },
    "V34": {
        "id": "V34",
        "plane": 4,
        "name": "Unrestricted Ingress CIDR (0.0.0.0/0 on sensitive ports)",
        "severity": "HIGH",
        "standard": "MITRE T1190",
        "mitre": "T1190",
        "description": "Exposes internal management or debug ports to the entire public internet.",
        "remediation": "Restrict ingress CIDRs and enforce API gateway authentication"
    },
    "V35": {
        "id": "V35",
        "plane": 4,
        "name": "Plaintext In-Transit Traffic (Missing mTLS)",
        "severity": "MEDIUM",
        "standard": "NSA Ch. 3",
        "mitre": "T1040",
        "description": "Pod-to-pod traffic lacks cryptographic encryption and authentication.",
        "remediation": "Enforce mutual TLS (mTLS) via service mesh (Istio/Linkerd)"
    },
    "V36": {
        "id": "V36",
        "plane": 4,
        "name": "Overexposed NodePort Service (Ports 30000-32767)",
        "severity": "MEDIUM",
        "standard": "CIS 5.3.1",
        "mitre": "T1046",
        "description": "Opens node-level listener across all cluster nodes without routing control.",
        "remediation": "Replace NodePort with standard Ingress or internal LoadBalancer"
    },
    "V37": {
        "id": "V37",
        "plane": 4,
        "name": "Unrestricted Internal CoreDNS Querying",
        "severity": "LOW",
        "standard": "MITRE T1071.004",
        "mitre": "T1071",
        "description": "Allows pods to resolve arbitrary cluster services and probe DNS topology.",
        "remediation": "Implement DNS policy scoping or CoreDNS security plugins"
    },

    # ---------------- Plane 5: Control Plane, Infrastructure & etcd ----------------
    "V38": {
        "id": "V38",
        "plane": 5,
        "name": "Anonymous Authentication Enabled on API Server",
        "severity": "CRITICAL",
        "standard": "CIS 1.2.1",
        "mitre": "T1078",
        "description": "API server accepts unauthenticated requests (--anonymous-auth=true).",
        "remediation": "Set --anonymous-auth=false on kube-apiserver"
    },
    "V39": {
        "id": "V39",
        "plane": 5,
        "name": "Unencrypted etcd Client/Peer Communication",
        "severity": "CRITICAL",
        "standard": "CIS 2.1-2.4",
        "mitre": "T1552",
        "description": "etcd cluster communication lacks mutual TLS certificates.",
        "remediation": "Configure --cert-file, --key-file, and --client-cert-auth for etcd"
    },
    "V40": {
        "id": "V40",
        "plane": 5,
        "name": "Missing Kubernetes API Audit Logging",
        "severity": "HIGH",
        "standard": "CIS 1.2.19-1.2.21",
        "mitre": "T1562",
        "description": "API requests are not recorded to audit logs, preventing forensic analysis.",
        "remediation": "Configure --audit-log-path and --audit-policy-file on API server"
    },
    "V41": {
        "id": "V41",
        "plane": 5,
        "name": "Kubelet Anonymous Access Enabled (Port 10250)",
        "severity": "CRITICAL",
        "standard": "CIS 4.2.1",
        "mitre": "T1609",
        "description": "Allows executing commands on nodes via unauthenticated kubelet endpoints.",
        "remediation": "Set authentication.anonymous.enabled: false in KubeletConfig"
    },
    "V42": {
        "id": "V42",
        "plane": 5,
        "name": "Kubelet Read-Only Port Enabled (Port 10255)",
        "severity": "HIGH",
        "standard": "CIS 4.2.4",
        "mitre": "T1082",
        "description": "Exposes node workload metrics and pod metadata without authentication.",
        "remediation": "Set readOnlyPort: 0 in KubeletConfiguration"
    },
    "V43": {
        "id": "V43",
        "plane": 5,
        "name": "Missing Admission Controllers (NodeRestriction/PodSecurity)",
        "severity": "HIGH",
        "standard": "CIS 1.2.14-1.2.17",
        "mitre": "T1562",
        "description": "NodeRestriction or PodSecurity admission plugins are inactive.",
        "remediation": "Add NodeRestriction and PodSecurity to --enable-admission-plugins"
    },
    "V44": {
        "id": "V44",
        "plane": 5,
        "name": "Cloud Metadata Service (IMDSv1) Accessible to Pods",
        "severity": "CRITICAL",
        "standard": "MITRE T1552.005",
        "mitre": "T1552",
        "description": "Pods can query 169.254.169.254 to steal AWS IAM / GCP node credentials.",
        "remediation": "Block 169.254.169.254 via NetworkPolicy or enforce IMDSv2 hop limit=1"
    },

    # ---------------- Plane 6: Volumes, Host Storage & Secrets Management ----------------
    "V45": {
        "id": "V45",
        "plane": 6,
        "name": "HostPath Mount: Root Directory (/)",
        "severity": "CRITICAL",
        "standard": "CIS 5.2.8 / C-0048",
        "mitre": "T1611",
        "description": "Container mounts the host node root directory, enabling full node compromise.",
        "remediation": "Restrict hostPath volume mounts using admission control"
    },
    "V46": {
        "id": "V46",
        "plane": 6,
        "name": "HostPath Mount: Docker / Containerd Socket",
        "severity": "CRITICAL",
        "standard": "CIS 5.2.8 / MITRE T1611",
        "mitre": "T1611",
        "description": "Mounting /var/run/docker.sock allows spawning sibling privileged containers.",
        "remediation": "Never mount container runtime sockets inside workloads"
    },
    "V47": {
        "id": "V47",
        "plane": 6,
        "name": "HostPath Mount: Node Configuration (/etc, /var/log)",
        "severity": "HIGH",
        "standard": "CIS 5.2.8",
        "mitre": "T1083",
        "description": "Permits reading or modifying node configuration files and audit logs.",
        "remediation": "Disallow mounting sensitive host system paths"
    },
    "V48": {
        "id": "V48",
        "plane": 6,
        "name": "Unencrypted Kubernetes Secrets at Rest in etcd",
        "severity": "HIGH",
        "standard": "CIS 1.2.29",
        "mitre": "T1552",
        "description": "Secrets stored in plaintext in etcd without an EncryptionConfiguration provider.",
        "remediation": "Enable encryption at rest with KMS (aescbc/aesgcm/secretbox)"
    },
    "V49": {
        "id": "V49",
        "plane": 6,
        "name": "Sensitive Secrets Exposed via Environment Variables",
        "severity": "MEDIUM",
        "standard": "NSA Ch. 4",
        "mitre": "T1552",
        "description": "Secrets in environment variables can be inspected via /proc/<pid>/environ.",
        "remediation": "Mount secrets as read-only volume files rather than env vars"
    },
    "V50": {
        "id": "V50",
        "plane": 6,
        "name": "Unconstrained PersistentVolume Access Mode",
        "severity": "LOW",
        "standard": "CIS 5.2.9",
        "mitre": "T1083",
        "description": "ReadWriteMany volume permissions allow concurrent tampering across pods.",
        "remediation": "Use ReadWriteOnce unless multi-pod write concurrency is strictly required"
    },

    # ---------------- Plane 7: Runtime Kernel Telemetry & Exploitation Signals ----------------
    "V51": {
        "id": "V51",
        "plane": 7,
        "name": "Interactive Shell Spawned in Running Container",
        "severity": "HIGH",
        "standard": "Falco: Terminal shell in container",
        "mitre": "T1059",
        "description": "Execution of /bin/bash, /bin/sh, or python interactive shell at runtime.",
        "remediation": "Investigate pod exec activity; use ephemeral debug containers"
    },
    "V52": {
        "id": "V52",
        "plane": 7,
        "name": "Outbound Network Reconnaissance Tool Launched",
        "severity": "HIGH",
        "standard": "Falco: Network tool launched",
        "mitre": "T1046",
        "description": "Running nmap, netcat, or dig inside production container.",
        "remediation": "Strip networking utilities from production container images"
    },
    "V53": {
        "id": "V53",
        "plane": 7,
        "name": "System Binary or /etc Modification Attempt",
        "severity": "CRITICAL",
        "standard": "Falco: File below etc altered",
        "mitre": "T1222",
        "description": "Runtime modification of /etc/passwd, /etc/shadow, or system binaries.",
        "remediation": "Enforce read-only root filesystems and alert immediately"
    },
    "V54": {
        "id": "V54",
        "plane": 7,
        "name": "Kernel Module Loading Syscall (init_module / finit_module)",
        "severity": "CRITICAL",
        "standard": "Falco: Kernel module injection",
        "mitre": "T1547",
        "description": "Attempt to inject kernel modules or rootkits into the host OS kernel.",
        "remediation": "Drop CAP_SYS_MODULE and restrict node host access"
    },
    "V55": {
        "id": "V55",
        "plane": 7,
        "name": "Outbound Connection to Known Crypto-Mining Pool",
        "severity": "HIGH",
        "standard": "Falco: Detect outbound cryptomining",
        "mitre": "T1496",
        "description": "Network traffic to Stratum or known Monero mining pool ports (3333/5555).",
        "remediation": "Terminate pod immediately and quarantine compromised credentials"
    },
    "V56": {
        "id": "V56",
        "plane": 7,
        "name": "Reading Sensitive Kernel / Host Memory (/proc/kcore, /dev/mem)",
        "severity": "CRITICAL",
        "standard": "Falco: Read sensitive file untrusted",
        "mitre": "T1005",
        "description": "Direct memory dump attempt to extract keys or bypass kernel ASLR.",
        "remediation": "Block /dev and /proc access and isolate node"
    }
}


def scan_manifest_for_vulnerabilities(doc: Dict[str, Any]) -> List[str]:
    """
    Scans a Kubernetes YAML document and returns the detected vulnerability IDs (e.g. ['V01', 'V02']).
    """
    detected = []
    if not isinstance(doc, dict):
        return detected

    kind = doc.get("kind", "")
    metadata = doc.get("metadata", {}) or {}

    # Extract Pod Spec safely
    pod_spec = {}
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    if kind == "Pod":
        pod_spec = spec
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        tmpl = spec.get("template") if isinstance(spec.get("template"), dict) else {}
        pod_spec = tmpl.get("spec") if isinstance(tmpl.get("spec"), dict) else {}
    elif kind == "CronJob":
        job_tmpl = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
        job_spec = job_tmpl.get("spec") if isinstance(job_tmpl.get("spec"), dict) else {}
        tmpl = job_spec.get("template") if isinstance(job_spec.get("template"), dict) else {}
        pod_spec = tmpl.get("spec") if isinstance(tmpl.get("spec"), dict) else {}

    # ---------------- Plane 3: RBAC Documents ----------------
    if kind in {"Role", "ClusterRole"}:
        rules = doc.get("rules") or []
        for r in rules:
            if not isinstance(r, dict):
                continue
            res = r.get("resources") or []
            verbs = r.get("verbs") or []
            if "*" in res:
                detected.append("V24")
            if "*" in verbs:
                detected.append("V25")
            if "pods/exec" in res or "exec" in res:
                detected.append("V27")
            if "secrets" in res:
                detected.append("V28")
            if "bind" in verbs or "escalate" in verbs:
                detected.append("V29")

    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        role_ref = doc.get("roleRef", {}) if isinstance(doc.get("roleRef"), dict) else {}
        subjects = doc.get("subjects") or []
        if role_ref.get("name") == "cluster-admin":
            detected.append("V26")
        for s in subjects:
            if isinstance(s, dict) and s.get("name") == "default":
                detected.append("V30")

    # ---------------- Plane 4: Network Policies & Services ----------------
    if kind == "Service":
        spec_svc = doc.get("spec", {}) if isinstance(doc.get("spec"), dict) else {}
        if spec_svc.get("type") == "NodePort":
            detected.append("V36")

    # ---------------- Workload Scanning ----------------
    if not pod_spec or not isinstance(pod_spec, dict):
        return sorted(list(set(detected)))

    pod_sec = pod_spec.get("securityContext", {}) if isinstance(pod_spec.get("securityContext"), dict) else {}

    # Host Namespaces
    if pod_spec.get("hostNetwork"):
        detected.append("V09")
    if pod_spec.get("hostPID"):
        detected.append("V10")
    if pod_spec.get("hostIPC"):
        detected.append("V11")

    # Service Account Token
    if pod_spec.get("automountServiceAccountToken") is not False:
        detected.append("V23")

    # HostPath Volumes
    volumes = pod_spec.get("volumes") or []
    for vol in volumes:
        if not isinstance(vol, dict):
            continue
        hp = vol.get("hostPath") if isinstance(vol.get("hostPath"), dict) else None
        if hp:
            path = hp.get("path", "")
            if path in {"/", "/root"}:
                detected.append("V45")
            elif "docker.sock" in path or "containerd.sock" in path:
                detected.append("V46")
            elif path.startswith("/etc") or path.startswith("/var/log"):
                detected.append("V47")

    # Containers
    raw_containers = (
        (pod_spec.get("containers") or [])
        + (pod_spec.get("initContainers") or [])
        + (pod_spec.get("ephemeralContainers") or [])
    )
    containers = [c for c in raw_containers if isinstance(c, dict)]

    for c in containers:
        c_sec = c.get("securityContext", {}) if isinstance(c.get("securityContext"), dict) else {}
        image = str(c.get("image", ""))

        # Floating Tag / Image Checks
        if image:
            last_part = image.split("/")[-1]
            if "@sha256:" not in image and (":" not in last_part or last_part.endswith(":latest")):
                detected.append("V15")

        # Privileged
        if c_sec.get("privileged"):
            detected.append("V01")

        # Root User
        uid = c_sec.get("runAsUser", pod_sec.get("runAsUser"))
        non_root = c_sec.get("runAsNonRoot", pod_sec.get("runAsNonRoot"))
        if uid == 0 or (uid is None and non_root is not True):
            detected.append("V02")

        # Privilege Escalation
        if c_sec.get("allowPrivilegeEscalation", True):
            detected.append("V03")

        # Root Filesystem
        if c_sec.get("readOnlyRootFilesystem", False) is not True:
            detected.append("V04")

        # Capabilities
        caps = c_sec.get("capabilities") or {}
        drop = [str(x).upper() for x in (caps.get("drop") or [])]
        add = [str(x).upper() for x in (caps.get("add") or [])]

        if "ALL" not in drop:
            detected.append("V08")
        if "CAP_SYS_ADMIN" in add or "SYS_ADMIN" in add:
            detected.append("V05")
        if any(x in add for x in ["CAP_NET_ADMIN", "NET_ADMIN", "CAP_NET_RAW", "NET_RAW"]):
            detected.append("V06")
        if "CAP_SYS_PTRACE" in add or "SYS_PTRACE" in add:
            detected.append("V07")

        # Seccomp
        seccomp = c_sec.get("seccompProfile", pod_sec.get("seccompProfile"))
        if not seccomp:
            detected.append("V12")

        # Resources Limits
        res = c.get("resources") or {}
        limits = res.get("limits") or {}
        if "cpu" not in limits:
            detected.append("V13")
        if "memory" not in limits:
            detected.append("V14")

        # HostPorts
        ports = c.get("ports") or []
        for p in ports:
            if p.get("hostPort"):
                detected.append("V33")

        # Secrets in ENV
        env = c.get("env") or []
        for e in env:
            val = str(e.get("value", "")).lower()
            name = str(e.get("name", "")).lower()
            if any(k in name for k in ["password", "secret", "token", "apikey", "api_key"]) and val:
                detected.append("V18")
                detected.append("V49")

    return sorted(list(set(detected)))


def scan_file_for_vulnerabilities(filepath: str) -> List[str]:
    """Scans a YAML manifest file (all documents) for the 56 vulnerabilities."""
    detected = set()
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if isinstance(doc, dict):
                    detected.update(scan_manifest_for_vulnerabilities(doc))
    except Exception:
        pass
    return sorted(list(detected))
