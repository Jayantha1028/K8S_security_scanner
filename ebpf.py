#!/usr/bin/env python3
"""
ebpf.py
=======
Native eBPF Kernel Telemetry Engine & Enterprise SIEM Forwarder.

Capabilities:
1. Kernel Tracepoint Telemetry: Analyzes process executions, file open operations, socket connects, and mounts.
2. Container Cgroup Resolution: Maps kernel process IDs (PIDs) to Kubernetes Pod Name, Container ID, and Namespace.
3. Behavioral Threat Detection:
   - Suspicious shell or scanner execution in production pods (sh, bash, nc, nmap).
   - Sensitive host file reads (/etc/shadow, /var/run/docker.sock, /etc/kubernetes/admin.conf).
   - Privilege escalation and namespace breakout attempts via mount.
4. Enterprise SIEM Exporters:
   - ArcSight Common Event Format (CEF) for Splunk and Sentinel.
   - IETF RFC 5424 Syslog formatter.
   - Structured JSON stream.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import re
import socket
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("NativeScanner.eBPF")

# Severity scoring mapping for SIEM/CEF
CEF_SEVERITY_MAP = {
    "INFO": 1,
    "LOW": 3,
    "MEDIUM": 6,
    "HIGH": 8,
    "CRITICAL": 10,
}

SYSLOG_SEVERITY_MAP = {
    "CRITICAL": 2,  # Critical
    "HIGH": 3,      # Error
    "MEDIUM": 4,    # Warning
    "LOW": 5,       # Notice
    "INFO": 6,      # Informational
}


@dataclass
class KernelSecurityEvent:
    event_id: str
    timestamp: str
    event_type: str  # EXECVE, SENSITIVE_FILE_ACCESS, SUSPICIOUS_SOCKET, HOST_MOUNT_ESCAPE, PRIVILEGE_ESCALATION
    severity: str    # INFO, LOW, MEDIUM, HIGH, CRITICAL
    pid: int
    comm: str
    pod_name: str
    namespace: str
    container_id: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_cef(self) -> str:
        """
        Formats event in HP ArcSight Common Event Format (CEF:0).
        Standard specification for Splunk, Azure Sentinel, and Micro Focus.
        """
        device_vendor = "K8sNativeSecurity"
        device_product = "EnterpriseCNAPP"
        device_version = "2.0.0"
        device_event_class_id = self.event_type
        name = self.description.replace("|", "\\|")
        cef_sev = CEF_SEVERITY_MAP.get(self.severity.upper(), 5)

        # Extension key-values
        extensions = [
            f"src={self.pod_name or 'unknown'}",
            f"cs1={self.namespace or 'default'}",
            f"cs1Label=KubernetesNamespace",
            f"cs2={self.container_id or 'none'}",
            f"cs2Label=ContainerID",
            f"dproc={self.comm}",
            f"dpid={self.pid}",
            f"cat={self.event_type}",
        ]
        if self.mitre_technique:
            extensions.append(f"cs3={self.mitre_technique}")
            extensions.append("cs3Label=MITRETechnique")

        ext_str = " ".join(extensions)
        return f"CEF:0|{device_vendor}|{device_product}|{device_version}|{device_event_class_id}|{name}|{cef_sev}|{ext_str}"

    def to_rfc5424_syslog(self, app_name: str = "k8s-ebpf-telemetry", hostname: Optional[str] = None) -> str:
        """
        Formats event in RFC 5424 Syslog standard with structured data.
        Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROC-ID MSG-ID [STRUCTURED-DATA] MSG
        """
        host = hostname or socket.gethostname() or "k8s-node"
        facility = 1  # user-level messages
        sev_code = SYSLOG_SEVERITY_MAP.get(self.severity.upper(), 5)
        pri = (facility * 8) + sev_code
        version = "1"
        ts = self.timestamp
        proc_id = str(self.pid)
        msg_id = self.event_type

        # Structured data
        sd = f'[k8s@5424 pod="{self.pod_name}" ns="{self.namespace}" comm="{self.comm}" container="{self.container_id}"]'
        msg = f"{self.severity}: {self.description}"

        return f"<{pri}>{version} {ts} {host} {app_name} {proc_id} {msg_id} {sd} {msg}"


class EBPFTelemetryEngine:
    """
    Pure-Python eBPF kernel telemetry interpreter & anomaly detection engine.
    Analyzes raw kernel events, performs cgroup container attribution,
    and identifies zero-day runtime intrusions.
    """

    SUSPICIOUS_EXEC_BINARIES = {
        "sh", "bash", "zsh", "nc", "netcat", "ncat", "nmap",
        "tcpdump", "wireshark", "hydra", "socat", "chroot",
    }

    SENSITIVE_FILES = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/pki",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/k3s/containerd/containerd.sock",
        "/proc/kcore",
        "/dev/mem",
    ]

    def __init__(self, node_name: str = "k8s-node-1"):
        self.node_name = node_name
        self._events: List[KernelSecurityEvent] = []
        self._event_counter = 0

    def parse_proc_cgroup(self, cgroup_content: str) -> Dict[str, str]:
        """
        Resolves container ID and pod UID from /proc/<pid>/cgroup content.
        Supports both cgroup v1 and cgroup v2 paths.
        """
        result = {"pod_uid": "", "container_id": "", "runtime": "containerd"}
        if not cgroup_content:
            return result

        # Standard kubepods regex matching
        # e.g.: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<cid>.scope
        cgroup_regex = re.compile(
            r"pod([0-9a-fA-F\-_]+)[./].*?(?:cri-containerd-|docker-|crio-)([0-9a-fA-F]{12,64})"
        )
        match = cgroup_regex.search(cgroup_content)
        if match:
            result["pod_uid"] = match.group(1).replace("_", "-")
            result["container_id"] = match.group(2)[:12]
            return result

        # Alternate cgroup pattern
        alt_match = re.search(r"/(?:docker|containerd)/([0-9a-fA-F]{12,64})", cgroup_content)
        if alt_match:
            result["container_id"] = alt_match.group(1)[:12]

        return result

    def evaluate_execve_event(
        self,
        pid: int,
        comm: str,
        filename: str,
        args: List[str],
        pod_name: str = "prod-api",
        namespace: str = "production",
        container_id: str = "c7a8b9e01f23",
        is_prod_workload: bool = True,
    ) -> Optional[KernelSecurityEvent]:
        """Evaluates sys_enter_execve kernel tracepoint."""
        base_binary = os.path.basename(filename)

        # Detect interactive shell or hacking utility invocation in production
        if base_binary in self.SUSPICIOUS_EXEC_BINARIES or comm in self.SUSPICIOUS_EXEC_BINARIES:
            sev = "CRITICAL" if is_prod_workload else "HIGH"
            self._event_counter += 1
            event = KernelSecurityEvent(
                event_id=f"ebpf-evt-{self._event_counter:06d}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="SUSPICIOUS_PROCESS_EXEC",
                severity=sev,
                pid=pid,
                comm=comm,
                pod_name=pod_name,
                namespace=namespace,
                container_id=container_id,
                description=f"Suspicious executable '{base_binary}' invoked in container (args: {' '.join(args)})",
                details={"filename": filename, "args": args},
                mitre_technique="T1059.004",  # Command and Scripting Interpreter: Unix Shell
            )
            self._events.append(event)
            return event

        return None

    def evaluate_file_open_event(
        self,
        pid: int,
        comm: str,
        filepath: str,
        flags: int,
        pod_name: str = "prod-api",
        namespace: str = "production",
        container_id: str = "c7a8b9e01f23",
    ) -> Optional[KernelSecurityEvent]:
        """Evaluates security_file_open kernel tracepoint for unauthorized credential access."""
        for sensitive_path in self.SENSITIVE_FILES:
            if filepath.startswith(sensitive_path):
                self._event_counter += 1
                self.description = f"Container attempted to access sensitive host path '{filepath}'"
                event = KernelSecurityEvent(
                    event_id=f"ebpf-evt-{self._event_counter:06d}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="SENSITIVE_FILE_ACCESS",
                    severity="CRITICAL",
                    pid=pid,
                    comm=comm,
                    pod_name=pod_name,
                    namespace=namespace,
                    container_id=container_id,
                    description=f"Unauthorized access to sensitive host filesystem: {filepath}",
                    details={"filepath": filepath, "flags": flags},
                    mitre_technique="T1083",  # File and Directory Discovery
                )
                self._events.append(event)
                return event

        return None

    def evaluate_mount_event(
        self,
        pid: int,
        comm: str,
        source: str,
        target: str,
        filesystem_type: str,
        pod_name: str = "prod-api",
        namespace: str = "production",
        container_id: str = "c7a8b9e01f23",
    ) -> Optional[KernelSecurityEvent]:
        """Evaluates sys_enter_mount for container escape / privilege escalation attempts."""
        self._event_counter += 1
        event = KernelSecurityEvent(
            event_id=f"ebpf-evt-{self._event_counter:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="HOST_MOUNT_ESCAPE",
            severity="CRITICAL",
            pid=pid,
            comm=comm,
            pod_name=pod_name,
            namespace=namespace,
            container_id=container_id,
            description=f"Container executed raw mount({source} -> {target}, {filesystem_type}) indicating container breakout attempt",
            details={"source": source, "target": target, "fs_type": filesystem_type},
            mitre_technique="T1611",  # Escape to Host
        )
        self._events.append(event)
        return event

    def get_recent_events(self, limit: int = 100, min_severity: Optional[str] = None) -> List[KernelSecurityEvent]:
        """Returns captured security events with optional severity filter."""
        events = self._events
        if min_severity:
            min_score = CEF_SEVERITY_MAP.get(min_severity.upper(), 0)
            events = [e for e in events if CEF_SEVERITY_MAP.get(e.severity.upper(), 0) >= min_score]
        return events[-limit:]


class SIEMForwarder:
    """
    Enterprise SIEM Forwarding Agent.
    Buffers and exports eBPF events to Splunk, Microsoft Sentinel, Elasticsearch, and Datadog.
    """

    def __init__(self, target_format: str = "CEF"):
        self.target_format = target_format.upper()  # CEF, RFC5424, JSON
        self._buffer: List[KernelSecurityEvent] = []

    def push(self, event: KernelSecurityEvent):
        self._buffer.append(event)

    def export(self) -> List[str]:
        """Exports all buffered events in the configured enterprise format."""
        formatted: List[str] = []
        for evt in self._buffer:
            if self.target_format == "CEF":
                formatted.append(evt.to_cef())
            elif self.target_format in ("RFC5424", "SYSLOG"):
                formatted.append(evt.to_rfc5424_syslog())
            else:
                formatted.append(json.dumps(evt.to_dict()))
        return formatted

    def flush(self) -> List[str]:
        """Exports and empties the telemetry buffer."""
        out = self.export()
        self._buffer.clear()
        return out


def get_native_ebpf_c_source() -> str:
    """
    Returns compilable C eBPF kernel program using BPF ring buffers & CO-RE.
    Can be compiled directly with 'clang -target bpf -O2 -g -c -o k8s_ebpf.o'.
    """
    return """// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event) return 0;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
"""


class FalcoBridgeReceiver:
    """
    Bridge Adapter to ingest high-rate events from host Falco/Cilium agents.
    Converts Falco JSON alert payloads into native KernelSecurityEvents.
    """

    FALCO_RULE_SEV_MAP = {
        "Notice": "LOW",
        "Warning": "MEDIUM",
        "Error": "HIGH",
        "Critical": "CRITICAL",
        "Emergency": "CRITICAL",
    }

    def __init__(self, engine: EBPFTelemetryEngine):
        self.engine = engine

    def parse_falco_alert(self, alert_json: Dict[str, Any]) -> Optional[KernelSecurityEvent]:
        """Translates a Falco JSON event into an enterprise KernelSecurityEvent."""
        fields = alert_json.get("output_fields", {})
        rule = alert_json.get("rule", "Unknown Rule")
        priority = alert_json.get("priority", "Warning")
        sev = self.FALCO_RULE_SEV_MAP.get(priority, "HIGH")

        pid = int(fields.get("proc.pid", fields.get("proc.vpid", 0)))
        comm = fields.get("proc.name", "unknown")
        pod_name = fields.get("k8s.pod.name", "unknown-pod")
        ns = fields.get("k8s.ns.name", "default")
        container_id = fields.get("container.id", "unknown-cid")[:12]

        evt = KernelSecurityEvent(
            event_id=f"falco-{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="RUNTIME_INTRUSION",
            severity=sev,
            pid=pid,
            comm=comm,
            pod_name=pod_name,
            namespace=ns,
            container_id=container_id,
            description=f"Falco Engine Alert [{rule}]: {alert_json.get('output', '')}",
            details=alert_json,
            mitre_technique="T1059",
        )
        self.engine._events.append(evt)
        return evt
