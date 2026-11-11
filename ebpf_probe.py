#!/usr/bin/env python3
"""
native_scanner/ebpf_probe.py
============================
In-tree eBPF Kernel Probe Controller for the Independent Native Scanner.
"""

from dataclasses import asdict, dataclass
import logging
import os
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("NativeScanner.EBPFProbe")


@dataclass
class EBPFTraceEvent:
    syscall_name: str
    comm: str
    pod_name: str
    namespace: str = "default"
    container_name: str = "main"
    target_path: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    uid: int = 10001
    pid: int = 4210


class NativeEBPFKernelProbe:
    """Manages low-level in-tree eBPF C probes and event delivery."""

    def __init__(self, c_source_path: Optional[Path] = None):
        if c_source_path:
            self.c_source_path = Path(c_source_path)
        else:
            self.c_source_path = Path(__file__).resolve().parents[2] / "ebpf" / "probe.bpf.c"

    def load_bpf_source(self) -> str:
        """Reads raw in-tree eBPF C source code."""
        if self.c_source_path.exists():
            return self.c_source_path.read_text(encoding="utf-8", errors="replace")
        return ""

    def is_kernel_bpf_available(self) -> bool:
        """Detects if host OS supports native kernel eBPF tracepoint attachment."""
        if os.name != "posix" or sys.platform == "darwin":
            return False
        tracefs = Path("/sys/kernel/debug/tracing")
        tracepoint_execve = Path("/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve")
        return tracefs.exists() and tracepoint_execve.exists()
