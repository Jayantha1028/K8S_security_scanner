#!/usr/bin/env python3
"""
native_scanner/repl.py
======================
Interactive Multi-Turn AI Copilot REPL for Kubernetes Security.
Provides a conversational terminal session with persistent memory,
slash commands (/scan, /dag, /vex, /fix, /apply, /target), and
rich ANSI formatting for live DevSecOps triage.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Readline support for line editing and command history
try:
    import readline
except ImportError:
    readline = None

# Resilient dual-mode imports
try:
    from .agent import SecurityAgent, LLMClient
    from .scanner import NativeSecurityScanner
    from .vex import ContextualVEXEngine
    from .gitops import GitOpsRemediator
    from .cluster_scanner import LiveClusterScanner
    from .lifecycle import ContainerLifecycleOrchestrator
except ImportError:
    from agent import SecurityAgent, LLMClient
    from scanner import NativeSecurityScanner
    from vex import ContextualVEXEngine
    from gitops import GitOpsRemediator
    from cluster_scanner import LiveClusterScanner
    from lifecycle import ContainerLifecycleOrchestrator

HISTORY_FILE = os.path.expanduser("~/.k8s_security_agent_history")


class Ansi:
    """Terminal styling helper with automatic TTY detection."""
    IS_TTY = sys.stdout.isatty()

    RESET = "\033[0m" if IS_TTY else ""
    BOLD = "\033[1m" if IS_TTY else ""
    DIM = "\033[2m" if IS_TTY else ""

    RED = "\033[31m" if IS_TTY else ""
    GREEN = "\033[32m" if IS_TTY else ""
    YELLOW = "\033[33m" if IS_TTY else ""
    BLUE = "\033[34m" if IS_TTY else ""
    MAGENTA = "\033[35m" if IS_TTY else ""
    CYAN = "\033[36m" if IS_TTY else ""
    WHITE = "\033[37m" if IS_TTY else ""

    @classmethod
    def color(cls, text: str, color_code: str, bold: bool = False) -> str:
        if not cls.IS_TTY:
            return text
        prefix = f"{cls.BOLD}{color_code}" if bold else color_code
        return f"{prefix}{text}{cls.RESET}"


SLASH_COMMANDS = [
    "/help",
    "/target",
    "/scan",
    "/dag",
    "/vex",
    "/fix",
    "/apply",
    "/cluster",
    "/lifecycle",
    "/history",
    "/clear",
    "/exit",
    "/quit",
]


def setup_readline():
    """Initializes command history and tab completion."""
    if not readline:
        return

    def completer(text: str, state: int):
        options = [cmd for cmd in SLASH_COMMANDS if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")

    if os.path.exists(HISTORY_FILE):
        try:
            readline.read_history_file(HISTORY_FILE)
        except Exception:
            pass


def save_readline():
    """Flushes command history to disk."""
    if readline:
        try:
            readline.set_history_length(1000)
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass


class InteractiveCopilotREPL:
    """
    Multi-Turn Interactive Conversational AI Copilot for Kubernetes.
    """

    def __init__(
        self,
        agent: Optional[SecurityAgent] = None,
        target: Optional[str] = None,
    ):
        self.agent = agent or SecurityAgent()
        self.target = target or "."
        self.conversation_history: List[Dict[str, str]] = []
        self.last_remediation_plan = None
        self.running = True

    def display_banner(self):
        """Prints the startup greeting and status dashboard."""
        provider = self.agent.llm.provider.upper()
        model = self.agent.llm.model
        print(Ansi.color("╔══════════════════════════════════════════════════════════════════════════════╗", Ansi.CYAN, bold=True))
        print(Ansi.color("║       KUBERNETES NATIVE SECURITY COPILOT — INTERACTIVE AI REPL               ║", Ansi.CYAN, bold=True))
        print(Ansi.color("╚══════════════════════════════════════════════════════════════════════════════╝", Ansi.CYAN, bold=True))
        print(f"  {Ansi.color('Cognitive Brain', Ansi.BOLD)} : {Ansi.color(provider, Ansi.GREEN)} ({model})")
        print(f"  {Ansi.color('Active Target', Ansi.BOLD)}   : {Ansi.color(self.target, Ansi.YELLOW)}")
        print(f"  {Ansi.color('Shortcuts', Ansi.BOLD)}       : Type {Ansi.color('/help', Ansi.CYAN)} for commands, {Ansi.color('/scan', Ansi.CYAN)} to audit, {Ansi.color('/exit', Ansi.RED)} to quit.")
        print("────────────────────────────────────────────────────────────────────────────────")

    def handle_slash_command(self, cmd_line: str) -> str:
        """Processes built-in interactive control commands."""
        parts = cmd_line.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit", "/q"):
            self.running = False
            return "Exiting Kubernetes Copilot session. Stay secure!"

        elif cmd == "/help":
            return """
Available Copilot Commands:
  /target <path>       Switch active manifest file, directory, or cluster target
  /scan                Perform AST manifest scan (56 rules) on current target
  /dag                 Analyze cross-resource attack graph & blast radius
  /vex                 Run OpenVEX contextual exploitability & noise reduction
  /fix                 Plan Kustomize strategic merge patches for non-compliant workloads
  /apply               Apply planned remediation patches directly in-place
  /cluster [ns]        Perform live cluster CSPM scan on current or specified namespace
  /history             Show recent conversation turns
  /clear               Clear conversation memory window
  /help                Display this help overview
  /exit, /quit         Terminate the interactive session
"""

        elif cmd == "/target":
            if not arg:
                return f"Current target: {self.target}. Usage: /target <path_or_dir>"
            p = Path(arg)
            if not p.exists():
                return f"Warning: Target '{arg}' does not exist on disk."
            self.target = arg
            return f"Active target updated to: {self.target}"

        elif cmd == "/scan":
            p = Path(self.target)
            if not p.exists():
                return f"Error: Target '{self.target}' not found."
            print(Ansi.color(f"[*] Scanning manifests in '{self.target}'...", Ansi.DIM))
            res = self.agent.tool_scan_manifest(self.target)
            data = json.loads(res)
            # Inject scan results into conversation context
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /scan on '{self.target}'. Found {data.get('total_findings')} findings ({data.get('critical_or_high')} Critical/High).",
            })
            total = data.get("total_findings", 0)
            crit = data.get("critical_or_high", 0)
            return (
                f"[✓] Scan Completed for '{self.target}':\n"
                f"    - Manifests Analyzed : {data.get('total_files', 0)}\n"
                f"    - Total Findings     : {total}\n"
                f"    - Critical / High    : {crit}\n"
                f"    Ask me questions about these findings (e.g. 'How do I fix the critical findings?')"
            )

        elif cmd == "/dag":
            p = Path(self.target)
            if not p.exists():
                return f"Error: Target '{self.target}' not found."
            print(Ansi.color(f"[*] Computing cross-resource attack graph for '{self.target}'...", Ansi.DIM))
            res = self.agent.tool_analyze_attack_graph(self.target)
            data = json.loads(res)
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /dag. Blast radius score: {data.get('blast_radius_score')}/100. Attack paths: {len(data.get('sample_paths', []))}.",
            })
            lines = [
                f"[✓] Attack Path DAG Analysis for '{self.target}':",
                f"    - Blast Radius Index : {data.get('blast_radius_score', 0):.1f} / 100.0",
                f"    - Active Attack Paths: {data.get('attack_paths_count', 0)}",
            ]
            for path in data.get("sample_paths", []):
                lines.append(f"      ⚡ {path}")
            return "\n".join(lines)

        elif cmd == "/vex":
            engine = ContextualVEXEngine()
            doc = engine.generate_vex_for_manifest(self.target)
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /vex. Total CVEs: {doc.total_cves}, Exploitable: {doc.exploitable_cves}, Mitigated: {doc.mitigated_cves}, Noise reduction: {doc.noise_reduction_ratio:.1f}%.",
            })
            return engine.format_terminal_summary(doc)

        elif cmd == "/fix":
            p = Path(self.target)
            if not p.exists():
                return f"Error: Target '{self.target}' not found."
            remediator = GitOpsRemediator()
            plan = remediator.plan_remediation(str(p))
            self.last_remediation_plan = plan
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /fix. Generated {len(plan.workload_diffs)} remediation patches.",
            })
            if not plan.workload_diffs:
                return f"[✓] Workloads in '{self.target}' meet least-privilege baseline. No patches needed."

            lines = [
                f"[✓] Remediation Plan Generated for '{self.target}':",
                f"    - Failing Workloads : {plan.failing_manifests_count}",
                f"    - Patches Prepared  : {len(plan.workload_diffs)}",
                "",
                "Preview of Applied Security Fixes:",
            ]
            for diff in plan.workload_diffs[:2]:
                lines.append(f"  --- {diff.workload_id} ({diff.before_score} -> {diff.after_score}) ---")
                for patch in diff.patches_applied:
                    lines.append(f"    + {patch}")
            lines.append("\nType '/apply' to apply these patches in-place, or ask me to modify them.")
            return "\n".join(lines)

        elif cmd == "/apply":
            if not self.last_remediation_plan or not self.last_remediation_plan.workload_diffs:
                return "No pending remediation plan. Run '/fix' first to generate patches."
            remediator = GitOpsRemediator()
            count = remediator.apply_in_place(self.last_remediation_plan)
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /apply. Modified {count} manifests in-place.",
            })
            self.last_remediation_plan = None
            return f"{Ansi.color('[✓]', Ansi.GREEN, bold=True)} Applied hardening fixes in-place across {count} manifest(s)."

        elif cmd == "/cluster":
            ns = arg or None
            cs = LiveClusterScanner()
            print(Ansi.color(f"[*] Auditing live cluster (namespace={ns or 'ALL'})...", Ansi.DIM))
            rep = cs.scan_cluster(namespace=ns)
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /cluster. Workloads scanned: {rep.workloads_scanned}, findings: {len(rep.findings)}.",
            })
            return (
                f"[✓] Live Cluster CSPM Audit Completed:\n"
                f"    - Mode              : {rep.mode}\n"
                f"    - Workloads Scanned : {rep.workloads_scanned}\n"
                f"    - Total Findings    : {len(rep.findings)}\n"
                f"    - Status            : {'Compliant' if rep.success else 'Drift Detected'}"
            )

        elif cmd == "/lifecycle":
            p = Path(self.target)
            if not p.exists():
                return f"Error: Target '{self.target}' not found."
            print(Ansi.color(f"[*] Auditing 5-phase container lifecycle for '{self.target}'...", Ansi.DIM))
            orch = ContainerLifecycleOrchestrator()
            rep = orch.audit_lifecycle(str(p))
            self.conversation_history.append({
                "role": "system",
                "content": f"User executed /lifecycle. Score: {rep.overall_lifecycle_score:.1f}/100, Verdict: {rep.gate_verdict}.",
            })
            return orch.format_terminal_summary(rep)

        elif cmd == "/history":
            if not self.conversation_history:
                return "No conversation history yet."
            lines = ["Conversation History:"]
            for idx, turn in enumerate(self.conversation_history, start=1):
                role = turn.get("role", "User").upper()
                snippet = turn.get("content", "").replace("\n", " ")[:80]
                lines.append(f"  {idx}. [{role}] {snippet}...")
            return "\n".join(lines)

        elif cmd == "/clear":
            self.conversation_history.clear()
            self.last_remediation_plan = None
            return "Conversation history cleared."

        return f"Unknown command '{cmd}'. Type '/help' for available commands."

    def handle_input(self, user_input: str) -> str:
        """
        Processes a single user turn: either a slash command or an AI query.
        Public method callable by CLI or unit tests.
        """
        line = user_input.strip()
        if not line:
            return ""

        # Handle slash commands
        if line.startswith("/"):
            return self.handle_slash_command(line)

        # Natural Language Multi-Turn AI Query
        self.conversation_history.append({"role": "user", "content": line})

        res = self.agent.reason_and_act(
            prompt=line,
            target=self.target,
            history=self.conversation_history,
        )

        answer = res.get("final_answer", "")
        self.conversation_history.append({"role": "assistant", "content": answer})
        return answer

    def start(self):
        """Starts the interactive prompt loop."""
        setup_readline()
        self.display_banner()

        try:
            while self.running:
                prompt_str = f"\n{Ansi.color('k8s-copilot', Ansi.CYAN, bold=True)} ({Ansi.color(Path(self.target).name or '.', Ansi.YELLOW)}) > "
                try:
                    user_input = input(prompt_str)
                except EOFError:
                    print()
                    break
                except KeyboardInterrupt:
                    print(f"\n{Ansi.color('Type /exit to quit.', Ansi.DIM)}")
                    continue

                if not user_input.strip():
                    continue

                output = self.handle_input(user_input)
                if output:
                    print(output)

        finally:
            save_readline()
            print(f"\n{Ansi.color('Goodbye!', Ansi.GREEN)}")


def start_copilot_repl(target: Optional[str] = None, provider: str = "auto", model: Optional[str] = None):
    """Entry point to launch the interactive copilot REPL."""
    llm = LLMClient(provider=provider, model=model)
    agent = SecurityAgent(llm_client=llm)
    repl = InteractiveCopilotREPL(agent=agent, target=target)
    repl.start()


if __name__ == "__main__":
    start_copilot_repl()
