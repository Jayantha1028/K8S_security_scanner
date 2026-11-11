#!/usr/bin/env python3
"""
declarative_rule_engine.py
==========================
Declarative Custom Policy Rule Engine for Kubernetes Security Assessment.

Enables SecOps teams to define enterprise policy rules in standard YAML/JSON
without modifying core scanner Python code.

Supports pre-compiled fast AST path lookups and expressive predicate operators:
  eq, neq, in, not_in, contains, regex_match, regex_not_match,
  gt, lt, gte, lte, is_null, is_not_null, is_true, is_false.
"""

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

import yaml


@dataclass
class DeclarativeRule:
    id: str
    name: str
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    plane: int = 1
    kinds: List[str] = field(default_factory=lambda: ["*"])
    target: str = "containers"  # containers, pod, metadata, spec, volumes
    field_path: str = ""
    operator: str = "eq"
    expected_value: Any = None
    message: str = ""
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class DeclarativeRuleEngine:
    """
    High-performance pre-compiled declarative rule evaluator.
    Evaluates Kubernetes document ASTs against custom rule predicates in < 0.1 ms.
    """

    def __init__(self, rules: Optional[List[DeclarativeRule]] = None):
        self.rules: List[DeclarativeRule] = []
        self._compiled_regexes: Dict[str, re.Pattern] = {}
        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule: DeclarativeRule):
        self.rules.append(rule)
        # Pre-compile regex operators for sub-millisecond evaluation
        if rule.operator in ("regex_match", "regex_not_match") and isinstance(rule.expected_value, str):
            try:
                self._compiled_regexes[rule.id] = re.compile(rule.expected_value)
            except re.error:
                pass

    def load_rules_from_dict(self, data: List[Dict[str, Any]]):
        """Loads and compiles rules from a list of rule dictionaries."""
        for r_dict in data:
            rule = DeclarativeRule(
                id=r_dict.get("id", f"CR-{len(self.rules) + 1:03d}"),
                name=r_dict.get("name", "Custom Policy Rule"),
                severity=r_dict.get("severity", "HIGH").upper(),
                plane=int(r_dict.get("plane", 1)),
                kinds=r_dict.get("kinds", ["*"]),
                target=r_dict.get("target", "containers"),
                field_path=r_dict.get("field_path", ""),
                operator=r_dict.get("operator", "eq").lower(),
                expected_value=r_dict.get("expected_value"),
                message=r_dict.get("message", "Custom policy constraint violated"),
                remediation=r_dict.get("remediation", "Update manifest to comply with policy"),
                metadata=r_dict.get("metadata", {}),
            )
            self.add_rule(rule)

    def load_rules_from_yaml_file(self, filepath: str):
        """Loads rules from a YAML policy file."""
        p = Path(filepath)
        if not p.is_file():
            return
        content = p.read_text(encoding="utf-8", errors="replace")
        parsed = yaml.safe_load(content)
        if isinstance(parsed, list):
            self.load_rules_from_dict(parsed)
        elif isinstance(parsed, dict) and "rules" in parsed:
            self.load_rules_from_dict(parsed["rules"])

    def load_rules_from_directory(self, dirpath: str, recursive: bool = True):
        """Loads all .yaml and .yml policy rules within a directory."""
        p = Path(dirpath)
        if not p.is_dir():
            return
        pattern = "**/*.y*ml" if recursive else "*.y*ml"
        for file in sorted(p.glob(pattern)):
            if file.is_file() and not file.name.startswith("."):
                try:
                    self.load_rules_from_yaml_file(str(file))
                except Exception:
                    pass

    def evaluate_document(self, doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single Kubernetes manifest AST against loaded declarative rules.
        Returns a list of finding dictionaries.
        """
        findings = []
        if not isinstance(doc, dict):
            return findings

        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {}) or {}
        doc_name = metadata.get("name", "unnamed")
        doc_ns = metadata.get("namespace", "default")
        pod_spec = self._extract_pod_spec(doc)

        for rule in self.rules:
            # Kind filter check
            if "*" not in rule.kinds and kind not in rule.kinds:
                continue

            # Route by target scope
            if rule.target == "metadata":
                val = self._extract_field(metadata, rule.field_path)
                if self._check_condition(rule, val):
                    findings.append(self._create_violation(rule, target=f"{doc_ns}/{doc_name}", kind=kind))

            elif rule.target in ("pod", "spec"):
                val = self._extract_field(pod_spec if rule.target == "pod" else doc.get("spec", {}), rule.field_path)
                if self._check_condition(rule, val):
                    findings.append(self._create_violation(rule, target=f"{doc_ns}/{doc_name}", kind=kind))

            elif rule.target == "containers":
                containers = (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    c_name = c.get("name", "container")
                    val = self._extract_field(c, rule.field_path)
                    if self._check_condition(rule, val):
                        findings.append(self._create_violation(rule, target=f"{doc_ns}/{doc_name}/{c_name}", kind=kind))

            elif rule.target == "volumes":
                for v in pod_spec.get("volumes", []) or []:
                    if not isinstance(v, dict):
                        continue
                    v_name = v.get("name", "volume")
                    val = self._extract_field(v, rule.field_path)
                    if self._check_condition(rule, val):
                        findings.append(self._create_violation(rule, target=f"{doc_ns}/{doc_name}:{v_name}", kind=kind))

        return findings

    def _check_condition(self, rule: DeclarativeRule, actual_value: Any) -> bool:
        """Evaluates whether the actual value satisfies the violation condition."""
        op = rule.operator
        expected = rule.expected_value

        if op == "eq":
            return actual_value == expected
        elif op == "neq":
            return actual_value != expected
        elif op == "gt":
            return actual_value is not None and actual_value > expected
        elif op == "lt":
            return actual_value is not None and actual_value < expected
        elif op == "gte":
            return actual_value is not None and actual_value >= expected
        elif op == "lte":
            return actual_value is not None and actual_value <= expected
        elif op == "in":
            return isinstance(expected, (list, tuple, set)) and actual_value in expected
        elif op == "not_in":
            return isinstance(expected, (list, tuple, set)) and actual_value not in expected
        elif op == "contains":
            return actual_value is not None and str(expected) in str(actual_value)
        elif op == "is_null":
            return actual_value is None
        elif op == "is_not_null":
            return actual_value is not None
        elif op == "is_true":
            return actual_value is True
        elif op == "is_false":
            return actual_value is False
        elif op == "regex_match":
            compiled = self._compiled_regexes.get(rule.id)
            if compiled and actual_value is not None:
                return bool(compiled.search(str(actual_value)))
            elif actual_value is not None and isinstance(expected, str):
                return bool(re.search(expected, str(actual_value)))
            return False
        elif op == "regex_not_match":
            compiled = self._compiled_regexes.get(rule.id)
            if compiled and actual_value is not None:
                return not bool(compiled.search(str(actual_value)))
            elif actual_value is not None and isinstance(expected, str):
                return not bool(re.search(expected, str(actual_value)))
            return False

        return False

    @staticmethod
    def _extract_field(data: Any, path: str) -> Any:
        """Navigates dot-separated path and list indices (e.g. 'securityContext.capabilities.drop' or 'ports.0.containerPort')."""
        if not path or data is None:
            return data
        curr = data
        clean_parts = path.replace("[", ".").replace("]", "").split(".")
        for part in clean_parts:
            if not part:
                continue
            if isinstance(curr, dict):
                curr = curr.get(part)
            elif isinstance(curr, (list, tuple)):
                if part.isdigit():
                    idx = int(part)
                    curr = curr[idx] if 0 <= idx < len(curr) else None
                else:
                    return None
            else:
                return None
        return curr

    @staticmethod
    def _extract_pod_spec(doc: Dict[str, Any]) -> Dict[str, Any]:
        kind = doc.get("kind", "")
        spec = doc.get("spec", {}) or {}
        if kind == "Pod":
            return spec
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            return spec.get("template", {}).get("spec", {}) or {}
        if kind == "CronJob":
            return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}) or {}
        return {}

    @staticmethod
    def _create_violation(rule: DeclarativeRule, target: str, kind: str) -> Dict[str, Any]:
        return {
            "vuln_id": rule.id,
            "plane": rule.plane,
            "severity": rule.severity,
            "title": rule.name,
            "target": target,
            "kind": kind,
            "description": rule.message,
            "remediation": rule.remediation,
            "is_custom_rule": True,
        }
