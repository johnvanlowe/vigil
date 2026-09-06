"""Deterministic detection linting and anti-brittleness gate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from core.detections.candidates import DetectionCandidate

_IPV4_RE = re.compile(
    r"\b(?!0\.0\.0\.0)(?!127\.0\.0\.1)(?!255\.255\.255\.255)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
)
_SUBNET_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")
_SPECIFIC_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9_.-]+\.(?:corp|local|internal|lan)|(?:srv|dc|ws|host|pc|workstation|laptop)[a-zA-Z0-9_-]*|dc01|dc02)\b",
    re.IGNORECASE,
)
_SPECIFIC_USER_RE = re.compile(
    r"\b(?:user\s*:\s*['\"]?(?:john|admin\d+|administrator|bob|alice|svc_[a-zA-Z0-9_]+)['\"]?)\b",
    re.IGNORECASE,
)


@dataclass
class LintResult:
    """Result of linting and anti-brittleness evaluation."""

    passed: bool
    syntax_valid: bool
    anti_brittleness_passed: bool
    detected_literals: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    rewrite_guidance: Optional[str] = None


def lint_candidate(candidate: DetectionCandidate) -> LintResult:
    """Lint candidate rule syntax and enforce anti-brittleness invariants.

    Rejects any detection keyed to literal IPs, hosts, users, or subnets,
    returning actionable rewrite guidance.
    """
    errors: List[str] = []
    syntax_valid = True

    # 1. Syntax check
    if candidate.format.lower() in ("sigma", "yaml"):
        try:
            yaml.safe_load(candidate.rule_content)
        except Exception as exc:
            syntax_valid = False
            errors.append(f"YAML syntax error: {exc}")
    elif candidate.format.lower() == "elastic":
        if "=" not in candidate.rule_content and ":" not in candidate.rule_content:
            syntax_valid = False
            errors.append("Invalid rule format: expected key-value definitions.")

    # 2. Hard rule: Anti-brittleness check
    content = candidate.rule_content
    detected_literals: List[str] = []

    ips = _IPV4_RE.findall(content)
    if ips:
        detected_literals.extend([f"IP: {ip}" for ip in set(ips)])

    subnets = _SUBNET_RE.findall(content)
    if subnets:
        detected_literals.extend([f"Subnet: {net}" for net in set(subnets)])

    hosts = _SPECIFIC_HOST_RE.findall(content)
    if hosts:
        detected_literals.extend([f"Host: {h}" for h in set(hosts)])

    users = _SPECIFIC_USER_RE.findall(content)
    if users:
        detected_literals.extend([f"User: {u}" for u in set(users)])

    anti_brittleness_passed = len(detected_literals) == 0
    guidance = None

    if not anti_brittleness_passed:
        literals_summary = ", ".join(detected_literals)
        guidance = (
            f"Anti-brittleness rejection: Rule contains environment-specific literals ({literals_summary}). "
            "Rewrite guidance: Replace specific hostnames, IPs, or users with behavioral invariants "
            "(e.g., process lineage, command-line arguments, unusual parent-child relationships, or "
            "standard administrative share access patterns)."
        )
        errors.append(guidance)

    passed = syntax_valid and anti_brittleness_passed

    return LintResult(
        passed=passed,
        syntax_valid=syntax_valid,
        anti_brittleness_passed=anti_brittleness_passed,
        detected_literals=detected_literals,
        errors=errors,
        rewrite_guidance=guidance,
    )
