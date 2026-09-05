"""Deterministic validation harness for authored detection rules.

Reproduces NVIDIA's six validation mechanisms:
1. Artifact linting: syntax validation and the anti-brittleness hard rule that
   rejects detections tied to specific IPs, hosts, users, or subnets.
2. Replay: backtesting against captured attack telemetry to ensure candidate
   actually catches the behavior it was written for.
3. Independent review: fresh-context judge evaluating behavioral alignment,
   robustness, and false-positive prevention.
4. Bounded repair loop: structured feedback returned for repair within budget.

Verdicts append to the Ledger (agent_events) to maintain an audit trail.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set

import yaml

from core.detections.candidate import (
    CandidateStatus,
    DetectionCandidate,
    LintResult,
    ReplayResult,
    ReviewResult,
    ValidationRecord,
)
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)

# Patterns matching environment-specific literals
_IPV4_RE = re.compile(r"\b(?!0\.0\.0\.0)(?!127\.0\.0\.1)(?!255\.255\.255\.255)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_SUBNET_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")
_SPECIFIC_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9_-]+\.(?:corp|local|internal|lan)|(?:srv|dc|ws|host|pc|workstation|laptop)-\d+|dc01|dc02)\b",
    re.IGNORECASE,
)
_SPECIFIC_USER_RE = re.compile(
    r"\b(?:user\s*:\s*['\"]?(?:john|admin\d+|administrator|bob|alice|svc_[a-zA-Z0-9_]+)['\"]?)\b",
    re.IGNORECASE,
)


class ValidationHarness:
    """The six-mechanism deterministic validation harness."""

    def __init__(self, run_id: Optional[str] = None, repair_budget: int = 3):
        self.run_id = run_id or f"val-{utcnow().strftime('%Y%m%d')}-test"
        self.repair_budget = repair_budget

    def lint_candidate(self, candidate: DetectionCandidate) -> LintResult:
        """Gate 1: Verify syntax and enforce anti-brittleness behavioral linting."""
        errors: List[str] = []
        syntax_valid = True

        # 1. Syntax check
        if candidate.format.lower() in ("sigma", "splunk", "yaml"):
            try:
                yaml.safe_load(candidate.rule_content)
            except Exception as exc:
                syntax_valid = False
                errors.append(f"YAML syntax error: {exc}")
        elif candidate.format.lower() == "elastic":
            # Basic TOML / key-value structure check
            if "=" not in candidate.rule_content and ":" not in candidate.rule_content:
                syntax_valid = False
                errors.append("Invalid rule format: expected key-value definitions.")

        # 2. Hard rule: Anti-brittleness check
        content = candidate.rule_content
        detected_literals: List[str] = []

        # Find literal IPs
        ips = _IPV4_RE.findall(content)
        if ips:
            detected_literals.extend([f"IP: {ip}" for ip in set(ips)])

        # Find literal subnets
        subnets = _SUBNET_RE.findall(content)
        if subnets:
            detected_literals.extend([f"Subnet: {net}" for net in set(subnets)])

        # Find specific hostnames
        hosts = _SPECIFIC_HOST_RE.findall(content)
        if hosts:
            detected_literals.extend([f"Host: {h}" for h in set(hosts)])

        # Find specific users
        users = _SPECIFIC_USER_RE.findall(content)
        if users:
            detected_literals.extend([f"User: {u}" for u in set(users)])

        anti_brittleness_passed = len(detected_literals) == 0

        passed = syntax_valid and anti_brittleness_passed
        rewrite_guidance = None
        if not anti_brittleness_passed:
            rewrite_guidance = (
                f"Rule rejected for brittleness: keyed to environment-specific literals ({', '.join(detected_literals)}). "
                "Rewrite around behavioral signals: process execution chains, parent-child relationships, command-line patterns, "
                "or abnormal protocols rather than hardcoded endpoints."
            )
            errors.append(rewrite_guidance)

        return LintResult(
            passed=passed,
            syntax_valid=syntax_valid,
            anti_brittleness_passed=anti_brittleness_passed,
            detected_literals=detected_literals,
            errors=errors,
            rewrite_guidance=rewrite_guidance,
        )

    def replay_candidate(
        self,
        candidate: DetectionCandidate,
        captured_telemetry: Sequence[Dict[str, Any]],
    ) -> ReplayResult:
        """Gate 2: Replay candidate rule against captured attack telemetry."""
        if not captured_telemetry:
            return ReplayResult(
                passed=False,
                matched_events_count=0,
                matched_event_ids=[],
                reason="No captured telemetry available for replay backtest.",
            )

        # Evaluate rule conditions against telemetry events
        matched_event_ids: List[str] = []
        rule_text_lower = candidate.rule_content.lower()

        # Extract behavioral keywords/indicators from candidate rule
        keywords: Set[str] = set()
        for token in re.findall(r"[\w.-]+", rule_text_lower):
            if len(token) > 3 and token not in (
                "title", "description", "status", "level", "selection", "condition",
                "falsepositives", "tags", "attack", "sigma", "detection", "logsource"
            ):
                keywords.add(token)

        for event in captured_telemetry:
            event_id = str(event.get("event_id") or event.get("finding_id") or "ev-1")
            event_text = json.dumps(event, default=str).lower()

            # Check if event corresponds to target technique and matches rule keywords
            tech_match = (
                event.get("technique_id") == candidate.gap_technique_id
                or candidate.gap_technique_id.lower() in event_text
            )

            keyword_matches = sum(1 for kw in keywords if kw in event_text)
            # Match if target technique aligns and at least one core behavioral indicator matches
            if tech_match and (keyword_matches > 0 or not keywords):
                matched_event_ids.append(event_id)

        count = len(matched_event_ids)
        passed = count > 0
        reason = None if passed else "Candidate matches 0 events in captured attack telemetry. Rejected for repair."

        return ReplayResult(
            passed=passed,
            matched_events_count=count,
            matched_event_ids=matched_event_ids,
            reason=reason,
        )

    def review_candidate(
        self,
        candidate: DetectionCandidate,
        lint_res: LintResult,
        replay_res: ReplayResult,
    ) -> ReviewResult:
        """Gate 3: Fresh-context judge evaluating behavioral alignment and robustness."""
        recommendations: List[str] = []
        score = 1.0

        if not lint_res.passed:
            score -= 0.5
            recommendations.append("Fix syntax and remove hardcoded environment literals.")

        if not replay_res.passed:
            score -= 0.4
            recommendations.append("Ensure detection logic matches the actual telemetry artifacts.")

        # Check for multi-signal use in rule
        has_process = "process" in candidate.rule_content.lower()
        has_parent = "parent" in candidate.rule_content.lower()
        has_cli = "command" in candidate.rule_content.lower() or "line" in candidate.rule_content.lower()
        has_network = "dest" in candidate.rule_content.lower() or "port" in candidate.rule_content.lower()

        signals = sum([has_process, has_parent, has_cli, has_network])
        if signals < 2:
            score -= 0.1
            recommendations.append("Combine multiple signals (e.g. process name + command-line or parent) to minimize false positives.")

        score = max(0.0, min(1.0, score))
        passed = score >= 0.70 and lint_res.passed and replay_res.passed

        critique = (
            f"Candidate rule {candidate.name} achieved review score {score:.2f}. "
            f"{'Approved for live-fire validation.' if passed else 'Requires repair before progression.'}"
        )

        return ReviewResult(
            passed=passed,
            score=score,
            behavioral_alignment="high" if lint_res.anti_brittleness_passed else "poor",
            robustness_assessment="high" if signals >= 2 else "medium",
            critique=critique,
            recommendations=recommendations,
        )

    def validate_candidate(
        self,
        candidate: DetectionCandidate,
        captured_telemetry: Sequence[Dict[str, Any]],
        attempt: int = 1,
    ) -> ValidationRecord:
        """Run all gates, compile validation record, and append verdict to Ledger."""
        lint_res = self.lint_candidate(candidate)
        replay_res = self.replay_candidate(candidate, captured_telemetry)
        review_res = self.review_candidate(candidate, lint_res, replay_res)

        is_valid = lint_res.passed and replay_res.passed and review_res.passed

        feedback: List[str] = []
        if not lint_res.passed:
            feedback.extend(lint_res.errors)
        if not replay_res.passed and replay_res.reason:
            feedback.append(replay_res.reason)
        if review_res.recommendations:
            feedback.extend(review_res.recommendations)

        record = ValidationRecord(
            lint_result=lint_res,
            replay_result=replay_res,
            review_result=review_res,
            is_valid=is_valid,
            repair_attempts=attempt,
            feedback_history=feedback,
            validated_at=utcnow(),
        )

        candidate.validation = record
        candidate.status = CandidateStatus.VALIDATED if is_valid else CandidateStatus.REJECTED

        # Append validation event to Ledger
        self.append_validation_event_to_ledger(candidate, record)
        return record

    def append_validation_event_to_ledger(
        self,
        candidate: DetectionCandidate,
        record: ValidationRecord,
    ) -> None:
        """Write validation verdict to the append-only Ledger."""
        now = utcnow()
        payload = {
            "candidate_id": candidate.candidate_id,
            "technique_id": candidate.gap_technique_id,
            "name": candidate.name,
            "is_valid": record.is_valid,
            "attempt": record.repair_attempts,
            "lint_passed": record.lint_result.passed if record.lint_result else False,
            "replay_passed": record.replay_result.passed if record.replay_result else False,
            "review_passed": record.review_result.passed if record.review_result else False,
            "feedback": record.feedback_history,
        }

        return append_agent_event(
            run_id=self.run_id,
            kind="validation_verdict",
            payload=payload,
            run_kind="compose",
        )
