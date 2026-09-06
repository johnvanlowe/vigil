"""Customer-owned overlay storage, promotion, and automatic demotion.

Promoted detections write to a customer-owned overlay separate from upstream
detection corpora (Sigma, Splunk, Elastic, KQL). Promotion is human or pre-authorized.
When a promoted rule turns noisy and exceeds the false-positive threshold, it is
automatically demoted with a recorded Ledger event (the one permitted self-demotion).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.detections.candidates import CandidateStatus, DetectionCandidate
from core.policies.schema import Policy
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)

DEFAULT_FP_COUNT_THRESHOLD = 5
DEFAULT_FP_RATE_THRESHOLD = 0.10


@dataclass
class OverlayRule:
    """A rule residing in the customer-owned overlay."""

    rule_id: str
    rule_name: str
    technique_id: str
    environment_id: str
    format: str
    content: str
    active: bool = True
    promoted_by: str = "analyst"
    promoted_at: datetime = field(default_factory=utcnow)
    demoted_at: Optional[datetime] = None
    demotion_reason: Optional[str] = None
    true_positive_count: int = 0
    false_positive_count: int = 0

    @property
    def fp_rate(self) -> float:
        total = self.true_positive_count + self.false_positive_count
        return (self.false_positive_count / total) if total > 0 else 0.0


class CustomerOverlayService:
    """Manages the customer-owned detection overlay."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        fp_count_threshold: int = DEFAULT_FP_COUNT_THRESHOLD,
        fp_rate_threshold: float = DEFAULT_FP_RATE_THRESHOLD,
    ):
        self.storage_dir = storage_dir or (
            Path(__file__).resolve().parents[2] / "data" / "overlay"
        )
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.fp_count_threshold = fp_count_threshold
        self.fp_rate_threshold = fp_rate_threshold
        self._rules: Dict[str, OverlayRule] = {}

    def promote(
        self,
        candidate: DetectionCandidate,
        actor: str,
        autonomy_policy: Optional[Policy] = None,
    ) -> OverlayRule:
        """Promote candidate into customer overlay; requires human or pre-authorized policy."""
        is_pre_authorized = False
        if autonomy_policy and autonomy_policy.kind.value == "autonomy":
            is_pre_authorized = bool(autonomy_policy.params.get("pre_authorized_promotion", False))

        if not is_pre_authorized and (not actor or actor.lower() in ("system", "agent")):
            raise PermissionError(
                "Promotion requires an authorized human actor or pre-authorized Policy(kind=autonomy)."
            )

        rule_id = candidate.candidate_id
        rule_path = self.storage_dir / f"{rule_id}.yml"
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(candidate.rule_content)

        overlay_rule = OverlayRule(
            rule_id=rule_id,
            rule_name=candidate.rule_name,
            technique_id=candidate.technique_id,
            environment_id=candidate.environment_id,
            format=candidate.format,
            content=candidate.rule_content,
            active=True,
            promoted_by=actor,
        )
        self._rules[rule_id] = overlay_rule
        candidate.status = CandidateStatus.PROMOTED
        candidate.promoted_at = utcnow()

        # Emit schema v1 promotion event
        payload = {
            "schema_version": 1,
            "candidate_id": rule_id,
            "rule_name": candidate.rule_name,
            "format": candidate.format,
            "environment_id": candidate.environment_id,
            "authorized_by": actor,
            "pre_authorized": is_pre_authorized,
            "overlay_path": str(rule_path),
        }
        try:
            append_agent_event(
                run_id=f"overlay-{rule_id}",
                kind="promotion",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append promotion event to ledger: %s", exc)

        return overlay_rule

    def record_feedback(
        self,
        rule_id: str,
        is_false_positive: bool,
    ) -> Optional[OverlayRule]:
        """Record production feedback on a rule; triggers automatic demotion if threshold exceeded."""
        rule = self._rules.get(rule_id)
        if not rule or not rule.active:
            return rule

        if is_false_positive:
            rule.false_positive_count += 1
        else:
            rule.true_positive_count += 1

        # Check demotion thresholds
        exceeds_count = rule.false_positive_count >= self.fp_count_threshold
        exceeds_rate = (
            rule.false_positive_count >= 3 and rule.fp_rate >= self.fp_rate_threshold
        )

        if exceeds_count or exceeds_rate:
            self.demote(
                rule_id=rule_id,
                reason=(
                    f"Automatic demotion: exceeded false-positive threshold "
                    f"({rule.false_positive_count} FPs, {rule.fp_rate:.1%} rate)"
                ),
            )

        return rule

    def demote(self, rule_id: str, reason: str, actor: str = "system_demotion_daemon") -> OverlayRule:
        """Demote an active overlay rule back to inactive status."""
        rule = self._rules.get(rule_id)
        if not rule:
            raise KeyError(f"Overlay rule {rule_id} not found")

        rule.active = False
        rule.demoted_at = utcnow()
        rule.demotion_reason = reason

        # Emit demotion ledger event
        payload = {
            "schema_version": 1,
            "rule_id": rule_id,
            "technique_id": rule.technique_id,
            "environment_id": rule.environment_id,
            "action": "demote",
            "reason": reason,
            "actor": actor,
            "fp_count": rule.false_positive_count,
            "tp_count": rule.true_positive_count,
        }
        try:
            append_agent_event(
                run_id=f"overlay-{rule_id}",
                kind="verdict",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append demotion verdict event: %s", exc)

        return rule

    def search_detections(
        self,
        query: str = "",
        technique_id: Optional[str] = None,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        """Search overlay detections, integrating with the detections domain."""
        matches: List[Dict[str, Any]] = []
        for r in self._rules.values():
            if not include_inactive and not r.active:
                continue
            if technique_id and r.technique_id.upper() != technique_id.upper():
                continue
            if query and query.lower() not in r.rule_name.lower() and query.lower() not in r.content.lower():
                continue

            matches.append({
                "rule_id": r.rule_id,
                "name": r.rule_name,
                "technique_id": r.technique_id,
                "environment_id": r.environment_id,
                "source": "customer_overlay",
                "active": r.active,
                "format": r.format,
                "fp_count": r.false_positive_count,
                "tp_count": r.true_positive_count,
            })
        return matches


_DEFAULT_OVERLAY = CustomerOverlayService()


def get_overlay_service() -> CustomerOverlayService:
    return _DEFAULT_OVERLAY
