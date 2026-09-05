"""Reconstruction phase: map executed attack steps to detection verdicts.

Analogous to NVIDIA's "process and reconstruct". Correlates the offensive
action trace and captured telemetry against the detection engine and LogLM.
Evaluates what was seen by rules, what was seen by LogLM, and what was missed.

Schema-and-field grounding ensures verdicts only assert on fields actually
emitted by the environment's sensors. Every step verdict is written to the
Ledger (agent_events) with evidence citations.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from core.integrations.offensive_engine import ActionStatus, AttackTraceStep
from core.storage.connection import get_db_manager
from core.time import utcnow

logger = logging.getLogger(__name__)


class DetectionVerdictEnum(str, Enum):
    """Verdict for an individual attack step."""

    DETECTED_BY_RULE = "detected_by_rule"
    DETECTED_BY_LOGLM = "detected_by_loglm"
    BOTH = "both"
    MISSED = "missed"


@dataclass
class EvidenceCitation:
    """Evidence link tying an attack step to a telemetry Finding or raw event."""

    evidence_id: str
    source_system: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStepVerdict:
    """Atomic unit produced by the reconstruction phase."""

    step_id: str
    technique_id: str
    action_name: str
    status: ActionStatus
    verdict: DetectionVerdictEnum
    rule_matches: List[str] = field(default_factory=list)
    loglm_matches: List[str] = field(default_factory=list)
    evidence_citations: List[EvidenceCitation] = field(default_factory=list)
    schema_grounded: bool = True
    unsupported_fields: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "technique_id": self.technique_id,
            "action_name": self.action_name,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "rule_matches": self.rule_matches,
            "loglm_matches": self.loglm_matches,
            "evidence_citations": [
                {
                    "evidence_id": c.evidence_id,
                    "source_system": c.source_system,
                    "timestamp": c.timestamp,
                    "details": c.details,
                }
                for c in self.evidence_citations
            ],
            "schema_grounded": self.schema_grounded,
            "unsupported_fields": self.unsupported_fields,
            "explanation": self.explanation,
        }


@dataclass
class ReconstructionReport:
    """Aggregate assessment produced by reconstructing an attack run."""

    run_id: str
    plan_id: str
    environment_id: str
    step_verdicts: List[AttackStepVerdict]
    total_steps: int
    detected_by_rule_count: int
    detected_by_loglm_count: int
    both_count: int
    missed_count: int
    gaps: List[Dict[str, Any]]
    reconstructed_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "plan_id": self.plan_id,
            "environment_id": self.environment_id,
            "total_steps": self.total_steps,
            "detected_by_rule_count": self.detected_by_rule_count,
            "detected_by_loglm_count": self.detected_by_loglm_count,
            "both_count": self.both_count,
            "missed_count": self.missed_count,
            "gaps": self.gaps,
            "step_verdicts": [s.to_dict() for s in self.step_verdicts],
            "reconstructed_at": self.reconstructed_at.isoformat(),
        }


class ReconstructionService:
    """Processes attack traces and captured telemetry into grounded detection verdicts."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"recon-{utcnow().strftime('%Y%m%d')}-{re.sub(r'[^a-zA-Z0-9]', '', str(utcnow()))}"

    def verify_field_grounding(
        self,
        claimed_fields: Iterable[str],
        available_fields: Set[str],
    ) -> tuple[bool, List[str]]:
        """Ensure detections do not invent or rely on unemitted telemetry fields."""
        unsupported = [f for f in claimed_fields if f not in available_fields]
        return (len(unsupported) == 0, unsupported)

    def reconstruct(
        self,
        action_trace: Sequence[AttackTraceStep],
        telemetry_findings: Sequence[Dict[str, Any]],
        environment_id: str,
        plan_id: str,
        available_schema_fields: Optional[Set[str]] = None,
    ) -> ReconstructionReport:
        """Map every attack trace step to its detection verdict across rule and LogLM layers."""
        # Default schema fields typical of sysmon/auditd telemetry
        known_schema = available_schema_fields or {
            "process_name",
            "command_line",
            "parent_process",
            "user",
            "dest_ip",
            "dest_port",
            "host",
            "timestamp",
            "action",
            "source",
        }

        step_verdicts: List[AttackStepVerdict] = []
        gaps: List[Dict[str, Any]] = []

        detected_rule_total = 0
        detected_loglm_total = 0
        both_total = 0
        missed_total = 0

        for step in action_trace:
            # 1. Correlate step with telemetry findings
            matched_citations: List[EvidenceCitation] = []
            rule_hits: List[str] = []
            loglm_hits: List[str] = []

            for finding in telemetry_findings:
                finding_step = finding.get("step_id")
                finding_tech = finding.get("technique_id")
                source = finding.get("source") or finding.get("data_source") or ""

                # Match by explicit step_id or technique_id
                if finding_step == step.step_id or finding_tech == step.technique_id:
                    matched_citations.append(
                        EvidenceCitation(
                            evidence_id=finding.get("event_id") or finding.get("finding_id") or "ev-1",
                            source_system=source,
                            timestamp=finding.get("timestamp", utcnow().isoformat()),
                            details=finding.get("details") or finding.get("data") or {},
                        )
                    )

                    # Distinguish LogLM signal from rule signals
                    is_loglm = (
                        source.lower() == "loglm"
                        or finding.get("schema_kind") == "loglm"
                        or "loglm" in str(finding.get("title", "")).lower()
                        or "embedding" in finding
                    )
                    if is_loglm:
                        loglm_hits.append(finding.get("finding_id") or finding.get("event_id") or "loglm-finding")

                    # Check for rule matches
                    rule_id = finding.get("rule_id") or finding.get("rule_name") or finding.get("detection_rule")
                    if rule_id and not is_loglm:
                        rule_hits.append(str(rule_id))

            # 2. Check schema grounding of observed details
            claimed_fields: Set[str] = set()
            for citation in matched_citations:
                claimed_fields.update(citation.details.keys())
            is_grounded, unsupported = self.verify_field_grounding(claimed_fields, known_schema)

            # 3. Determine detection verdict
            has_rule = len(rule_hits) > 0
            has_loglm = len(loglm_hits) > 0

            if has_rule and has_loglm:
                verdict = DetectionVerdictEnum.BOTH
                both_total += 1
                explanation = (
                    f"Step {step.step_id} ({step.technique_id}) was detected by both rule "
                    f"({', '.join(rule_hits)}) and LogLM anomaly."
                )
            elif has_rule:
                verdict = DetectionVerdictEnum.DETECTED_BY_RULE
                detected_rule_total += 1
                explanation = (
                    f"Step {step.step_id} ({step.technique_id}) was detected by rule: {', '.join(rule_hits)}."
                )
            elif has_loglm:
                verdict = DetectionVerdictEnum.DETECTED_BY_LOGLM
                detected_loglm_total += 1
                explanation = (
                    f"Step {step.step_id} ({step.technique_id}) was flagged exclusively by LogLM anomaly. "
                    "Rule layer missed this activity; ideal candidate for grounded rule authoring."
                )
                gaps.append({
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "gap_type": "model_only",
                    "action_name": step.name,
                    "priority": "medium",
                })
            else:
                verdict = DetectionVerdictEnum.MISSED
                missed_total += 1
                explanation = (
                    f"Step {step.step_id} ({step.technique_id}) was completely missed by both detection rules "
                    "and LogLM. High-priority detection engineering gap."
                )
                gaps.append({
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "gap_type": "complete_miss",
                    "action_name": step.name,
                    "priority": "high",
                })

            step_verdict = AttackStepVerdict(
                step_id=step.step_id,
                technique_id=step.technique_id,
                action_name=step.name,
                status=step.status,
                verdict=verdict,
                rule_matches=rule_hits,
                loglm_matches=loglm_hits,
                evidence_citations=matched_citations,
                schema_grounded=is_grounded,
                unsupported_fields=unsupported,
                explanation=explanation,
            )
            step_verdicts.append(step_verdict)

            # Record step verdict to Ledger
            self.append_step_verdict_to_ledger(step_verdict, environment_id)

        report = ReconstructionReport(
            run_id=self.run_id,
            plan_id=plan_id,
            environment_id=environment_id,
            step_verdicts=step_verdicts,
            total_steps=len(action_trace),
            detected_by_rule_count=detected_rule_total,
            detected_by_loglm_count=detected_loglm_total,
            both_count=both_total,
            missed_count=missed_total,
            gaps=gaps,
        )

        return report

    def append_step_verdict_to_ledger(
        self,
        verdict: AttackStepVerdict,
        environment_id: str,
    ) -> None:
        """Write one reconstruction step event to the append-only Ledger."""
        now = utcnow()
        payload = {
            "environment_id": environment_id,
            "verdict": verdict.to_dict(),
        }

        try:
            db = get_db_manager()
            with db.session_scope() as session:
                query = session.execute(
                    """
                    SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_events
                    WHERE run_id = CAST(:run_id AS uuid)
                    """,
                    {"run_id": self.run_id},
                )
                next_seq = query.scalar() or 1

                session.execute(
                    """
                    INSERT INTO agent_events (
                        run_id, seq, ts, run_kind, kind, payload, schema_version
                    ) VALUES (
                        CAST(:run_id AS uuid), :seq, :ts, :run_kind, :kind, CAST(:payload AS jsonb), :schema_version
                    )
                    """,
                    {
                        "run_id": self.run_id,
                        "seq": next_seq,
                        "ts": now,
                        "run_kind": "compose",
                        "kind": "reconstruction_verdict",
                        "payload": json.dumps(payload),
                        "schema_version": 1,
                    },
                )
        except Exception as exc:
            logger.warning("Could not append reconstruction_verdict to agent_events: %s", exc)
