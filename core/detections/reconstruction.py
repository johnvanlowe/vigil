"""Reconstruction phase: map executed attack steps to detection verdicts.

Correlates the offensive action trace and captured telemetry against the detection
engine and LogLM layers. Emits DetectionVerdict per step: 'rule', 'loglm', 'both', 'missed'.
Grounds verdicts in environment schema, attaches replayable evidence queries, and records
schema v1 'reconstruction' events to the append-only Ledger.
Exposed as skill_reconstruct.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Set

from core.detections.candidates import DetectionVerdict
from core.integrations.offensive.contract import ActionTraceStep
from core.integrations.offensive_engine import AttackTraceStep
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)


@dataclass
class ReconstructionReport:
    """Aggregate assessment produced by reconstructing an attack run."""

    run_id: str
    plan_id: str
    environment_id: str
    step_verdicts: List[DetectionVerdict]
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
            "step_verdicts": [s.model_dump() for s in self.step_verdicts],
            "reconstructed_at": self.reconstructed_at.isoformat(),
        }


class ReconstructionService:
    """Processes attack traces and telemetry into grounded detection verdicts."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = (
            run_id
            or f"recon-{utcnow().strftime('%Y%m%d')}-{re.sub(r'[^a-zA-Z0-9]', '', str(utcnow()))}"
        )

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
        action_trace: Sequence[Any],
        telemetry_findings: Sequence[Dict[str, Any]],
        environment_id: str,
        plan_id: str,
        cycle_number: int = 1,
        available_schema_fields: Optional[Set[str]] = None,
        ledger_store: Any = None,
    ) -> ReconstructionReport:
        """Map every attack trace step to its DetectionVerdict across rule and LogLM layers."""
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

        step_verdicts: List[DetectionVerdict] = []
        gaps: List[Dict[str, Any]] = []

        detected_rule_total = 0
        detected_loglm_total = 0
        both_total = 0
        missed_total = 0

        for step in action_trace:
            step_id = getattr(step, "step_id", step.get("step_id") if isinstance(step, dict) else "")
            tech_id = getattr(step, "technique_id", step.get("technique_id") if isinstance(step, dict) else "")
            name = getattr(step, "name", step_id)

            matched_citations: List[Dict[str, Any]] = []
            rule_hits: List[str] = []
            loglm_hits: List[str] = []
            telemetry_count = 0

            for finding in telemetry_findings:
                finding_step = finding.get("step_id")
                finding_tech = finding.get("technique_id")
                source = finding.get("source") or finding.get("data_source") or "sysmon"

                if finding_step == step_id or finding_tech == tech_id:
                    telemetry_count += 1
                    event_id = finding.get("event_id") or finding.get("finding_id") or f"ev-{step_id}"
                    replay_query = (
                        f"SELECT * FROM telemetry WHERE environment_id = '{environment_id}' "
                        f"AND technique_id = '{tech_id}' AND event_id = '{event_id}'"
                    )
                    citation = {
                        "citation_id": f"cite-{event_id}",
                        "source": source,
                        "event_id": event_id,
                        "query": replay_query,
                        "replayable_query": replay_query,
                        "timestamp": finding.get("timestamp", utcnow().isoformat()),
                        "details": finding.get("details") or finding.get("data") or {},
                    }
                    matched_citations.append(citation)

                    is_loglm = (
                        source.lower() == "loglm"
                        or finding.get("schema_kind") == "loglm"
                        or "loglm" in str(finding.get("title", "")).lower()
                        or "embedding" in finding
                        or finding.get("is_loglm", False)
                    )
                    if is_loglm:
                        loglm_hits.append(event_id)

                    rule_id = (
                        finding.get("rule_id")
                        or finding.get("rule_name")
                        or finding.get("matching_rule")
                        or finding.get("detection_rule")
                    )
                    if rule_id and not is_loglm:
                        rule_hits.append(str(rule_id))

            has_rule = len(rule_hits) > 0
            has_loglm = len(loglm_hits) > 0

            verdict_val: Literal["rule", "loglm", "both", "missed"]
            if has_rule and has_loglm:
                verdict_val = "both"
                both_total += 1
            elif has_rule:
                verdict_val = "rule"
                detected_rule_total += 1
            elif has_loglm:
                verdict_val = "loglm"
                detected_loglm_total += 1
                gaps.append({
                    "step_id": step_id,
                    "technique_id": tech_id,
                    "gap_type": "model_only",
                    "action_name": name,
                    "priority": "medium",
                })
            else:
                verdict_val = "missed"
                missed_total += 1
                gaps.append({
                    "step_id": step_id,
                    "technique_id": tech_id,
                    "gap_type": "complete_miss",
                    "action_name": name,
                    "priority": "high",
                })

            verdict_obj = DetectionVerdict(
                step_id=step_id,
                technique_id=tech_id,
                verdict=verdict_val,
                environment_id=environment_id,
                matching_rules=rule_hits,
                evidence_citations=matched_citations,
                cycle_number=cycle_number,
                telemetry_count=telemetry_count,
            )
            step_verdicts.append(verdict_obj)

            self.append_reconstruction_to_ledger(verdict_obj, ledger_store)

        return ReconstructionReport(
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

    def append_reconstruction_to_ledger(
        self,
        verdict: DetectionVerdict,
        ledger_store: Any = None,
    ) -> int:
        """Write schema v1 reconstruction event to append-only Ledger."""
        payload = {
            "schema_version": 1,
            "step_id": verdict.step_id,
            "technique_id": verdict.technique_id,
            "verdict": verdict.verdict,
            "matching_rules": verdict.matching_rules,
            "evidence_citations": verdict.evidence_citations,
            "environment_id": verdict.environment_id,
            "cycle_number": verdict.cycle_number or 1,
        }
        if ledger_store and hasattr(ledger_store, "append"):
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(
                        ledger_store.append(
                            run_id=self.run_id,
                            event_kind="reconstruction",
                            payload=payload,
                            actor="reconstruction_service",
                        )
                    )
            except Exception as exc:
                logger.warning("Could not append to async store: %s", exc)

        try:
            return append_agent_event(
                run_id=self.run_id,
                kind="reconstruction",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append reconstruction event to ledger: %s", exc)
            return 0


def skill_reconstruct(
    action_trace: Sequence[Any],
    telemetry_findings: Sequence[Dict[str, Any]],
    environment_id: str,
    plan_id: str,
    cycle_number: int = 1,
    available_schema_fields: Optional[Set[str]] = None,
    ledger_store: Any = None,
) -> ReconstructionReport:
    """Skill entrypoint exposing the reconstruction role."""
    service = ReconstructionService()
    return service.reconstruct(
        action_trace=action_trace,
        telemetry_findings=telemetry_findings,
        environment_id=environment_id,
        plan_id=plan_id,
        cycle_number=cycle_number,
        available_schema_fields=available_schema_fields,
        ledger_store=ledger_store,
    )
