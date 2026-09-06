"""Deterministic validation harness package.

Integrates linting, anti-brittleness literals check, telemetry replay,
bounded repair loops, and audit logging to the append-only Ledger.
Exposed as skill_validate_detection.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from core.detections.candidates import CandidateStatus, DetectionCandidate, ValidationRecord
from core.detections.validation.lint import LintResult, lint_candidate
from core.detections.validation.replay import ReplayResult, replay_candidate
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)

DEFAULT_REPAIR_BUDGET = 3


class ValidationService:
    """Orchestrates candidate validation gates within repair budget."""

    def __init__(self, run_id: Optional[str] = None, repair_budget: int = DEFAULT_REPAIR_BUDGET):
        self.run_id = run_id or f"val-{utcnow().strftime('%Y%m%d')}-001"
        self.repair_budget = repair_budget

    def validate(
        self,
        candidate: DetectionCandidate,
        captured_telemetry: Sequence[Dict[str, Any]],
        repair_attempts: int = 0,
        judge_verdict: Optional[bool] = None,
        judge_feedback: Optional[str] = None,
        ledger_store: Any = None,
    ) -> ValidationRecord:
        """Evaluate candidate through deterministic gates: lint, replay, and budget."""
        lint_res = lint_candidate(candidate)
        replay_res = replay_candidate(candidate, captured_telemetry)

        # Candidate is valid only if it clears both deterministic gates
        is_valid = lint_res.passed and replay_res.matched
        if judge_verdict is not None:
            is_valid = is_valid and judge_verdict

        error = None
        if not lint_res.passed:
            error = lint_res.rewrite_guidance or "; ".join(lint_res.errors)
        elif not replay_res.matched:
            error = replay_res.feedback

        record = ValidationRecord(
            candidate_id=candidate.candidate_id,
            environment_id=candidate.environment_id,
            is_valid=is_valid,
            passed_lint=lint_res.passed,
            passed_replay=replay_res.matched,
            passed_judge=judge_verdict if judge_verdict is not None else False,
            repair_attempts=repair_attempts,
            repair_history=[
                {
                    "attempt": repair_attempts,
                    "passed_lint": lint_res.passed,
                    "passed_replay": replay_res.matched,
                    "error": error,
                }
            ],
            lint_feedback=lint_res.rewrite_guidance,
            replay_matches_count=replay_res.matches_count,
            judge_feedback=judge_feedback,
            error=error,
        )

        # Update candidate status
        candidate.validation_record = record
        candidate.status = CandidateStatus.VALIDATED if is_valid else CandidateStatus.REJECTED

        # Append validation_verdict Ledger event (schema v1)
        self.append_validation_verdict_to_ledger(record, ledger_store)
        return record

    def append_validation_verdict_to_ledger(
        self,
        record: ValidationRecord,
        ledger_store: Any = None,
    ) -> int:
        """Write schema v1 validation_verdict event to the append-only Ledger."""
        payload = {
            "schema_version": 1,
            "candidate_id": record.candidate_id,
            "environment_id": record.environment_id,
            "is_valid": record.is_valid,
            "passed_lint": record.passed_lint,
            "passed_replay": record.passed_replay,
            "passed_judge": record.passed_judge,
            "repair_attempts": record.repair_attempts,
            "error": record.error,
        }

        if ledger_store and hasattr(ledger_store, "append"):
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(
                        ledger_store.append(
                            run_id=self.run_id,
                            event_kind="validation_verdict",
                            payload=payload,
                            actor="validation_service",
                        )
                    )
            except Exception as exc:
                logger.warning("Could not append async validation verdict: %s", exc)

        try:
            return append_agent_event(
                run_id=self.run_id,
                kind="validation_verdict",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append validation_verdict to ledger: %s", exc)
            return 0


def skill_validate_detection(
    candidate: DetectionCandidate,
    captured_telemetry: Sequence[Dict[str, Any]],
    repair_attempts: int = 0,
    judge_verdict: Optional[bool] = None,
    judge_feedback: Optional[str] = None,
    ledger_store: Any = None,
) -> ValidationRecord:
    """Skill entrypoint exposing the detection validation harness."""
    service = ValidationService()
    return service.validate(
        candidate=candidate,
        captured_telemetry=captured_telemetry,
        repair_attempts=repair_attempts,
        judge_verdict=judge_verdict,
        judge_feedback=judge_feedback,
        ledger_store=ledger_store,
    )


__all__ = [
    "LintResult",
    "ReplayResult",
    "ValidationService",
    "lint_candidate",
    "replay_candidate",
    "skill_validate_detection",
]
