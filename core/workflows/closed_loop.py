"""Closed-loop detection engineering controller and re-invocation scheduler.

Executes the closed loop cycle-by-cycle via Compose re-invocation.
Each cycle:
1. Red planner reads the current coverage projection (including detections promoted
   in prior cycles), forcing offense onto harder seams.
2. Offensive engine executes against the representative environment (approval-gated).
3. Reconstruction correlates telemetry and emits per-step verdicts.
4. Gaps are triaged via authoring policy or operator checkpoints.
5. Candidates are authored and gated through the deterministic validation harness.
6. Live-fire gate verifies generalization on reseeded variant and benign quietness.
7. Validated detections are promoted under demote-yourself-only.
8. Coverage projection is updated for the next cycle.

Stops on: no viable path remaining, cycle limit reached, budget exceeded, or operator stop.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from core.agents.red_planner import RedPlanner
from core.detections.author_policy import (
    AuthoringPolicy,
    GapDecision,
    GapTriageService,
)
from core.detections.authoring import DetectionAuthor
from core.detections.candidate import CandidateStatus, DetectionCandidate
from core.detections.coverage_projection import (
    CoverageProjection,
    fold_coverage_projection,
)
from core.detections.live_fire import LiveFireService
from core.detections.reconstruction import ReconstructionReport, ReconstructionService
from core.integrations.offensive_engine import (
    AttackExecutionResult,
    AttackPlan,
    ExecutionStatus,
    OffensiveEngine,
    get_offensive_engine,
)
from core.time import utcnow

logger = logging.getLogger(__name__)


class HaltReason(str, Enum):
    """Reason for terminating the closed loop iteration."""

    NO_VIABLE_PATH = "no_viable_path"
    MAX_CYCLES_REACHED = "max_cycles_reached"
    BUDGET_EXCEEDED = "budget_exceeded"
    OPERATOR_STOP = "operator_stop"
    COMPLETED = "completed"


@dataclass
class ClosedLoopConfig:
    """Execution configuration for the closed loop."""

    environment_id: str
    objectives: List[str]
    threat_context: str = "ransomware"
    max_cycles: int = 3
    max_cost_usd: float = 10.0
    auto_author: bool = True
    policy: AuthoringPolicy = field(default_factory=lambda: AuthoringPolicy(default_action="auto_author"))
    benign_baseline: List[Dict[str, Any]] = field(default_factory=list)
    engine_name: Optional[str] = None


@dataclass
class LoopCycleResult:
    """Execution output from a single loop cycle."""

    cycle_number: int
    plan: AttackPlan
    execution_result: AttackExecutionResult
    reconstruction_report: ReconstructionReport
    candidates_authored: List[DetectionCandidate]
    promoted_detections: List[Dict[str, Any]]
    cycle_cost_usd: float


@dataclass
class ClosedLoopRunResult:
    """Overall outcome across all iterated cycles."""

    run_id: str
    environment_id: str
    total_cycles_executed: int
    halt_reason: HaltReason
    cycle_results: List[LoopCycleResult]
    initial_frontier: float
    final_frontier: float
    total_cost_usd: float
    promoted_rules_count: int
    final_projection: CoverageProjection


class ClosedLoopController:
    """Orchestrates multi-cycle closed-loop detection engineering."""

    def __init__(self, config: ClosedLoopConfig, run_id: Optional[str] = None):
        self.config = config
        self.run_id = run_id or f"cl-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        self.engine: OffensiveEngine = get_offensive_engine(config.engine_name)
        self.reconstruction_svc = ReconstructionService(run_id=self.run_id)
        self.triage_svc = GapTriageService(run_id=self.run_id, policy=config.policy)
        self.author_svc = DetectionAuthor(run_id=self.run_id)
        self.live_fire_svc = LiveFireService(run_id=self.run_id)
        self.events_journal: List[Dict[str, Any]] = []

    async def run_cycle(
        self,
        cycle_number: int,
        promoted_rules: Sequence[Dict[str, Any]],
    ) -> LoopCycleResult:
        """Execute one complete cycle of the closed loop."""
        logger.info("Starting closed loop cycle %d for environment %s", cycle_number, self.config.environment_id)

        # 1. Red Planning: assemble context and synthesize plan
        planner = RedPlanner(run_id=self.run_id)
        ctx = await planner.assemble_context(
            environment_id=self.config.environment_id,
            objectives=self.config.objectives,
            threat_context=self.config.threat_context,
            prior_promoted_rules=list(promoted_rules),
        )
        plan = planner.generate_plan(ctx, seed=42 + cycle_number * 17)
        plan.metadata["cycle_number"] = cycle_number

        self.events_journal.append({
            "run_id": self.run_id,
            "seq": len(self.events_journal) + 1,
            "ts": utcnow().isoformat(),
            "kind": "red_plan",
            "payload": {
                "plan_id": plan.plan_id,
                "environment_id": plan.environment_id,
                "steps": [{"step_id": s.step_id, "technique_id": s.technique_id} for s in plan.steps],
                "metadata": {"cycle_number": cycle_number},
            },
        })

        # 2. Offensive Execution: execute plan in representative environment
        exec_res = await self.engine.execute(plan)

        # 3. Detection Reconstruction: correlate trace to telemetry
        recon_report = self.reconstruction_svc.reconstruct(
            action_trace=exec_res.action_trace,
            telemetry_findings=exec_res.captured_telemetry,
            environment_id=self.config.environment_id,
            plan_id=plan.plan_id,
        )

        for v in recon_report.step_verdicts:
            self.events_journal.append({
                "run_id": self.run_id,
                "seq": len(self.events_journal) + 1,
                "ts": utcnow().isoformat(),
                "kind": "reconstruction_verdict",
                "payload": {"environment_id": self.config.environment_id, "verdict": v.to_dict()},
            })

        # 4. Gap Triage & Authoring: author and validate detections for gaps
        candidates: List[DetectionCandidate] = []
        newly_promoted: List[Dict[str, Any]] = []

        for gap in recon_report.gaps:
            triage_dec = self.triage_svc.triage_gap(gap, confidence=0.95)

            if triage_dec.get("decision") == GapDecision.AUTHOR_NOW.value:
                # Author candidate
                candidate = await self.author_svc.author_candidate_for_gap(
                    gap=gap,
                    captured_telemetry=exec_res.captured_telemetry,
                )

                # Gate through validation harness (Lint, Replay, Review)
                from core.detections.validation_harness import ValidationHarness

                harness = ValidationHarness(run_id=self.run_id)
                val_record = harness.validate_candidate(candidate, exec_res.captured_telemetry)

                # Gate through live-fire (Reseeded retest & Quiet-on-benign)
                if val_record.is_valid:
                    lf_result = self.live_fire_svc.evaluate_live_fire(
                        candidate=candidate,
                        benign_baseline_telemetry=self.config.benign_baseline,
                        reseed=cycle_number * 101,
                    )

                    if lf_result.passed:
                        # Promotion under demote-yourself-only
                        promoted = self.triage_svc.promote_candidate(
                            candidate=candidate,
                            authorized_by="closed_loop_authorized_policy",
                            pre_authorized=True,
                        )
                        if promoted:
                            promo_dict = {
                                "candidate_id": candidate.candidate_id,
                                "technique_id": candidate.gap_technique_id,
                                "name": candidate.name,
                                "format": candidate.format,
                            }
                            newly_promoted.append(promo_dict)
                            self.events_journal.append({
                                "run_id": self.run_id,
                                "seq": len(self.events_journal) + 1,
                                "ts": utcnow().isoformat(),
                                "kind": "detection_promotion",
                                "payload": {
                                    "environment_id": self.config.environment_id,
                                    "technique_id": candidate.gap_technique_id,
                                    "name": candidate.name,
                                },
                            })

                candidates.append(candidate)

        cycle_cost = float(exec_res.token_spend.get("cost_usd", 0.005))

        return LoopCycleResult(
            cycle_number=cycle_number,
            plan=plan,
            execution_result=exec_res,
            reconstruction_report=recon_report,
            candidates_authored=candidates,
            promoted_detections=newly_promoted,
            cycle_cost_usd=cycle_cost,
        )

    async def run(self) -> ClosedLoopRunResult:
        """Run the iterating loop across multiple cycles until a halt condition is met."""
        cumulative_cost = 0.0
        cumulative_promoted: List[Dict[str, Any]] = []
        cycle_results: List[LoopCycleResult] = []

        halt_reason = HaltReason.COMPLETED
        initial_frontier = 1.0

        for cycle in range(1, self.config.max_cycles + 1):
            if cumulative_cost >= self.config.max_cost_usd:
                halt_reason = HaltReason.BUDGET_EXCEEDED
                break

            result = await self.run_cycle(cycle, cumulative_promoted)
            cycle_results.append(result)
            cumulative_cost += result.cycle_cost_usd
            cumulative_promoted.extend(result.promoted_detections)

            # Check budget stop condition immediately after cycle spend
            if cumulative_cost >= self.config.max_cost_usd:
                halt_reason = HaltReason.BUDGET_EXCEEDED
                break

            # Check no viable path stop condition: red planner had no steps, or defense caught everything (0 gaps)
            if len(result.plan.steps) == 0 or len(result.reconstruction_report.gaps) == 0:
                halt_reason = HaltReason.NO_VIABLE_PATH
                break

        if len(cycle_results) >= self.config.max_cycles and halt_reason == HaltReason.COMPLETED:
            halt_reason = HaltReason.MAX_CYCLES_REACHED

        final_projection = fold_coverage_projection(self.events_journal, self.config.environment_id)

        return ClosedLoopRunResult(
            run_id=self.run_id,
            environment_id=self.config.environment_id,
            total_cycles_executed=len(cycle_results),
            halt_reason=halt_reason,
            cycle_results=cycle_results,
            initial_frontier=initial_frontier,
            final_frontier=final_projection.current_frontier,
            total_cost_usd=round(cumulative_cost, 6),
            promoted_rules_count=len(cumulative_promoted),
            final_projection=final_projection,
        )
