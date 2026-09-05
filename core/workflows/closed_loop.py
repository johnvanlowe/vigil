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
8. Coverage projection is read durably from the Ledger for the next cycle.

Stops on: no viable path remaining, cycle limit reached, budget exceeded, operator stop,
awaiting approval, or execution failure.
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
    read_coverage_projection,
)
from core.detections.live_fire import LiveFireService, get_default_benign_baseline
from core.detections.reconstruction import ReconstructionReport, ReconstructionService
from core.detections.validation_harness import ValidationHarness
from core.integrations.offensive_engine import (
    AttackExecutionResult,
    AttackPlan,
    EnvironmentScope,
    ExecutionStatus,
    OffensiveEngine,
    get_offensive_engine,
)
from core.response.checkpoints import raise_for_checkpoint
from core.time import utcnow

logger = logging.getLogger(__name__)


class HaltReason(str, Enum):
    """Reason for terminating the closed loop iteration."""

    NO_VIABLE_PATH = "no_viable_path"
    MAX_CYCLES_REACHED = "max_cycles_reached"
    BUDGET_EXCEEDED = "budget_exceeded"
    OPERATOR_STOP = "operator_stop"
    COMPLETED = "completed"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTION_FAILED = "execution_failed"
    UNAUTHORIZED_ENVIRONMENT = "unauthorized_environment"


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
    benign_baseline: List[Dict[str, Any]] = field(default_factory=get_default_benign_baseline)
    engine_name: Optional[str] = None
    pre_approved_offense: bool = False
    pre_authorized_promotion: bool = False
    require_benign_baseline: bool = True
    scope: Optional[EnvironmentScope] = None


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
        self.run_id = str(run_id) if run_id else f"cl-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        self.engine: OffensiveEngine = get_offensive_engine(config.engine_name)
        self.planner = RedPlanner(run_id=self.run_id)
        self.reconstruction_svc = ReconstructionService(run_id=self.run_id)
        self.triage_svc = GapTriageService(run_id=self.run_id, policy=config.policy)
        self.author_svc = DetectionAuthor(run_id=self.run_id)
        self.validation_harness = ValidationHarness(run_id=self.run_id)
        self.live_fire_svc = LiveFireService(run_id=self.run_id)

    def _derive_gap_confidence(self, gap: Dict[str, Any]) -> float:
        """Derive confidence score grounded in gap signals and anomaly score."""
        for key in ("confidence", "anomaly_score", "loglm_score"):
            if key in gap and isinstance(gap[key], (int, float)):
                return float(gap[key])

        gap_type = gap.get("gap_type")
        priority = str(gap.get("priority", "medium")).lower()

        base = 0.92 if gap_type == "model_only" else (0.82 if gap_type == "complete_miss" else 0.85)
        if priority == "high":
            return min(0.98, base + 0.05)
        elif priority == "low":
            return max(0.70, base - 0.10)
        return base

    async def run_cycle(
        self,
        cycle_number: int,
        promoted_rules: Sequence[Dict[str, Any]],
    ) -> LoopCycleResult:
        """Execute one complete cycle of the closed loop."""
        logger.info("Starting closed loop cycle %d for environment %s", cycle_number, self.config.environment_id)

        # 1. Red Planning: assemble context and synthesize plan
        ctx = await self.planner.assemble_context(
            environment_id=self.config.environment_id,
            objectives=self.config.objectives,
            threat_context=self.config.threat_context,
            prior_promoted_rules=list(promoted_rules),
        )
        plan = self.planner.generate_plan(
            ctx,
            seed=42 + cycle_number * 17,
            cycle_number=cycle_number,
        )

        planning_cost = 0.002

        # 2. Offensive Safety Gate: validate environment and enforce approval
        if self.config.scope and not self.config.scope.is_target_authorized():
            logger.warning(
                "Safety gate refusal: environment %s not authorized under scope (production=%s)",
                self.config.environment_id,
                self.config.scope.is_production,
            )
            exec_res = AttackExecutionResult(
                plan_id=plan.plan_id,
                run_id=self.run_id,
                status=ExecutionStatus.FAILED,
                error="Unauthorized environment refused by EnvironmentScope safety check",
            )
            return LoopCycleResult(
                cycle_number=cycle_number,
                plan=plan,
                execution_result=exec_res,
                reconstruction_report=ReconstructionReport(
                    run_id=self.run_id,
                    plan_id=plan.plan_id,
                    environment_id=self.config.environment_id,
                    step_verdicts=[],
                    total_steps=0,
                    detected_by_rule_count=0,
                    detected_by_loglm_count=0,
                    both_count=0,
                    missed_count=0,
                    gaps=[],
                ),
                candidates_authored=[],
                promoted_detections=[],
                cycle_cost_usd=planning_cost,
            )

        is_valid_env = await self.engine.validate_environment(self.config.environment_id)
        if not is_valid_env:
            logger.warning("Safety gate refusal: environment %s failed engine validation", self.config.environment_id)
            exec_res = AttackExecutionResult(
                plan_id=plan.plan_id,
                run_id=self.run_id,
                status=ExecutionStatus.FAILED,
                error=f"Unauthorized environment: {self.config.environment_id!r} rejected by offensive engine validation",
            )
            return LoopCycleResult(
                cycle_number=cycle_number,
                plan=plan,
                execution_result=exec_res,
                reconstruction_report=ReconstructionReport(
                    run_id=self.run_id,
                    plan_id=plan.plan_id,
                    environment_id=self.config.environment_id,
                    step_verdicts=[],
                    total_steps=0,
                    detected_by_rule_count=0,
                    detected_by_loglm_count=0,
                    both_count=0,
                    missed_count=0,
                    gaps=[],
                ),
                candidates_authored=[],
                promoted_detections=[],
                cycle_cost_usd=planning_cost,
            )

        if not self.config.pre_approved_offense:
            checkpoint_id = f"chk-offense-{self.run_id}-{cycle_number}"
            raise_for_checkpoint(
                run_id=self.run_id,
                checkpoint_id=checkpoint_id,
                title=f"Authorize offensive execution on {self.config.environment_id}",
                description=f"Automated offensive campaign plan {plan.plan_id} targeting {self.config.environment_id}.",
                reason="Offensive execution requires operator pre-approval under safety gate.",
                parameters={"environment_id": self.config.environment_id, "plan_id": plan.plan_id},
            )
            exec_res = AttackExecutionResult(
                plan_id=plan.plan_id,
                run_id=self.run_id,
                status=ExecutionStatus.PENDING_APPROVAL,
                error="Offensive execution paused. Awaiting human operator approval.",
            )
            return LoopCycleResult(
                cycle_number=cycle_number,
                plan=plan,
                execution_result=exec_res,
                reconstruction_report=ReconstructionReport(
                    run_id=self.run_id,
                    plan_id=plan.plan_id,
                    environment_id=self.config.environment_id,
                    step_verdicts=[],
                    total_steps=0,
                    detected_by_rule_count=0,
                    detected_by_loglm_count=0,
                    both_count=0,
                    missed_count=0,
                    gaps=[],
                ),
                candidates_authored=[],
                promoted_detections=[],
                cycle_cost_usd=planning_cost,
            )

        # Execute offensive plan (gated)
        exec_res = await self.engine.execute(plan)

        # 3. Execution Status Inspection: handle FAILED / STOPPED / PENDING_APPROVAL
        if exec_res.status in (ExecutionStatus.FAILED, ExecutionStatus.STOPPED, ExecutionStatus.PENDING_APPROVAL):
            logger.warning("Offensive execution stopped or failed with status: %s", exec_res.status)
            cycle_cost = float(exec_res.token_spend.get("cost_usd", 0.0)) + planning_cost
            return LoopCycleResult(
                cycle_number=cycle_number,
                plan=plan,
                execution_result=exec_res,
                reconstruction_report=ReconstructionReport(
                    run_id=self.run_id,
                    plan_id=plan.plan_id,
                    environment_id=self.config.environment_id,
                    step_verdicts=[],
                    total_steps=0,
                    detected_by_rule_count=0,
                    detected_by_loglm_count=0,
                    both_count=0,
                    missed_count=0,
                    gaps=[],
                ),
                candidates_authored=[],
                promoted_detections=[],
                cycle_cost_usd=cycle_cost,
            )

        # 4. Detection Reconstruction: correlate trace to telemetry
        recon_report = self.reconstruction_svc.reconstruct(
            action_trace=exec_res.action_trace,
            telemetry_findings=exec_res.captured_telemetry,
            environment_id=self.config.environment_id,
            plan_id=plan.plan_id,
        )

        # 5. Gap Triage & Authoring: author and validate detections for gaps
        candidates: List[DetectionCandidate] = []
        newly_promoted: List[Dict[str, Any]] = []

        authoring_spend = 0.0
        validation_spend = 0.0
        triage_spend = 0.0

        for gap in recon_report.gaps:
            confidence = self._derive_gap_confidence(gap)
            triage_dec = self.triage_svc.triage_gap(gap, confidence=confidence)
            triage_spend += 0.001

            if triage_dec.get("decision") == GapDecision.AUTHOR_NOW.value:
                candidate = await self.author_svc.author_candidate_for_gap(
                    gap=gap,
                    captured_telemetry=exec_res.captured_telemetry,
                )
                authoring_spend += 0.005

                val_record = self.validation_harness.validate_candidate(candidate, exec_res.captured_telemetry)
                validation_spend += 0.003

                if val_record.is_valid:
                    lf_result = self.live_fire_svc.evaluate_live_fire(
                        candidate=candidate,
                        benign_baseline_telemetry=self.config.benign_baseline,
                        reseed=cycle_number * 101,
                        require_benign_corpus=self.config.require_benign_baseline,
                    )

                    if lf_result.passed:
                        # Promotion under demote-yourself-only: derive from config / policy
                        is_pre_auth = self.config.pre_authorized_promotion or not self.config.policy.require_human_promotion
                        authorized_by = "closed_loop_policy" if is_pre_auth else "agent"

                        if not is_pre_auth:
                            checkpoint_id = f"chk-promote-{candidate.candidate_id}"
                            raise_for_checkpoint(
                                run_id=self.run_id,
                                checkpoint_id=checkpoint_id,
                                title=f"Authorize Detection Promotion: {candidate.name}",
                                description=f"Candidate {candidate.name} ({candidate.gap_technique_id}) passed validation and live-fire. Authorize promotion?",
                                reason="Promotion requires human operator approval under demote-yourself-only policy.",
                                parameters={"candidate_id": candidate.candidate_id, "technique_id": candidate.gap_technique_id},
                            )

                        promoted = self.triage_svc.promote_candidate(
                            candidate=candidate,
                            authorized_by=authorized_by,
                            pre_authorized=is_pre_auth,
                        )
                        if promoted:
                            promo_dict = {
                                "candidate_id": candidate.candidate_id,
                                "technique_id": candidate.gap_technique_id,
                                "name": candidate.name,
                                "format": candidate.format,
                            }
                            newly_promoted.append(promo_dict)

                candidates.append(candidate)

        offensive_spend = float(exec_res.token_spend.get("cost_usd", 0.005))
        cycle_cost = round(offensive_spend + planning_cost + authoring_spend + validation_spend + triage_spend, 6)

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

        # Read initial frontier from pre-cycle durable coverage projection
        pre_projection = read_coverage_projection(self.config.environment_id)
        initial_frontier = pre_projection.current_frontier

        for cycle in range(1, self.config.max_cycles + 1):
            if cumulative_cost >= self.config.max_cost_usd:
                halt_reason = HaltReason.BUDGET_EXCEEDED
                break

            result = await self.run_cycle(cycle, cumulative_promoted)
            cycle_results.append(result)
            cumulative_cost += result.cycle_cost_usd
            cumulative_promoted.extend(result.promoted_detections)

            # Check execution status stops
            if result.execution_result.status == ExecutionStatus.FAILED:
                if "unauthorized" in str(result.execution_result.error).lower():
                    halt_reason = HaltReason.UNAUTHORIZED_ENVIRONMENT
                else:
                    halt_reason = HaltReason.EXECUTION_FAILED
                break

            if result.execution_result.status in (ExecutionStatus.STOPPED, ExecutionStatus.PENDING_APPROVAL):
                halt_reason = HaltReason.AWAITING_APPROVAL
                break

            # Check budget stop condition immediately after cycle spend
            if cumulative_cost >= self.config.max_cost_usd:
                halt_reason = HaltReason.BUDGET_EXCEEDED
                break

            # Check no-viable-path stop condition:
            # Red plan had zero steps to execute
            if len(result.plan.steps) == 0:
                halt_reason = HaltReason.NO_VIABLE_PATH
                break

            # If defense caught everything and no gaps remain, loop successfully completed
            if len(result.reconstruction_report.gaps) == 0:
                halt_reason = HaltReason.COMPLETED
                break

        if len(cycle_results) >= self.config.max_cycles and halt_reason == HaltReason.COMPLETED:
            if cycle_results and len(cycle_results[-1].reconstruction_report.gaps) > 0:
                halt_reason = HaltReason.MAX_CYCLES_REACHED

        final_projection = read_coverage_projection(self.config.environment_id)

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
