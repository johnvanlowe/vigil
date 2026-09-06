"""CLI and runtime engine for autonomous closed-loop detection engineering."""

from __future__ import annotations

import argparse
import logging
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.agents.red_planner.planner import RedPlanner, RedPlannerContext
from core.detections.authoring import DetectionAuthor
from core.detections.coverage import CoverageService
from core.detections.reconstruction import ReconstructionService
from core.detections.validation.lint import lint_candidate
from core.detections.validation.replay import replay_candidate
from core.integrations.offensive.contract import RedPlan
from core.integrations.offensive.stub import StubOffensiveEngine
from core.policies.schema import PolicyKind
from core.policies.service import PolicyService
from core.verification.judge import judge_candidate

logger = logging.getLogger(__name__)


@dataclass
class LoopResult:
    """Consolidated outcome of closed-loop execution."""

    environment_id: str
    cycles_completed: int
    halt_reason: str  # cycle_cap, budget_cap, operator_stop
    total_spend_usd: float
    promoted_detections: List[Dict[str, Any]] = field(default_factory=list)
    plans: List[RedPlan] = field(default_factory=list)
    contexts: List[RedPlannerContext] = field(default_factory=list)


class ClosedLoopRunner:
    """Orchestrates closed-loop detection engineering iterations."""

    def __init__(
        self,
        environment_id: str = "temporange",
        max_cycles: int = 1,
        budget_cap_usd: Optional[float] = None,
        session_factory: Optional[Any] = None,
        operator_stop_check: Optional[Callable[[], bool]] = None,
        policy_service: Optional[PolicyService] = None,
        coverage_service: Optional[CoverageService] = None,
    ):
        self.environment_id = environment_id
        self.max_cycles = max_cycles
        self.operator_stop_check = operator_stop_check or (lambda: False)
        self.session_factory = session_factory
        self.policy_service = policy_service or PolicyService(session_factory=session_factory)
        self.coverage_service = coverage_service or CoverageService(session_factory=session_factory)

        # Resolve budget cap from policy if not passed explicitly
        if budget_cap_usd is not None:
            self.budget_cap_usd = budget_cap_usd
        else:
            budget_pol = self.policy_service.get_policy(PolicyKind.BUDGET, scope=environment_id)
            if budget_pol and "max_daily_usd" in budget_pol.params:
                self.budget_cap_usd = float(budget_pol.params["max_daily_usd"])
            else:
                self.budget_cap_usd = 50.0

        self.ledger_events: List[Dict[str, Any]] = []

    async def run(self) -> LoopResult:
        """Run loop cycles until cycle cap, budget exhaustion, or operator stop."""
        cycles_completed = 0
        total_spend = 0.0
        promoted_rules: List[Dict[str, Any]] = []
        plans: List[RedPlan] = []
        contexts: List[RedPlannerContext] = []
        halt_reason = "cycle_cap"

        stub = StubOffensiveEngine(
            authorized_environments=[self.environment_id, "staging-range", "test-env", "sandbox-01", "temporange"]
        )

        while cycles_completed < self.max_cycles:
            # 1. Operator stop check
            if self.operator_stop_check():
                halt_reason = "operator_stop"
                break

            # 2. Budget cap check before starting cycle
            cycle_estimated_cost = 0.25
            if total_spend + cycle_estimated_cost > self.budget_cap_usd:
                halt_reason = "budget_cap"
                break

            cycle_num = cycles_completed + 1
            run_id = f"loop-{uuid.uuid4().hex[:8]}"

            # 3. Read current coverage view & prior promoted rules
            posture = self.coverage_service.project_from_events(
                self.ledger_events, environment_id=self.environment_id
            )
            prior_promoted = [
                {"technique_id": t.technique_id, "rule_name": t.matching_rules[0] if t.matching_rules else ""}
                for t in posture.techniques.values()
                if t.layer == "promoted"
            ]

            # 4. Red Planning grounded in coverage and prior promotions
            planner = RedPlanner(run_id=run_id)
            ctx = await planner.assemble_context(
                environment_id=self.environment_id,
                objectives=["Assess coverage seams and close gaps"],
                prior_promoted_rules=prior_promoted,
            )
            contexts.append(ctx)

            plan = planner.generate_red_plan(ctx, cycle_number=cycle_num)
            plans.append(plan)

            # 5. Execute red attack (via stub / fixture)
            run_res = await stub.run(plan)
            trace_steps = run_res.action_trace
            telemetry_records = run_res.captured_telemetry

            # 6. Reconstruct telemetry
            recon_svc = ReconstructionService(run_id=run_id)
            recon = recon_svc.reconstruct(
                action_trace=trace_steps,
                telemetry_findings=telemetry_records,
                environment_id=self.environment_id,
                plan_id=plan.plan_id,
                cycle_number=cycle_num,
            )

            # 7. Authoring for gaps
            author = DetectionAuthor(run_id=run_id)
            for gap in recon.gaps:
                candidate = await author.author_candidate_for_gap(
                    gap=gap,
                    captured_telemetry=telemetry_records,
                    environment_id=self.environment_id,
                )

                # 8. Validation (Lint, Replay, Judge)
                lint_res = lint_candidate(candidate)
                replay_res = replay_candidate(candidate, telemetry_records)
                judge_res = await judge_candidate(candidate, run_id=run_id)

                if judge_res.is_valid and lint_res.passed and replay_res.matched:
                    promoted_info = {
                        "environment_id": self.environment_id,
                        "candidate_id": candidate.candidate_id,
                        "rule_name": candidate.rule_name,
                        "technique_id": candidate.technique_id,
                        "cycle_number": cycle_num,
                    }
                    promoted_rules.append(promoted_info)

                    # Append promotion event to ledger events
                    self.ledger_events.append({
                        "kind": "promotion",
                        "payload": promoted_info,
                    })

            # Record cycle spend
            total_spend += cycle_estimated_cost
            cycles_completed += 1

        if cycles_completed >= self.max_cycles and halt_reason == "cycle_cap":
            halt_reason = "cycle_cap"

        return LoopResult(
            environment_id=self.environment_id,
            cycles_completed=cycles_completed,
            halt_reason=halt_reason,
            total_spend_usd=round(total_spend, 2),
            promoted_detections=promoted_rules,
            plans=plans,
            contexts=contexts,
        )


async def run_loop_cli(
    environment: str = "temporange",
    max_cycles: int = 1,
    budget_cap_usd: Optional[float] = None,
    session_factory: Optional[Any] = None,
    operator_stop_check: Optional[Callable[[], bool]] = None,
) -> LoopResult:
    """Programmatic entry point for vigil loop run."""
    runner = ClosedLoopRunner(
        environment_id=environment,
        max_cycles=max_cycles,
        budget_cap_usd=budget_cap_usd,
        session_factory=session_factory,
        operator_stop_check=operator_stop_check,
    )
    return await runner.run()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run autonomous closed-loop detection engineering cycles.")
    parser.add_argument("--environment", default="temporange", help="Target test range/environment")
    parser.add_argument("--max-cycles", type=int, default=1, help="Maximum loop iterations")
    parser.add_argument("--budget-cap-usd", type=float, default=None, help="Ceiling for LLM spend")

    args = parser.parse_args()
    import asyncio

    result = asyncio.run(
        run_loop_cli(
            environment=args.environment,
            max_cycles=args.max_cycles,
            budget_cap_usd=args.budget_cap_usd,
        )
    )

    print(f"=== Closed-Loop Complete ({result.environment_id}) ===")
    print(f"Cycles Completed:    {result.cycles_completed}")
    print(f"Halt Reason:         {result.halt_reason}")
    print(f"Total Spend:         ${result.total_spend_usd:.2f}")
    print(f"Promoted Detections: {len(result.promoted_detections)}")


if __name__ == "__main__":
    main()
