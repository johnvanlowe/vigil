"""Daemon budget enforcement with fail-static posture on budget exhaustion."""

from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

from core.metrics.registry import get_metrics
from core.policies.schema import PolicyKind
from core.policies.service import PolicyService
from core.storage.ledger import append_agent_event

logger = logging.getLogger(__name__)

DEFAULT_BUDGET_USD_CAPS = {
    "compose": 10.0,
    "investigate": 5.0,
    "triage": 2.0,
    "hunt": 15.0,
}


class DaemonBudgetEnforcer:
    """Enforces per-run_kind spending caps and triggers fail-static degradation."""

    def __init__(self, policy_service: Optional[PolicyService] = None):
        self.policy_service = policy_service or PolicyService()

    def get_budget_cap(self, run_kind: str) -> float:
        """Fetch budget cap in USD for the run_kind from Policy(kind=budget)."""
        policy = self.policy_service.get_policy(PolicyKind.BUDGET, scope=run_kind)
        if policy and "max_cost_usd" in policy.params:
            cap = float(policy.params["max_cost_usd"])
            get_metrics().spend_budget_usd.labels(run_kind=run_kind).set(cap)
            return cap
        fallback = DEFAULT_BUDGET_USD_CAPS.get(run_kind, 5.0)
        get_metrics().spend_budget_usd.labels(run_kind=run_kind).set(fallback)
        return fallback

    def check_and_enforce(
        self,
        run_id: str,
        run_kind: str,
        current_spend_usd: float,
    ) -> Tuple[bool, Optional[str]]:
        """Verify spend against policy. If exhausted, emits event and halts execution.

        Returns (is_allowed, halt_reason).
        """
        cap = self.get_budget_cap(run_kind)
        if current_spend_usd >= cap:
            # Emit budget_exhausted event to Ledger
            try:
                append_agent_event(
                    run_id=run_id,
                    kind="budget_exhausted",
                    payload={
                        "schema_version": 1,
                        "run_id": run_id,
                        "run_kind": run_kind,
                        "budget_usd": cap,
                        "spend_usd": current_spend_usd,
                        "reason": f"Run spend (${current_spend_usd:.4f}) reached budget cap (${cap:.4f})",
                    },
                    run_kind=run_kind,
                )
            except Exception as exc:
                logger.error("Failed to append budget_exhausted event: %s", exc)

            # Increment metric
            try:
                get_metrics().budget_exhausted_total.labels(run_kind=run_kind).inc()
            except Exception:
                pass

            logger.warning(
                "Run %s halted: spend $%.4f reached budget cap $%.4f for %s",
                run_id, current_spend_usd, cap, run_kind
            )
            return False, f"Budget cap reached: ${cap:.2f} USD"

        return True, None
