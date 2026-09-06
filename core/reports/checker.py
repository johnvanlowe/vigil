"""Report checker gate on hunt reports via skill_judge."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from core.policies.schema import PolicyKind
from core.policies.service import PolicyService
from core.reports.citations import Report
from core.verification.judge import judge_report_claims


class ReportCheckResult(BaseModel):
    passed: bool
    feedback: str
    reproduced_claims: List[Dict[str, Any]] = Field(default_factory=list)


async def check_report_gate(
    report: Report,
    query_executor: Optional[Callable[[str], Any]] = None,
    policy_service: Optional[PolicyService] = None,
    run_id: Optional[str] = None,
) -> ReportCheckResult:
    """Run semi-deterministic checker gate on report claims.

    Re-runs queries behind claims in context isolation; rejects if reproduction fails.
    """
    svc = policy_service or PolicyService()
    autonomy_policy = svc.get_policy(PolicyKind.AUTONOMY, scope="report_checker")

    # If policy explicitly disables checker, pass through
    if autonomy_policy and autonomy_policy.params.get("skip_report_checker"):
        return ReportCheckResult(
            passed=True,
            feedback="Report checker bypassed by explicit policy.",
        )

    claims_data = [
        {
            "claim_id": c.claim_id,
            "statement": c.statement,
            "citation": c.citation.model_dump() if c.citation else None,
        }
        for c in report.claims
    ]

    all_verified, results = await judge_report_claims(
        claims=claims_data,
        query_executor=query_executor,
        run_id=run_id,
    )

    if not all_verified:
        failed_claims = [r["claim_id"] for r in results if not r.get("verified")]
        return ReportCheckResult(
            passed=False,
            feedback=f"Verification failed on claims: {', '.join(failed_claims)}. Evidence queries did not reproduce claims.",
            reproduced_claims=results,
        )

    return ReportCheckResult(
        passed=True,
        feedback="All cited claims successfully reproduced and verified.",
        reproduced_claims=results,
    )
