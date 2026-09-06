"""Evidence citation models and report validation for Vigil show-the-work."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from core.time import utcnow


class Citation(BaseModel):
    """A typed evidence citation that resolves to a replayable query."""

    source: str = Field(..., description="Data source name (e.g. sysmon, zeek, auth)")
    query: str = Field(..., description="Replayable query string (e.g. SQL, KQL, Splunk SPL)")
    time_window: str = Field(..., description="Time window for query execution (e.g. 2026-09-05T00:00:00Z/P1D)")
    expected_result: Optional[Any] = Field(default=None, description="Expected query match or evidence row summary")


class ReportClaim(BaseModel):
    """An individual factual claim within a hunt or incident report."""

    claim_id: str
    statement: str
    citation: Optional[Citation] = None


class Report(BaseModel):
    """An audit report containing claims and replayable evidence citations."""

    report_id: str
    title: str
    claims: List[ReportClaim] = Field(default_factory=list)
    status: Literal["draft", "final"] = "draft"
    author: str = "reporter_agent"
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())


def validate_and_finalize_report(report: Report) -> Report:
    """Validate that every claim has an evidence citation; uncited reports stay draft."""
    if not report.claims:
        report.status = "draft"
        return report

    all_cited = all(
        claim.citation is not None and bool(claim.citation.query.strip())
        for claim in report.claims
    )

    if all_cited:
        report.status = "final"
    else:
        report.status = "draft"

    return report
