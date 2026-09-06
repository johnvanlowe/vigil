"""Tests for report checker gate via skill_judge."""

import pytest
from core.reports.checker import check_report_gate
from core.reports.citations import Citation, Report, ReportClaim


@pytest.mark.asyncio
async def test_report_checker_accepts_verified_claims():
    """Checker approves when evidence queries reproduce the claims."""
    citation = Citation(
        source="suricata",
        query="alert tcp any any -> any 443",
        time_window="2026-09-05/P1D",
        expected_result={"hits": 12},
    )
    report = Report(
        report_id="rep-101",
        title="Valid Report",
        claims=[ReportClaim(claim_id="c1", statement="C2 traffic on 443", citation=citation)],
    )

    def mock_query_executor(query: str):
        if query == "alert tcp any any -> any 443":
            return {"hits": 12}
        return None

    res = await check_report_gate(report, query_executor=mock_query_executor)
    assert res.passed is True
    assert "successfully reproduced" in res.feedback


@pytest.mark.asyncio
async def test_report_checker_rejects_unreproduced_claims():
    """Checker rejects when query results do not match expected claim result."""
    citation = Citation(
        source="sysmon",
        query="EventID == 10",
        time_window="2026-09-05/P1D",
        expected_result={"hits": 5},
    )
    report = Report(
        report_id="rep-102",
        title="Unverified Report",
        claims=[ReportClaim(claim_id="c_bad", statement="LSASS memory dump occurred", citation=citation)],
    )

    def mock_query_executor(query: str):
        # Returns mismatch
        return {"hits": 0}

    res = await check_report_gate(report, query_executor=mock_query_executor)
    assert res.passed is False
    assert "Verification failed on claims: c_bad" in res.feedback
