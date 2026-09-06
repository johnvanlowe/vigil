"""Tests for evidence citations and report finalization requirements."""

from core.reports.citations import Citation, Report, ReportClaim, validate_and_finalize_report


def test_uncited_claim_forces_draft_status():
    """A report with an uncited claim cannot be marked final."""
    claim1 = ReportClaim(
        claim_id="c1",
        statement="Lateral movement observed across finance subnet",
        citation=None,  # Missing citation
    )
    report = Report(
        report_id="rep-1",
        title="Incident Analysis",
        claims=[claim1],
    )

    validated = validate_and_finalize_report(report)
    assert validated.status == "draft"


def test_fully_cited_report_finalizes():
    """A report where every claim cites a valid replayable query marks as final."""
    citation = Citation(
        source="sysmon",
        query="EventID == 1 and Image == 'powershell.exe'",
        time_window="2026-09-05T00:00:00Z/P1D",
        expected_result={"count": 5},
    )
    claim = ReportClaim(
        claim_id="c1",
        statement="Encoded PowerShell execution detected",
        citation=citation,
    )
    report = Report(
        report_id="rep-2",
        title="Hunt Findings Report",
        claims=[claim],
    )

    validated = validate_and_finalize_report(report)
    assert validated.status == "final"
