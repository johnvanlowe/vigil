"""Tests for the Judge independent review skill and candidate verification."""

import pytest
from core.detections.candidates import DetectionCandidate
from core.verification.judge import judge_candidate, judge_report_claims


@pytest.mark.asyncio
async def test_judge_accepts_clean_behavioral_candidate():
    """Judge validates behavioral candidate with good scores."""
    candidate = DetectionCandidate(
        candidate_id="cand-good",
        environment_id="range-01",
        technique_id="T1059.001",
        rule_name="Suspicious PowerShell Downloader",
        rule_content="title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: 'Invoke-WebRequest'",
        rationale="Catches web downloader invocations behaviorally",
    )

    verdict = await judge_candidate(candidate)
    assert verdict.is_valid is True
    assert verdict.behavioral_alignment >= 0.85
    assert "Approved" in verdict.feedback


@pytest.mark.asyncio
async def test_judge_rejects_candidate_with_brittle_literals():
    """Judge rejects candidates with environment IP or host literals."""
    candidate = DetectionCandidate(
        candidate_id="cand-brittle",
        environment_id="range-01",
        technique_id="T1059.001",
        rule_name="Brittle Rule",
        rule_content="title: Brittle Rule\ndetection:\n  selection:\n    DestinationIp: '192.168.1.50'\n    Host: 'server-01.corp.local'",
        rationale="Overfitted to specific range machine",
    )

    verdict = await judge_candidate(candidate)
    assert verdict.is_valid is False
    assert verdict.behavioral_alignment < 0.5
    assert "Rejected" in verdict.feedback
