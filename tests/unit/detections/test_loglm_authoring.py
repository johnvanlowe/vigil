"""Unit tests for LogLM-grounded authoring for model-only gaps."""

import pytest

from core.detections.authoring import DetectionAuthor
from core.detections.candidate import CandidateStatus
from core.detections.validation_harness import ValidationHarness


@pytest.mark.asyncio
async def test_loglm_grounded_authoring_for_model_only_gap():
    """Verify a model-only gap produces a candidate grounded in LogLM behavioral features."""
    author = DetectionAuthor()
    harness = ValidationHarness()

    gap = {
        "step_id": "step-loglm-1",
        "technique_id": "T1059.001",
        "action_name": "Obfuscated PowerShell Invocation",
        "gap_type": "model_only",
        "loglm_finding_id": "f-loglm-9921",
    }

    telemetry = [
        {
            "event_id": "ev-pws-1",
            "step_id": "step-loglm-1",
            "technique_id": "T1059.001",
            "details": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -w hidden -enc aW52b2tl...",
            },
        }
    ]

    candidate = await author.author_candidate_for_gap(
        gap=gap,
        captured_telemetry=telemetry,
        target_format="sigma",
    )

    # 1. Candidate is typed Pydantic artifact
    assert candidate.gap_technique_id == "T1059.001"
    assert candidate.loglm_neighborhood_used is True
    assert len(candidate.grounding_features) > 0
    assert "encoded_command_line_switch" in candidate.grounding_features

    # 2. Candidate must clear behavioral anti-brittleness linting!
    lint_result = harness.lint_candidate(candidate)
    assert lint_result.passed is True
    assert lint_result.anti_brittleness_passed is True
    assert lint_result.detected_literals == []

    # 3. Candidate matches telemetry in replay
    replay_result = harness.replay_candidate(candidate, telemetry)
    assert replay_result.passed is True
