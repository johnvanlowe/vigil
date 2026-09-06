"""Tests for LogLM-grounded authoring and fallback when LogLM MCP is absent."""

import pytest
from unittest.mock import AsyncMock

from core.detections.candidates import DetectionCandidate
from core.detections.grounding_loglm import LogLMGroundingService
from core.detections.validation.lint import lint_candidate


@pytest.mark.asyncio
async def test_loglm_grounded_authoring_derives_from_neighborhood_and_clears_lint():
    """Verify loglm-only candidate uses embedding neighborhood features and clears anti-brittleness lint."""
    mock_mcp = AsyncMock()
    mock_mcp.call_tool.return_value = {
        "features": ["admin_share_access", "smb_named_pipe_traverse", "anomalous_parent_process"]
    }

    service = LogLMGroundingService(mcp_client=mock_mcp)

    candidate = DetectionCandidate(
        candidate_id="cand-loglm-001",
        environment_id="staging-range",
        technique_id="T1021.002",
        rule_name="Behavioral SMB Admin Share Access",
        rule_content="""
title: Behavioral SMB Admin Share Access
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "IPC$"
      - "ADMIN$"
      - "C$"
  condition: selection
""",
        rationale="Initial draft",
    )

    gap = {
        "step_id": "step-03-anomaly",
        "technique_id": "T1021.002",
        "verdict": "loglm",
        "gap_type": "model_only",
        "loglm_finding_id": "f-loglm-smb-01",
    }

    grounded = await service.ground_authoring(gap, candidate)

    assert grounded.metadata["loglm_grounded"] is True
    assert "admin_share_access" in grounded.rationale
    assert "LogLM embedding neighborhood" in grounded.rationale

    # Must clear the anti-brittleness behavioral lint
    lint_res = lint_candidate(grounded)
    assert lint_res.passed is True
    assert lint_res.anti_brittleness_passed is True
    assert len(lint_res.detected_literals) == 0


@pytest.mark.asyncio
async def test_loglm_absent_proceeds_without_assist_and_reports_in_rationale():
    """Verify that when LogLM MCP is absent, authoring proceeds and notes absence in rationale."""
    # Service without MCP client
    service = LogLMGroundingService(mcp_client=None)

    candidate = DetectionCandidate(
        candidate_id="cand-loglm-002",
        environment_id="staging-range",
        technique_id="T1048",
        rule_name="Exfiltration Rule",
        rule_content="""
title: Alternative Protocol Exfiltration
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "curl"
      - "Invoke-WebRequest"
  condition: selection
""",
        rationale="Initial draft",
    )

    gap = {
        "step_id": "step-04-exfil",
        "technique_id": "T1048",
        "verdict": "loglm",
        "gap_type": "model_only",
    }

    grounded = await service.ground_authoring(gap, candidate)

    assert grounded.metadata["loglm_grounded"] is False
    assert "Proceeded without LogLM grounding assist" in grounded.rationale
    assert "LogLM MCP absent/unreachable" in grounded.rationale

    lint_res = lint_candidate(grounded)
    assert lint_res.passed is True
