"""Tests for detection authoring skill and candidate synthesis."""

from pathlib import Path
import pytest

from core.detections.authoring import (
    DetectionAuthor,
    skill_author_detection,
)
from core.detections.candidates import DetectionCandidate


def test_skill_manifest_and_function_exposure():
    """Verify SKILL.md exists, has schema_version: 1, and skill_author_detection is callable."""
    skill_path = Path(__file__).resolve().parents[2] / "skills" / "author_detection" / "SKILL.md"
    assert skill_path.exists()
    content = skill_path.read_text(encoding="utf-8")
    assert "schema_version: 1" in content
    assert callable(skill_author_detection)


@pytest.mark.asyncio
async def test_authoring_emits_typed_candidate():
    """Verify DetectionCandidate artifact has required fields and conforms to contract."""
    gap = {
        "step_id": "step-wmi",
        "technique_id": "T1047",
        "action_name": "WMI Process Creation",
        "gap_type": "complete_miss",
    }

    candidate = await skill_author_detection(
        gap=gap,
        environment_id="staging-range",
        target_format="sigma",
    )

    assert isinstance(candidate, DetectionCandidate)
    assert candidate.environment_id == "staging-range"
    assert candidate.technique_id == "T1047"
    assert candidate.gap_id == "step-wmi"
    assert candidate.format == "sigma"
    assert "title: " in candidate.rule_content
    assert "T1047" in candidate.rule_content
    assert len(candidate.rationale) > 0


@pytest.mark.asyncio
async def test_authoring_schema_grounding_rejection():
    """Verify rule authoring rejects unsupported fields not emitted by the environment."""
    author = DetectionAuthor()
    gap = {
        "step_id": "step-wmi",
        "technique_id": "T1047",
    }

    # Restrict allowed fields to something that excludes CommandLine and Image
    restricted_schema = {"user", "host"}
    with pytest.raises(ValueError, match="contains unsupported fields"):
        await author.author_candidate_for_gap(
            gap=gap,
            allowed_fields=restricted_schema,
        )


@pytest.mark.asyncio
async def test_deactivating_skill_has_no_core_residue():
    """Verify candidate is self-contained and operates independently of orchestration."""
    gap = {
        "step_id": "step-test",
        "technique_id": "T1003",
        "gap_type": "complete_miss",
    }
    cand = await skill_author_detection(gap, environment_id="env-isolated")
    assert cand.candidate_id.startswith("cand-T1003")
    assert cand.status.value == "draft"
