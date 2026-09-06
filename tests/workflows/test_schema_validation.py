"""Tests for WORKFLOW.md and SKILL.md frontmatter JSON Schema validation."""

from pathlib import Path
import warnings
import pytest

from core.skills.validate import validate_all_skills, validate_skill_frontmatter
from core.workflows.validate import parse_frontmatter, validate_all_workflows, validate_workflow_frontmatter
from scripts.create_workflow import build_template


def test_all_builtin_workflows_validate():
    """Verify all built-in WORKFLOW.md playbooks validate against workflow_v1.json."""
    workflows = validate_all_workflows()
    assert len(workflows) >= 5
    for wf in workflows:
        data = validate_workflow_frontmatter(wf)
        assert "name" in data
        assert "description" in data


def test_all_loop_skills_validate():
    """Verify all four loop skills (reconstruction, authoring, validation, judge) validate against skill_v1.json."""
    skills = validate_all_skills()
    assert len(skills) >= 4
    skill_names = set()
    for sf in skills:
        data = validate_skill_frontmatter(sf)
        assert "name" in data
        assert "description" in data
        skill_names.add(data["name"])

    assert "reconstruction" in skill_names
    assert "author_detection" in skill_names
    assert "validate_detection" in skill_names
    assert "judge" in skill_names


def test_unknown_keys_warn_in_1_0_fail_in_2_0(tmp_path):
    """Verify unknown frontmatter keys produce a warning in 1.0 and fail when strict."""
    wf_file = tmp_path / "WORKFLOW.md"
    wf_file.write_text(
        """---
name: custom-workflow
description: Test workflow
unknown_custom_key_for_future: some_value
---
# Content
""",
        encoding="utf-8",
    )

    # In 1.0 mode: warns but succeeds
    with pytest.warns(UserWarning, match="Unknown frontmatter keys"):
        data = validate_workflow_frontmatter(wf_file, fail_on_unknown=False)
    assert data["name"] == "custom-workflow"

    # In 2.0 mode (fail_on_unknown=True): raises ValueError
    with pytest.raises(ValueError, match="Unknown frontmatter keys"):
        validate_workflow_frontmatter(wf_file, fail_on_unknown=True)


def test_create_workflow_script_emits_v1():
    """Verify scripts/create_workflow.py emits schema_version: 1."""
    template = build_template("test-scaffold-wf", ["investigator", "reporter"])
    assert "schema_version: 1" in template
    assert "name: test-scaffold-wf" in template
