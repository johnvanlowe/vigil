"""Frontmatter JSON Schema validation for WORKFLOW.md playbooks.

Warns on unknown keys in Vigil 1.0, fails in 2.0.
"""

from __future__ import annotations

import json
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Tuple

import jsonschema
import yaml

logger = logging.getLogger(__name__)

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "schemas" / "workflow_v1.json"
)


def load_workflow_schema() -> Dict[str, Any]:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Extract YAML frontmatter from markdown content."""
    lines = content.strip().splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, content

    end_idx = -1
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break

    if end_idx == -1:
        return {}, content

    yaml_block = "\n".join(lines[1:end_idx])
    body = "\n".join(lines[end_idx + 1:])
    try:
        data = yaml.safe_load(yaml_block) or {}
        return data, body
    except Exception as exc:
        raise ValueError(f"Failed to parse YAML frontmatter: {exc}")


def validate_workflow_frontmatter(path: Path, fail_on_unknown: bool = False) -> Dict[str, Any]:
    """Validate a WORKFLOW.md file against workflow_v1.json schema."""
    content = path.read_text(encoding="utf-8")
    frontmatter, _ = parse_frontmatter(content)
    if not frontmatter:
        raise ValueError(f"No YAML frontmatter found in {path}")

    schema = load_workflow_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(frontmatter))
    if errors:
        msg = f"Validation failed for {path}: " + "; ".join(e.message for e in errors)
        raise jsonschema.ValidationError(msg)

    # Check unknown keys
    known_keys = set(schema.get("properties", {}).keys())
    unknown_keys = set(frontmatter.keys()) - known_keys
    if unknown_keys:
        warning_msg = f"{path}: Unknown frontmatter keys {sorted(unknown_keys)} (warn in 1.0, fail in 2.0)"
        if fail_on_unknown:
            raise ValueError(warning_msg)
        warnings.warn(warning_msg, UserWarning, stacklevel=2)
        logger.warning(warning_msg)

    return frontmatter


def validate_all_workflows(root_dir: Optional[Path] = None) -> List[Path]:
    """Validate all built-in playbooks under definitions directory."""
    if root_dir is None:
        root_dir = Path(__file__).resolve().parent / "definitions"

    validated: List[Path] = []
    for wf in root_dir.rglob("WORKFLOW.md"):
        validate_workflow_frontmatter(wf)
        validated.append(wf)
    return validated
