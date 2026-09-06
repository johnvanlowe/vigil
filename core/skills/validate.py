"""Frontmatter JSON Schema validation for SKILL.md bundles.

Warns on unknown keys in Vigil 1.0, fails in 2.0.
"""

from __future__ import annotations

import json
import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jsonschema
import yaml

logger = logging.getLogger(__name__)

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "schemas" / "skill_v1.json"
)


def load_skill_schema() -> Dict[str, Any]:
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


def validate_skill_frontmatter(path: Path, fail_on_unknown: bool = False) -> Dict[str, Any]:
    """Validate a SKILL.md file against skill_v1.json schema."""
    content = path.read_text(encoding="utf-8")
    frontmatter, _ = parse_frontmatter(content)
    if not frontmatter:
        raise ValueError(f"No YAML frontmatter found in {path}")

    schema = load_skill_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(frontmatter))
    if errors:
        msg = f"Validation failed for {path}: " + "; ".join(e.message for e in errors)
        raise jsonschema.ValidationError(msg)

    known_keys = set(schema.get("properties", {}).keys())
    unknown_keys = set(frontmatter.keys()) - known_keys
    if unknown_keys:
        warning_msg = f"{path}: Unknown skill frontmatter keys {sorted(unknown_keys)} (warn in 1.0, fail in 2.0)"
        if fail_on_unknown:
            raise ValueError(warning_msg)
        warnings.warn(warning_msg, UserWarning, stacklevel=2)
        logger.warning(warning_msg)

    return frontmatter


def validate_all_skills(skills_dir: Optional[Path] = None) -> List[Path]:
    """Validate all skill bundles under skills directory."""
    if skills_dir is None:
        skills_dir = Path(__file__).resolve().parents[2] / "skills"

    validated: List[Path] = []
    for sf in skills_dir.rglob("SKILL.md"):
        validate_skill_frontmatter(sf)
        validated.append(sf)
    return validated
