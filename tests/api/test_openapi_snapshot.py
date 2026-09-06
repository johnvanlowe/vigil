"""Test ensuring OpenAPI contract stability via snapshot comparison."""

import json
from pathlib import Path
import pytest

from services.api.main import app


def test_openapi_schema_matches_snapshot():
    """Verify that current FastAPI OpenAPI schema matches the committed snapshot."""
    snapshot_path = Path(__file__).parent / "openapi.snapshot.json"
    assert snapshot_path.exists(), "OpenAPI snapshot file tests/api/openapi.snapshot.json must exist"

    with open(snapshot_path, "r", encoding="utf-8") as f:
        expected_schema = json.load(f)

    current_schema = app.openapi()

    # Compare paths keys (API endpoints)
    current_paths = set(current_schema.get("paths", {}).keys())
    expected_paths = set(expected_schema.get("paths", {}).keys())

    added_paths = current_paths - expected_paths
    removed_paths = expected_paths - current_paths

    assert not removed_paths, f"Breaking change: OpenAPI endpoints removed: {removed_paths}"
    assert not added_paths, f"New endpoints added without updating snapshot: {added_paths}"

    # Verify info title and version
    assert current_schema.get("info", {}).get("title") == expected_schema.get("info", {}).get("title")
