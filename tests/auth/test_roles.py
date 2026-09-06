"""Tests for role-based access control, tool restrictions, and credential rotation."""

import pytest
from fastapi import HTTPException

from services.api.auth.roles import (
    UserRole,
    enforce_action_tool_permission,
    enforce_policy_loosen_permission,
    is_credential_rotation_required,
    mark_credential_rotated,
    mark_credential_rotation_required,
    verify_not_used_default_credentials_again,
)


def test_roles_enum_and_values():
    """Verify role enum values."""
    assert UserRole.ADMIN.value == "admin"
    assert UserRole.ANALYST.value == "analyst"
    assert UserRole.VIEWER.value == "viewer"


def test_viewer_cannot_call_action_tools():
    """Verify viewer role is strictly forbidden from executing action tools."""
    # Viewer must raise 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        enforce_action_tool_permission(UserRole.VIEWER)
    assert exc_info.value.status_code == 403
    assert "viewer" in exc_info.value.detail.lower()

    # Analyst and Admin are allowed
    enforce_action_tool_permission(UserRole.ANALYST)
    enforce_action_tool_permission(UserRole.ADMIN)


def test_analyst_cannot_loosen_policy():
    """Verify analyst role cannot loosen policy; loosening requires admin."""
    # Analyst cannot loosen
    with pytest.raises(HTTPException) as exc_info:
        enforce_policy_loosen_permission(UserRole.ANALYST, direction="loosen")
    assert exc_info.value.status_code == 403
    assert "cannot loosen policy" in exc_info.value.detail

    # Analyst can tighten
    enforce_policy_loosen_permission(UserRole.ANALYST, direction="tighten")

    # Admin can loosen
    enforce_policy_loosen_permission(UserRole.ADMIN, direction="loosen")


def test_default_credentials_cannot_be_used_twice():
    """Verify default credentials (admin/admin123) cannot be reused after initial login."""
    test_user = "test_first_run_admin"

    # First login with default password succeeds and marks usage
    verify_not_used_default_credentials_again(test_user, "admin123")

    # Second login with default password is rejected
    with pytest.raises(HTTPException) as exc_info:
        verify_not_used_default_credentials_again(test_user, "admin123")
    assert exc_info.value.status_code == 403
    assert "expired" in exc_info.value.detail.lower()


def test_forced_credential_rotation_lifecycle():
    """Verify credential rotation state flags."""
    uid = "user-test-rotation-1"
    assert is_credential_rotation_required(uid) is False

    mark_credential_rotation_required(uid)
    assert is_credential_rotation_required(uid) is True

    mark_credential_rotated(uid)
    assert is_credential_rotation_required(uid) is False
