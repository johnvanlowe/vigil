"""Role-based access control and forced credential rotation enforcement.

Defines roles enum (admin, analyst, viewer), action-level permission gates,
and credential rotation state machine.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional, Sequence, Union

from fastapi import Depends, HTTPException, Request, status

from core.storage.models import User


class UserRole(str, enum.Enum):
    """System RBAC roles with strict privilege tiers."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# In-memory tracking for default credential usage and forced rotation
_DEFAULT_CREDENTIAL_ROTATION_REQUIRED = set()  # user_ids that must rotate
_DEFAULT_CREDENTIALS_USED = set()  # usernames where default credentials were used


def mark_credential_rotation_required(user_id: str) -> None:
    """Mark that user must rotate their credentials before performing other actions."""
    _DEFAULT_CREDENTIAL_ROTATION_REQUIRED.add(user_id)


def is_credential_rotation_required(user_id: str) -> bool:
    """Check if user is pending forced credential rotation."""
    return user_id in _DEFAULT_CREDENTIAL_ROTATION_REQUIRED


def mark_credential_rotated(user_id: str) -> None:
    """Clear forced rotation requirement upon successful password update."""
    _DEFAULT_CREDENTIAL_ROTATION_REQUIRED.discard(user_id)


def verify_not_used_default_credentials_again(username: str, password_provided: str) -> None:
    """Ensure default credentials (e.g. admin123) cannot be used a second time."""
    if password_provided == "admin123":
        if username in _DEFAULT_CREDENTIALS_USED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Default credentials have expired. You must use your rotated password.",
            )
        # First time usage: record that it was used once and trigger forced rotation
        _DEFAULT_CREDENTIALS_USED.add(username)


class RoleChecker:
    """Route dependency ensuring user holds an authorized role and rotated credentials."""

    def __init__(self, allowed_roles: Sequence[UserRole]):
        self.allowed_roles = [r.value if isinstance(r, UserRole) else r for r in allowed_roles]

    def __call__(self, request: Request, current_user: Optional[User] = None) -> UserRole:
        # Resolve user role from current_user or request state / api key
        user_role = UserRole.VIEWER
        user_id = None

        if current_user:
            user_id = getattr(current_user, "user_id", None)
            role_name = getattr(current_user, "role_name", None) or getattr(current_user, "role", "viewer")
            try:
                user_role = UserRole(str(role_name).lower())
            except ValueError:
                user_role = UserRole.VIEWER

        # Check API key role if present in request headers
        api_key_role = request.headers.get("X-API-Key-Role")
        if api_key_role:
            try:
                user_role = UserRole(api_key_role.lower())
            except ValueError:
                pass

        # Check forced rotation
        if user_id and is_credential_rotation_required(user_id):
            # Allow only the rotation endpoint
            if not request.url.path.endswith("/rotate-credentials") and not request.url.path.endswith("/change-password"):
                raise HTTPException(
                    status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                    detail="Forced credential rotation required before accessing this resource.",
                )

        if user_role.value not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role.value}' is not authorized. Requires one of: {self.allowed_roles}",
            )

        return user_role


def require_admin(request: Request, current_user: Optional[User] = None) -> UserRole:
    """Ensure caller has ADMIN role."""
    return RoleChecker([UserRole.ADMIN])(request, current_user)


def require_analyst_or_admin(request: Request, current_user: Optional[User] = None) -> UserRole:
    """Ensure caller has ANALYST or ADMIN role (rejects VIEWER)."""
    return RoleChecker([UserRole.ADMIN, UserRole.ANALYST])(request, current_user)


def require_viewer_or_above(request: Request, current_user: Optional[User] = None) -> UserRole:
    """Ensure caller has at least VIEWER role."""
    return RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])(request, current_user)


def enforce_action_tool_permission(role: Union[UserRole, str]) -> None:
    """Action tools (containment, isolation, execution) cannot be called by viewers."""
    role_str = role.value if isinstance(role, UserRole) else str(role)
    if role_str.lower() == UserRole.VIEWER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role 'viewer' is read-only and not authorized to execute action tools.",
        )


def enforce_policy_loosen_permission(role: Union[UserRole, str], direction: str) -> None:
    """Analysts cannot loosen policy; loosening requires admin."""
    role_str = role.value if isinstance(role, UserRole) else str(role)
    if direction.lower() == "loosen" and role_str.lower() != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role_str}' cannot loosen policy. Loosening requires 'admin'.",
        )
