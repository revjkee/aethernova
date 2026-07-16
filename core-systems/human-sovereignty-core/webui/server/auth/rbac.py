# human-sovereignty-core/webui/server/auth/rbac.py

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable, Optional

from fastapi import Depends, HTTPException, Request, status


class RBACError(Exception):
    """Base RBAC error."""


class PermissionDenied(RBACError):
    """Raised when access is denied."""


class Role(str, Enum):
    """
    WebUI roles.

    IMPORTANT:
    - APPROVER role MUST NOT exist in WebUI by design.
    """

    VIEWER = "viewer"
    REVIEWER = "reviewer"


class Permission(str, Enum):
    """
    Discrete permissions allowed in WebUI.
    """

    VIEW = "view"
    REVIEW = "review"


@dataclass(frozen=True)
class RoleDefinition:
    role: Role
    permissions: FrozenSet[Permission]


ROLE_MATRIX: FrozenSet[RoleDefinition] = frozenset(
    {
        RoleDefinition(
            role=Role.VIEWER,
            permissions=frozenset({Permission.VIEW}),
        ),
        RoleDefinition(
            role=Role.REVIEWER,
            permissions=frozenset({Permission.VIEW, Permission.REVIEW}),
        ),
    }
)


def _permissions_for_role(role: Role) -> FrozenSet[Permission]:
    for rd in ROLE_MATRIX:
        if rd.role == role:
            return rd.permissions
    return frozenset()


def _extract_role(request: Request) -> Optional[Role]:
    """
    Extract role from request.

    Contract:
    - Role must be injected by upstream auth (JWT, session, reverse proxy).
    - Stored in request.state.role as string.
    """
    raw = getattr(request.state, "role", None)
    if raw is None:
        return None
    try:
        return Role(raw)
    except ValueError:
        return None


def require_permission(required: Permission):
    """
    FastAPI dependency enforcing RBAC permission.

    Usage:
        Depends(require_permission(Permission.VIEW))
    """

    def dependency(request: Request) -> None:
        role = _extract_role(request)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthenticated",
            )

        perms = _permissions_for_role(role)
        if required not in perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )

    return dependency


def require_any_permission(required: Iterable[Permission]):
    """
    Require at least one permission from the set.
    """

    required_set = frozenset(required)

    def dependency(request: Request) -> None:
        role = _extract_role(request)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthenticated",
            )

        perms = _permissions_for_role(role)
        if perms.isdisjoint(required_set):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )

    return dependency


def assert_no_approver_role(role_value: str) -> None:
    """
    Defensive guard.

    Ensures APPROVER role can never be introduced silently.
    """
    if role_value.lower() == "approver":
        raise PermissionDenied("APPROVER role is forbidden by design")
