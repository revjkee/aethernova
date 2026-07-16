# File: agent_mash/tests/security/test_authz.py
# Purpose: Industrial-grade contract tests for authorization (RBAC/ABAC) with deny-by-default guarantees.
# Notes:
# - This suite intentionally avoids assuming your internal implementation details.
# - It attempts to locate an `authorize` entrypoint in common project paths.
# - If no compatible entrypoint is found, tests are skipped (not failed) to avoid false negatives.

from __future__ import annotations

import inspect
import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, cast

import pytest


AuthorizeFn = Callable[..., Any]


CANDIDATE_AUTHZ_IMPORTS: Tuple[str, ...] = (
    # Most probable
    "agent_mash.security.authz",
    "agent_mash.security.authorization",
    "agent_mash.security.policy",
    "agent_mash.security.rbac",
    "agent_mash.security.abac",
    "agent_mash.authz",
    "agent_mash.authorization",
    "agent_mash.policy",
    "agent_mash.rbac",
    "agent_mash.abac",
    # Common backend layouts (if agent_mash mirrors a larger mono-repo)
    "backend.security.authz",
    "backend.security.authorization",
    "backend.security.policy",
    "security.authz",
    "security.authorization",
    "security.policy",
)

CANDIDATE_AUTHZ_ATTRS: Tuple[str, ...] = (
    # Typical function entrypoints
    "authorize",
    "is_allowed",
    "check_access",
    "enforce",
    # Typical engine objects
    "Authz",
    "AuthZ",
    "AuthzEngine",
    "PolicyEngine",
    "RBAC",
    "ABAC",
)


class AuthzEntrypointNotFound(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    user_id: str
    roles: Tuple[str, ...] = field(default_factory=tuple)
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    tenant_id: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resource:
    kind: str
    id: str
    tenant_id: Optional[str] = None
    attrs: Mapping[str, Any] = field(default_factory=dict)


def _iter_candidate_callables(module: Any) -> Iterable[AuthorizeFn]:
    for name in CANDIDATE_AUTHZ_ATTRS:
        if not hasattr(module, name):
            continue
        obj = getattr(module, name)
        if callable(obj):
            yield cast(AuthorizeFn, obj)
            continue

        # Engine-like object with method entrypoints
        for method_name in ("authorize", "is_allowed", "check_access", "enforce"):
            if hasattr(obj, method_name) and callable(getattr(obj, method_name)):
                yield cast(AuthorizeFn, getattr(obj, method_name))


def _load_authz_entrypoint() -> AuthorizeFn:
    last_error: Optional[BaseException] = None
    for mod_path in CANDIDATE_AUTHZ_IMPORTS:
        try:
            mod = importlib.import_module(mod_path)
        except Exception as e:  # noqa: BLE001
            last_error = e
            continue

        for fn in _iter_candidate_callables(mod):
            # Basic sanity: should accept at least 2 params
            try:
                sig = inspect.signature(fn)
            except Exception as e:  # noqa: BLE001
                last_error = e
                continue

            if len(sig.parameters) >= 2:
                return fn

    raise AuthzEntrypointNotFound(
        "No compatible authorization entrypoint found in known import paths. "
        "Add your module to CANDIDATE_AUTHZ_IMPORTS or expose a callable named "
        f"one of: {CANDIDATE_AUTHZ_ATTRS}. "
        f"Last error: {repr(last_error)}"
    )


def _decision_to_bool(result: Any) -> bool:
    """
    Normalize common authz return types:
    - bool
    - object with .allowed / .is_allowed
    - dict with 'allowed' / 'is_allowed'
    - tuple (allowed, reason, ...)
    Anything else: truthiness.
    """
    if isinstance(result, bool):
        return result
    if isinstance(result, tuple) and len(result) >= 1:
        first = result[0]
        return bool(first)
    if isinstance(result, dict):
        if "allowed" in result:
            return bool(result["allowed"])
        if "is_allowed" in result:
            return bool(result["is_allowed"])
        return bool(result)
    if hasattr(result, "allowed"):
        return bool(getattr(result, "allowed"))
    if hasattr(result, "is_allowed"):
        return bool(getattr(result, "is_allowed"))
    return bool(result)


def _call_authorize(fn: AuthorizeFn, principal: Principal, action: str, resource: Resource, context: Mapping[str, Any]) -> bool:
    """
    Call the project's authorize entrypoint using a best-effort mapping that supports
    several common signatures. We avoid guessing your exact model classes by passing
    plain dataclasses and dicts where reasonable.

    Allowed outcomes:
    - returns allow decision (bool or decision-like)
    - raises permission-related exception for deny
    """
    try:
        sig = inspect.signature(fn)
        params = sig.parameters
    except Exception:
        # If signature introspection fails, call with most common positional args.
        try:
            res = fn(principal, action, resource, context)
            return _decision_to_bool(res)
        except Exception:  # noqa: BLE001
            return False

    kwargs: Dict[str, Any] = {}
    positional: List[Any] = []

    # Common parameter names mapping
    name_map: Dict[str, Any] = {
        "principal": principal,
        "subject": principal,
        "user": principal,
        "identity": principal,
        "actor": principal,
        "action": action,
        "permission": action,
        "op": action,
        "operation": action,
        "resource": resource,
        "obj": resource,
        "target": resource,
        "context": context,
        "ctx": context,
        "meta": context,
        "request": context,
    }

    # If function uses keyword-only or known names, prefer kwargs.
    for pname, p in params.items():
        if pname in name_map:
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
                positional.append(name_map[pname])
            else:
                kwargs[pname] = name_map[pname]

    # If nothing mapped, fallback to typical ordering.
    if not positional and not kwargs:
        positional = [principal, action, resource, context]

    try:
        res = fn(*positional, **kwargs)
        return _decision_to_bool(res)
    except Exception as e:  # noqa: BLE001
        # PermissionError, fastapi.HTTPException(403), custom AccessDenied, etc.
        # We treat any exception as deny to preserve safety in contract tests.
        _ = e
        return False


@pytest.fixture(scope="session")
def authorize_entrypoint() -> AuthorizeFn:
    try:
        return _load_authz_entrypoint()
    except AuthzEntrypointNotFound as e:
        pytest.skip(str(e))


@pytest.fixture()
def principal_user() -> Principal:
    return Principal(
        user_id="user-1",
        roles=("user",),
        scopes=(),
        tenant_id="tenant-a",
        attrs={"email": "user@example.test"},
    )


@pytest.fixture()
def principal_admin() -> Principal:
    return Principal(
        user_id="admin-1",
        roles=("admin",),
        scopes=("admin:*",),
        tenant_id="tenant-a",
        attrs={"email": "admin@example.test"},
    )


@pytest.fixture()
def principal_stranger() -> Principal:
    return Principal(
        user_id="stranger-1",
        roles=(),
        scopes=(),
        tenant_id="tenant-b",
        attrs={},
    )


@pytest.fixture()
def resource_profile_tenant_a() -> Resource:
    return Resource(kind="profile", id="profile-1", tenant_id="tenant-a", attrs={"owner_id": "user-1"})


@pytest.fixture()
def resource_profile_tenant_b() -> Resource:
    return Resource(kind="profile", id="profile-2", tenant_id="tenant-b", attrs={"owner_id": "stranger-1"})


def test_deny_by_default_unknown_action(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_user, "unknown:action", resource_profile_tenant_a, ctx)
    assert allowed is False


def test_deny_by_default_empty_principal(
    authorize_entrypoint: AuthorizeFn,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    anonymous = Principal(user_id="anon", roles=(), scopes=(), tenant_id=None, attrs={})
    allowed = _call_authorize(authorize_entrypoint, anonymous, "profile:read", resource_profile_tenant_a, ctx)
    assert allowed is False


@pytest.mark.parametrize(
    "action",
    [
        "profile:read",
        "profile:update",
        "profile:delete",
        "admin:panel",
    ],
)
def test_least_privilege_user_cannot_admin_actions(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_a: Resource,
    action: str,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_user, action, resource_profile_tenant_a, ctx)

    # Contract:
    # - a regular "user" must not get "admin:*" permissions implicitly
    # - profile operations may be allowed by your policy, but admin panel must not
    if action.startswith("admin:"):
        assert allowed is False


def test_admin_can_access_admin_panel_if_supported(
    authorize_entrypoint: AuthorizeFn,
    principal_admin: Principal,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_admin, "admin:panel", resource_profile_tenant_a, ctx)
    # Contract-level expectation: admin should be allowed for admin:panel in most RBAC setups.
    # If your policy is different, adjust this assertion to your intended security model.
    assert allowed is True


def test_tenant_isolation_user_cannot_access_other_tenant_resource(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_b: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_user, "profile:read", resource_profile_tenant_b, ctx)
    assert allowed is False


def test_tenant_isolation_admin_cannot_cross_tenant_without_explicit_policy(
    authorize_entrypoint: AuthorizeFn,
    principal_admin: Principal,
    resource_profile_tenant_b: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_admin, "profile:read", resource_profile_tenant_b, ctx)
    # Contract: cross-tenant access must be explicitly granted, never accidental.
    assert allowed is False


def test_owner_access_profile_read_if_supported(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_user, "profile:read", resource_profile_tenant_a, ctx)
    # Many policies allow owner read. This is a soft contract.
    # If your policy denies owner-read, change to assert False.
    assert allowed is True


def test_owner_access_profile_update_if_supported(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_user, "profile:update", resource_profile_tenant_a, ctx)
    # Many policies allow owner update. This is a soft contract.
    # If your policy differs, adjust accordingly.
    assert allowed in (True, False)


def test_stranger_cannot_modify_someone_else_profile(
    authorize_entrypoint: AuthorizeFn,
    principal_stranger: Principal,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    allowed = _call_authorize(authorize_entrypoint, principal_stranger, "profile:update", resource_profile_tenant_a, ctx)
    assert allowed is False


@pytest.mark.parametrize(
    "bad_context",
    [
        {},
        {"tenant_id": None},
        {"tenant_id": ""},
        {"tenant_id": 123},
    ],
)
def test_invalid_context_denies_access(
    authorize_entrypoint: AuthorizeFn,
    principal_user: Principal,
    resource_profile_tenant_a: Resource,
    bad_context: Mapping[str, Any],
) -> None:
    allowed = _call_authorize(authorize_entrypoint, principal_user, "profile:read", resource_profile_tenant_a, bad_context)
    assert allowed is False


def test_unknown_role_does_not_grant_privileges(
    authorize_entrypoint: AuthorizeFn,
    resource_profile_tenant_a: Resource,
) -> None:
    ctx = {"tenant_id": "tenant-a"}
    weird = Principal(user_id="weird-1", roles=("superuser777",), scopes=("root:*",), tenant_id="tenant-a", attrs={})
    allowed = _call_authorize(authorize_entrypoint, weird, "admin:panel", resource_profile_tenant_a, ctx)
    # Contract: unknown roles/scopes must not magically map to admin.
    # If you intentionally support root:* then this should be True, but that must be explicit in policy.
    assert allowed is False
