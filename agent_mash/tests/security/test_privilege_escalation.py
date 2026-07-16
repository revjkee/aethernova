# agent_mash/tests/security/test_privilege_escalation.py
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import pytest


logger = logging.getLogger(__name__)


# -----------------------------
# Configuration
# -----------------------------

@dataclass(frozen=True)
class SecurityExpectations:
    """
    Acceptable status codes for "forbidden" outcomes.

    Notes:
    - 401: unauthenticated
    - 403: authenticated but forbidden
    - 404: route/resource is hidden to prevent probing
    """
    forbidden_statuses: Tuple[int, ...] = (401, 403, 404)
    conflict_statuses: Tuple[int, ...] = (400, 409, 422)
    ok_statuses: Tuple[int, ...] = (200, 201, 202, 204)


EXPECT = SecurityExpectations()


# -----------------------------
# Fixture resolver (portable)
# -----------------------------

class FixtureResolver:
    """
    Safely resolves optional fixtures without hard-failing the test suite.
    If a fixture is missing, tests that require it can skip with clear reason.
    """

    def __init__(self, request: pytest.FixtureRequest) -> None:
        self._request = request

    def try_get(self, name: str) -> Optional[Any]:
        try:
            return self._request.getfixturevalue(name)
        except Exception:
            return None

    def require(self, name: str, reason: str) -> Any:
        val = self.try_get(name)
        if val is None:
            pytest.skip(reason)
        return val


# -----------------------------
# HTTP abstraction (sync/async)
# -----------------------------

def _normalize_headers(h: Optional[Mapping[str, str]]) -> Dict[str, str]:
    if not h:
        return {}
    return {str(k): str(v) for k, v in dict(h).items()}


def _is_async_client(client: Any) -> bool:
    # Heuristic: httpx.AsyncClient and many async wrappers have "aclose" coroutine.
    return hasattr(client, "aclose") or hasattr(client, "get") and hasattr(client.get, "__call__") and hasattr(client, "__aenter__")


async def _maybe_await(x: Any) -> Any:
    if hasattr(x, "__await__"):
        return await x
    return x


async def http_request(
    client: Any,
    method: str,
    url: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Sends request using either sync client (requests-like/FastAPI TestClient)
    or async client (httpx.AsyncClient).
    Returns response object as-is.
    """
    method_u = method.upper().strip()
    hdrs = _normalize_headers(headers)

    kwargs: Dict[str, Any] = {"headers": hdrs}
    if json_body is not None:
        kwargs["json"] = json_body
    if params is not None:
        kwargs["params"] = params

    fn = getattr(client, method_u.lower(), None) or getattr(client, "request", None)
    if fn is None:
        raise RuntimeError(f"Client does not support HTTP method: {method_u}")

    resp = fn(url, **kwargs) if method_u.lower() != "request" else fn(method_u, url, **kwargs)
    return await _maybe_await(resp)


def resp_status(resp: Any) -> int:
    code = getattr(resp, "status_code", None)
    if isinstance(code, int):
        return code
    raise RuntimeError("Response object has no integer status_code")


def resp_json(resp: Any) -> Any:
    if hasattr(resp, "json"):
        try:
            return resp.json()
        except Exception:
            return None
    try:
        return json.loads(getattr(resp, "text", "") or "")
    except Exception:
        return None


# -----------------------------
# Target selection (override via fixtures if needed)
# -----------------------------

@dataclass(frozen=True)
class EndpointTarget:
    method: str
    path: str
    description: str


def default_admin_only_targets() -> List[EndpointTarget]:
    """
    Generic admin-only endpoints commonly found in systems.
    Override by providing fixture `admin_only_targets` returning List[EndpointTarget] or list of dicts.
    """
    return [
        EndpointTarget("GET", "/admin", "admin root"),
        EndpointTarget("GET", "/admin/users", "list users"),
        EndpointTarget("POST", "/admin/users", "create user"),
        EndpointTarget("PATCH", "/admin/users/1", "modify user"),
        EndpointTarget("DELETE", "/admin/users/1", "delete user"),
        EndpointTarget("GET", "/internal/metrics", "internal metrics"),
        EndpointTarget("GET", "/metrics", "prometheus metrics"),
    ]


def default_idor_targets(user_id: Union[int, str], other_user_id: Union[int, str]) -> List[EndpointTarget]:
    """
    Generic user-owned resource endpoints.
    Override by providing fixture `idor_targets(user_id, other_user_id)`.
    """
    return [
        EndpointTarget("GET", f"/users/{other_user_id}", "read other user profile"),
        EndpointTarget("GET", f"/profiles/{other_user_id}", "read other user profile alias"),
        EndpointTarget("GET", f"/accounts/{other_user_id}", "read other user account"),
        EndpointTarget("GET", f"/wallets/{other_user_id}", "read other user wallet"),
        EndpointTarget("PATCH", f"/users/{other_user_id}", "modify other user profile"),
        EndpointTarget("DELETE", f"/users/{other_user_id}", "delete other user"),
        EndpointTarget("GET", f"/users/{user_id}/sessions", "read own sessions (control)"),
    ]


def default_role_change_targets(user_id: Union[int, str]) -> List[EndpointTarget]:
    """
    Endpoints where role/escalation attempts are often possible.
    Override by providing fixture `role_change_targets(user_id)`.
    """
    return [
        EndpointTarget("PATCH", f"/users/{user_id}", "attempt role escalation via user profile update"),
        EndpointTarget("PUT", f"/users/{user_id}", "attempt role escalation via full replace"),
        EndpointTarget("PATCH", "/me", "attempt role escalation via self endpoint"),
        EndpointTarget("PATCH", "/profile", "attempt role escalation via profile endpoint"),
    ]


# -----------------------------
# Payloads
# -----------------------------

def escalation_payloads() -> List[Dict[str, Any]]:
    """
    Common mass-assignment / privilege escalation fields.
    """
    return [
        {"role": "admin"},
        {"role": "superuser"},
        {"is_admin": True},
        {"is_staff": True},
        {"is_superuser": True},
        {"scopes": ["admin:*"]},
        {"permissions": ["*"]},
        {"rbac": {"role": "admin"}},
        {"groups": ["admins"]},
        {"access_level": 9999},
        {"tenant_id": "other-tenant"},
        {"tenantId": "other-tenant"},
        {"account_status": "active"},
    ]


def tenant_spoof_payloads(other_tenant_id: Optional[str]) -> List[Dict[str, Any]]:
    if not other_tenant_id:
        return [{"tenant_id": "other-tenant"}, {"tenantId": "other-tenant"}]
    return [{"tenant_id": other_tenant_id}, {"tenantId": other_tenant_id}]


# -----------------------------
# Assertions helpers
# -----------------------------

def assert_forbidden(status_code: int, context: str) -> None:
    assert status_code in EXPECT.forbidden_statuses, (
        f"{context}: expected forbidden status in {EXPECT.forbidden_statuses}, got {status_code}"
    )


def assert_not_privileged_effect(
    before: Any,
    after: Any,
    context: str,
) -> None:
    """
    Best-effort check: if API returns user object, it must not show elevated role.
    If cannot parse, do not fail on content, only on status codes.
    """
    if not isinstance(after, (dict, list)) and after is not None:
        return

    def _extract_role(obj: Any) -> Optional[str]:
        if isinstance(obj, dict):
            for k in ("role", "user_role", "access_role"):
                v = obj.get(k)
                if isinstance(v, str):
                    return v.lower().strip()
        return None

    role_before = _extract_role(before)
    role_after = _extract_role(after)

    if role_before and role_after:
        assert role_after == role_before, f"{context}: role changed from {role_before} to {role_after}"


# -----------------------------
# Tests
# -----------------------------

@pytest.mark.security
@pytest.mark.privilege_escalation
@pytest.mark.asyncio
async def test_non_admin_cannot_access_admin_only_endpoints(request: pytest.FixtureRequest) -> None:
    r = FixtureResolver(request)

    user_client = r.try_get("user_client") or r.try_get("client")
    if user_client is None:
        pytest.skip("Missing fixture: user_client or client")

    user_headers = r.try_get("auth_headers_user") or r.try_get("user_headers") or {}
    targets_raw = r.try_get("admin_only_targets")

    targets: List[EndpointTarget]
    if targets_raw:
        targets = []
        for t in targets_raw:
            if isinstance(t, EndpointTarget):
                targets.append(t)
            elif isinstance(t, dict):
                targets.append(EndpointTarget(t["method"], t["path"], t.get("description", t["path"])))
            else:
                raise RuntimeError("admin_only_targets must contain EndpointTarget or dict")
    else:
        targets = default_admin_only_targets()

    for t in targets:
        resp = await http_request(user_client, t.method, t.path, headers=user_headers)
        code = resp_status(resp)
        assert_forbidden(code, f"Non-admin access to {t.method} {t.path} ({t.description})")


@pytest.mark.security
@pytest.mark.privilege_escalation
@pytest.mark.asyncio
async def test_idor_user_cannot_access_other_users_resources(request: pytest.FixtureRequest) -> None:
    r = FixtureResolver(request)

    user_client = r.try_get("user_client") or r.try_get("client")
    if user_client is None:
        pytest.skip("Missing fixture: user_client or client")

    user_headers = r.try_get("auth_headers_user") or r.try_get("user_headers") or {}

    user_id = r.try_get("user_id")
    other_user_id = r.try_get("other_user_id")

    test_user = r.try_get("test_user")
    other_user = r.try_get("other_user")

    if user_id is None and isinstance(test_user, dict):
        user_id = test_user.get("id")
    if other_user_id is None and isinstance(other_user, dict):
        other_user_id = other_user.get("id")

    if user_id is None or other_user_id is None:
        pytest.skip("Missing user_id/other_user_id fixtures (or test_user/other_user dicts with id)")

    idor_targets_factory = r.try_get("idor_targets")
    if callable(idor_targets_factory):
        targets = idor_targets_factory(user_id, other_user_id)
        targets_parsed: List[EndpointTarget] = []
        for t in targets:
            if isinstance(t, EndpointTarget):
                targets_parsed.append(t)
            elif isinstance(t, dict):
                targets_parsed.append(EndpointTarget(t["method"], t["path"], t.get("description", t["path"])))
            else:
                raise RuntimeError("idor_targets must return EndpointTarget or dict items")
        targets_final = targets_parsed
    else:
        targets_final = default_idor_targets(user_id, other_user_id)

    for t in targets_final:
        resp = await http_request(user_client, t.method, t.path, headers=user_headers)
        code = resp_status(resp)

        # Control endpoint (own sessions) may be OK; treat it separately.
        if f"/users/{user_id}/sessions" in t.path:
            assert code in EXPECT.ok_statuses + EXPECT.forbidden_statuses, (
                f"Control endpoint unexpected status: {t.method} {t.path} -> {code}"
            )
            continue

        assert_forbidden(code, f"IDOR attempt {t.method} {t.path} ({t.description})")


@pytest.mark.security
@pytest.mark.privilege_escalation
@pytest.mark.asyncio
async def test_user_cannot_escalate_role_via_profile_updates(request: pytest.FixtureRequest) -> None:
    r = FixtureResolver(request)

    user_client = r.try_get("user_client") or r.try_get("client")
    if user_client is None:
        pytest.skip("Missing fixture: user_client or client")

    user_headers = r.try_get("auth_headers_user") or r.try_get("user_headers") or {}

    user_id = r.try_get("user_id")
    test_user = r.try_get("test_user")
    if user_id is None and isinstance(test_user, dict):
        user_id = test_user.get("id")
    if user_id is None:
        pytest.skip("Missing user_id fixture (or test_user dict with id)")

    # Best-effort: if API provides "me" endpoint, capture before/after.
    before_resp = await http_request(user_client, "GET", "/me", headers=user_headers)
    before_obj = resp_json(before_resp) if resp_status(before_resp) in EXPECT.ok_statuses else None

    targets_raw = r.try_get("role_change_targets")
    if callable(targets_raw):
        targets_in = targets_raw(user_id)
    else:
        targets_in = default_role_change_targets(user_id)

    targets: List[EndpointTarget] = []
    for t in targets_in:
        if isinstance(t, EndpointTarget):
            targets.append(t)
        elif isinstance(t, dict):
            targets.append(EndpointTarget(t["method"], t["path"], t.get("description", t["path"])))
        else:
            raise RuntimeError("role_change_targets must return EndpointTarget or dict items")

    payloads = escalation_payloads()

    for t in targets:
        for payload in payloads:
            resp = await http_request(user_client, t.method, t.path, headers=user_headers, json_body=payload)
            code = resp_status(resp)

            # Allowed outcomes:
            # - forbidden (401/403/404)
            # - validation/conflict (400/409/422)
            # - OK but without any privileged effect (mass assignment ignored)
            if code in EXPECT.forbidden_statuses or code in EXPECT.conflict_statuses:
                continue

            assert code in EXPECT.ok_statuses, (
                f"Unexpected status for role escalation attempt {t.method} {t.path} payload={payload}: {code}"
            )

            # If OK, attempt to verify role did not change.
            after_resp = await http_request(user_client, "GET", "/me", headers=user_headers)
            after_obj = resp_json(after_resp) if resp_status(after_resp) in EXPECT.ok_statuses else None
            assert_not_privileged_effect(before_obj, after_obj, f"Role escalation via {t.method} {t.path}")


@pytest.mark.security
@pytest.mark.privilege_escalation
@pytest.mark.asyncio
async def test_user_cannot_spoof_tenant_context(request: pytest.FixtureRequest) -> None:
    r = FixtureResolver(request)

    user_client = r.try_get("user_client") or r.try_get("client")
    if user_client is None:
        pytest.skip("Missing fixture: user_client or client")

    user_headers = r.try_get("auth_headers_user") or r.try_get("user_headers") or {}

    other_tenant_id = r.try_get("other_tenant_id")
    tenant_id = r.try_get("tenant_id")

    # If tenant isolation is not used, skip.
    if tenant_id is None and other_tenant_id is None:
        pytest.skip("No tenant_id/other_tenant_id fixtures; tenant isolation checks not applicable")

    # Targets can be overridden by fixture, otherwise use generic profile endpoints.
    targets_raw = r.try_get("tenant_spoof_targets")
    if targets_raw:
        targets = []
        for t in targets_raw:
            if isinstance(t, EndpointTarget):
                targets.append(t)
            elif isinstance(t, dict):
                targets.append(EndpointTarget(t["method"], t["path"], t.get("description", t["path"])))
            else:
                raise RuntimeError("tenant_spoof_targets must contain EndpointTarget or dict")
    else:
        targets = [
            EndpointTarget("PATCH", "/me", "attempt tenant spoof via /me"),
            EndpointTarget("PATCH", "/profile", "attempt tenant spoof via /profile"),
        ]

    payloads = tenant_spoof_payloads(other_tenant_id)

    for t in targets:
        for payload in payloads:
            resp = await http_request(user_client, t.method, t.path, headers=user_headers, json_body=payload)
            code = resp_status(resp)

            if code in EXPECT.forbidden_statuses or code in EXPECT.conflict_statuses:
                continue

            # If API returns OK, ensure it did not accept tenant change in response body.
            assert code in EXPECT.ok_statuses, (
                f"Unexpected status for tenant spoof attempt {t.method} {t.path} payload={payload}: {code}"
            )
            body = resp_json(resp)
            if isinstance(body, dict):
                # Ensure returned tenant is not the spoofed one (best-effort).
                spoofed = payload.get("tenant_id") or payload.get("tenantId")
                returned = body.get("tenant_id") or body.get("tenantId")
                if spoofed is not None and returned is not None:
                    assert str(returned) != str(spoofed), (
                        f"Tenant spoof accepted in response: {t.method} {t.path} returned tenant={returned}"
                    )


@pytest.mark.security
@pytest.mark.privilege_escalation
@pytest.mark.asyncio
async def test_non_admin_cannot_manage_users(request: pytest.FixtureRequest) -> None:
    """
    Covers common escalation vector: calling user-management endpoints as normal user.
    """
    r = FixtureResolver(request)

    user_client = r.try_get("user_client") or r.try_get("client")
    if user_client is None:
        pytest.skip("Missing fixture: user_client or client")

    user_headers = r.try_get("auth_headers_user") or r.try_get("user_headers") or {}

    other_user_id = r.try_get("other_user_id")
    other_user = r.try_get("other_user")
    if other_user_id is None and isinstance(other_user, dict):
        other_user_id = other_user.get("id")
    if other_user_id is None:
        other_user_id = "1"

    targets = [
        EndpointTarget("POST", "/users", "create user"),
        EndpointTarget("POST", "/users/invite", "invite user"),
        EndpointTarget("PATCH", f"/users/{other_user_id}", "modify arbitrary user"),
        EndpointTarget("DELETE", f"/users/{other_user_id}", "delete arbitrary user"),
        EndpointTarget("POST", f"/users/{other_user_id}/reset-password", "reset password"),
        EndpointTarget("POST", f"/users/{other_user_id}/mfa/reset", "reset mfa"),
        EndpointTarget("POST", f"/users/{other_user_id}/role", "change role"),
    ]

    sample_body = {"email": "test@example.com", "password": "Password123!", "role": "admin"}

    for t in targets:
        body = sample_body if t.method in ("POST", "PATCH", "PUT") else None
        resp = await http_request(user_client, t.method, t.path, headers=user_headers, json_body=body)
        code = resp_status(resp)
        assert_forbidden(code, f"Non-admin user management {t.method} {t.path} ({t.description})")
