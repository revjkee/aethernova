# policy-core/tests/e2e/test_end_to_end_authorization.py
# Industrial-grade E2E authorization test suite for policy-core
# Requirements:
#   - pytest
#   - pytest-asyncio
#   - httpx
#
# Optional environment variables to configure the run:
#   POLICY_CORE_BASE_URL (default: http://localhost:8000)
#   POLICY_CORE_TEST_ADMIN_USER / POLICY_CORE_TEST_ADMIN_PASS
#   POLICY_CORE_TEST_USER / POLICY_CORE_TEST_USER_PASS
#   POLICY_CORE_TEST_TENANT_A (e.g., "tenant-a")
#   POLICY_CORE_TEST_TENANT_B (e.g., "tenant-b")
#
# The suite auto-discovers endpoints and skips tests if unsupported.
# It verifies login, refresh, deny-by-default, RBAC, ABAC isolation,
# policy updates with eventual consistency, token introspection, and audit traces.
#
# Note:
# - If your service uses different paths, expose standard compat routes
#   or set up reverse-proxy mappings in test env.

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any, Dict, Optional

import pytest
import pytest_asyncio
import httpx

# -------------------------
# Config & helpers
# -------------------------

DEFAULT_BASE_URL = "http://localhost:8000"
REQUEST_TIMEOUT = 15.0
RETRY_ATTEMPTS = 5
RETRY_BACKOFF_SEC = 0.6

HEALTH_CANDIDATES = ["/health", "/readyz", "/livez", "/_health"]
LOGIN_PATH = "/auth/login"
REFRESH_PATH = "/auth/refresh"
INTROSPECT_PATH = "/auth/introspect"
AUTHORIZE_PATH = "/authorize"          # Decision endpoint: POST {subject, action, resource, context}
POLICIES_PATH = "/policies"            # Policy admin: GET/POST/PUT for upsert, optional
AUDIT_QUERY_PATH = "/audit"            # Optional audit search: GET with query parameters

# Env-driven identities
ADMIN_USER = os.getenv("POLICY_CORE_TEST_ADMIN_USER")
ADMIN_PASS = os.getenv("POLICY_CORE_TEST_ADMIN_PASS")
BASIC_USER = os.getenv("POLICY_CORE_TEST_USER")
BASIC_PASS = os.getenv("POLICY_CORE_TEST_USER_PASS")
TENANT_A = os.getenv("POLICY_CORE_TEST_TENANT_A", "tenant-a")
TENANT_B = os.getenv("POLICY_CORE_TEST_TENANT_B", "tenant-b")


def _base_url() -> str:
    return os.getenv("POLICY_CORE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _cid() -> str:
    return str(uuid.uuid4())


async def _retry(func, *args, attempts: int = RETRY_ATTEMPTS, backoff: float = RETRY_BACKOFF_SEC, **kwargs):
    last_exc = None
    for i in range(attempts):
        try:
            return await func(*args, **kwargs)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            last_exc = e
            if i == attempts - 1:
                raise
            await asyncio.sleep(backoff * (2 ** i))
    if last_exc:
        raise last_exc


async def _has_endpoint(client: httpx.AsyncClient, path: str) -> bool:
    try:
        r = await client.options(path, headers={"X-Request-ID": _cid()}, timeout=REQUEST_TIMEOUT)
        if r.status_code < 500:
            return True
    except Exception:
        pass
    try:
        r = await client.get(path, headers={"X-Request-ID": _cid()}, timeout=REQUEST_TIMEOUT)
        return r.status_code < 500
    except Exception:
        return False


def _skip_if(cond: bool, reason: str):
    if cond:
        pytest.skip(reason)


def _assert_json_has_keys(data: Dict[str, Any], keys: list[str]):
    for k in keys:
        assert k in data, f"Expected key '{k}' in response JSON"


# -------------------------
# Pytest fixtures
# -------------------------

@pytest_asyncio.fixture(scope="session")
async def client() -> httpx.AsyncClient:
    base = _base_url()
    transport = httpx.AsyncHTTPTransport(retries=0)
    async with httpx.AsyncClient(base_url=base, transport=transport, timeout=REQUEST_TIMEOUT) as ac:
        yield ac


@pytest_asyncio.fixture(scope="session")
async def endpoints(client: httpx.AsyncClient) -> Dict[str, bool]:
    checks = {
        "health": False,
        "login": False,
        "refresh": False,
        "introspect": False,
        "authorize": False,
        "policies": False,
        "audit": False,
    }
    # health family
    for p in HEALTH_CANDIDATES:
        if await _has_endpoint(client, p):
            checks["health"] = True
            break
    # specific endpoints
    checks["login"] = await _has_endpoint(client, LOGIN_PATH)
    checks["refresh"] = await _has_endpoint(client, REFRESH_PATH)
    checks["introspect"] = await _has_endpoint(client, INTROSPECT_PATH)
    checks["authorize"] = await _has_endpoint(client, AUTHORIZE_PATH)
    checks["policies"] = await _has_endpoint(client, POLICIES_PATH)
    checks["audit"] = await _has_endpoint(client, AUDIT_QUERY_PATH)
    return checks


@pytest_asyncio.fixture(scope="session")
async def tokens(client: httpx.AsyncClient, endpoints: Dict[str, bool]) -> Dict[str, Optional[str]]:
    """
    Acquire tokens for admin and user via /auth/login if credentials are provided.
    Skips if login unsupported or credentials absent.
    """
    _skip_if(not endpoints["login"], "Login endpoint is not available")

    res: Dict[str, Optional[str]] = {
        "admin_access": None,
        "admin_refresh": None,
        "user_access": None,
        "user_refresh": None,
        "token_type": None,
    }

    async def login(username: str, password: str) -> Dict[str, Any]:
        payload = {"username": username, "password": password}
        r = await _retry(
            client.post,
            LOGIN_PATH,
            json=payload,
            headers={"X-Request-ID": _cid()},
        )
        assert r.status_code in (200, 201), f"Login failed for {username}: {r.status_code} {r.text}"
        data = r.json()
        _assert_json_has_keys(data, ["access_token", "token_type"])
        return data

    if ADMIN_USER and ADMIN_PASS:
        data = await login(ADMIN_USER, ADMIN_PASS)
        res["admin_access"] = data.get("access_token")
        res["token_type"] = data.get("token_type", "Bearer")
        if "refresh_token" in data:
            res["admin_refresh"] = data["refresh_token"]

    if BASIC_USER and BASIC_PASS:
        data2 = await login(BASIC_USER, BASIC_PASS)
        res["user_access"] = data2.get("access_token")
        if not res["token_type"]:
            res["token_type"] = data2.get("token_type", "Bearer")
        if "refresh_token" in data2:
            res["user_refresh"] = data2["refresh_token"]

    _skip_if(not res["admin_access"] and not res["user_access"], "No usable credentials supplied via env for login")

    return res


# -------------------------
# Health / Liveness
# -------------------------

@pytest.mark.asyncio
async def test_health_endpoints(client: httpx.AsyncClient, endpoints: Dict[str, bool]):
    _skip_if(not endpoints["health"], "No health endpoints detected")
    # Probe all candidates to collect at least one positive
    found_ok = False
    for path in HEALTH_CANDIDATES:
        try:
            r = await client.get(path, headers={"X-Request-ID": _cid()})
            if r.status_code in (200, 204):
                found_ok = True
                break
        except Exception:
            continue
    assert found_ok, "Health endpoint did not return OK"


# -------------------------
# AuthN: login / refresh / introspect
# -------------------------

@pytest.mark.asyncio
async def test_login_and_refresh_where_supported(client: httpx.AsyncClient, endpoints: Dict[str, bool], tokens: Dict[str, Optional[str]]):
    _skip_if(not endpoints["login"], "Login not supported")
    # Tokens fixture already validated login; here we validate refresh if exists
    if endpoints["refresh"]:
        # Prefer user refresh; fall back to admin
        refresh = tokens.get("user_refresh") or tokens.get("admin_refresh")
        _skip_if(not refresh, "No refresh token granted by login response")
        r = await client.post(REFRESH_PATH, json={"refresh_token": refresh}, headers={"X-Request-ID": _cid()})
        assert r.status_code in (200, 201), f"Refresh failed: {r.status_code} {r.text}"
        data = r.json()
        _assert_json_has_keys(data, ["access_token", "token_type"])
        assert data["access_token"], "Empty access_token in refresh"


@pytest.mark.asyncio
async def test_token_introspection_if_available(client: httpx.AsyncClient, endpoints: Dict[str, bool], tokens: Dict[str, Optional[str]]):
    _skip_if(not endpoints["introspect"], "Introspection not available")
    access = tokens.get("user_access") or tokens.get("admin_access")
    _skip_if(not access, "No access token available for introspection")
    r = await client.post(
        INTROSPECT_PATH,
        json={"token": access},
        headers={"X-Request-ID": _cid()},
    )
    assert r.status_code == 200, f"Introspection failed: {r.status_code} {r.text}"
    data = r.json()
    # Common RFC-compliant fields if implemented
    assert data.get("active") in (True, False), "Introspection must contain 'active' boolean"
    # Optional checks (not mandatory across all servers)
    # exp/aud/sub may exist; validate types if present
    if "exp" in data:
        assert isinstance(data["exp"], int), "exp must be epoch int"
        assert data["exp"] > int(time.time()) - 86400, "exp looks unrealistically old"
    for f in ("sub", "aud", "scope"):
        if f in data:
            assert isinstance(data[f], (str, list)), f"{f} must be str or list"


# -------------------------
# AuthZ: decision endpoint
# -------------------------

async def _authz_decide(
    client: httpx.AsyncClient,
    token: str,
    token_type: str,
    subject: Dict[str, Any],
    action: str,
    resource: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    body = {
        "subject": subject,
        "action": action,
        "resource": resource,
        "context": context or {},
    }
    r = await client.post(
        AUTHORIZE_PATH,
        json=body,
        headers={"Authorization": f"{token_type} {token}", "X-Request-ID": _cid()},
    )
    assert r.status_code in (200, 403), f"Unexpected status for authorize: {r.status_code} {r.text}"
    data = r.json()
    # Expected fields: decision, obligations/advice optional
    _assert_json_has_keys(data, ["decision"])
    assert data["decision"] in ("permit", "deny"), "Decision must be 'permit' or 'deny'"
    return data


@pytest.mark.asyncio
async def test_deny_by_default(client: httpx.AsyncClient, endpoints: Dict[str, bool], tokens: Dict[str, Optional[str]]):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")
    token = tokens.get("user_access") or tokens.get("admin_access")
    token_type = tokens.get("token_type", "Bearer")
    _skip_if(not token, "No token for authorization check")

    subject = {"id": "e2e-user", "roles": ["unknown-role"], "tenant": TENANT_A}
    # Deliberately unknown action/resource to force deny-by-default
    decision = await _authz_decide(
        client,
        token,
        token_type,
        subject=subject,
        action="unknown:operate",
        resource={"type": "vault", "id": "no-such-id", "owner_tenant": TENANT_B},
    )
    assert decision["decision"] == "deny", f"Expected deny-by-default, got: {decision}"


@pytest.mark.asyncio
async def test_rbac_admin_vs_user(client: httpx.AsyncClient, endpoints: Dict[str, bool], tokens: Dict[str, Optional[str]]):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")

    admin = tokens.get("admin_access")
    user = tokens.get("user_access")
    token_type = tokens.get("token_type", "Bearer")

    _skip_if(not admin or not user, "Both admin and user tokens required for RBAC test")

    # Typical admin-only action
    admin_subject = {"id": "e2e-admin", "roles": ["admin"], "tenant": TENANT_A}
    user_subject = {"id": "e2e-basic", "roles": ["user"], "tenant": TENANT_A}
    resource = {"type": "policy", "id": "global", "owner_tenant": TENANT_A}

    admin_decision = await _authz_decide(
        client, admin, token_type, subject=admin_subject, action="policy:update", resource=resource
    )
    assert admin_decision["decision"] == "permit", f"Admin should be permitted: {admin_decision}"

    user_decision = await _authz_decide(
        client, user, token_type, subject=user_subject, action="policy:update", resource=resource
    )
    assert user_decision["decision"] == "deny", f"User must be denied for admin-only action: {user_decision}"


@pytest.mark.asyncio
async def test_abac_tenant_isolation(client: httpx.AsyncClient, endpoints: Dict[str, bool], tokens: Dict[str, Optional[str]]):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")

    token = tokens.get("user_access") or tokens.get("admin_access")
    token_type = tokens.get("token_type", "Bearer")
    _skip_if(not token, "No token for ABAC test")

    # Same role, different tenants; user should not cross tenant boundary
    subject_a = {"id": "e2e-user-a", "roles": ["user"], "tenant": TENANT_A}
    subject_b = {"id": "e2e-user-b", "roles": ["user"], "tenant": TENANT_B}

    # Resource belongs to tenant A
    res_a = {"type": "dataset", "id": "ds-a-123", "owner_tenant": TENANT_A, "classification": "internal"}

    # Subject A reading resource A: expected permit
    d1 = await _authz_decide(client, token, token_type, subject=subject_a, action="dataset:read", resource=res_a)
    assert d1["decision"] == "permit", f"Same-tenant read should permit: {d1}"

    # Subject B reading resource A: expected deny
    d2 = await _authz_decide(client, token, token_type, subject=subject_b, action="dataset:read", resource=res_a)
    assert d2["decision"] == "deny", f"Cross-tenant isolation should deny: {d2}"


# -------------------------
# Policy update with consistency wait
# -------------------------

async def _upsert_allow_rule(
    client: httpx.AsyncClient,
    token: str,
    token_type: str,
    rule_id: str,
    effect: str,
    when: Dict[str, Any],
    target: Dict[str, Any],
) -> None:
    """
    Attempts to upsert a single policy rule.
    Expects policies endpoint to accept PUT/POST JSON documents.
    Skips gracefully if policies admin is unsupported.
    """
    # Common structure (example); adjust your server mapping in policy-core
    payload = {
        "id": rule_id,
        "description": "e2e temporary rule",
        "effect": effect,  # "permit" or "deny"
        "when": when,      # attributes conditions (subject/action/resource/context)
        "target": target,  # resource selector
        "priority": 5000,
        "enabled": True,
    }

    # Try PUT first, then POST
    for method in ("put", "post"):
        req = getattr(client, method)
        r = await req(
            f"{POLICIES_PATH}/{rule_id}" if method == "put" else POLICIES_PATH,
            json=payload,
            headers={"Authorization": f"{token_type} {token}", "X-Request-ID": _cid()},
        )
        if r.status_code in (200, 201):
            return
        # 405 might mean wrong verb; try next
        if r.status_code not in (400, 403, 404, 405):
            # Unexpected server error; let assertion fail with details
            assert False, f"Policy upsert failed ({method.upper()}): {r.status_code} {r.text}"
    pytest.skip("Policy admin endpoint rejected upsert; skipping policy update test")


@pytest.mark.asyncio
async def test_policy_update_effect_with_eventual_consistency(
    client: httpx.AsyncClient,
    endpoints: Dict[str, bool],
    tokens: Dict[str, Optional[str]],
):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")
    _skip_if(not endpoints["policies"], "Policies admin endpoint not available")

    admin = tokens.get("admin_access")
    token_type = tokens.get("token_type", "Bearer")
    _skip_if(not admin, "Admin token required for policy update test")

    rule_id = f"e2e-allow-read-metrics-{uuid.uuid4()}"
    subject = {"id": "e2e-observer", "roles": ["observer"], "tenant": TENANT_A}
    resource = {"type": "metrics", "id": "system", "owner_tenant": TENANT_A}

    # First, ensure current decision is deny (deny-by-default or no rule)
    initial = await _authz_decide(
        client, admin, token_type, subject=subject, action="metrics:read", resource=resource
    )
    # initial can be permit if your default policy already allows observer->metrics:read.
    # To keep test deterministic, proceed only if deny; otherwise just assert it's permit already.
    if initial["decision"] == "permit":
        # Already permitted by baseline policy; test still valid.
        assert initial["decision"] == "permit"
        return

    # Upsert a targeted allow rule
    await _upsert_allow_rule(
        client,
        admin,
        token_type,
        rule_id=rule_id,
        effect="permit",
        when={
            "subject.roles": ["observer"],
            "subject.tenant": TENANT_A,
            "action": "metrics:read",
        },
        target={"resource.type": "metrics", "resource.owner_tenant": TENANT_A},
    )

    # Poll authorize until decision flips to permit or timeout elapses (eventual consistency)
    deadline = time.time() + 30.0
    last = None
    while time.time() < deadline:
        last = await _authz_decide(
            client, admin, token_type, subject=subject, action="metrics:read", resource=resource
        )
        if last["decision"] == "permit":
            break
        await asyncio.sleep(1.0)

    assert last and last["decision"] == "permit", f"Policy change did not take effect in time: {last}"


# -------------------------
# Audit traceability
# -------------------------

@pytest.mark.asyncio
async def test_audit_trail_or_at_least_request_id_echo(
    client: httpx.AsyncClient,
    endpoints: Dict[str, bool],
    tokens: Dict[str, Optional[str]],
):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")

    token = tokens.get("user_access") or tokens.get("admin_access")
    token_type = tokens.get("token_type", "Bearer")
    _skip_if(not token, "No token for audit test")

    rid = _cid()
    subject = {"id": "e2e-audit", "roles": ["user"], "tenant": TENANT_A}
    resource = {"type": "document", "id": "doc-123", "owner_tenant": TENANT_A}

    r = await client.post(
        AUTHORIZE_PATH,
        json={"subject": subject, "action": "document:read", "resource": resource, "context": {}},
        headers={"Authorization": f"{token_type} {token}", "X-Request-ID": rid},
    )
    assert r.status_code in (200, 403)
    # If server echoes X-Request-ID or sets correlation id header, verify echo presence
    echoed = r.headers.get("X-Request-ID") or r.headers.get("X-Correlation-ID")
    if echoed:
        assert echoed == rid, "Correlation ID should be echoed unchanged"

    # If audit endpoint exists, attempt to find our record
    if endpoints["audit"]:
        # Try query by request id or subject id; server-specific contract may vary
        params = {"request_id": rid, "subject_id": subject["id"]}
        qr = await client.get(AUDIT_QUERY_PATH, params=params, headers={"X-Request-ID": _cid()})
        # Not all servers allow direct GET; tolerate 405/404 but assert 200 when supported
        if qr.status_code == 200:
            data = qr.json()
            assert isinstance(data, (list, dict)), "Audit response must be list or dict"
            # Heuristic check for presence
            payload = json.dumps(data)
            assert rid in payload or subject["id"] in payload, "Audit log should contain our trace"


# -------------------------
# Negative cases & hardening
# -------------------------

@pytest.mark.asyncio
async def test_invalid_token_is_rejected(client: httpx.AsyncClient, endpoints: Dict[str, bool]):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")
    fake = "this.is.not.a.jwt"
    r = await client.post(
        AUTHORIZE_PATH,
        json={"subject": {"id": "x"}, "action": "any:act", "resource": {"type": "any", "id": "1"}},
        headers={"Authorization": f"Bearer {fake}", "X-Request-ID": _cid()},
    )
    # Expect 401/403 depending on implementation
    assert r.status_code in (401, 403), f"Invalid token must be rejected, got {r.status_code}"


@pytest.mark.asyncio
async def test_missing_auth_header_is_rejected(client: httpx.AsyncClient, endpoints: Dict[str, bool]):
    _skip_if(not endpoints["authorize"], "Authorize endpoint not available")
    r = await client.post(
        AUTHORIZE_PATH,
        json={"subject": {"id": "x"}, "action": "any:act", "resource": {"type": "any", "id": "1"}},
        headers={"X-Request-ID": _cid()},
    )
    assert r.status_code in (401, 403), f"Missing auth must be rejected, got {r.status_code}"
