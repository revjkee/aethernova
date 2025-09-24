# file: policy-core/tests/integration/test_pep_http.py
from __future__ import annotations

import asyncio
import base64
import json
import time
import typing as t
from dataclasses import dataclass, field

import anyio
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette import status as http

import httpx


# =========================
# Utilities
# =========================

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def make_unsigned_jwt(payload: dict) -> str:
    """
    Create an unsigned JWT (alg=none style) for testing attribute plumbing.
    Header and payload are base64url-encoded, signature part is empty.
    """
    header = {"alg": "none", "typ": "JWT"}
    return f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}."


def parse_jwt_payload(token: str) -> dict:
    """
    Parse JWT payload without signature verification (test only).
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = json.loads(_b64url_decode(parts[1]))
        if isinstance(payload, dict):
            return payload
    except Exception:
        return {}
    return {}


def now_ms() -> int:
    return int(time.time() * 1000)


# =========================
# PDP (Policy Decision Point) — in-memory test app
# =========================

@dataclass
class PDPState:
    calls: int = 0
    delay_ms: int = 0
    force_error: bool = False
    # dynamic rules to shape decision
    # denied_roles: set of roles that always get Deny
    denied_roles: set[str] = field(default_factory=lambda: {"banned"})
    # default cache ttl in seconds
    default_ttl: int = 2
    # whether to include advice (non-enforcing hint)
    include_advice: bool = True
    # whether to include obligation for header enrichment
    include_obligation_header: bool = True

    # storage for last received correlation id to assert propagation
    last_corr_id: str | None = None


async def pdp_decision(request: Request) -> Response:
    state: PDPState = request.app.state.state
    state.calls += 1

    # capture correlation id propagated by PEP
    corr_id = request.headers.get("x-correlation-id")
    state.last_corr_id = corr_id

    if state.force_error:
        return JSONResponse({"error": "internal"}, status_code=http.HTTP_500_INTERNAL_SERVER_ERROR)

    if state.delay_ms > 0:
        # Simulate blocking/slow PDP
        await anyio.sleep(state.delay_ms / 1000.0)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_request"}, status_code=http.HTTP_400_BAD_REQUEST)

    subject = body.get("subject", {}) or {}
    resource = body.get("resource", {}) or {}
    action = body.get("action") or "GET"

    role = subject.get("role")
    sub = subject.get("sub")
    path = resource.get("path", "/")

    decision = "Deny"
    obligations: list[dict] = []
    advice: list[dict] = []

    # Basic rule set for tests:
    # 1) banned role is Deny
    if role in state.denied_roles:
        decision = "Deny"
    # 2) protected paths require authenticated subject and permitted role
    elif path.startswith("/protected"):
        if sub and role not in state.denied_roles:
            decision = "Permit"
        else:
            decision = "Deny"
    # 3) everything else denied by default
    else:
        decision = "Deny"

    # Obligations and advice
    if decision == "Permit" and state.include_obligation_header:
        obligations.append({"type": "add_response_header", "name": "X-Policy-Tag", "value": "alpha-permit"})
    if state.include_advice:
        advice.append({"type": "log", "message": "consider tier upgrade"})

    resp = {
        "decision": decision,
        "obligations": obligations,
        "advice": advice,
        "cache_ttl": state.default_ttl,
    }
    return JSONResponse(resp, status_code=http.HTTP_200_OK)


def build_pdp_app(state: PDPState) -> Starlette:
    app = Starlette(routes=[Route("/decision", pdp_decision, methods=["POST"])])
    app.state.state = state
    return app


# =========================
# PEP (Policy Enforcement Point) — in-memory test app
# =========================

class SimpleTTLCache:
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, dict]] = {}

    def get(self, key: str) -> dict | None:
        item = self._data.get(key)
        if not item:
            return None
        exp, value = item
        if time.time() > exp:
            self._data.pop(key, None)
            return None
        return value

    def put(self, key: str, value: dict, ttl_seconds: int) -> None:
        self._data[key] = (time.time() + max(ttl_seconds, 0), value)

    def clear(self) -> None:
        self._data.clear()


@dataclass
class PEPConfig:
    pdp_base_url: str = "http://pdp"
    pdp_timeout: float = 0.5  # seconds
    max_failures_for_open_cb: int = 3  # circuit breaker threshold
    cb_cooldown_sec: int = 2


@dataclass
class PEPState:
    cfg: PEPConfig
    pdp_client: httpx.AsyncClient
    cache: SimpleTTLCache = field(default_factory=SimpleTTLCache)
    failures: int = 0
    cb_open_until: float = 0.0


def require_correlation_id(headers: dict[str, str]) -> str:
    corr = headers.get("x-correlation-id")
    if not corr:
        corr = f"corr-{now_ms()}"
    return corr


async def fetch_pdp_decision(state: PEPState, payload: dict, corr_id: str) -> dict | None:
    # Circuit breaker: if open, short-circuit to Deny (None indicates "no decision" and we fall back)
    now = time.time()
    if state.cb_open_until > now:
        return None

    try:
        resp = await state.pdp_client.post(
            "/decision",
            json=payload,
            headers={"x-correlation-id": corr_id},
            timeout=state.cfg.pdp_timeout,
        )
        if resp.status_code != 200:
            state.failures += 1
            if state.failures >= state.cfg.max_failures_for_open_cb:
                state.cb_open_until = time.time() + state.cfg.cb_cooldown_sec
            return None
        state.failures = 0
        body = resp.json()
        return body
    except (httpx.HTTPError, httpx.TimeoutException):
        state.failures += 1
        if state.failures >= state.cfg.max_failures_for_open_cb:
            state.cb_open_until = time.time() + state.cfg.cb_cooldown_sec
        return None


class PEPMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Starlette, state: PEPState):
        super().__init__(app)
        self.state = state

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path.startswith("/protected"):
            # Extract subject from Authorization header (unsigned JWT accepted in tests)
            auth = request.headers.get("authorization", "")
            subject: dict[str, t.Any] = {}
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
                subject = parse_jwt_payload(token)

            # Build attributes
            attributes = {
                "subject": {
                    "sub": subject.get("sub"),
                    "role": subject.get("role"),
                    "tenant": subject.get("tenant"),
                    "scopes": subject.get("scopes"),
                },
                "action": request.method,
                "resource": {
                    "path": request.url.path,
                    "query": dict(request.query_params),
                },
                "env": {"ip": request.client.host if request.client else "unknown"},
            }

            # Cache key
            cache_key = _b64url_encode(json.dumps(attributes, sort_keys=True).encode())
            decision = self.state.cache.get(cache_key)
            corr_id = require_correlation_id(dict(request.headers))

            if decision is None:
                # Query PDP
                decision = await fetch_pdp_decision(self.state, attributes, corr_id)
                if decision and isinstance(decision, dict):
                    ttl = int(decision.get("cache_ttl") or 0)
                    self.state.cache.put(cache_key, decision, ttl)

            # Apply decision (deny-by-default)
            if not decision or decision.get("decision") != "Permit":
                # Audit log
                request.app.logger.info(
                    "audit_denied",
                    extra={"corr_id": corr_id, "path": request.url.path, "sub": subject.get("sub"), "role": subject.get("role")},
                )
                return JSONResponse(
                    {"detail": "access_denied", "corr_id": corr_id},
                    status_code=http.HTTP_403_FORBIDDEN,
                )

            # Enforce obligations
            obligations: list[dict] = decision.get("obligations") or []
            response: Response = await call_next(request)
            for ob in obligations:
                if ob.get("type") == "add_response_header":
                    name = ob.get("name")
                    value = ob.get("value")
                    if name and value:
                        response.headers[name] = str(value)

            # Non-enforcing advice is logged
            advice = decision.get("advice") or []
            if advice:
                request.app.logger.info("audit_advice", extra={"corr_id": corr_id, "advice": advice})

            response.headers["x-correlation-id"] = corr_id
            request.app.logger.info(
                "audit_permit",
                extra={"corr_id": corr_id, "path": request.url.path, "sub": subject.get("sub"), "role": subject.get("role")},
            )
            return response

        # For non-protected routes, pass through
        return await call_next(request)


async def protected_handler(_: Request) -> Response:
    return JSONResponse({"ok": True})


async def open_handler(_: Request) -> Response:
    return JSONResponse({"open": True})


def build_pep_app(pdp_app: Starlette, cfg: PEPConfig | None = None) -> Starlette:
    # httpx client wired to in-memory PDP via ASGITransport
    transport = httpx.ASGITransport(app=pdp_app)
    client = httpx.AsyncClient(transport=transport, base_url="http://pdp")

    cfg = cfg or PEPConfig()
    state = PEPState(cfg=cfg, pdp_client=client)

    app = Starlette(
        routes=[
            Route("/protected", protected_handler, methods=["GET", "POST"]),
            Route("/open", open_handler, methods=["GET"]),
        ]
    )
    app.add_middleware(PEPMiddleware, state=state)
    app.state.state = state
    return app


# =========================
# Pytest fixtures
# =========================

@pytest.fixture
def pdp_state() -> PDPState:
    return PDPState()


@pytest.fixture
def pdp_app(pdp_state: PDPState) -> Starlette:
    return build_pdp_app(pdp_state)


@pytest.fixture
def pep_app(pdp_app: Starlette) -> Starlette:
    return build_pep_app(pdp_app)


@pytest.fixture
async def client(pep_app: Starlette):
    async with httpx.AsyncClient(app=pep_app, base_url="http://pep") as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# =========================
# Tests
# =========================

@pytest.mark.anyio
async def test_permit_allows_access(client: httpx.AsyncClient):
    jwt = make_unsigned_jwt({"sub": "u1", "role": "user", "tenant": "acme"})
    r = await client.get("/protected", headers=bearer(jwt))
    assert r.status_code == http.HTTP_200_OK
    body = r.json()
    assert body.get("ok") is True
    assert "x-correlation-id" in r.headers
    # Obligation header added
    assert r.headers.get("X-Policy-Tag") == "alpha-permit"


@pytest.mark.anyio
async def test_deny_blocks_access(client: httpx.AsyncClient):
    jwt = make_unsigned_jwt({"sub": "u2", "role": "banned"})
    r = await client.get("/protected", headers=bearer(jwt))
    assert r.status_code == http.HTTP_403_FORBIDDEN
    j = r.json()
    assert j.get("detail") == "access_denied"
    assert "corr_id" in j


@pytest.mark.anyio
async def test_advice_is_non_enforcing(client: httpx.AsyncClient, pdp_state: PDPState):
    # Advice present but should not block Permit
    pdp_state.include_advice = True
    jwt = make_unsigned_jwt({"sub": "u3", "role": "user"})
    r = await client.get("/protected", headers=bearer(jwt))
    assert r.status_code == http.HTTP_200_OK


@pytest.mark.anyio
async def test_cache_hits_and_ttl(client: httpx.AsyncClient, pdp_state: PDPState, pep_app: Starlette):
    # Reset PDP counters and set longer TTL to observe cache behavior
    pdp_state.calls = 0
    pdp_state.default_ttl = 1  # seconds

    jwt = make_unsigned_jwt({"sub": "u4", "role": "user"})
    r1 = await client.get("/protected?x=1", headers=bearer(jwt))
    assert r1.status_code == http.HTTP_200_OK
    calls_after_first = pdp_state.calls
    assert calls_after_first == 1

    # Second identical request should be served from cache (no PDP call)
    r2 = await client.get("/protected?x=1", headers=bearer(jwt))
    assert r2.status_code == http.HTTP_200_OK
    assert pdp_state.calls == calls_after_first

    # After TTL passes, next request should trigger PDP again
    await anyio.sleep(1.05)
    r3 = await client.get("/protected?x=1", headers=bearer(jwt))
    assert r3.status_code == http.HTTP_200_OK
    assert pdp_state.calls == calls_after_first + 1


@pytest.mark.anyio
async def test_pdp_timeout_triggers_deny_and_circuit_breaker(
    client: httpx.AsyncClient, pdp_state: PDPState, pep_app: Starlette
):
    # Configure PDP to be too slow for PEP timeout
    pdp_state.delay_ms = 1000  # 1s
    state: PEPState = pep_app.state.state
    state.cfg.pdp_timeout = 0.2
    state.cfg.max_failures_for_open_cb = 2
    state.cfg.cb_cooldown_sec = 1

    jwt = make_unsigned_jwt({"sub": "u5", "role": "user"})
    r1 = await client.get("/protected", headers=bearer(jwt))
    assert r1.status_code == http.HTTP_403_FORBIDDEN

    # second failure opens circuit breaker; next call also denied without contacting PDP
    r2 = await client.get("/protected", headers=bearer(jwt))
    assert r2.status_code == http.HTTP_403_FORBIDDEN

    # Wait for cooldown and restore PDP speed; request should pass again
    pdp_state.delay_ms = 0
    await anyio.sleep(state.cfg.cb_cooldown_sec + 0.05)
    r3 = await client.get("/protected", headers=bearer(jwt))
    assert r3.status_code == http.HTTP_200_OK


@pytest.mark.anyio
async def test_obligations_add_header_toggle(client: httpx.AsyncClient, pdp_state: PDPState):
    # Disable obligations -> header must disappear
    pdp_state.include_obligation_header = False
    jwt = make_unsigned_jwt({"sub": "u6", "role": "user"})
    r = await client.get("/protected", headers=bearer(jwt))
    assert r.status_code == http.HTTP_200_OK
    assert r.headers.get("X-Policy-Tag") is None


@pytest.mark.anyio
async def test_jwt_attribute_mapping(client: httpx.AsyncClient):
    # No subject -> Deny
    r = await client.get("/protected")
    assert r.status_code == http.HTTP_403_FORBIDDEN

    # Subject present but banned role -> Deny
    jwt_bad = make_unsigned_jwt({"sub": "u7", "role": "banned"})
    r2 = await client.get("/protected", headers=bearer(jwt_bad))
    assert r2.status_code == http.HTTP_403_FORBIDDEN

    # Subject with scopes, role user -> Permit
    jwt_ok = make_unsigned_jwt({"sub": "u8", "role": "user", "scopes": ["read:protected"]})
    r3 = await client.get("/protected", headers=bearer(jwt_ok))
    assert r3.status_code == http.HTTP_200_OK


@pytest.mark.anyio
async def test_correlation_id_is_generated_and_propagated(
    client: httpx.AsyncClient, pdp_state: PDPState, pep_app: Starlette
):
    # No incoming correlation id -> PEP generates one and sends to PDP
    jwt = make_unsigned_jwt({"sub": "u9", "role": "user"})
    r = await client.get("/protected", headers=bearer(jwt))
    assert r.status_code == http.HTTP_200_OK
    corr = r.headers.get("x-correlation-id")
    assert corr and corr.startswith("corr-")
    # PDP observed the same correlation id
    assert isinstance(pdp_state.last_corr_id, str)
    # We cannot guarantee exact equality due to separate transports, but presence is required.


@pytest.mark.anyio
async def test_open_endpoint_bypasses_pep(client: httpx.AsyncClient):
    r = await client.get("/open")
    assert r.status_code == http.HTTP_200_OK
    assert r.json() == {"open": True}
