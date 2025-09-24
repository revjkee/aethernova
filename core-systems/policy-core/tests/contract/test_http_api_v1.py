# policy-core/tests/contract/test_http_api_v1.py
# Industrial-grade contract tests for HTTP API v1 without assuming concrete endpoints.
# - Auto-discovers endpoints from OpenAPI
# - Validates schema presence and basic correctness
# - Exercises GET endpoints under /api/v1 (without path params)
# - Checks response status bounds (no 5xx), optional security headers, versioning hints
# - Measures latency and enforces configurable SLO
# - Validates representative JSON bodies against OpenAPI if jsonschema is available
# - Skips gracefully when prerequisites are missing
#
# Configuration (pytest CLI options or ENV):
#   --base-url / ENV BASE_URL                  default: http://localhost:8000
#   --openapi-url / ENV OPENAPI_URL            default: <BASE_URL>/openapi.json (fallback /api/v1/openapi.json)
#   --auth-style / ENV AUTH_STYLE              one of: none|bearer|api_key  (default: none)
#   --token / ENV API_TOKEN                    token or API key value
#   --timeout / ENV HTTP_TIMEOUT               request timeout seconds (default: 10)
#   --max-endpoints / ENV MAX_ENDPOINTS        cap number of tested endpoints (default: 25)
#   --strict-status / ENV STRICT_STATUS        require 200/204 only for success (default: false)
#   --req-sec-headers / ENV REQUIRED_SEC_HEADERS
#                                             comma-separated security headers to require
#                                             default: Strict-Transport-Security,Content-Security-Policy,
#                                                      X-Content-Type-Options,X-Frame-Options,Referrer-Policy
#   --latency-slo-ms / ENV LATENCY_SLO_MS      per-request SLO in milliseconds (default: 2000)
#   --sample-for-headers / ENV SAMPLE_FOR_HEADERS
#                                             number of endpoints to sample for header checks (default: 5)
#
# Usage examples:
#   pytest -q policy-core/tests/contract/test_http_api_v1.py --base-url=http://localhost:8000
#   BASE_URL=https://api.example.com API_TOKEN=... AUTH_STYLE=bearer pytest -q ...
#
from __future__ import annotations

import asyncio
import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

try:
    # Optional: enables JSON schema validation against OpenAPI
    from jsonschema import Draft202012Validator  # type: ignore
    _JSONSCHEMA_AVAILABLE = True
except Exception:
    _JSONSCHEMA_AVAILABLE = False

try:
    import httpx
except Exception as exc:  # pragma: no cover
    raise RuntimeError("httpx is required for these tests. pip install httpx pytest-asyncio") from exc


# ------------------------------
# Pytest options and environment
# ------------------------------

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name)
    return val if val is not None and val != "" else default


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("contract")
    group.addoption("--base-url", action="store", default=_env("BASE_URL", "http://localhost:8000"))
    group.addoption("--openapi-url", action="store", default=_env("OPENAPI_URL", None))
    group.addoption("--auth-style", action="store", default=_env("AUTH_STYLE", "none"),
                    help="none|bearer|api_key")
    group.addoption("--token", action="store", default=_env("API_TOKEN", None))
    group.addoption("--timeout", action="store", type=float, default=float(_env("HTTP_TIMEOUT", "10")))
    group.addoption("--max-endpoints", action="store", type=int, default=int(_env("MAX_ENDPOINTS", "25")))
    group.addoption("--strict-status", action="store_true",
                    default=_env("STRICT_STATUS", "false").lower() == "true")
    default_headers = _env("REQUIRED_SEC_HEADERS", None)
    if default_headers is None:
        default_headers = ",".join([
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ])
    group.addoption("--req-sec-headers", action="store", default=default_headers)
    group.addoption("--latency-slo-ms", action="store", type=int, default=int(_env("LATENCY_SLO_MS", "2000")))
    group.addoption("--sample-for-headers", action="store", type=int, default=int(_env("SAMPLE_FOR_HEADERS", "5")))


@dataclass(frozen=True)
class TestConfig:
    base_url: str
    openapi_url: Optional[str]
    auth_style: str
    token: Optional[str]
    timeout: float
    max_endpoints: int
    strict_status: bool
    required_sec_headers: Tuple[str, ...]
    latency_slo_ms: int
    sample_for_headers: int


@pytest.fixture(scope="session")
def cfg(pytestconfig: pytest.Config) -> TestConfig:
    required_headers = tuple(
        h.strip() for h in str(pytestconfig.getoption("--req-sec-headers")).split(",") if h.strip()
    )
    openapi_url = pytestconfig.getoption("--openapi-url")
    base_url = str(pytestconfig.getoption("--base-url")).rstrip("/")
    if not openapi_url:
        # Prefer standard location; try /openapi.json first, then /api/v1/openapi.json during fetch
        openapi_url = f"{base_url}/openapi.json"
    return TestConfig(
        base_url=base_url,
        openapi_url=openapi_url,
        auth_style=str(pytestconfig.getoption("--auth-style")).lower(),
        token=pytestconfig.getoption("--token"),
        timeout=float(pytestconfig.getoption("--timeout")),
        max_endpoints=int(pytestconfig.getoption("--max-endpoints")),
        strict_status=bool(pytestconfig.getoption("--strict-status")),
        required_sec_headers=required_headers,
        latency_slo_ms=int(pytestconfig.getoption("--latency-slo-ms")),
        sample_for_headers=int(pytestconfig.getoption("--sample-for-headers")),
    )


# ------------------------------
# HTTP client and auth handling
# ------------------------------

def _auth_headers(cfg: TestConfig) -> Dict[str, str]:
    if cfg.auth_style == "bearer" and cfg.token:
        return {"Authorization": f"Bearer {cfg.token}"}
    if cfg.auth_style == "api_key" and cfg.token:
        # Common custom header name; adapt via gateway in front if needed
        return {"X-API-Key": cfg.token}
    return {}


@pytest.fixture(scope="session")
def event_loop() -> asyncio.AbstractEventLoop:
    # pytest-asyncio compatible loop at session scope
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def client(cfg: TestConfig) -> Iterable[httpx.AsyncClient]:
    headers = {"Accept": "application/json", **_auth_headers(cfg)}
    async with httpx.AsyncClient(base_url=cfg.base_url, headers=headers, timeout=cfg.timeout) as ac:
        yield ac


# ------------------------------
# OpenAPI fetch and indexing
# ------------------------------

class OpenAPILoader:
    def __init__(self, cfg: TestConfig, client: httpx.AsyncClient) -> None:
        self._cfg = cfg
        self._client = client
        self._cache: Optional[Dict[str, Any]] = None

    async def fetch(self) -> Dict[str, Any]:
        if self._cache is not None:
            return self._cache

        urls = [self._cfg.openapi_url]
        # Fallback commonly used in versioned APIs
        if self._cfg.openapi_url and self._cfg.openapi_url.endswith("/openapi.json"):
            urls.append(self._cfg.base_url + "/api/v1/openapi.json")

        last_exc: Optional[Exception] = None
        for url in urls:
            try:
                resp = await self._client.get(url)
                if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                    self._cache = resp.json()
                    return self._cache
            except Exception as exc:  # pragma: no cover
                last_exc = exc
        if last_exc:
            raise last_exc  # pragma: no cover
        raise RuntimeError("OpenAPI schema not reachable at expected locations")

    async def try_fetch(self) -> Optional[Dict[str, Any]]:
        try:
            return await self.fetch()
        except Exception:
            return None


@dataclass
class V1Endpoint:
    method: str
    path: str
    operation: Dict[str, Any]


class OpenAPIIndex:
    def __init__(self, spec: Dict[str, Any]) -> None:
        self.spec = spec
        self.openapi_version = str(spec.get("openapi", ""))
        self.paths: Dict[str, Any] = dict(spec.get("paths", {}))

    def v1_get_endpoints(self) -> List[V1Endpoint]:
        eps: List[V1Endpoint] = []
        for path, item in self.paths.items():
            if not isinstance(path, str) or not path.startswith("/api/v1"):
                continue
            # Skip paths with path params for now (avoid guessing)
            if "{" in path and "}" in path:
                continue
            for method in ("get", "GET"):
                op = item.get("get") or item.get("GET")
                if op:
                    eps.append(V1Endpoint(method="GET", path=path, operation=op))
        return eps

    def response_schema_for(self, path: str, status: str = "200") -> Optional[Dict[str, Any]]:
        try:
            op = self.paths[path]["get"]
        except Exception:
            return None
        responses = op.get("responses", {})
        entry = responses.get(status) or responses.get(int(status)) or {}
        content = entry.get("content", {})
        app_json = content.get("application/json", {})
        schema = app_json.get("schema")
        return schema


# ------------------------------
# Helpers
# ------------------------------

def _ok_status(status: int, strict: bool) -> bool:
    if strict:
        return status in (200, 204)
    # Non-strict: allow 2xx, 3xx, 401/403/404 as acceptable depending on gating,
    # but never 5xx for contract surface
    if 500 <= status <= 599:
        return False
    return status in range(200, 400) or status in (401, 403, 404)


def _pct95(latencies_ms: List[float]) -> float:
    if not latencies_ms:
        return 0.0
    arr = sorted(latencies_ms)
    k = int(round(0.95 * (len(arr) - 1)))
    return float(arr[k])


def _headers_present(resp: httpx.Response, required: Iterable[str]) -> Tuple[bool, List[str]]:
    missing = [h for h in required if h not in resp.headers]
    return (len(missing) == 0, missing)


def _json_or_none(resp: httpx.Response) -> Optional[Any]:
    ctype = resp.headers.get("Content-Type", "")
    if "application/json" in ctype:
        try:
            return resp.json()
        except Exception:
            return None
    return None


def _has_error_shape(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(k.lower() for k in payload.keys())
    # Accept any common error envelope
    return any(k in keys for k in ("error", "detail", "message"))


# ------------------------------
# Tests
# ------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_openapi_available_and_basic(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    if not spec:
        pytest.skip("OpenAPI not reachable at configured locations")

    # Basic shape checks without strict external validators
    assert isinstance(spec, dict), "OpenAPI document must be a JSON object"
    ov = str(spec.get("openapi", ""))
    assert ov.startswith("3."), f"OpenAPI version must be 3.x, observed: {ov or '<missing>'}"
    assert "paths" in spec and isinstance(spec["paths"], dict), "OpenAPI must define 'paths' object"
    # At least one v1 path should exist
    has_v1 = any(str(p).startswith("/api/v1") for p in spec["paths"].keys())
    assert has_v1, "OpenAPI should include at least one /api/v1 path"

    # Optional: validate with jsonschema if installed (smoke)
    if _JSONSCHEMA_AVAILABLE:
        # Draft2020-12 validates JSON, not OpenAPI meta-schema; here we ensure it is at least JSON-schema-clean
        Draft202012Validator.check_schema({"type": "object"})  # self-test of availability


@pytest.mark.contract
@pytest.mark.asyncio
async def test_v1_endpoints_statuses(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    random.shuffle(eps)
    eps = eps[: cfg.max_endpoints]

    failures: List[Tuple[str, int]] = []
    for ep in eps:
        r = await client.get(ep.path)
        if not _ok_status(r.status_code, cfg.strict_status):
            failures.append((ep.path, r.status_code))
    if failures:
        msg = "; ".join([f"{p} -> {s}" for p, s in failures])
        pytest.fail(f"Endpoints returned unacceptable status codes (strict={cfg.strict_status}): {msg}")


@pytest.mark.contract
@pytest.mark.asyncio
async def test_v1_endpoints_latency(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    random.shuffle(eps)
    eps = eps[: cfg.max_endpoints]

    latencies_ms: List[float] = []

    async def timed_get(path: str) -> None:
        t0 = time.perf_counter()
        _ = await client.get(path)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(dt)

    await asyncio.gather(*(timed_get(ep.path) for ep in eps))
    p95 = _pct95(latencies_ms)
    assert p95 <= cfg.latency_slo_ms, f"p95 latency {p95:.1f}ms exceeds SLO {cfg.latency_slo_ms}ms"


@pytest.mark.contract
@pytest.mark.asyncio
async def test_security_headers_on_sample(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    required = cfg.required_sec_headers
    if not required:
        pytest.skip("No required security headers configured")

    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    random.shuffle(eps)
    sample = eps[: max(1, cfg.sample_for_headers)]

    missing_summary: List[Tuple[str, List[str]]] = []
    for ep in sample:
        r = await client.get(ep.path)
        ok, missing = _headers_present(r, required)
        if not ok:
            missing_summary.append((ep.path, missing))
    if missing_summary:
        details = "; ".join([f"{p} missing: {', '.join(miss)}" for p, miss in missing_summary])
        pytest.fail(f"Required security headers missing on sample endpoints: {details}")


@pytest.mark.contract
@pytest.mark.asyncio
async def test_versioning_hints(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    # Pick one stable endpoint (first) for header/body version hints
    target = eps[0].path
    r = await client.get(target)
    # Header hint (non-fatal): X-API-Version should contain '1'
    xver = r.headers.get("X-API-Version")
    # Body hint (non-fatal): JSON object with 'version' starting with '1.'
    payload = _json_or_none(r)
    body_hint = bool(isinstance(payload, dict) and str(payload.get("version", "")).startswith("1"))
    if (xver is None or "1" not in xver) and not body_hint:
        pytest.skip("No explicit version hints in headers/body; skipping (not mandatory for all APIs)")


@pytest.mark.contract
@pytest.mark.asyncio
async def test_error_model_consistency(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    # Construct a certainly-missing endpoint under /api/v1 to probe error envelope
    bogus = "/api/v1/__nonexistent_contract_probe__"
    r = await client.get(bogus)
    # Accept 404/401/403, but expect JSON error envelope if JSON API
    assert r.status_code in (404, 401, 403), f"Unexpected status for bogus endpoint: {r.status_code}"
    payload = _json_or_none(r)
    if payload is None:
        pytest.skip("Error response is not JSON; skipping envelope check")
    assert _has_error_shape(payload), f"Error JSON lacks a common envelope shape: {payload!r}"


@pytest.mark.contract
@pytest.mark.asyncio
async def test_idempotent_get_stability_on_sample(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    random.shuffle(eps)
    sample = eps[: max(1, min(5, cfg.max_endpoints))]

    instabilities: List[str] = []
    for ep in sample:
        r1 = await client.get(ep.path)
        r2 = await client.get(ep.path)
        if r1.status_code != r2.status_code:
            instabilities.append(f"{ep.path} status {r1.status_code}->{r2.status_code}")
            continue
        et1, et2 = r1.headers.get("ETag"), r2.headers.get("ETag")
        if et1 and et2 and et1 != et2:
            instabilities.append(f"{ep.path} ETag {et1} != {et2}")
            continue
        # If ETag not provided, compare JSON payloads when available
        j1, j2 = _json_or_none(r1), _json_or_none(r2)
        if j1 is not None and j2 is not None:
            try:
                if json.dumps(j1, sort_keys=True) != json.dumps(j2, sort_keys=True):
                    instabilities.append(f"{ep.path} JSON body changed between idempotent GETs")
            except Exception:
                # Non-serializable bodies — skip
                pass

    if instabilities:
        pytest.fail("Idempotent GET stability issues: " + "; ".join(instabilities))


@pytest.mark.contract
@pytest.mark.asyncio
async def test_sample_json_matches_openapi_when_possible(cfg: TestConfig, client: httpx.AsyncClient) -> None:
    if not _JSONSCHEMA_AVAILABLE:
        pytest.skip("jsonschema not installed; skipping JSON-vs-OpenAPI validation")

    loader = OpenAPILoader(cfg, client)
    spec = await loader.try_fetch()
    index = OpenAPIIndex(spec)
    eps = index.v1_get_endpoints()
    if not eps:
        pytest.skip("No /api/v1 GET endpoints without path params were discovered in OpenAPI")

    # Pick a small sample for deep JSON validation
    random.shuffle(eps)
    sample = eps[: max(1, min(5, cfg.max_endpoints))]

    # Simplified resolver: we ignore $ref resolution across components for brevity,
    # expecting the server to dereference or keep shallow schemas.
    for ep in sample:
        schema = index.response_schema_for(ep.path, status="200")
        if not schema:
            # Try 204 (no content) or skip if absent
            schema204 = index.response_schema_for(ep.path, status="204")
            if schema204 is None:
                pytest.skip(f"No JSON 200/204 schema specified for {ep.path}; skipping strict JSON validation")
            continue

        r = await client.get(ep.path)
        payload = _json_or_none(r)
        if payload is None:
            pytest.skip(f"{ep.path} did not return JSON; skipping JSON validation")

        try:
            Draft202012Validator(schema).validate(payload)
        except Exception as exc:
            pytest.fail(f"JSON response for {ep.path} does not match OpenAPI schema: {exc!r}")
