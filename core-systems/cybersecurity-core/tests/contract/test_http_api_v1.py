# -*- coding: utf-8 -*-
# File: cybersecurity-core/tests/contract/test_http_api_v1.py
# Purpose: Industrial-grade contract tests for HTTP API v1
# Notes:
#   - Base URL is configured via env: API_BASE_URL (default: http://localhost:8080)
#   - Optional bearer token via env: API_AUTH_TOKEN
#   - Optional OpenAPI URL via env: API_OPENAPI_URL (defaults to /openapi.json discovery)
#   - Tests are resilient: if a capability is not exposed, related tests are skipped, not failed.

import json
import os
import re
from typing import Dict, Iterable, Optional, Tuple, Any, List

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080").rstrip("/")
DEFAULT_OPENAPI_CANDIDATES: Tuple[str, ...] = ("/openapi.json", "/v1/openapi.json", "/swagger.json")
DEFAULT_TIMEOUT = float(os.getenv("API_TIMEOUT_SEC", "10.0"))

# Security headers we expect on JSON endpoints, per OWASP guidance.
SECURITY_HEADERS_REQUIRED = (
    "X-Content-Type-Options",  # nosniff
    "X-Frame-Options",         # DENY or SAMEORIGIN
)

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

JSON_CT_RE = re.compile(r"(?:^|;)\s*(application/(?:[\w.+-]*\+)?json)\b", re.I)


def _build_session() -> requests.Session:
    retry = Retry(
        total=int(os.getenv("API_RETRY_TOTAL", "3")),
        connect=int(os.getenv("API_RETRY_CONNECT", "2")),
        read=int(os.getenv("API_RETRY_READ", "2")),
        backoff_factor=float(os.getenv("API_RETRY_BACKOFF", "0.2")),
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=50)
    s = requests.Session()
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


@pytest.fixture(scope="session")
def base_url() -> str:
    return DEFAULT_BASE_URL


@pytest.fixture(scope="session")
def auth_token() -> Optional[str]:
    t = os.getenv("API_AUTH_TOKEN")
    return t.strip() if t else None


@pytest.fixture(scope="session")
def session() -> requests.Session:
    return _build_session()


def _join(base_url: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base_url + path


def _is_json_content(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return bool(JSON_CT_RE.search(ct))


def _json(resp: requests.Response) -> Any:
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        pytest.fail(f"Response is not valid JSON. Content-Type={resp.headers.get('Content-Type')} Body={resp.text[:200]}")


def _request(
    session: requests.Session,
    method: str,
    url: str,
    auth_token: Optional[str] = None,
    **kwargs,
) -> requests.Response:
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("Accept", "application/json")
    if auth_token:
        headers.setdefault("Authorization", f"Bearer {auth_token}")
    return session.request(method=method, url=url, headers=headers, timeout=DEFAULT_TIMEOUT, **kwargs)


def _discover_openapi(session: requests.Session, base_url: str, auth_token: Optional[str]) -> Optional[Dict[str, Any]]:
    for p in (os.getenv("API_OPENAPI_URL"),) + DEFAULT_OPENAPI_CANDIDATES:
        if not p:
            continue
        url = _join(base_url, p)
        try:
            resp = _request(session, "GET", url, auth_token)
        except Exception:
            continue
        if resp.status_code in (200,) and _is_json_content(resp):
            data = _json(resp)
            # OpenAPI v3 must have top-level "openapi" string like "3.0.0" or "3.1.0"
            if isinstance(data, dict) and isinstance(data.get("openapi"), str) and data["openapi"].startswith("3."):
                return data
    return None


def _first_available_endpoint(
    session: requests.Session, base_url: str, candidates: Iterable[str], auth_token: Optional[str]
) -> Optional[str]:
    for path in candidates:
        url = _join(base_url, path)
        try:
            resp = _request(session, "GET", url, auth_token)
        except requests.RequestException:
            continue
        if resp.status_code not in (404, 501):
            return path
        # Try HEAD if GET not allowed
        try:
            resp = _request(session, "HEAD", url, auth_token)
        except requests.RequestException:
            continue
        if resp.status_code not in (404, 405, 501):
            return path
    return None


def _extract_simple_get_json_paths(spec: Dict[str, Any]) -> List[str]:
    paths = []
    for p, item in (spec.get("paths") or {}).items():
        get_op = item.get("get") if isinstance(item, dict) else None
        if not isinstance(get_op, dict):
            continue
        # Skip if operation defines required parameters in query/path
        params = [pp for pp in get_op.get("parameters", []) if pp.get("required") is True]
        if params:
            continue
        # Skip if requestBody is required
        if "requestBody" in get_op:
            continue
        # Check for JSON response
        responses = get_op.get("responses", {})
        for code, resp in responses.items():
            try:
                code_int = int(code)
            except Exception:
                continue
            if 200 <= code_int < 300:
                content = (resp or {}).get("content", {})
                if any(ct.lower().startswith("application/json") or ct.lower().endswith("+json") for ct in content.keys()):
                    paths.append(p)
                    break
    return paths[:10]  # keep it short


@pytest.fixture(scope="session")
def openapi_spec(session: requests.Session, base_url: str, auth_token: Optional[str]) -> Optional[Dict[str, Any]]:
    return _discover_openapi(session, base_url, auth_token)


def test_openapi_document_available(session: requests.Session, base_url: str, auth_token: Optional[str]):
    spec = _discover_openapi(session, base_url, auth_token)
    if not spec:
        pytest.skip("OpenAPI document not exposed")
    assert isinstance(spec.get("openapi"), str) and spec["openapi"].startswith("3."), \
        f"Expected OpenAPI 3.x, got: {spec.get('openapi')}"


def test_health_endpoint(session: requests.Session, base_url: str, auth_token: Optional[str]):
    path = _first_available_endpoint(
        session, base_url, candidates=("/health", "/ready", "/livez", "/readyz", "/v1/health", "/healthz"), auth_token=auth_token
    )
    if not path:
        pytest.skip("No health-like endpoint found")
    resp = _request(session, "GET", _join(base_url, path), auth_token)
    assert resp.status_code in (200, 204), f"Unexpected status {resp.status_code} for {path}"
    if _is_json_content(resp):
        data = _json(resp)
        if isinstance(data, dict) and "status" in data:
            assert str(data["status"]).lower() in ("ok", "healthy", "up", "ready"), f"Unexpected status payload: {data}"


def test_security_headers_on_json_endpoint(session: requests.Session, base_url: str, auth_token: Optional[str], openapi_spec):
    # Pick a simple GET returning JSON; else fallback to /
    candidate_paths = _extract_simple_get_json_paths(openapi_spec) if openapi_spec else []
    if not candidate_paths:
        # Fallbacks
        candidate_paths = ["/", "/v1/status", "/v1/version"]
    path = _first_available_endpoint(session, base_url, candidate_paths, auth_token)
    if not path:
        pytest.skip("No JSON endpoint to validate headers")
    resp = _request(session, "GET", _join(base_url, path), auth_token)
    # If it's not JSON, skip (APIs may return HTML at /)
    if not _is_json_content(resp):
        pytest.skip(f"{path} does not return JSON")
    for h in SECURITY_HEADERS_REQUIRED:
        assert h in resp.headers, f"Missing security header: {h} on {path}"
    xcto = resp.headers.get("X-Content-Type-Options", "")
    assert xcto.lower() == "nosniff", f"X-Content-Type-Options should be 'nosniff', got: {xcto}"
    xfo = resp.headers.get("X-Frame-Options", "")
    assert xfo.upper() in ("DENY", "SAMEORIGIN"), f"X-Frame-Options should be DENY or SAMEORIGIN, got: {xfo}"
    # If HTTPS, require HSTS
    if _join(base_url, path).startswith("https://"):
        assert "Strict-Transport-Security" in resp.headers, "HSTS header required over HTTPS"


def test_metrics_endpoint_if_present(session: requests.Session, base_url: str, auth_token: Optional[str]):
    path = _first_available_endpoint(session, base_url, candidates=("/metrics", "/actuator/prometheus"), auth_token=auth_token)
    if not path:
        pytest.skip("No Prometheus metrics endpoint found")
    resp = _request(session, "GET", _join(base_url, path), auth_token, headers={"Accept": "*/*"})
    ct = resp.headers.get("Content-Type", "").lower()
    assert resp.status_code == 200, f"Metrics endpoint {path} should return 200"
    assert any(ct.startswith(p) for p in ("text/plain", "application/openmetrics-text")), \
        f"Unexpected metrics Content-Type: {ct}"
    body = resp.text
    assert ("# HELP" in body) or ("# TYPE" in body) or re.search(r"^[a-zA-Z_:][a-zA-Z0-9_:]*\s+\d", body, re.M), \
        "Metrics body does not look like Prometheus/OpenMetrics exposition"


def test_cors_preflight_if_cors_present(session: requests.Session, base_url: str, auth_token: Optional[str], openapi_spec):
    candidate_paths = _extract_simple_get_json_paths(openapi_spec) if openapi_spec else ["/", "/v1/status"]
    path = _first_available_endpoint(session, base_url, candidate_paths, auth_token)
    if not path:
        pytest.skip("No endpoint for CORS test")
    # Probe for CORS allow-origin on GET
    probe = _request(session, "GET", _join(base_url, path), auth_token)
    allow_origin = probe.headers.get("Access-Control-Allow-Origin")
    if not allow_origin:
        pytest.skip("CORS not enabled on this endpoint")
    # Emulate a browser preflight
    origin = os.getenv("API_CORS_TEST_ORIGIN", "https://example.com")
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }
    resp = _request(session, "OPTIONS", _join(base_url, path), auth_token, headers=headers)
    assert resp.status_code in (200, 204), f"Unexpected preflight status: {resp.status_code}"
    assert resp.headers.get("Access-Control-Allow-Origin") in ("*", origin), "Invalid ACAO in preflight response"
    allow_methods = resp.headers.get("Access-Control-Allow-Methods", "")
    assert "GET" in allow_methods, "GET should be allowed in CORS preflight"


def test_version_semver(session: requests.Session, base_url: str, auth_token: Optional[str], openapi_spec):
    # Prefer OpenAPI info.version
    if openapi_spec and isinstance(openapi_spec.get("info"), dict) and "version" in openapi_spec["info"]:
        ver = str(openapi_spec["info"]["version"])
        assert SEMVER_RE.match(ver), f"OpenAPI info.version not in semver format: {ver}"
        return
    # Otherwise, try common endpoints
    candidates = ("/version", "/v1/version", "/status", "/v1/status", "/about")
    path = _first_available_endpoint(session, base_url, candidates, auth_token)
    if not path:
        pytest.skip("No version endpoint found")
    resp = _request(session, "GET", _join(base_url, path), auth_token)
    if not _is_json_content(resp):
        pytest.skip("Version endpoint did not return JSON")
    data = _json(resp) or {}
    # Find any field containing 'version'
    ver = None
    if isinstance(data, dict):
        for k, v in data.items():
            if "version" in k.lower():
                ver = str(v)
                break
    if not ver:
        pytest.skip("No 'version' field found in JSON")
    assert SEMVER_RE.match(ver), f"Version is not semver: {ver}"


def test_datetime_fields_look_like_rfc3339(session: requests.Session, base_url: str, auth_token: Optional[str], openapi_spec):
    # Use a simple GET JSON endpoint and heuristically check any 'time'/'timestamp' fields
    candidate_paths = _extract_simple_get_json_paths(openapi_spec) if openapi_spec else []
    if not candidate_paths:
        pytest.skip("No suitable JSON endpoint to check datetime fields")
    path = candidate_paths[0]
    resp = _request(session, "GET", _join(base_url, path), auth_token)
    if not _is_json_content(resp):
        pytest.skip("Endpoint did not return JSON")
    data = _json(resp)
    if not isinstance(data, dict):
        pytest.skip("JSON is not an object; skipping datetime checks")
    date_like = {k: v for k, v in data.items() if isinstance(v, str) and any(s in k.lower() for s in ("time", "timestamp", "updated", "created"))}
    if not date_like:
        pytest.skip("No date-like fields in JSON")
    bad = {k: v for k, v in date_like.items() if not RFC3339_RE.match(v)}
    assert not bad, f"Fields not RFC3339: {bad}"
