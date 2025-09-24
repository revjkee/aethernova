# tests/contract/test_http_api_v1.py
"""
Contract tests for Physical Integration Core HTTP API v1.

Two execution modes:
  1) Live HTTP server via env API_BASE_URL (e.g. http://localhost:8080)
  2) In-process ASGI if an app can be imported (best-effort):
       - physical_integration.api.app:app
       - physical_integration.api:build_app()
       - physical_integration.api:get_app()

Requirements:
  - pytest
  - httpx>=0.24 (async client)
Set optional env:
  - API_BASE_URL
  - API_BEARER_TOKEN
  - API_DEVICE_ID (default: dev-001)
  - API_TWIN_ID (default: dev-001)
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import pytest
import httpx

pytestmark = pytest.mark.contract

# ------------------------------
# Helpers and fixtures
# ------------------------------

HEALTH_CANDIDATES = ("/health", "/healthz", "/readyz", "/livez", "/v1/health")
OPENAPI_CANDIDATES = ("/openapi.json", "/v1/openapi.json")

DEFAULT_TIMEOUT = httpx.Timeout(connect=3.0, read=10.0, write=10.0, pool=3.0)
RETRY_STATUS = {502, 503, 504}
MAX_RETRIES = 3


def _bearer_headers() -> Dict[str, str]:
    token = os.getenv("API_BEARER_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _id_headers() -> Dict[str, str]:
    # Idempotency-Key generated per test where needed
    return {}


def _get_ids() -> Tuple[str, str]:
    dev = os.getenv("API_DEVICE_ID", "dev-001")
    twin = os.getenv("API_TWIN_ID", dev)
    return dev, twin


async def _choose_existing_path(client: httpx.AsyncClient, candidates: Sequence[str]) -> Optional[str]:
    for p in candidates:
        try:
            r = await client.get(p)
            if r.status_code == 200:
                return p
        except Exception:
            continue
    return None


def _assert_json_object(obj: Any, *, fields: Mapping[str, type], allow_extra: bool = True) -> None:
    assert isinstance(obj, dict), f"Expected object, got {type(obj)}"
    for k, t in fields.items():
        assert k in obj, f"Missing field '{k}'"
        v = obj[k]
        if t is type(None):
            assert v is None, f"Field '{k}' expected None, got {type(v)}"
        elif t is float:
            assert isinstance(v, (int, float)) and math.isfinite(float(v)), f"Field '{k}' must be finite number"
        else:
            assert isinstance(v, t), f"Field '{k}' must be {t}, got {type(v)}"
    if not allow_extra:
        extras = set(obj.keys()) - set(fields.keys())
        assert not extras, f"Unexpected fields present: {extras}"


def _mk_patch_set(path: Sequence[str], value: Any) -> Dict[str, Any]:
    return {"op": "set", "path": "/".join(path), "value": value}


def _mk_patch_remove(path: Sequence[str]) -> Dict[str, Any]:
    return {"op": "remove", "path": "/".join(path)}


def _idem_key() -> str:
    return f"ct-{int(time.time()*1000)}-{os.getpid()}"


async def _retrying_request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
    last_exc: Optional[BaseException] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = await client.request(method, url, **kwargs)
            if r.status_code in RETRY_STATUS:
                await asyncio.sleep(min(0.2 * attempt, 1.0))
                continue
            return r
        except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as e:
            last_exc = e
            await asyncio.sleep(min(0.2 * attempt, 1.0))
    if last_exc:
        raise last_exc
    raise AssertionError("unreachable")


@pytest.fixture(scope="session")
def base_url() -> Optional[str]:
    url = os.getenv("API_BASE_URL", "").strip().rstrip("/")
    return url or None


@pytest.fixture(scope="session")
def asgi_app():
    """
    Try to import an ASGI app to run tests in-process.
    """
    try:
        from physical_integration.api.app import app as a  # type: ignore
        return a
    except Exception:
        pass
    try:
        from physical_integration.api import build_app  # type: ignore
        return build_app()
    except Exception:
        pass
    try:
        from physical_integration.api import get_app  # type: ignore
        return get_app()
    except Exception:
        pass
    return None


@pytest.fixture(scope="session")
async def client(base_url, asgi_app):
    """
    Provide a single AsyncClient either for live HTTP or in-process ASGI.
    Skip all tests gracefully if neither is available.
    """
    headers = {
        "Accept": "application/json",
        **_bearer_headers(),
    }

    if base_url:
        async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=DEFAULT_TIMEOUT, follow_redirects=True) as c:
            yield c
            return

    if asgi_app is not None:
        transport = httpx.ASGITransport(app=asgi_app)
        async with httpx.AsyncClient(base_url="http://asgi", transport=transport, headers=headers, timeout=DEFAULT_TIMEOUT, follow_redirects=True) as c:
            yield c
            return

    pytest.skip("Neither API_BASE_URL nor ASGI app available")


# ------------------------------
# Tests
# ------------------------------

@pytest.mark.asyncio
async def test_health_endpoint_available(client: httpx.AsyncClient):
    path = await _choose_existing_path(client, HEALTH_CANDIDATES)
    if not path:
        pytest.skip("No health endpoint found among candidates")
    r = await client.get(path)
    assert r.status_code == 200, f"Health check failed at {path}: {r.status_code} {r.text}"
    # Accept JSON or plain text
    ctype = r.headers.get("Content-Type", "")
    assert ("application/json" in ctype) or ("text/plain" in ctype), f"Unexpected Content-Type: {ctype}"


@pytest.mark.asyncio
async def test_openapi_contract_present(client: httpx.AsyncClient):
    path = await _choose_existing_path(client, OPENAPI_CANDIDATES)
    if not path:
        pytest.skip("No OpenAPI endpoint exposed")
    r = await client.get(path)
    assert r.status_code == 200, f"OpenAPI endpoint {path} not 200"
    spec = r.json()
    assert "openapi" in spec and "paths" in spec, "Invalid OpenAPI document"
    # Expect at least a v1 namespace
    assert any(p.startswith("/v1/") for p in spec.get("paths", {}).keys()), "OpenAPI must include /v1/* paths"


@pytest.mark.asyncio
async def test_get_device_state_contract(client: httpx.AsyncClient):
    device_id, _ = _get_ids()
    r = await _retrying_request(client, "GET", f"/v1/devices/{device_id}/state")
    assert r.status_code == 200, f"GET device state failed: {r.status_code} {r.text}"
    assert "application/json" in r.headers.get("Content-Type", ""), "Response must be application/json"
    payload = r.json()
    _assert_json_object(
        payload,
        fields={"state": dict, "version": (str, type(None)), "modified_ts": (int, float, type(None))},  # type: ignore
    )


@pytest.mark.asyncio
async def test_patch_device_state_with_if_match_and_idempotency(client: httpx.AsyncClient):
    device_id, _ = _get_ids()
    # Fetch current
    r0 = await client.get(f"/v1/devices/{device_id}/state")
    if r0.status_code == 404:
        pytest.skip(f"Device {device_id} not found")
    assert r0.status_code == 200, f"Cannot read device state: {r0.status_code} {r0.text}"
    js0 = r0.json()
    prev_ver = js0.get("version")

    # Build minimal patch (set transient field under _test)
    patch = [
        _mk_patch_set(["_test", "flag"], True),
        _mk_patch_set(["_test", "ts"], int(time.time())),
    ]
    idem = _idem_key()
    headers = {
        "If-Match": prev_ver or "",
        "Idempotency-Key": idem,
        **_bearer_headers(),
    }
    r1 = await client.patch(f"/v1/devices/{device_id}/state", json=patch, headers=headers)
    assert r1.status_code in {200, 204}, f"PATCH device state failed: {r1.status_code} {r1.text}"
    v1 = r1.json().get("version") if r1.headers.get("Content-Type", "").startswith("application/json") else None

    # Repeat same request to test idempotency behavior
    r2 = await client.patch(f"/v1/devices/{device_id}/state", json=patch, headers=headers)
    assert r2.status_code in {200, 204}, f"Idempotent PATCH must not error: {r2.status_code} {r2.text}"
    if r2.headers.get("Content-Type", "").startswith("application/json"):
        v2 = r2.json().get("version")
        # Accept either equal or newer version; must not regress
        if v1 and v2:
            assert isinstance(v1, str) and isinstance(v2, str)
            assert v2 >= v1 or v2 == v1, "Version must be monotonic non-decreasing"


@pytest.mark.asyncio
async def test_get_twin_state_and_patch_roundtrip(client: httpx.AsyncClient):
    _, twin_id = _get_ids()
    r0 = await client.get(f"/v1/twin/{twin_id}/state")
    if r0.status_code == 404:
        pytest.skip(f"Twin {twin_id} not found")
    assert r0.status_code == 200, f"Cannot read twin state: {r0.status_code} {r0.text}"
    js0 = r0.json()
    _assert_json_object(js0, fields={"state": dict, "version": (str, type(None)), "modified_ts": (int, float, type(None))})  # type: ignore

    # Propose patch (toggle a bool)
    old_flag = bool(js0["state"].get("_test", {}).get("twin_flag", False))
    patch = [_mk_patch_set(["_test", "twin_flag"], not old_flag)]
    idem = _idem_key()
    headers = {"If-Match": js0.get("version") or "", "Idempotency-Key": idem, **_bearer_headers()}
    r1 = await client.patch(f"/v1/twin/{twin_id}/state", json=patch, headers=headers)
    assert r1.status_code in {200, 204}, f"PATCH twin state failed: {r1.status_code} {r1.text}"

    # Read back and verify
    r2 = await client.get(f"/v1/twin/{twin_id}/state")
    assert r2.status_code == 200
    js2 = r2.json()
    got = js2["state"].get("_test", {}).get("twin_flag")
    assert got == (not old_flag), f"Twin flag not updated, expected {not old_flag}, got {got}"


@pytest.mark.asyncio
async def test_calibration_validate_endpoint(client: httpx.AsyncClient):
    """
    POST /v1/calibration/validate
    Payload mirrors validators.py expectations: series + meta; expect 'overall_passed' in response.
    """
    # Build synthetic calibration payload
    n = 200
    ts = [i * 0.001 for i in range(n)]  # 1 kHz
    meas = [math.sin(i * 0.01) for i in range(n)]
    residuals = [0.0 for _ in range(n)]
    payload = {
        "series": {
            "timestamp": ts,
            "measurement": meas,
            "residuals": residuals,
        },
        "meta": {
            "sensor_type": "synthetic",
            "version": "1.0.0",
            "calibration_matrix": [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        },
    }

    r = await client.post("/v1/calibration/validate", json=payload)
    if r.status_code == 404:
        pytest.skip("Calibration validation endpoint not implemented")
    assert r.status_code == 200, f"Validation endpoint must return 200: {r.status_code} {r.text}"
    assert "application/json" in r.headers.get("Content-Type", "")
    js = r.json()
    # Minimal contract: top-level fields
    _assert_json_object(js, fields={"overall_passed": bool, "results": list})
    # Each result: name, passed, issues, metrics
    if js["results"]:
        first = js["results"][0]
        assert isinstance(first, dict)
        assert "name" in first and "passed" in first and "issues" in first and "metrics" in first, "Invalid result item structure"
