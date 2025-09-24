# mythos-core/tests/contract/test_http_api_v1.py
# Python >= 3.11
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pytest

try:
    import httpx
except Exception as e:  # pragma: no cover
    pytest.skip(f"httpx is required for contract tests: {e}", allow_module_level=True)

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
OPENAPI_PATH = "/openapi.json"
HEALTH_PATHS = ("/health", "/status", "/livez", "/readyz")
BASE_URL = "http://test"
REQ_TIMEOUT = 10.0
SNAPSHOT_FILE = Path(__file__).parent / "golden" / "openapi_v1.sha256"
UPDATE_SNAPSHOTS = os.getenv("MYTHOS_UPDATE_SNAPSHOTS", "0") == "1"


# -----------------------------------------------------------------------------
# App discovery
# -----------------------------------------------------------------------------
def _load_asgi_app():
    """
    Tries common import points:
      - mythos_core.api.app:get_app()
      - mythos_core.api.v1:build_app()
      - mythos_core.api.app:app (ASGI instance)

    If none found -> skip tests at module level.
    """
    try:
        # Factory preferred
        from mythos_core.api.app import get_app  # type: ignore

        app = get_app()
        return app
    except Exception:
        pass
    try:
        from mythos_core.api.v1 import build_app  # type: ignore

        app = build_app()
        return app
    except Exception:
        pass
    try:
        from mythos_core.api.app import app as asgi_app  # type: ignore

        return asgi_app
    except Exception:
        pass
    pytest.skip("ASGI app not found: expected mythos_core.api.app:get_app() or api.v1:build_app()", allow_module_level=True)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(scope="session")
def app():
    return _load_asgi_app()


@pytest.fixture(scope="session")
def anyio_backend():
    # httpx AsyncClient uses anyio under the hood
    return "asyncio"


@pytest.fixture(scope="session")
async def client(app):
    async with httpx.AsyncClient(app=app, base_url=BASE_URL, timeout=REQ_TIMEOUT) as ac:
        yield ac


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
async def _fetch_openapi(client: httpx.AsyncClient) -> Dict[str, Any]:
    r = await client.get(OPENAPI_PATH)
    assert r.status_code == 200, f"openapi.json not available: HTTP {r.status_code}"
    try:
        data = r.json()
    except Exception as e:
        pytest.fail(f"openapi.json is not valid JSON: {e}")
    assert isinstance(data, dict), "openapi.json must be a JSON object"
    assert "openapi" in data and isinstance(data["openapi"], str), "missing 'openapi' version"
    assert "paths" in data and isinstance(data["paths"], dict), "missing 'paths'"
    return data


def _v1_paths(openapi: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    for p, spec in openapi.get("paths", {}).items():
        if isinstance(p, str) and p.startswith("/v1/"):
            out.append((p, spec or {}))
    return out


def _iter_ops(path_item: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for method, op in path_item.items():
        if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"} and isinstance(op, dict):
            yield method.lower(), op


def _has_path_params(path: str) -> bool:
    return "{" in path and "}" in path


def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


# -----------------------------------------------------------------------------
# Tests: OpenAPI contract
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_openapi_exists_and_basic_contract(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    info = openapi.get("info", {})
    assert isinstance(info, dict), "info must be an object"
    title = info.get("title")
    version = info.get("version")
    assert isinstance(title, str) and title.strip(), "info.title must be a non-empty string"
    assert isinstance(version, str) and version.strip(), "info.version must be a non-empty string"
    # OpenAPI 3.x required fields check
    assert openapi["openapi"].startswith("3."), "OpenAPI version must be 3.x"


@pytest.mark.anyio
async def test_openapi_has_v1_paths(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    v1 = _v1_paths(openapi)
    assert v1, "No /v1/* paths declared in OpenAPI"


@pytest.mark.anyio
async def test_v1_operations_have_required_fields(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    missing = []
    for path, item in _v1_paths(openapi):
        for method, op in _iter_ops(item):
            if method == "options":  # OPTIONS often auto-injected by CORS
                continue
            if "operationId" not in op or not isinstance(op["operationId"], str) or not op["operationId"].strip():
                missing.append((path, method, "operationId"))
            if "responses" not in op or not isinstance(op["responses"], dict) or not op["responses"]:
                missing.append((path, method, "responses"))
            if "tags" not in op or not isinstance(op["tags"], list) or not op["tags"]:
                missing.append((path, method, "tags"))
    assert not missing, f"Missing required fields in operations: {missing}"


# -----------------------------------------------------------------------------
# Tests: Live GET requests for simple v1 endpoints
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_get_v1_endpoints_return_json_when_no_path_params(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    tested = 0
    failures: List[Tuple[str, int, str]] = []

    for path, item in _v1_paths(openapi):
        if _has_path_params(path):
            continue
        # Prefer GET only
        op = item.get("get")
        if not isinstance(op, dict):
            continue
        resp_declared = op.get("responses", {})
        # we accept 200/2xx family
        r = await client.get(path)
        if not (200 <= r.status_code < 300):
            failures.append((path, r.status_code, r.text[:200]))
            continue
        # must be JSON
        try:
            _ = r.json()
        except Exception as e:
            failures.append((path, r.status_code, f"Invalid JSON: {e}"))
            continue
        tested += 1

    assert tested > 0, "No simple GET /v1 endpoints without path params to test"
    assert not failures, f"Failures for GET /v1 endpoints: {failures}"


# -----------------------------------------------------------------------------
# Tests: POST validation behavior (if POST without path params exists)
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_post_v1_endpoints_validate_request_body(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    tested = 0
    accepted: List[str] = []
    proper_4xx: List[Tuple[str, int]] = []
    unexpected: List[Tuple[str, int, str]] = []

    for path, item in _v1_paths(openapi):
        if _has_path_params(path):
            continue
        op = item.get("post")
        if not isinstance(op, dict):
            continue

        r = await client.post(path, json={})
        tested += 1
        if 200 <= r.status_code < 300:
            # server accepts empty JSON — contract allows defaults
            accepted.append(path)
            # still must be JSON
            _ = r.json()
        elif r.status_code in (400, 415, 422):
            proper_4xx.append((path, r.status_code))
        else:
            unexpected.append((path, r.status_code, r.text[:200]))

    # It's ok if there are no POST endpoints
    if tested == 0:
        pytest.skip("No simple POST /v1 endpoints without path params")

    assert not unexpected, f"Unexpected status codes for POST /v1: {unexpected}"
    # At least one endpoint should either accept {} or properly reject with 4xx
    assert (accepted or proper_4xx), "POST endpoints neither accepted {} nor returned validation 4xx"


# -----------------------------------------------------------------------------
# Tests: Health endpoint (optional)
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_health_endpoint_if_present(client: httpx.AsyncClient):
    for path in HEALTH_PATHS:
        r = await client.get(path)
        if r.status_code == 404:
            continue
        assert 200 <= r.status_code < 300, f"{path} returned {r.status_code}"
        try:
            body = r.json()
        except Exception:
            pytest.fail(f"{path} should return JSON")
        # flexible shape but must contain status-like field
        assert any(k in body for k in ("status", "state", "ok")), f"{path} JSON must contain status/state/ok"
        return
    pytest.skip("No health endpoint exposed")


# -----------------------------------------------------------------------------
# Tests: Error contract
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_404_error_shape(client: httpx.AsyncClient):
    r = await client.get("/v1/__definitely_not_exists__")
    assert r.status_code == 404
    # JSON problem details or FastAPI error {"detail": "..."}
    try:
        body = r.json()
    except Exception as e:
        pytest.fail(f"404 response must be JSON: {e}")
    assert isinstance(body, dict), "404 JSON body must be object"
    assert any(k in body for k in ("detail", "error", "message")), "404 JSON must contain detail/error/message"


# -----------------------------------------------------------------------------
# Tests: CORS preflight (optional)
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_cors_preflight_if_enabled(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    target = None
    for path, item in _v1_paths(openapi):
        if _has_path_params(path):
            continue
        if "get" in item:
            target = path
            break
    if not target:
        pytest.skip("No simple /v1 GET endpoint for CORS check")

    headers = {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "GET",
    }
    r = await client.options(target, headers=headers)
    if r.status_code in (404, 405):
        pytest.skip("CORS not enabled or OPTIONS not handled")
    # If CORS is enabled, must include ACAO header
    allow_origin = r.headers.get("access-control-allow-origin")
    assert allow_origin is not None, "Expected Access-Control-Allow-Origin in CORS preflight response"


# -----------------------------------------------------------------------------
# Tests: OpenAPI snapshot (hash) for change detection
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_openapi_snapshot_hash(client: httpx.AsyncClient):
    openapi = await _fetch_openapi(client)
    # consider only v1 subset to reduce churn
    subset = {
        "openapi": openapi.get("openapi"),
        "info": openapi.get("info"),
        "paths": {k: v for k, v in openapi.get("paths", {}).items() if isinstance(k, str) and k.startswith("/v1/")},
        "components": openapi.get("components", {}),
    }
    digest = hashlib.sha256(_canonical_json(subset)).hexdigest()

    SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if UPDATE_SNAPSHOTS:
        SNAPSHOT_FILE.write_text(digest, encoding="utf-8")
        # Ensure file is written and readable
        stored = SNAPSHOT_FILE.read_text(encoding="utf-8").strip()
        assert stored == digest
        return

    if not SNAPSHOT_FILE.exists():
        pytest.xfail("OpenAPI snapshot not found. Run with MYTHOS_UPDATE_SNAPSHOTS=1 to create it.")
    else:
        stored = SNAPSHOT_FILE.read_text(encoding="utf-8").strip()
        assert stored == digest, (
            "OpenAPI v1 contract changed. If intentional, update snapshot with "
            "MYTHOS_UPDATE_SNAPSHOTS=1"
        )
