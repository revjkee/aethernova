# agent_mash/tests/integration/api/test_agent_routes.py
"""
Integration API tests for Agent routes.

Unverified parts:
- Import path of FastAPI app
- Exact route prefixes and payload schemas
- Auth dependency paths and security model

Because I cannot verify these project-specific details, adjust:
- APP_IMPORT_CANDIDATES
- ROUTES (prefixes)
- Optional auth override hook in build_client()

Design goals:
- Deterministic, async-first, strict assertions
- Contract-style checks for status codes and response shapes
- Clear failure messages
"""

from __future__ import annotations

import importlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

import pytest
import httpx


# -----------------------------
# Configuration to adapt
# -----------------------------

APP_IMPORT_CANDIDATES: tuple[str, ...] = (
    # Replace with your real app location first.
    # Example: "agent_mash.app.main:app"
    "agent_mash.app.main:app",
    "agent_mash.main:app",
    "agent_mash.api.main:app",
    "app.main:app",
)

# Route prefixes to adapt to your real API.
# Keep them centralized so changes are one-line edits.
@dataclass(frozen=True, slots=True)
class Routes:
    agent_base: str = "/agents"         # list/create
    agent_item: str = "/agents/{id}"    # get/update/delete
    health: str = "/health"             # optional health endpoint


ROUTES = Routes()

# Timeouts for integration tests (still local in-memory ASGI).
HTTP_TIMEOUT = 10.0


# -----------------------------
# Helpers (strict assertions)
# -----------------------------

def _fail(msg: str) -> None:
    raise AssertionError(msg)


def _try_import_app() -> Any:
    """
    Import FastAPI app by trying candidate import strings: "module.path:attr".
    Fails with a clear message listing candidates.

    I cannot verify this because the real path is project-specific.
    """
    errors: list[str] = []
    for spec in APP_IMPORT_CANDIDATES:
        try:
            mod_path, attr = spec.split(":", 1)
            mod = importlib.import_module(mod_path)
            app = getattr(mod, attr)
            return app
        except Exception as e:  # noqa: BLE001
            errors.append(f"{spec} -> {type(e).__name__}: {e}")
    _fail(
        "Cannot import FastAPI app. Update APP_IMPORT_CANDIDATES.\n"
        + "\n".join(errors)
    )
    return None


def assert_status(resp: httpx.Response, expected: int | tuple[int, ...]) -> None:
    if isinstance(expected, int):
        exp = (expected,)
    else:
        exp = expected
    if resp.status_code not in exp:
        body = resp.text
        if len(body) > 2000:
            body = body[:2000] + "...(truncated)"
        _fail(
            f"Unexpected status: {resp.status_code}, expected {exp}. "
            f"URL={resp.request.url} BODY={body}"
        )


def assert_json(resp: httpx.Response) -> Any:
    ctype = resp.headers.get("content-type", "")
    if "application/json" not in ctype:
        body = resp.text
        if len(body) > 2000:
            body = body[:2000] + "...(truncated)"
        _fail(f"Expected JSON response, got content-type={ctype}. BODY={body}")
    try:
        return resp.json()
    except Exception as e:  # noqa: BLE001
        _fail(f"Invalid JSON: {type(e).__name__}: {e}. BODY={resp.text}")
    return None


def assert_has_keys(obj: Any, keys: Iterable[str]) -> None:
    if not isinstance(obj, dict):
        _fail(f"Expected dict, got {type(obj).__name__}: {obj!r}")
    missing = [k for k in keys if k not in obj]
    if missing:
        _fail(f"Missing keys {missing}. Got keys={sorted(obj.keys())}")


def extract_id(payload: Any) -> str:
    """
    Tries common id fields.
    """
    if isinstance(payload, dict):
        for k in ("id", "agent_id", "uuid"):
            v = payload.get(k)
            if isinstance(v, str) and v:
                return v
    _fail(f"Cannot extract id from payload: {payload!r}")
    return ""


def is_uuid_like(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value))


# -----------------------------
# Client factory
# -----------------------------

@pytest.fixture(scope="session")
def app() -> Any:
    """
    FastAPI app import.
    """
    return _try_import_app()


@pytest.fixture
async def client(app: Any) -> httpx.AsyncClient:
    """
    In-memory ASGI client.
    Optional: add dependency overrides for auth if your API requires it.

    I cannot verify your auth dependency, so no overrides are applied by default.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        timeout=HTTP_TIMEOUT,
        headers={"accept": "application/json"},
    ) as ac:
        yield ac


# -----------------------------
# Contract payload builders
# -----------------------------

def build_create_payload() -> dict[str, Any]:
    """
    Minimal create payload. Adapt to your schema.

    I cannot verify this.
    """
    return {
        "name": "test-agent",
        "type": "generic",
        "enabled": True,
        "meta": {"source": "integration-test"},
    }


def build_update_payload() -> dict[str, Any]:
    """
    Minimal update payload. Adapt to your schema.

    I cannot verify this.
    """
    return {
        "name": "test-agent-updated",
        "enabled": False,
        "meta": {"updated": True},
    }


# -----------------------------
# Tests
# -----------------------------

@pytest.mark.asyncio
async def test_health_optional(client: httpx.AsyncClient) -> None:
    """
    Health endpoint is optional: if missing, we accept 404.
    """
    resp = await client.get(ROUTES.health)
    if resp.status_code == 404:
        return
    assert_status(resp, (200, 204))
    if resp.status_code == 200:
        data = assert_json(resp)
        if isinstance(data, dict):
            # Common patterns: {"status":"ok"} or similar.
            if "status" in data:
                assert isinstance(data["status"], str)


@pytest.mark.asyncio
async def test_agents_list_contract(client: httpx.AsyncClient) -> None:
    """
    List endpoint must return JSON list or envelope with 'items'.
    """
    resp = await client.get(ROUTES.agent_base)
    assert_status(resp, (200, 401, 403))

    if resp.status_code in (401, 403):
        # Auth is required in your project. This is acceptable.
        return

    data = assert_json(resp)

    if isinstance(data, list):
        # List of agents
        for item in data[:5]:
            if isinstance(item, dict):
                # Minimal: should have an id-like field
                _ = extract_id(item)
        return

    if isinstance(data, dict):
        # Envelope format
        if "items" in data and isinstance(data["items"], list):
            for item in data["items"][:5]:
                if isinstance(item, dict):
                    _ = extract_id(item)
            return

    _fail(f"Unexpected list response shape: {data!r}")


@pytest.mark.asyncio
async def test_agents_crud_happy_path_or_auth_required(client: httpx.AsyncClient) -> None:
    """
    CRUD happy path, but if auth is enforced and no override exists, we accept 401/403.
    """
    create_payload = build_create_payload()

    create_resp = await client.post(ROUTES.agent_base, json=create_payload)
    if create_resp.status_code in (401, 403):
        return

    assert_status(create_resp, (200, 201))
    created = assert_json(create_resp)

    # Response can be agent object or envelope
    agent_obj = created.get("data") if isinstance(created, dict) and "data" in created else created
    agent_id = extract_id(agent_obj)

    # Optional UUID-like check (best-effort)
    if isinstance(agent_id, str) and "-" in agent_id:
        assert is_uuid_like(agent_id), f"agent_id is not UUID-like: {agent_id}"

    # GET
    get_resp = await client.get(ROUTES.agent_item.format(id=agent_id))
    assert_status(get_resp, 200)
    got = assert_json(get_resp)
    got_obj = got.get("data") if isinstance(got, dict) and "data" in got else got
    got_id = extract_id(got_obj)
    assert got_id == agent_id, f"GET returned different id: {got_id} != {agent_id}"

    # UPDATE (PUT or PATCH may be used in your API; we try PATCH first, then PUT)
    update_payload = build_update_payload()

    patch_resp = await client.patch(ROUTES.agent_item.format(id=agent_id), json=update_payload)
    if patch_resp.status_code == 405:
        patch_resp = await client.put(ROUTES.agent_item.format(id=agent_id), json=update_payload)

    assert_status(patch_resp, (200, 204))
    if patch_resp.status_code == 200:
        upd = assert_json(patch_resp)
        upd_obj = upd.get("data") if isinstance(upd, dict) and "data" in upd else upd
        _ = extract_id(upd_obj)

    # DELETE
    del_resp = await client.delete(ROUTES.agent_item.format(id=agent_id))
    assert_status(del_resp, (200, 202, 204))

    # GET after delete should be 404 or 410 (or auth error depending on server behavior)
    get2_resp = await client.get(ROUTES.agent_item.format(id=agent_id))
    assert_status(get2_resp, (404, 410, 401, 403))


@pytest.mark.asyncio
async def test_agents_create_validation_or_auth_required(client: httpx.AsyncClient) -> None:
    """
    Invalid create payload should be rejected with 400/422 (or auth required).
    """
    invalid_payload = {"name": ""}

    resp = await client.post(ROUTES.agent_base, json=invalid_payload)
    if resp.status_code in (401, 403):
        return

    assert_status(resp, (400, 422))
    _ = resp.text  # keep for debugging on failure


@pytest.mark.asyncio
async def test_agents_get_not_found_or_auth_required(client: httpx.AsyncClient) -> None:
    """
    Non-existing id should return 404/410 (or auth required).
    """
    fake_id = "00000000-0000-0000-0000-000000000000"

    resp = await client.get(ROUTES.agent_item.format(id=fake_id))
    if resp.status_code in (401, 403):
        return

    assert_status(resp, (404, 410))


@pytest.mark.asyncio
async def test_agents_delete_not_found_or_auth_required(client: httpx.AsyncClient) -> None:
    """
    Deleting non-existing id should return 404/410 or be idempotent (200/204).
    """
    fake_id = "00000000-0000-0000-0000-000000000000"

    resp = await client.delete(ROUTES.agent_item.format(id=fake_id))
    if resp.status_code in (401, 403):
        return

    assert_status(resp, (200, 202, 204, 404, 410))
