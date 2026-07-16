# agent_mash/tests/e2e/scenarios/test_agent_lifecycle.py

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import httpx
import pytest


@dataclass(frozen=True)
class E2EConfig:
    base_url: str
    api_key: Optional[str]
    verify_tls: bool
    timeout_s: float
    poll_interval_s: float
    max_wait_s: float
    retry_attempts: int
    retry_backoff_s: float
    request_id_header: str

    @staticmethod
    def from_env() -> "E2EConfig":
        base_url = (os.getenv("AGENT_MASH_BASE_URL") or "").strip().rstrip("/")
        api_key = (os.getenv("AGENT_MASH_API_KEY") or "").strip() or None

        verify_tls_raw = (os.getenv("AGENT_MASH_VERIFY_TLS") or "true").strip().lower()
        verify_tls = verify_tls_raw not in {"0", "false", "no", "off"}

        timeout_s = float(os.getenv("AGENT_MASH_TIMEOUT_S") or "20")
        poll_interval_s = float(os.getenv("AGENT_MASH_POLL_INTERVAL_S") or "0.5")
        max_wait_s = float(os.getenv("AGENT_MASH_MAX_WAIT_S") or "30")

        retry_attempts = int(os.getenv("AGENT_MASH_RETRY_ATTEMPTS") or "3")
        retry_backoff_s = float(os.getenv("AGENT_MASH_RETRY_BACKOFF_S") or "0.4")

        request_id_header = (os.getenv("AGENT_MASH_REQUEST_ID_HEADER") or "X-Request-Id").strip()

        return E2EConfig(
            base_url=base_url,
            api_key=api_key,
            verify_tls=verify_tls,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
            max_wait_s=max_wait_s,
            retry_attempts=retry_attempts,
            retry_backoff_s=retry_backoff_s,
            request_id_header=request_id_header,
        )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_dumps_safe(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return "<unserializable>"


def _is_transient_http_status(status_code: int) -> bool:
    return status_code in {408, 425, 429, 500, 502, 503, 504}


def _make_headers(cfg: E2EConfig, request_id: str) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        cfg.request_id_header: request_id,
    }
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    return headers


async def _request_with_retries(
    client: httpx.AsyncClient,
    cfg: E2EConfig,
    method: str,
    path: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    expected_status: Optional[Tuple[int, ...]] = None,
) -> httpx.Response:
    url = f"{cfg.base_url}{path}"
    request_id = f"e2e-{uuid.uuid4()}"
    headers = _make_headers(cfg, request_id)

    last_exc: Optional[BaseException] = None
    for attempt in range(1, cfg.retry_attempts + 1):
        try:
            resp = await client.request(method, url, headers=headers, json=json_body)
            if expected_status and resp.status_code in expected_status:
                return resp

            if _is_transient_http_status(resp.status_code) and attempt < cfg.retry_attempts:
                await asyncio.sleep(cfg.retry_backoff_s * attempt)
                continue

            if expected_status and resp.status_code not in expected_status:
                body_preview = resp.text[:2000]
                raise AssertionError(
                    "Unexpected HTTP status.\n"
                    f"method={method} path={path} url={url}\n"
                    f"expected={expected_status} got={resp.status_code}\n"
                    f"request_id={request_id}\n"
                    f"response_headers={dict(resp.headers)}\n"
                    f"response_body_preview={body_preview}"
                )

            return resp
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt < cfg.retry_attempts:
                await asyncio.sleep(cfg.retry_backoff_s * attempt)
                continue
            raise

    if last_exc:
        raise last_exc
    raise RuntimeError("Request retry loop ended unexpectedly.")


def _assert_json_object(data: Any, *, context: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise AssertionError(f"{context}: expected JSON object, got {type(data).__name__}: {_json_dumps_safe(data)}")
    return data


def _extract_id(payload: Dict[str, Any]) -> str:
    for key in ("id", "agent_id", "uuid"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    raise AssertionError(f"Agent id not found in payload keys={list(payload.keys())}")


def _extract_status(payload: Dict[str, Any]) -> str:
    for key in ("status", "state"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().upper()
    raise AssertionError(f"Agent status not found in payload keys={list(payload.keys())}")


async def _wait_for_status(
    client: httpx.AsyncClient,
    cfg: E2EConfig,
    agent_id: str,
    desired: str,
) -> Dict[str, Any]:
    deadline = time.monotonic() + cfg.max_wait_s
    last_payload: Optional[Dict[str, Any]] = None

    while time.monotonic() < deadline:
        resp = await _request_with_retries(
            client,
            cfg,
            "GET",
            f"/v1/agents/{agent_id}",
            expected_status=(200,),
        )
        payload = _assert_json_object(resp.json(), context="GET agent payload")
        last_payload = payload

        status = _extract_status(payload)
        if status == desired.upper():
            return payload

        await asyncio.sleep(cfg.poll_interval_s)

    raise AssertionError(
        "Timed out waiting for agent status.\n"
        f"agent_id={agent_id} desired={desired} max_wait_s={cfg.max_wait_s}\n"
        f"last_payload={_json_dumps_safe(last_payload)}"
    )


@pytest.fixture(scope="session")
def e2e_cfg() -> E2EConfig:
    cfg = E2EConfig.from_env()
    if not cfg.base_url:
        pytest.skip("E2E skipped: env AGENT_MASH_BASE_URL is not set.")
    return cfg


@pytest.fixture()
async def http_client(e2e_cfg: E2EConfig) -> httpx.AsyncClient:
    timeout = httpx.Timeout(connect=e2e_cfg.timeout_s, read=e2e_cfg.timeout_s, write=e2e_cfg.timeout_s, pool=e2e_cfg.timeout_s)
    async with httpx.AsyncClient(verify=e2e_cfg.verify_tls, timeout=timeout, follow_redirects=True) as client:
        yield client


@pytest.mark.asyncio
async def test_agent_lifecycle_create_start_stop_delete(http_client: httpx.AsyncClient, e2e_cfg: E2EConfig) -> None:
    unique = uuid.uuid4().hex
    agent_name = f"e2e-agent-{unique}"
    agent_id: Optional[str] = None

    create_body = {
        "name": agent_name,
        "kind": "generic",
        "metadata": {
            "purpose": "e2e",
            "created_at_ms": _now_ms(),
        },
    }

    try:
        create_resp = await _request_with_retries(
            http_client,
            e2e_cfg,
            "POST",
            "/v1/agents",
            json_body=create_body,
            expected_status=(200, 201),
        )
        create_payload = _assert_json_object(create_resp.json(), context="POST /v1/agents payload")
        agent_id = _extract_id(create_payload)

        get_payload = await _request_with_retries(
            http_client,
            e2e_cfg,
            "GET",
            f"/v1/agents/{agent_id}",
            expected_status=(200,),
        )
        get_data = _assert_json_object(get_payload.json(), context="GET agent after create payload")
        assert _extract_id(get_data) == agent_id
        assert isinstance(get_data.get("name"), str) and get_data["name"] == agent_name

        start_resp = await _request_with_retries(
            http_client,
            e2e_cfg,
            "POST",
            f"/v1/agents/{agent_id}:start",
            json_body={"reason": "e2e"},
            expected_status=(200, 202, 204),
        )
        if start_resp.status_code in (200, 202) and start_resp.content:
            _assert_json_object(start_resp.json(), context="POST start response payload")

        await _wait_for_status(http_client, e2e_cfg, agent_id, desired="RUNNING")

        stop_resp = await _request_with_retries(
            http_client,
            e2e_cfg,
            "POST",
            f"/v1/agents/{agent_id}:stop",
            json_body={"reason": "e2e"},
            expected_status=(200, 202, 204),
        )
        if stop_resp.status_code in (200, 202) and stop_resp.content:
            _assert_json_object(stop_resp.json(), context="POST stop response payload")

        await _wait_for_status(http_client, e2e_cfg, agent_id, desired="STOPPED")

        delete_resp = await _request_with_retries(
            http_client,
            e2e_cfg,
            "DELETE",
            f"/v1/agents/{agent_id}",
            expected_status=(200, 202, 204),
        )
        if delete_resp.status_code in (200, 202) and delete_resp.content:
            _assert_json_object(delete_resp.json(), context="DELETE response payload")

        await _request_with_retries(
            http_client,
            e2e_cfg,
            "GET",
            f"/v1/agents/{agent_id}",
            expected_status=(404, 410),
        )

    finally:
        if agent_id:
            try:
                await _request_with_retries(
                    http_client,
                    e2e_cfg,
                    "DELETE",
                    f"/v1/agents/{agent_id}",
                    expected_status=(200, 202, 204, 404, 410),
                )
            except Exception:
                pass
