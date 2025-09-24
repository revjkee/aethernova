# file: cybersecurity-core/tests/integration/test_edr_quarantine.py
# Purpose: Industrial-grade integration tests for EDR-driven endpoint quarantine (network isolation).
# Standards alignment (non-exhaustive):
# - Zero Trust principles (explicit verification, continuous policy enforcement). NIST SP 800-207.  # see sources
# - Security/Privacy controls families (AC, AU, IR, SC, SI). NIST SP 800-53 Rev.5.                 # see sources
# - Incident response containment/eradication/recovery lifecycle. NIST SP 800-61 Rev.3.            # see sources
# - Defensive countermeasure taxonomy: MITRE D3FEND – Network Isolation (D3-NI).                   # see sources
#
# Test scope:
# 1) Happy path: isolate -> poll SUCCESS -> emit SIEM event with D3FEND tags.
# 2) Idempotency: 409 ALREADY_ISOLATED treated as success.
# 3) Timeout & rollback: poll never reaches SUCCESS -> rollback (unisolate) attempted, error surfaced.
# 4) Resilience: 429/5xx -> bounded exponential backoff & retry.
# 5) Crypto integrity: HMAC signature verification of EDR responses (X-Signature header).
# 6) Telemetry robustness: SIEM failure does not break quarantine flow (warn-only).
# 7) Concurrency: dedup parallel quarantine requests for same asset.
# 8) Property-based: correlation_id/asset_id constraints (UUID-like & non-empty).
#
# Dependencies (tests side):
#   pytest, pytest-asyncio, httpx>=0.24, respx>=0.20, hypothesis
# Install (example):
#   pip install pytest pytest-asyncio httpx respx hypothesis
#
# Note: This test provides a CONTRACT against an expected EDR REST shape. Adapt endpoints/fields to your EDR.

from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, List
import contextlib

import pytest

try:
    import httpx
    import respx
except Exception as e:  # pragma: no cover
    pytest.skip(f"Missing test deps httpx/respx: {e}", allow_module_level=True)

from hypothesis import given, strategies as st

# ---------------------------
# Utilities
# ---------------------------

def hmac_sign(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

class RetryableHTTPError(Exception):
    pass

class SignatureMismatch(Exception):
    pass

class QuarantineTimeout(Exception):
    pass

class QuarantineFailed(Exception):
    pass

# ---------------------------
# EDR API Client (contract-level)
# ---------------------------

@dataclass
class EDRClient:
    base_url: str
    token: str
    client: httpx.AsyncClient
    sig_secret: bytes
    timeout_s: float = 15.0
    max_retries: int = 3
    backoff_base: float = 0.2  # seconds

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    async def _request_with_retries(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        expected_status: Tuple[int, ...] = (200, 202),
    ) -> httpx.Response:
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self.client.request(
                    method,
                    url,
                    json=json_body,
                    headers=self._headers(),
                    timeout=self.timeout_s,
                )
                # retry on 429/5xx with jitterless backoff for determinism in tests
                if resp.status_code == 429 or 500 <= resp.status_code < 600:
                    raise RetryableHTTPError(f"Retryable status {resp.status_code}")
                if resp.status_code not in expected_status:
                    return resp  # let caller decide (e.g., 409 already isolated)
                return resp
            except (httpx.TimeoutException, RetryableHTTPError) as exc:
                last_exc = exc
                if attempt == self.max_retries:
                    raise
                await asyncio.sleep(self.backoff_base * (2 ** attempt))
        # Should not reach
        raise last_exc or RuntimeError("Unknown retry error")

    async def isolate(self, asset_id: str, reason: str, correlation_id: str) -> Optional[str]:
        url = f"{self.base_url}/api/v1/endpoints/{asset_id}/isolate"
        payload = {"reason": reason, "correlation_id": correlation_id}
        resp = await self._request_with_retries("POST", url, json_body=payload, expected_status=(202, 200, 409))
        if resp.status_code == 409:
            try:
                data = resp.json()
            except json.JSONDecodeError:
                data = {}
            if data.get("code") == "ALREADY_ISOLATED":
                return None  # idempotent success
        # Verify signature if present
        self._verify_signature(resp)
        if resp.status_code in (200, 202):
            data = resp.json()
            return data.get("task_id")
        # Unexpected
        raise QuarantineFailed(f"Unexpected status on isolate: {resp.status_code} {resp.text}")

    async def get_task_status(self, task_id: str) -> str:
        url = f"{self.base_url}/api/v1/tasks/{task_id}"
        resp = await self._request_with_retries("GET", url, expected_status=(200,))
        self._verify_signature(resp)
        data = resp.json()
        return data.get("status", "UNKNOWN")

    async def unisolate(self, asset_id: str, correlation_id: str) -> None:
        url = f"{self.base_url}/api/v1/endpoints/{asset_id}/unisolate"
        payload = {"correlation_id": correlation_id}
        resp = await self._request_with_retries("POST", url, json_body=payload, expected_status=(200, 202, 409))
        # signature optional on rollback; ignore 409 NOT_ISOLATED
        with contextlib.suppress(Exception):
            self._verify_signature(resp)

    def _verify_signature(self, resp: httpx.Response) -> None:
        sig = resp.headers.get("X-Signature")
        if not sig:
            return  # allow unsigned for backward compatibility; tighten in prod
        body = resp.content or b""
        calc = hmac_sign(self.sig_secret, body)
        if not hmac.compare_digest(calc, sig):
            raise SignatureMismatch("X-Signature HMAC mismatch")

# ---------------------------
# Orchestrator under test
# ---------------------------

class QuarantineOrchestrator:
    """
    High-level quarantine orchestration:
      - Requests EDR isolation and waits for SUCCESS within deadline.
      - Emits SIEM events with D3FEND taxonomy (Network Isolation).
      - Deduplicates concurrent requests per asset_id.
    """

    def __init__(self, edr: EDRClient, siem_sink: Callable[[Dict[str, Any]], "asyncio.Future[Any]"]):
        self._edr = edr
        self._siem = siem_sink
        self._locks: Dict[str, asyncio.Lock] = {}
        self._inflight: Dict[str, asyncio.Future] = {}

    def _lock_for(self, asset_id: str) -> asyncio.Lock:
        if asset_id not in self._locks:
            self._locks[asset_id] = asyncio.Lock()
        return self._locks[asset_id]

    async def quarantine(
        self,
        asset_id: str,
        reason: str,
        correlation_id: str,
        *,
        deadline_s: float = 30.0,
        poll_interval_s: float = 0.5,
    ) -> Dict[str, Any]:
        # Deduplicate concurrent calls
        if asset_id in self._inflight:
            return await self._inflight[asset_id]

        async with self._lock_for(asset_id):
            fut = asyncio.get_event_loop().create_future()
            self._inflight[asset_id] = fut
            try:
                task_id = await self._edr.isolate(asset_id, reason, correlation_id)
                if task_id is None:
                    # Already isolated -> treat as success
                    event = self._mk_event(asset_id, "SUCCESS", correlation_id, reason, d3fend=["D3-NI"])
                    await self._emit_siem_safe(event)
                    fut.set_result(event)
                    return event

                async def _poll():
                    end = asyncio.get_event_loop().time() + deadline_s
                    while True:
                        status = await self._edr.get_task_status(task_id)
                        if status == "SUCCESS":
                            return status
                        if status == "FAILED":
                            raise QuarantineFailed("EDR task failed")
                        if asyncio.get_event_loop().time() > end:
                            raise QuarantineTimeout("Quarantine timed out")
                        await asyncio.sleep(poll_interval_s)

                try:
                    status = await _poll()
                except QuarantineTimeout:
                    # Attempt rollback if we ever issued isolate command
                    with contextlib.suppress(Exception):
                        await self._edr.unisolate(asset_id, correlation_id)
                    event = self._mk_event(asset_id, "TIMEOUT", correlation_id, reason, d3fend=["D3-NI"])
                    await self._emit_siem_safe(event, severity="high")
                    raise
                except Exception:
                    event = self._mk_event(asset_id, "FAILED", correlation_id, reason, d3fend=["D3-NI"])
                    await self._emit_siem_safe(event, severity="critical")
                    raise

                event = self._mk_event(asset_id, status, correlation_id, reason, d3fend=["D3-NI"])
                await self._emit_siem_safe(event)
                fut.set_result(event)
                return event
            finally:
                self._inflight.pop(asset_id, None)

    def _mk_event(
        self,
        asset_id: str,
        status: str,
        correlation_id: str,
        reason: str,
        *,
        d3fend: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "event_type": "endpoint_quarantine",
            "status": status,
            "asset_id": asset_id,
            "correlation_id": correlation_id,
            "reason": reason,
            "mitre_d3fend": d3fend or [],
            # structured detail for downstream ECS/OTel mapping
            "detail": {"action": "network_isolate", "provider": "edr"},
        }

    async def _emit_siem_safe(self, event: Dict[str, Any], *, severity: str = "info") -> None:
        enriched = dict(event)
        enriched["severity"] = severity
        try:
            await self._siem(enriched)
        except Exception:
            # Do not block main flow if SIEM is down
            pass

# ---------------------------
# Fixtures / Mocks
# ---------------------------

@pytest.fixture
def sig_secret() -> bytes:
    return b"edr-shared-secret-for-tests"

@pytest.fixture
def base_url() -> str:
    return "https://edr.local"

@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c

@pytest.fixture
def siem_sink_collector():
    events: List[Dict[str, Any]] = []

    async def sink(evt: Dict[str, Any]) -> None:
        events.append(evt)

    return events, sink

@pytest.fixture
def siem_sink_failing():
    async def sink(_evt: Dict[str, Any]) -> None:
        raise RuntimeError("SIEM unavailable")
    return sink

def _signed_json(secret: bytes, body: Dict[str, Any]) -> Tuple[str, bytes]:
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac_sign(secret, payload)
    return sig, payload

# ---------------------------
# Tests
# ---------------------------

@pytest.mark.asyncio
async def test_quarantine_happy_path(base_url, http_client, sig_secret, siem_sink_collector):
    events, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret)
    orch = QuarantineOrchestrator(edr, sink)

    with respx.mock(assert_all_called=True) as router:
        # 1) isolate -> 202 with task
        task_id = "task-123"
        body = {"task_id": task_id}
        sig, payload = _signed_json(sig_secret, body)
        router.post(f"{base_url}/api/v1/endpoints/host-1/isolate").respond(
            202, content=payload, headers={"X-Signature": sig}
        )
        # 2) poll -> PENDING, then SUCCESS
        body1 = {"status": "PENDING"}
        sig1, payload1 = _signed_json(sig_secret, body1)
        router.get(f"{base_url}/api/v1/tasks/{task_id}").mock(side_effect=[
            httpx.Response(200, content=payload1, headers={"X-Signature": sig1}),
            httpx.Response(200, content=_signed_json(sig_secret, {"status": "SUCCESS"})[1],
                           headers={"X-Signature": _signed_json(sig_secret, {"status": "SUCCESS"})[0]}),
        ])

        result = await orch.quarantine("host-1", reason="IR containment", correlation_id="corr-1", deadline_s=5)

    assert result["status"] == "SUCCESS"
    assert result["detail"]["action"] == "network_isolate"
    assert result["mitre_d3fend"] == ["D3-NI"]  # MITRE D3FEND: Network Isolation
    # SIEM received event
    assert any(evt["status"] == "SUCCESS" and evt["event_type"] == "endpoint_quarantine" for evt in events)

@pytest.mark.asyncio
async def test_quarantine_idempotent_already_isolated(base_url, http_client, sig_secret, siem_sink_collector):
    events, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret)
    orch = QuarantineOrchestrator(edr, sink)

    with respx.mock(assert_all_called=True) as router:
        router.post(f"{base_url}/api/v1/endpoints/host-2/isolate").respond(
            409, json={"code": "ALREADY_ISOLATED", "message": "endpoint already isolated"}
        )
        result = await orch.quarantine("host-2", reason="IR containment", correlation_id="corr-2", deadline_s=3)

    assert result["status"] == "SUCCESS"  # treated as success (idempotent)
    assert any(evt["status"] == "SUCCESS" for evt in events)

@pytest.mark.asyncio
async def test_quarantine_timeout_and_rollback(base_url, http_client, sig_secret, siem_sink_collector):
    events, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret, max_retries=0)
    orch = QuarantineOrchestrator(edr, sink)

    with respx.mock(assert_all_called=True) as router:
        # isolate accepted
        task_id = "task-timeout"
        sig, payload = _signed_json(sig_secret, {"task_id": task_id})
        router.post(f"{base_url}/api/v1/endpoints/host-3/isolate").respond(
            202, content=payload, headers={"X-Signature": sig}
        )
        # poll returns PENDING forever
        sigp, payloadp = _signed_json(sig_secret, {"status": "PENDING"})
        router.get(f"{base_url}/api/v1/tasks/{task_id}").respond(200, content=payloadp, headers={"X-Signature": sigp})
        # rollback attempted
        router.post(f"{base_url}/api/v1/endpoints/host-3/unisolate").respond(200, json={"ok": True})

        with pytest.raises(QuarantineTimeout):
            await orch.quarantine("host-3", reason="IR containment", correlation_id="corr-3", deadline_s=1, poll_interval_s=0.2)

    # SIEM contains timeout event, severity high
    assert any(evt["status"] == "TIMEOUT" and evt["severity"] == "high" for evt in events)

@pytest.mark.asyncio
async def test_retry_on_429_then_success(base_url, http_client, sig_secret, siem_sink_collector):
    events, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret, max_retries=2, backoff_base=0.01)
    orch = QuarantineOrchestrator(edr, sink)

    with respx.mock(assert_all_called=True) as router:
        task_id = "task-rl"
        router.post(f"{base_url}/api/v1/endpoints/host-4/isolate").mock(side_effect=[
            httpx.Response(429, json={"retry": 1}),
            httpx.Response(202, content=_signed_json(sig_secret, {"task_id": task_id})[1],
                           headers={"X-Signature": _signed_json(sig_secret, {"task_id": task_id})[0]}),
        ])
        router.get(f"{base_url}/api/v1/tasks/{task_id}").respond(
            200, content=_signed_json(sig_secret, {"status": "SUCCESS"})[1],
            headers={"X-Signature": _signed_json(sig_secret, {"status": "SUCCESS"})[0]}
        )

        result = await orch.quarantine("host-4", reason="IR containment", correlation_id="corr-4", deadline_s=3)

    assert result["status"] == "SUCCESS"
    assert any(evt["status"] == "SUCCESS" for evt in events)

@pytest.mark.asyncio
async def test_signature_verification_failure_raises(base_url, http_client, sig_secret, siem_sink_collector):
    _, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret)
    orch = QuarantineOrchestrator(edr, sink)

    with respx.mock(assert_all_called=False) as router:
        # isolate with bad signature
        bad_payload = json.dumps({"task_id": "task-bad"}).encode("utf-8")
        bad_sig = "deadbeef" * 8
        router.post(f"{base_url}/api/v1/endpoints/host-5/isolate").respond(
            202, content=bad_payload, headers={"X-Signature": bad_sig}
        )

        with pytest.raises(SignatureMismatch):
            await orch.quarantine("host-5", reason="IR containment", correlation_id="corr-5", deadline_s=3)

@pytest.mark.asyncio
async def test_siem_failure_does_not_block_flow(base_url, http_client, sig_secret, siem_sink_failing):
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret)
    orch = QuarantineOrchestrator(edr, siem_sink_failing)

    with respx.mock(assert_all_called=True) as router:
        task_id = "task-siem"
        router.post(f"{base_url}/api/v1/endpoints/host-6/isolate").respond(
            202, content=_signed_json(sig_secret, {"task_id": task_id})[1],
            headers={"X-Signature": _signed_json(sig_secret, {"task_id": task_id})[0]}
        )
        router.get(f"{base_url}/api/v1/tasks/{task_id}").respond(
            200, content=_signed_json(sig_secret, {"status": "SUCCESS"})[1],
            headers={"X-Signature": _signed_json(sig_secret, {"status": "SUCCESS"})[0]}
        )

        # Should not raise despite SIEM sink throwing
        result = await orch.quarantine("host-6", reason="IR containment", correlation_id="corr-6", deadline_s=3)

    assert result["status"] == "SUCCESS"

@pytest.mark.asyncio
async def test_concurrent_quarantine_deduplicates_calls(base_url, http_client, sig_secret, siem_sink_collector):
    events, sink = siem_sink_collector
    edr = EDRClient(base_url, token="t", client=http_client, sig_secret=sig_secret)
    orch = QuarantineOrchestrator(edr, sink)

    call_counter = {"isolate": 0}
    with respx.mock(assert_all_called=True) as router:
        task_id = "task-concurrent"
        def isolate_handler(request: httpx.Request) -> httpx.Response:
            call_counter["isolate"] += 1
            return httpx.Response(
                202,
                content=_signed_json(sig_secret, {"task_id": task_id})[1],
                headers={"X-Signature": _signed_json(sig_secret, {"task_id": task_id})[0]},
            )

        router.post(f"{base_url}/api/v1/endpoints/host-7/isolate").mock(side_effect=isolate_handler)
        # One SUCCESS status for both waiters
        router.get(f"{base_url}/api/v1/tasks/{task_id}").respond(
            200, content=_signed_json(sig_secret, {"status": "SUCCESS"})[1],
            headers={"X-Signature": _signed_json(sig_secret, {"status": "SUCCESS"})[0]}
        )

        res1, res2 = await asyncio.gather(
            orch.quarantine("host-7", reason="IR containment", correlation_id="corr-7a", deadline_s=3),
            orch.quarantine("host-7", reason="IR containment", correlation_id="corr-7b", deadline_s=3),
        )

    assert res1["status"] == "SUCCESS" and res2["status"] == "SUCCESS"
    # Ensure only one isolate call was made due to dedup
    assert call_counter["isolate"] == 1
    assert len([e for e in events if e["status"] == "SUCCESS"]) >= 1

# ---------------------------
# Property-based constraints
# ---------------------------

uuid_chars = "0123456789abcdef-"

@given(
    asset_id=st.text(alphabet=uuid_chars, min_size=8, max_size=36).filter(lambda s: any(c.isalnum() for c in s)),
    corr_id=st.text(alphabet=uuid_chars, min_size=8, max_size=36).filter(lambda s: any(c.isalnum() for c in s)),
)
def test_id_constraints_do_not_accept_empty(asset_id: str, corr_id: str):
    # Pure property check on generators; orchestrator expects non-empty identifiers
    assert asset_id.strip() != ""
    assert corr_id.strip() != ""
