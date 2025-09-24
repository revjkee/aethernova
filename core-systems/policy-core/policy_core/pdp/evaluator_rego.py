# -*- coding: utf-8 -*-
"""
Industrial-grade Rego evaluator for OPA (Policy Decision Point).
- Async HTTP client (httpx) with timeouts, retries, jittered backoff
- Concurrency limiting (asyncio.Semaphore)
- Simple circuit breaker (failure threshold & reset window)
- In-memory LRU+TTL decision cache
- Structured logging & optional OpenTelemetry tracing/metrics
- Supports /v1/data/<path> evaluate and /v1/compile partial evaluation
- Strict error taxonomy & helpful diagnostics

Author: policy-core
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import random
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, Union, List

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError(
        "httpx is required for evaluator_rego.py. Install with: pip install httpx"
    ) from e

# Optional OpenTelemetry integration (no hard dependency)
try:  # pragma: no cover - optional
    from opentelemetry import trace, metrics
    from opentelemetry.trace import SpanKind
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False
    trace = None
    metrics = None
    SpanKind = None

# ---------------------------------------------------------------------------
# Configuration & Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PDPConfig:
    base_url: str = "http://127.0.0.1:8181"
    token: Optional[str] = None
    namespace: Optional[str] = None  # logical grouping for logs/metrics
    timeout_seconds: float = 2.5
    connect_timeout_seconds: float = 1.0
    retries: int = 2
    backoff_base: float = 0.2  # seconds
    backoff_max: float = 1.5   # seconds
    verify_ssl: bool = True
    max_concurrency: int = 64
    cache_ttl_seconds: float = 2.0
    cache_max_entries: int = 10_000
    circuit_fail_threshold: int = 12
    circuit_reset_seconds: int = 30
    default_headers: Optional[Dict[str, str]] = None
    log_decision_payloads: bool = False  # set to True for deep debugging
    mask_secrets: bool = True            # mask token and sensitive fields in logs

@dataclass(frozen=True)
class EvaluationResult:
    request_id: str
    policy_path: str
    raw_result: Any
    decision: Optional[bool]
    latency_ms: float
    from_cache: bool
    cached_ttl_left_ms: Optional[float] = None
    explain: Optional[str] = None  # future: could carry trace or OPA explain

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PolicyEngineError(Exception):
    """Base error for PDP evaluator."""

class OPAConnectionError(PolicyEngineError):
    """Cannot reach OPA or network failure."""

class OPAProtocolError(PolicyEngineError):
    """OPA responded with unexpected structure or unsupported status."""

class PolicyNotFound(PolicyEngineError):
    """Target policy path not found in OPA."""

class InvalidInput(PolicyEngineError):
    """Provided input does not conform to expected constraints."""

class CircuitOpen(PolicyEngineError):
    """Circuit breaker is open due to prior failures."""

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = {"authorization", "token", "password", "secret", "api_key", "x-api-key", "x-auth-token"}

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _stable_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _hash_key(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
    return h.hexdigest()

def _mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    masked = {}
    for k, v in headers.items():
        if k.lower() in _SENSITIVE_KEYS:
            masked[k] = "***"
        else:
            masked[k] = v
    return masked

def _mask_secrets_in_payload(data: Any) -> Any:
    if isinstance(data, dict):
        return {k: ("***" if k.lower() in _SENSITIVE_KEYS else _mask_secrets_in_payload(v))
                for k, v in data.items()}
    if isinstance(data, list):
        return [_mask_secrets_in_payload(v) for v in data]
    return data

# ---------------------------------------------------------------------------
# TTL + LRU cache
# ---------------------------------------------------------------------------

class _TTL_LRU(OrderedDict):
    """Simple in-memory TTL + LRU cache."""

    def __init__(self, max_entries: int, ttl_seconds: float) -> None:
        super().__init__()
        self._max = max_entries
        self._ttl = ttl_seconds

    def _evict(self) -> None:
        while len(self) > self._max:
            self.popitem(last=False)

    def _expired(self, ts: float) -> bool:
        return (time.monotonic() - ts) > self._ttl

    def get_with_ttl(self, key: str) -> Optional[Tuple[Any, float]]:
        item = super().get(key)
        if not item:
            return None
        value, ts = item
        if self._expired(ts):
            with contextlib.suppress(KeyError):
                del self[key]
            return None
        # move to end (LRU)
        self.move_to_end(key)
        ttl_left = max(0.0, self._ttl - (time.monotonic() - ts))
        return value, ttl_left

    def set(self, key: str, value: Any) -> None:
        super().__setitem__(key, (value, time.monotonic()))
        self.move_to_end(key)
        self._evict()

# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class RegoEvaluator:
    """
    Async evaluator for OPA Rego policies.

    Typical use:
        cfg = PDPConfig(base_url="http://opa:8181", token="...", ...)
        evaluator = RegoEvaluator(cfg)
        await evaluator.start()
        try:
            res = await evaluator.evaluate("authz/allow", {"sub": "...", "act": "read", "obj": "doc:1"})
            if res.decision is True:
                ...
        finally:
            await evaluator.aclose()
    """

    def __init__(self, cfg: PDPConfig) -> None:
        self._cfg = cfg
        self._logger = logging.getLogger("policy_core.pdp.evaluator_rego")
        self._logger.setLevel(logging.INFO)
        self._client: Optional[httpx.AsyncClient] = None

        # concurrency
        self._sem = asyncio.Semaphore(value=max(1, cfg.max_concurrency))

        # retries / circuit breaker
        self._fail_count = 0
        self._circuit_open_until: Optional[float] = None

        # cache
        self._cache = _TTL_LRU(cfg.cache_max_entries, cfg.cache_ttl_seconds)

        # metrics
        self._metric_evals_total = 0
        self._metric_evals_errors = 0
        self._metric_cache_hits = 0
        self._metric_latency_sum_ms = 0.0

        # OpenTelemetry
        if _OTEL_AVAILABLE:  # pragma: no cover - optional
            self._tracer = trace.get_tracer(__name__)
            try:
                self._meter = metrics.get_meter(__name__)
            except Exception:
                self._meter = None
        else:
            self._tracer = None
            self._meter = None

    # ---------------- Lifecycle ----------------

    async def start(self) -> None:
        headers = self._cfg.default_headers.copy() if self._cfg.default_headers else {}
        if self._cfg.token:
            headers["Authorization"] = f"Bearer {self._cfg.token}"

        # build httpx client
        self._client = httpx.AsyncClient(
            base_url=self._cfg.base_url.rstrip("/"),
            headers=headers,
            timeout=httpx.Timeout(
                timeout=self._cfg.timeout_seconds,
                connect=self._cfg.connect_timeout_seconds
            ),
            verify=self._cfg.verify_ssl,
        )

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ---------------- Public API ----------------

    async def evaluate(
        self,
        policy_path: str,
        input_obj: Dict[str, Any],
        *,
        explain: Optional[str] = None,  # "full"|"notes"|None (OPA explain)
        use_cache: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> EvaluationResult:
        """
        Evaluate data.<policy_path> with POST /v1/data/<policy_path>.

        Returns:
            EvaluationResult with `decision` if result looks like boolean.
            If not boolean, `decision` is None and raw_result contains payload.
        """
        if not self._client:
            raise PolicyEngineError("Evaluator not started. Call await start().")

        self._check_circuit()

        req_id = str(uuid.uuid4())
        start_ts = time.monotonic()

        # cache
        cache_key = None
        if use_cache:
            cache_key = self._cache_key(policy_path, input_obj, explain)
            cached = self._cache.get_with_ttl(cache_key)
            if cached:
                raw, ttl_left = cached
                decision = self._extract_boolean_decision(raw)
                latency_ms = (time.monotonic() - start_ts) * 1000.0
                self._metric_cache_hits += 1
                self._metric_evals_total += 1
                return EvaluationResult(
                    request_id=req_id,
                    policy_path=policy_path,
                    raw_result=raw,
                    decision=decision,
                    latency_ms=latency_ms,
                    from_cache=True,
                    cached_ttl_left_ms=ttl_left * 1000.0,
                    explain=explain
                )

        # request
        params = {}
        if explain in {"full", "notes"}:
            params["explain"] = explain

        body = {"input": input_obj}
        hdrs = (headers or {}).copy()

        self._log_request(req_id, policy_path, body, hdrs)

        async with self._span("pdp.evaluate", {"policy_path": policy_path}):
            async with self._sem:
                raw = await self._with_retries(
                    self._do_post_data,
                    policy_path,
                    body,
                    params,
                    hdrs,
                )

        latency_ms = (time.monotonic() - start_ts) * 1000.0
        self._metric_evals_total += 1
        self._metric_latency_sum_ms += latency_ms

        # check result
        if raw is None:
            self._record_failure()
            raise OPAProtocolError("OPA returned empty response.")

        # interpret & cache
        decision = self._extract_boolean_decision(raw)
        if use_cache and cache_key is not None:
            self._cache.set(cache_key, raw)

        self._record_success()
        self._log_result(req_id, policy_path, decision, raw, latency_ms)

        return EvaluationResult(
            request_id=req_id,
            policy_path=policy_path,
            raw_result=raw,
            decision=decision,
            latency_ms=latency_ms,
            from_cache=False,
            explain=explain
        )

    async def evaluate_boolean(
        self,
        policy_path: str,
        input_obj: Dict[str, Any],
        *,
        default: bool = False,
        **kwargs: Any
    ) -> bool:
        """
        Convenience for boolean policies (e.g., data.authz.allow).
        If returned value is not boolean, returns `default`.
        """
        res = await self.evaluate(policy_path, input_obj, **kwargs)
        if res.decision is None:
            return default
        return res.decision

    async def compile_partial(
        self,
        policy_path: str,
        input_obj: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Partial evaluation via /v1/compile.
        Returns OPA's structured partial result (queries & support).
        """
        if not self._client:
            raise PolicyEngineError("Evaluator not started. Call await start().")

        self._check_circuit()

        query = f"data.{policy_path}"
        body = {"query": query, "input": input_obj}
        req_id = str(uuid.uuid4())
        start_ts = time.monotonic()

        self._log_request(req_id, f"compile:{policy_path}", body, headers or {})

        async with self._span("pdp.compile_partial", {"policy_path": policy_path}):
            async with self._sem:
                raw = await self._with_retries(
                    self._do_post_compile,
                    body,
                    headers or {},
                )

        latency_ms = (time.monotonic() - start_ts) * 1000.0
        self._metric_evals_total += 1
        self._metric_latency_sum_ms += latency_ms

        if raw is None:
            self._record_failure()
            raise OPAProtocolError("OPA returned empty response for compile.")

        self._record_success()
        self._log_result(req_id, f"compile:{policy_path}", None, raw, latency_ms)
        return raw

    # ---------------- Internals ----------------

    async def _with_retries(self, fn, *args, **kwargs):
        """
        Run an async call with configured retries and jittered exponential backoff.
        """
        last_exc = None
        for attempt in range(self._cfg.retries + 1):
            try:
                return await fn(*args, **kwargs)
            except (httpx.TimeoutException, httpx.HTTPError) as e:
                last_exc = e
                self._logger.warning(
                    "OPA request failed (attempt %d/%d): %s",
                    attempt + 1, self._cfg.retries + 1, str(e)
                )
                self._record_failure()
                if attempt < self._cfg.retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                else:
                    break
            except PolicyEngineError as e:
                # Non-transient failures shouldn't be retried (e.g., 404 policy not found)
                self._record_failure()
                raise e
            except Exception as e:
                # Unknown error: treat as transient with retries
                last_exc = e
                self._record_failure()
                self._logger.exception("Unexpected error in OPA call.")
                if attempt < self._cfg.retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                else:
                    break

        raise OPAConnectionError(f"OPA request failed after retries: {last_exc}")

    def _backoff_delay(self, attempt: int) -> float:
        base = min(self._cfg.backoff_max, self._cfg.backoff_base * (2 ** attempt))
        # full jitter
        return random.uniform(0.0, base)

    def _cache_key(self, policy_path: str, input_obj: Dict[str, Any], explain: Optional[str]) -> str:
        parts = [
            policy_path.strip("."),
            _stable_dumps(input_obj),
            explain or "",
        ]
        return _hash_key(*parts)

    def _check_circuit(self) -> None:
        if self._circuit_open_until is None:
            return
        if time.monotonic() < self._circuit_open_until:
            raise CircuitOpen(
                f"Circuit open due to prior failures; retry after {round(self._circuit_open_until - time.monotonic(), 2)}s."
            )
        # reset window elapsed
        self._circuit_open_until = None
        self._fail_count = 0

    def _record_failure(self) -> None:
        self._fail_count += 1
        if self._fail_count >= self._cfg.circuit_fail_threshold:
            self._circuit_open_until = time.monotonic() + self._cfg.circuit_reset_seconds
            self._logger.error(
                "Circuit opened (failures=%d). Will reset in %ds.",
                self._fail_count, self._cfg.circuit_reset_seconds
            )

    def _record_success(self) -> None:
        self._fail_count = 0
        self._circuit_open_until = None

    def _extract_boolean_decision(self, raw: Any) -> Optional[bool]:
        """
        Attempts to interpret OPA's response as boolean decision.
        Supports:
            - {"result": true/false}
            - {"result": {"allow": true/false}}
            - {"result": [{"expressions": [{"value": true/false}, ...]}]} (explain/notes)
        Otherwise returns None.
        """
        try:
            if isinstance(raw, dict) and "result" in raw:
                r = raw["result"]
                if isinstance(r, bool):
                    return r
                if isinstance(r, dict):
                    # heuristics: prefer 'allow'/'deny'
                    for key in ("allow", "result", "decision", "permit"):
                        if key in r and isinstance(r[key], bool):
                            return r[key]
                if isinstance(r, list) and r and isinstance(r[0], dict):
                    # explain path may include expressions with boolean value
                    exprs = r[0].get("expressions")
                    if isinstance(exprs, list) and exprs:
                        val = exprs[0].get("value")
                        if isinstance(val, bool):
                            return val
        except Exception:
            return None
        return None

    # ---------------- HTTP calls ----------------

    async def _do_post_data(
        self,
        policy_path: str,
        body: Dict[str, Any],
        params: Dict[str, str],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        assert self._client is not None
        url_path = f"/v1/data/{policy_path.strip('/')}"
        try:
            resp = await self._client.post(url_path, json=body, params=params, headers=headers)
        except httpx.TimeoutException as e:
            raise OPAConnectionError(f"Timeout calling {url_path}") from e
        except httpx.HTTPError as e:
            raise OPAConnectionError(f"HTTP error calling {url_path}: {e}") from e

        if resp.status_code == 404:
            raise PolicyNotFound(f"Policy not found at path: {policy_path}")
        if resp.status_code == 400:
            # likely invalid input or bad query
            raise InvalidInput(f"OPA 400: {resp.text}")
        if resp.status_code >= 500:
            raise OPAConnectionError(f"OPA server error {resp.status_code}: {resp.text}")
        if resp.status_code not in (200, 201):
            raise OPAProtocolError(f"Unexpected status {resp.status_code}: {resp.text}")

        try:
            return resp.json()
        except Exception as e:
            raise OPAProtocolError("Failed to decode OPA JSON response.") from e

    async def _do_post_compile(
        self,
        body: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        assert self._client is not None
        url_path = "/v1/compile"
        try:
            resp = await self._client.post(url_path, json=body, headers=headers)
        except httpx.TimeoutException as e:
            raise OPAConnectionError(f"Timeout calling {url_path}") from e
        except httpx.HTTPError as e:
            raise OPAConnectionError(f"HTTP error calling {url_path}: {e}") from e

        if resp.status_code == 404:
            raise PolicyNotFound("Compile endpoint or referenced path not found.")
        if resp.status_code == 400:
            raise InvalidInput(f"OPA 400 during compile: {resp.text}")
        if resp.status_code >= 500:
            raise OPAConnectionError(f"OPA server error {resp.status_code}: {resp.text}")
        if resp.status_code not in (200, 201):
            raise OPAProtocolError(f"Unexpected status {resp.status_code}: {resp.text}")

        try:
            return resp.json()
        except Exception as e:
            raise OPAProtocolError("Failed to decode OPA JSON compile response.") from e

    # ---------------- Logging & Tracing ----------------

    def _log_request(self, req_id: str, policy_path: str, body: Dict[str, Any], headers: Dict[str, str]) -> None:
        try:
            hdrs = _mask_headers(headers) if self._cfg.mask_secrets else headers
            payload = body
            if self._cfg.mask_secrets:
                payload = _mask_secrets_in_payload(body)
            event = {
                "evt": "pdp_request",
                "ns": self._cfg.namespace,
                "ts": _utc_now().isoformat(),
                "req_id": req_id,
                "policy_path": policy_path,
                "headers": hdrs,
            }
            if self._cfg.log_decision_payloads:
                event["body"] = payload
            self._logger.info(_stable_dumps(event))
        except Exception:
            pass

    def _log_result(
        self,
        req_id: str,
        policy_path: str,
        decision: Optional[bool],
        raw: Any,
        latency_ms: float
    ) -> None:
        try:
            payload = raw
            if self._cfg.mask_secrets:
                payload = _mask_secrets_in_payload(raw)
            event = {
                "evt": "pdp_result",
                "ns": self._cfg.namespace,
                "ts": _utc_now().isoformat(),
                "req_id": req_id,
                "policy_path": policy_path,
                "decision": decision,
                "latency_ms": round(latency_ms, 2),
                "from_cache": False,
            }
            if self._cfg.log_decision_payloads:
                event["raw"] = payload
            self._logger.info(_stable_dumps(event))
        except Exception:
            pass

    @contextlib.asynccontextmanager
    async def _span(self, name: str, attrs: Optional[Dict[str, Any]] = None):
        if not _OTEL_AVAILABLE or self._tracer is None:  # pragma: no cover
            yield
            return
        span = self._tracer.start_span(name, kind=SpanKind.CLIENT if SpanKind else None)
        try:
            if attrs:
                for k, v in attrs.items():
                    try:
                        span.set_attribute(k, v)
                    except Exception:
                        pass
            yield
        finally:
            span.end()

    # ---------------- Metrics snapshot ----------------

    def snapshot_metrics(self) -> Dict[str, Union[int, float]]:
        """
        Return a shallow snapshot of internal counters. Useful for scraping.
        """
        avg_latency = (
            (self._metric_latency_sum_ms / self._metric_evals_total)
            if self._metric_evals_total > 0 else 0.0
        )
        return {
            "evals_total": self._metric_evals_total,
            "evals_errors": self._metric_evals_errors,
            "cache_hits": self._metric_cache_hits,
            "avg_latency_ms": round(avg_latency, 3),
            "circuit_open": 1 if self._circuit_open_until and time.monotonic() < self._circuit_open_until else 0,
            "failures_in_window": self._fail_count,
        }

# ---------------------------------------------------------------------------
# Example factory (kept minimal; not executed here)
# ---------------------------------------------------------------------------

def build_default_evaluator() -> RegoEvaluator:
    """
    Convenience builder honoring environment variables:
      OPA_BASE_URL, OPA_TOKEN, OPA_VERIFY_SSL (0/1), OPA_NAMESPACE
    """
    base_url = os.getenv("OPA_BASE_URL", "http://127.0.0.1:8181")
    token = os.getenv("OPA_TOKEN")
    verify = os.getenv("OPA_VERIFY_SSL", "1") != "0"
    namespace = os.getenv("OPA_NAMESPACE", "policy-core")
    cfg = PDPConfig(base_url=base_url, token=token, verify_ssl=verify, namespace=namespace)
    return RegoEvaluator(cfg)
