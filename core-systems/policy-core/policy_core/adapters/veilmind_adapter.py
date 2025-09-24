# -*- coding: utf-8 -*-
"""
VeilMind PDP Adapter for policy-core.

Industrial features:
- Async httpx client with strict timeouts and connection pooling
- Exponential backoff with jitter + bounded retries
- Circuit Breaker (open/half-open/closed) to avoid cascading failures
- TTL decision cache (keyed by tenant/subject/roles/action/path)
- Optional HMAC-SHA256 request signing (X-Signature)
- Correlation headers propagation (X-Request-ID / X-Correlation-ID)
- Structured audit logging (JSON) with reason & rule metadata
- Optional Prometheus metrics (graceful fallback)
- Health check endpoint probe

Compatibility:
- Returns `Decision` / `Effect` imported from policy_core.pep.middleware_http
- Implements `evaluate(ctx)` expected by PolicyEnforcementMiddleware

Author: Aethernova / NeuroCity policy-core
"""

from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# External (optional) deps
try:
    import httpx  # type: ignore
except Exception as _e:  # pragma: no cover
    httpx = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

# Import internal Decision/Effect for runtime compatibility with PEP
from policy_core.pep.middleware_http import Decision, Effect  # type: ignore

LOGGER = logging.getLogger("policy_core.adapters.veilmind")
LOGGER.setLevel(logging.INFO)


# ============================ Metrics ============================

class _Metrics:
    def __init__(self, ns: str, enabled: bool):
        self.enabled = enabled and (Counter is not None and Histogram is not None)
        if self.enabled:
            self.req_total = Counter(f"{ns}_requests_total", "Total VeilMind requests", ["op"])
            self.err_total = Counter(f"{ns}_errors_total", "VeilMind errors", ["op", "type"])
            self.decisions = Counter(f"{ns}_decisions_total", "VeilMind decisions", ["effect", "from_cache"])
            self.latency = Histogram(f"{ns}_latency_seconds", "VeilMind request latency", ["op"])
            self.cb_state = Counter(f"{ns}_circuit_events_total", "Circuit breaker events", ["state"])
            self.cache_hits = Counter(f"{ns}_cache_hits_total", "Adapter cache hits", ["op"])
            self.cache_miss = Counter(f"{ns}_cache_miss_total", "Adapter cache miss", ["op"])
        else:
            self.req_total = self.err_total = self.decisions = self.latency = self.cb_state = self.cache_hits = self.cache_miss = None

    def inc_req(self, op: str):
        if self.enabled:
            self.req_total.labels(op=op).inc()

    def inc_err(self, op: str, typ: str):
        if self.enabled:
            self.err_total.labels(op=op, type=typ).inc()

    def observe_latency(self, op: str, seconds: float):
        if self.enabled:
            self.latency.labels(op=op).observe(seconds)

    def decision(self, effect: Effect, from_cache: bool):
        if self.enabled:
            self.decisions.labels(effect=effect.value, from_cache=str(from_cache).lower()).inc()

    def cache(self, op: str, hit: bool):
        if self.enabled:
            (self.cache_hits if hit else self.cache_miss).labels(op=op).inc()

    def circuit(self, state: str):
        if self.enabled:
            self.cb_state.labels(state=state).inc()


# ============================ TTL Cache ============================

class _TTLCache:
    def __init__(self, max_entries: int, default_ttl: int):
        self._max = max_entries
        self._default_ttl = max(1, int(default_ttl))
        self._store: Dict[Any, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.monotonic()

    async def get(self, key: Any) -> Optional[Any]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            exp, val = rec
            if exp <= self._now():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: Any, value: Any, ttl: Optional[int] = None):
        async with self._lock:
            # Lazy prune
            if len(self._store) >= self._max:
                now = self._now()
                expired = [k for k, (e, _) in self._store.items() if e <= now]
                for k in expired:
                    self._store.pop(k, None)
                if len(self._store) >= self._max:
                    # Drop ~2%
                    for k in list(self._store.keys())[: max(1, self._max // 50)]:
                        self._store.pop(k, None)
            self._store[key] = (self._now() + (ttl or self._default_ttl), value)

    async def clear(self):  # pragma: no cover
        async with self._lock:
            self._store.clear()


# ============================ Circuit Breaker ============================

class _CircuitBreaker:
    """
    Simple in-process circuit breaker:
    - Closed: normal operation
    - Open: short-circuit calls for open_duration
    - Half-open: allow up to `half_open_probe` requests to test recovery
    """
    def __init__(self, failure_threshold: int, open_duration: float, half_open_probe: int):
        self.failure_threshold = max(1, failure_threshold)
        self.open_duration = max(0.1, open_duration)
        self.half_open_probe = max(1, half_open_probe)

        self._state = "closed"
        self._fail_count = 0
        self._opened_at = 0.0
        self._probe_count = 0
        self._lock = asyncio.Lock()

    async def on_success(self):
        async with self._lock:
            self._fail_count = 0
            if self._state != "closed":
                self._state = "closed"
                self._probe_count = 0

    async def on_failure(self):
        async with self._lock:
            self._fail_count += 1
            if self._state == "closed" and self._fail_count >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()
            elif self._state == "half_open":
                # failure during half-open -> re-open
                self._state = "open"
                self._opened_at = time.monotonic()
                self._probe_count = 0

    async def allow(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            if self._state == "open":
                if now - self._opened_at >= self.open_duration:
                    self._state = "half_open"
                    self._probe_count = 0
                else:
                    return False
            if self._state == "half_open":
                if self._probe_count >= self.half_open_probe:
                    return False
                self._probe_count += 1
                return True
            return True

    @property
    def state(self) -> str:
        return self._state


# ============================ Config ============================

@dataclass
class VeilMindConfig:
    base_url: str
    api_key: Optional[str] = None
    # Timeouts
    connect_timeout: float = 0.5
    read_timeout: float = 1.5
    # Retries/backoff
    max_retries: int = 3
    backoff_initial: float = 0.05
    backoff_max: float = 0.5
    # Cache
    cache_ttl_seconds: int = 5
    cache_max_entries: int = 5000
    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_open_seconds: float = 10.0
    cb_half_open_probe: int = 2
    # Security
    hmac_secret: Optional[str] = None
    hmac_header: str = "X-Signature"
    # Headers
    request_id_header: str = "X-Request-ID"
    correlation_header: str = "X-Correlation-ID"
    tenant_header: str = "X-Tenant"
    # Endpoints
    decision_path: str = "/v1/decision"
    health_path: str = "/v1/health"
    # Metrics
    metrics_namespace: str = "policy_core_veilmind"
    metrics_enabled: bool = True

    @staticmethod
    def from_env(prefix: str = "VEILMIND_") -> "VeilMindConfig":  # pragma: no cover
        def _get(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(prefix + name, default)
        def _get_float(name: str, default: float) -> float:
            v = os.getenv(prefix + name)
            return default if v is None else float(v)
        def _get_int(name: str, default: int) -> int:
            v = os.getenv(prefix + name)
            return default if v is None else int(v)
        def _get_bool(name: str, default: bool) -> bool:
            v = os.getenv(prefix + name)
            return default if v is None else v.lower() in ("1", "true", "yes", "on")

        return VeilMindConfig(
            base_url=_get("BASE_URL", "") or "",
            api_key=_get("API_KEY"),
            connect_timeout=_get_float("CONNECT_TIMEOUT", 0.5),
            read_timeout=_get_float("READ_TIMEOUT", 1.5),
            max_retries=_get_int("MAX_RETRIES", 3),
            backoff_initial=_get_float("BACKOFF_INITIAL", 0.05),
            backoff_max=_get_float("BACKOFF_MAX", 0.5),
            cache_ttl_seconds=_get_int("CACHE_TTL_SECONDS", 5),
            cache_max_entries=_get_int("CACHE_MAX_ENTRIES", 5000),
            cb_failure_threshold=_get_int("CB_FAILURE_THRESHOLD", 5),
            cb_open_seconds=_get_float("CB_OPEN_SECONDS", 10.0),
            cb_half_open_probe=_get_int("CB_HALF_OPEN_PROBE", 2),
            hmac_secret=_get("HMAC_SECRET"),
            hmac_header=_get("HMAC_HEADER", "X-Signature") or "X-Signature",
            request_id_header=_get("REQUEST_ID_HEADER", "X-Request-ID") or "X-Request-ID",
            correlation_header=_get("CORRELATION_HEADER", "X-Correlation-ID") or "X-Correlation-ID",
            tenant_header=_get("TENANT_HEADER", "X-Tenant") or "X-Tenant",
            decision_path=_get("DECISION_PATH", "/v1/decision") or "/v1/decision",
            health_path=_get("HEALTH_PATH", "/v1/health") or "/v1/health",
            metrics_namespace=_get("METRICS_NAMESPACE", "policy_core_veilmind") or "policy_core_veilmind",
            metrics_enabled=_get_bool("METRICS_ENABLED", True),
        )


# ============================ Adapter ============================

class VeilMindPDPAdapter:
    """
    PDP adapter to VeilMind.
    Expected VeilMind response JSON (example):
      {
        "effect": "permit" | "deny",
        "obligations": [ { ... } ],
        "ttl_seconds": 5,
        "reason": "rule_matched",
        "rule_id": "rule-123"
      }
    Unknown fields are ignored.
    """

    def __init__(self, cfg: VeilMindConfig):
        if httpx is None:
            raise RuntimeError("httpx is required for VeilMindPDPAdapter but is not installed.")
        self.cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url.rstrip("/"),
            timeout=httpx.Timeout(connect=cfg.connect_timeout, read=cfg.read_timeout, write=cfg.read_timeout),
            headers=self._default_headers(),
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=200, keepalive_expiry=30.0),
        )
        self._metrics = _Metrics(cfg.metrics_namespace, cfg.metrics_enabled)
        self._cache = _TTLCache(cfg.cache_max_entries, cfg.cache_ttl_seconds)
        self._cb = _CircuitBreaker(cfg.cb_failure_threshold, cfg.cb_open_seconds, cfg.cb_half_open_probe)

    # ---------- Public API ----------

    async def evaluate(self, ctx: Any) -> Decision:
        """
        Evaluate PDP decision using VeilMind.
        `ctx` is RequestContext from PEP (duck-typed).
        """
        # Extract attributes from ctx with safe fallbacks
        tenant = _get_attr(ctx, "tenant", default="default")
        subject = _get_attr(ctx, "subject", default={})
        action = _get_attr(ctx, "action", default={})
        resource = _get_attr(ctx, "resource", default={})
        environment = _get_attr(ctx, "environment", default={})

        subject_id = str(subject.get("id") or "anonymous")
        roles = list(subject.get("roles") or [])
        method = str(action.get("method") or "GET")
        path = str(resource.get("path") or "/")

        # Cache key aligned to PEP semantics
        cache_key = (tenant, subject_id, tuple(sorted(map(str, roles))), method, path)
        cached = await self._cache.get(cache_key)
        self._metrics.cache("decision", hit=cached is not None)
        if cached is not None:
            self._metrics.decision(cached.effect, from_cache=True)
            return cached

        # Circuit breaker gate
        if not await self._cb.allow():
            self._metrics.circuit("open_short_circuit")
            # Deny-by-default to honor Zero-Trust
            deny = Decision(effect=Effect.DENY, obligations=[], ttl_seconds=1,
                            reason="cb_open", rule_id=None)
            await self._cache.set(cache_key, deny, ttl=1)
            self._metrics.decision(deny.effect, from_cache=False)
            return deny

        # Build payload
        payload = {
            "tenant": tenant,
            "subject": subject,
            "action": action,
            "resource": resource,
            "environment": environment,
        }

        headers = {}
        # Correlation headers propagation
        req_id = str(environment.get("request_id") or environment.get("requestId") or "")
        corr_id = str(environment.get("correlation_id") or environment.get("correlationId") or req_id or "")
        if req_id:
            headers[self.cfg.request_id_header] = req_id
        if corr_id:
            headers[self.cfg.correlation_header] = corr_id
        if tenant:
            headers[self.cfg.tenant_header] = str(tenant)
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"

        # HMAC signature (optional)
        body_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self.cfg.hmac_secret:
            sig = hmac.new(self.cfg.hmac_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers[self.cfg.hmac_header] = sig

        # Perform request with retry/backoff
        op = "decision"
        self._metrics.inc_req(op)
        t0 = time.monotonic()
        try:
            resp_json = await self._request_with_retries("POST", self.cfg.decision_path, headers, body_bytes)
            self._metrics.observe_latency(op, time.monotonic() - t0)
            await self._cb.on_success()
        except Exception as e:
            self._metrics.inc_err(op, type(e).__name__)
            await self._cb.on_failure()
            # Fallback deny (Zero-Trust)
            deny = Decision(effect=Effect.DENY, obligations=[], ttl_seconds=1,
                            reason=f"pdp_error:{type(e).__name__}", rule_id=None)
            await self._cache.set(cache_key, deny, ttl=1)
            self._metrics.decision(deny.effect, from_cache=False)
            LOGGER.warning(json.dumps({
                "op": "decision_error",
                "type": type(e).__name__,
                "path": self.cfg.decision_path,
                "tenant": tenant,
                "subject_id": subject_id
            }, ensure_ascii=False))
            return deny

        # Map VeilMind -> Decision
        decision = self._map_decision(resp_json)
        # Cache with TTL from decision
        ttl = max(1, int(decision.ttl_seconds or self.cfg.cache_ttl_seconds))
        await self._cache.set(cache_key, decision, ttl=ttl)
        self._metrics.decision(decision.effect, from_cache=False)

        # Audit-log (no secrets)
        LOGGER.info(json.dumps({
            "type": "veilmind_decision",
            "effect": decision.effect.value,
            "tenant": tenant,
            "subject_id": subject_id,
            "roles": roles,
            "method": method,
            "path": path,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "ttl": ttl
        }, ensure_ascii=False))
        return decision

    async def health(self) -> bool:
        """Simple health check of VeilMind endpoint."""
        op = "health"
        self._metrics.inc_req(op)
        t0 = time.monotonic()
        try:
            r = await self._client.get(self.cfg.health_path, timeout=self._client.timeout)
            ok = r.status_code // 100 == 2
            self._metrics.observe_latency(op, time.monotonic() - t0)
            if not ok:
                self._metrics.inc_err(op, f"HTTP_{r.status_code}")
            return ok
        except Exception as e:  # pragma: no cover
            self._metrics.inc_err(op, type(e).__name__)
            return False

    async def aclose(self):
        try:
            await self._client.aclose()
        except Exception:  # pragma: no cover
            pass

    # ---------- Internals ----------

    async def _request_with_retries(self, method: str, path: str, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        retries = max(0, self.cfg.max_retries)
        delay = max(0.0, self.cfg.backoff_initial)
        last_exc: Optional[Exception] = None

        for attempt in range(retries + 1):
            try:
                r = await self._client.request(method, path, content=body, headers=headers)
                if r.status_code // 100 == 2:
                    return _safe_json(r)
                # Treat 4xx (except 429) as final; 5xx/429 retryable
                if r.status_code == 429 or r.status_code // 100 == 5:
                    raise _HTTPRetryableError(f"HTTP {r.status_code}")
                else:
                    raise _HTTPFatalError(f"HTTP {r.status_code}")
            except _HTTPFatalError:
                raise
            except Exception as e:
                last_exc = e
                if attempt >= retries:
                    break
                # Backoff with jitter
                await asyncio.sleep(_jitter(delay, self.cfg.backoff_max))
                delay = min(self.cfg.backoff_max, delay * 2 if delay > 0 else self.cfg.backoff_initial)
        assert last_exc is not None
        raise last_exc

    @staticmethod
    def _map_effect(val: Any) -> Effect:
        s = str(val or "").lower().strip()
        if s == "permit":
            return Effect.PERMIT
        return Effect.DENY

    def _map_decision(self, data: Dict[str, Any]) -> Decision:
        """
        Map VeilMind response into internal Decision.
        Unknown obligation types are passed through; PEP will ignore or handle them.
        """
        effect = self._map_effect(data.get("effect"))
        obligations = data.get("obligations") or []
        # Normalize obligations to list[dict]
        if not isinstance(obligations, list):
            obligations = []
        obligations = [o for o in obligations if isinstance(o, dict)]

        ttl = int(data.get("ttl_seconds") or self.cfg.cache_ttl_seconds)
        ttl = 1 if ttl <= 0 else ttl
        reason = data.get("reason")
        rule_id = data.get("rule_id")

        # Basic size guards
        if len(obligations) > 256:
            obligations = obligations[:256]
        # Shallow sanitize header obligations to strings (defensive)
        for o in obligations:
            if o.get("type") in ("add_response_headers", "inject_request_headers"):
                hdrs = o.get("headers") or {}
                if isinstance(hdrs, dict):
                    o["headers"] = {str(k): str(v) for k, v in hdrs.items() if _is_safe_header(k, v)}
                else:
                    o["headers"] = {}

        return Decision(effect=effect, obligations=obligations, ttl_seconds=ttl, reason=reason, rule_id=rule_id)

    def _default_headers(self) -> Dict[str, str]:
        h = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "policy-core/veilmind-adapter",
        }
        if self.cfg.api_key:
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        return h


# ============================ Utils ============================

class _HTTPRetryableError(RuntimeError):
    pass


class _HTTPFatalError(RuntimeError):
    pass


def _safe_json(resp: "httpx.Response") -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        # Fall back to empty to force DENY upstream
        return {}

def _jitter(base: float, max_cap: float) -> float:
    lo = 0.5 * base
    hi = 1.0 * base
    val = random.uniform(lo, hi)
    return min(max_cap, max(0.0, val))

def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)

def _is_safe_header(k: Any, v: Any) -> bool:
    # Basic defense-in-depth against CR/LF injection in headers
    try:
        ks = str(k)
        vs = str(v)
    except Exception:
        return False
    return ("\r" not in ks and "\n" not in ks and "\r" not in vs and "\n" not in vs)
