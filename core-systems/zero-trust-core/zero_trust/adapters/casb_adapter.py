# path: zero-trust-core/zero_trust/adapters/casb_adapter.py
# -*- coding: utf-8 -*-
"""
CASB Adapter for Zero-Trust Core
Industrial-grade, async, strongly-typed, resilient.

Key features:
- Async httpx client with timeouts and retries (exp backoff)
- Token-bucket rate limiter
- Simple circuit breaker
- Pydantic models for strict validation
- HMAC-SHA256 webhook signature verification
- TTL in-memory cache
- Redaction-safe, structured logging
- Metrics and tracing via lightweight Protocols (dependency injection)
- Health check, policy push/fetch, access evaluation, session control, incidents

Requirements:
- Python 3.11+
- httpx>=0.27
- pydantic>=2.6

This file contains no external side effects and can be safely imported.
"""

from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union, runtime_checkable

try:
    import httpx
except Exception as e:  # pragma: no cover
    raise ImportError("httpx is required: pip install httpx>=0.27") from e

try:
    from pydantic import BaseModel, Field, HttpUrl, ValidationError, model_validator
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic v2 is required: pip install pydantic>=2.6") from e


__all__ = [
    "CASBError",
    "CASBAuthError",
    "CASBRateLimitError",
    "CASBConfigError",
    "CASBWebhookError",
    "CASBCircuitOpenError",
    "CASBConfig",
    "AccessContext",
    "AccessRequest",
    "AccessDecision",
    "PolicyRule",
    "Policy",
    "Session",
    "Incident",
    "DevicePosture",
    "WebhookEvent",
    "Metrics",
    "Tracer",
    "CASBAdapter",
    "GenericRESTCASBAdapter",
]

# ------------------------- Logging setup -------------------------

_LOG = logging.getLogger("zero_trust.casb_adapter")
if not _LOG.handlers:
    _handler = logging.StreamHandler()
    _formatter = logging.Formatter(
        fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)s}',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    _handler.setFormatter(_formatter)
    _LOG.addHandler(_handler)
_LOG.setLevel(logging.INFO)


def _j(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return json.dumps({"repr": repr(obj)}, ensure_ascii=False)


def _redact(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


# ------------------------- Exceptions -------------------------

class CASBError(RuntimeError):
    pass


class CASBAuthError(CASBError):
    pass


class CASBRateLimitError(CASBError):
    pass


class CASBConfigError(CASBError):
    pass


class CASBWebhookError(CASBError):
    pass


class CASBCircuitOpenError(CASBError):
    pass


# ------------------------- Config -------------------------

class CASBConfig(BaseModel):
    base_url: HttpUrl
    api_version: str = Field(default="v1")
    tenant_id: Optional[str] = None

    # Auth
    api_token: Optional[str] = None
    oauth_token: Optional[str] = None  # if CASB uses OAuth2 bearer
    webhook_secret: Optional[str] = None

    # HTTP client
    timeout_sec: float = Field(default=15.0, ge=1.0, le=120.0)
    verify_ssl: bool = True
    proxies: Optional[Dict[str, str]] = None
    extra_headers: Dict[str, str] = Field(default_factory=dict)

    # Resilience
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_factor: float = Field(default=0.5, ge=0.0, le=8.0)
    retry_statuses: Tuple[int, ...] = (408, 429, 500, 502, 503, 504)

    # Rate limiting (token bucket per adapter instance)
    rate_limit_per_minute: int = Field(default=600, ge=1, le=100000)

    # Circuit breaker
    cb_fail_threshold: int = Field(default=8, ge=1, le=1000)
    cb_recovery_time_sec: float = Field(default=30.0, ge=1.0, le=3600.0)

    # Caching
    cache_ttl_sec: float = Field(default=15.0, ge=0.0, le=3600.0)

    @model_validator(mode="after")
    def _validate_auth(self) -> "CASBConfig":
        if not (self.api_token or self.oauth_token):
            # Allow unauth for some endpoints, but warn
            _LOG.warning(_j({"event": "config_unauth", "msg": "No API/OAuth token configured; some endpoints may fail"}))
        return self

    @classmethod
    def from_env(cls, prefix: str = "CASB_") -> "CASBConfig":
        def g(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(prefix + name, default)

        # Base URL is required
        base = g("BASE_URL")
        if not base:
            raise CASBConfigError("Missing CASB_BASE_URL environment variable")

        cfg = cls(
            base_url=base,
            api_version=g("API_VERSION", "v1"),
            tenant_id=g("TENANT_ID") or None,
            api_token=g("API_TOKEN") or None,
            oauth_token=g("OAUTH_TOKEN") or None,
            webhook_secret=g("WEBHOOK_SECRET") or None,
            timeout_sec=float(g("TIMEOUT_SEC", "15")),
            verify_ssl=(g("VERIFY_SSL", "true").lower() == "true"),
            max_retries=int(g("MAX_RETRIES", "3")),
            backoff_factor=float(g("BACKOFF_FACTOR", "0.5")),
            rate_limit_per_minute=int(g("RATE_LIMIT_PER_MINUTE", "600")),
            cb_fail_threshold=int(g("CB_FAIL_THRESHOLD", "8")),
            cb_recovery_time_sec=float(g("CB_RECOVERY_TIME_SEC", "30")),
            cache_ttl_sec=float(g("CACHE_TTL_SEC", "15")),
        )
        # Optional proxies, headers via JSON
        proxies_json = g("PROXIES_JSON")
        if proxies_json:
            try:
                cfg.proxies = json.loads(proxies_json)
            except Exception as e:
                raise CASBConfigError(f"Invalid PROXIES_JSON: {e}") from e
        headers_json = g("EXTRA_HEADERS_JSON")
        if headers_json:
            try:
                cfg.extra_headers = json.loads(headers_json)
            except Exception as e:
                raise CASBConfigError(f"Invalid EXTRA_HEADERS_JSON: {e}") from e
        return cfg


# ------------------------- Domain Models -------------------------

class AccessContext(BaseModel):
    user_id: str = Field(min_length=1)
    device_id: Optional[str] = None
    ip: Optional[str] = None
    location: Optional[str] = None
    roles: Sequence[str] = Field(default_factory=list)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)


class AccessRequest(BaseModel):
    resource: str = Field(min_length=1)
    action: str = Field(min_length=1)  # e.g., "read", "write", "download"
    context: AccessContext


class AccessDecision(BaseModel):
    allow: bool
    reason: str
    obligations: Dict[str, Any] = Field(default_factory=dict)
    ttl_sec: Optional[float] = Field(default=None, ge=0.0)


class PolicyRule(BaseModel):
    id: str
    description: Optional[str] = None
    condition: Dict[str, Any] = Field(default_factory=dict)
    effect: str = Field(pattern="^(allow|deny)$")
    obligations: Dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    id: str
    name: str
    version: int = Field(ge=1)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rules: Sequence[PolicyRule] = Field(default_factory=list)


class Session(BaseModel):
    id: str
    user_id: str
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    ip: Optional[str] = None
    device_id: Optional[str] = None
    status: str = Field(pattern="^(active|blocked|revoked)$")


class Incident(BaseModel):
    id: str
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    category: str
    detected_at: datetime
    subject_user: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class DevicePosture(BaseModel):
    device_id: str
    posture: Dict[str, Any]
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WebhookEvent(BaseModel):
    id: str
    type: str
    created_at: datetime
    payload: Dict[str, Any] = Field(default_factory=dict)


# ------------------------- Metrics / Tracing Protocols -------------------------

@runtime_checkable
class Metrics(Protocol):
    def increment(self, name: str, tags: Optional[Mapping[str, str]] = None, value: int = 1) -> None: ...
    def observe(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None: ...
    def gauge(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None: ...


@runtime_checkable
class Tracer(Protocol):
    @asynccontextmanager
    async def span(self, name: str, **kwargs: Any):  # type: ignore[override]
        yield


# ------------------------- Rate Limiter (Token Bucket) -------------------------

class _TokenBucket:
    def __init__(self, rate_per_min: int) -> None:
        self.capacity = float(rate_per_min)
        self.tokens = float(rate_per_min)
        self.fill_rate = float(rate_per_min) / 60.0
        self.timestamp = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delta = now - self.timestamp
            self.timestamp = now
            self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
            if self.tokens < 1.0:
                # wait for one token
                wait_time = (1.0 - self.tokens) / self.fill_rate
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


# ------------------------- Circuit Breaker -------------------------

class _CircuitBreaker:
    def __init__(self, fail_threshold: int, recovery_time_sec: float) -> None:
        self.fail_threshold = fail_threshold
        self.recovery_time_sec = recovery_time_sec
        self.fail_count = 0
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def on_success(self) -> None:
        async with self._lock:
            self.fail_count = 0
            self.opened_at = None

    async def on_failure(self) -> None:
        async with self._lock:
            self.fail_count += 1
            if self.fail_count >= self.fail_threshold and self.opened_at is None:
                self.opened_at = time.monotonic()

    async def ensure_closed(self) -> None:
        async with self._lock:
            if self.opened_at is None:
                return
            elapsed = time.monotonic() - self.opened_at
            if elapsed >= self.recovery_time_sec:
                # half-open trial: reset counters but keep window notionally open
                self.fail_count = 0
                self.opened_at = None
            else:
                raise CASBCircuitOpenError("Circuit breaker is open, try later")


# ------------------------- TTL Cache -------------------------

class _TTLCache:
    def __init__(self, ttl_sec: float) -> None:
        self.ttl = ttl_sec
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            ts, val = item
            if (time.monotonic() - ts) > self.ttl:
                self._data.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            self._data[key] = (time.monotonic(), value)

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()


# ------------------------- Adapter Interface -------------------------

class CASBAdapter(ABC):
    """
    Abstract adapter for CASB integration
    """

    @abstractmethod
    async def health_check(self) -> bool: ...

    @abstractmethod
    async def evaluate_access(self, req: AccessRequest) -> AccessDecision: ...

    @abstractmethod
    async def push_policy(self, policy: Policy) -> Policy: ...

    @abstractmethod
    async def fetch_policies(self, updated_after: Optional[datetime] = None) -> Sequence[Policy]: ...

    @abstractmethod
    async def get_user_sessions(self, user_id: str) -> Sequence[Session]: ...

    @abstractmethod
    async def block_session(self, session_id: str, reason: str) -> None: ...

    @abstractmethod
    async def allow_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def fetch_incidents(self, severity: Optional[str] = None, limit: int = 100) -> Sequence[Incident]: ...

    @abstractmethod
    async def submit_device_posture(self, posture: DevicePosture) -> None: ...

    @abstractmethod
    def handle_webhook(self, payload: bytes, headers: Mapping[str, str]) -> WebhookEvent: ...

    @abstractmethod
    async def close(self) -> None: ...


# ------------------------- Generic REST CASB Adapter -------------------------

class GenericRESTCASBAdapter(CASBAdapter):
    """
    A generic RESTful CASB adapter that can be configured via CASBConfig.
    Expects a vendor API with endpoints similar to:
      - GET  /{api_version}/health
      - POST /{api_version}/access/evaluate
      - GET  /{api_version}/policies
      - POST /{api_version}/policies
      - GET  /{api_version}/sessions?user_id=...
      - POST /{api_version}/sessions/{id}:block
      - POST /{api_version}/sessions/{id}:allow
      - GET  /{api_version}/incidents
      - POST /{api_version}/devices/posture
    Adjust using extra_headers / tenant_id when necessary.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: CASBConfig,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self.tracer = tracer
        self._client = client
        self._own_client = client is None
        self._bucket = _TokenBucket(config.rate_limit_per_minute)
        self._circuit = _CircuitBreaker(config.cb_fail_threshold, config.cb_recovery_time_sec)
        self._cache = _TTLCache(config.cache_ttl_sec)

    # --------------------- Lifecycle ---------------------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: Dict[str, str] = {
                "Accept": "application/json",
                "User-Agent": f"zero-trust-core-casb-adapter/{self.VERSION}",
                **self.config.extra_headers,
            }
            if self.config.api_token:
                headers["Authorization"] = f"ApiToken {self.config.api_token}"
            if self.config.oauth_token:
                headers["Authorization"] = f"Bearer {self.config.oauth_token}"
            self._client = httpx.AsyncClient(
                base_url=str(self.config.base_url),
                timeout=httpx.Timeout(self.config.timeout_sec),
                verify=self.config.verify_ssl,
                headers=headers,
                proxies=self.config.proxies,
            )
        return self._client

    async def close(self) -> None:
        if self._client and self._own_client:
            await self._client.aclose()
            self._client = None

    # --------------------- Request helper with resilience ---------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        cache_key: Optional[str] = None,
        retry_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        await self._bucket.acquire()
        await self._circuit.ensure_closed()

        if cache_key:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                if self.metrics:
                    self.metrics.increment("casb.cache_hit", {"path": path})
                return cached

        client = await self._ensure_client()
        retries = self.config.max_retries if retry_override is None else retry_override

        last_err: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                t0 = time.perf_counter()
                resp = await client.request(
                    method=method,
                    url=f"/{self.config.api_version}{path}",
                    params=dict(params or {}),
                    json=json_body,
                )
                dt = time.perf_counter() - t0
                if self.metrics:
                    self.metrics.observe("casb.http_latency_sec", dt, {"method": method, "path": path})
                if 200 <= resp.status_code < 300:
                    data = resp.json()
                    await self._circuit.on_success()
                    if cache_key:
                        await self._cache.set(cache_key, data)
                    return data
                if resp.status_code == 401 or resp.status_code == 403:
                    await self._circuit.on_failure()
                    raise CASBAuthError(f"Unauthorized/Forbidden: {resp.status_code}")
                if resp.status_code == 429:
                    await self._circuit.on_failure()
                    if self.metrics:
                        self.metrics.increment("casb.http_429", {"path": path})
                    raise CASBRateLimitError("CASB rate limited (HTTP 429)")
                if resp.status_code in self.config.retry_statuses and attempt < retries:
                    await self._circuit.on_failure()
                    backoff = self.config.backoff_factor * (2 ** attempt)
                    await asyncio.sleep(backoff)
                    continue
                # Non-retryable
                await self._circuit.on_failure()
                raise CASBError(f"HTTP {resp.status_code}: {resp.text}")
            except CASBError as e:
                last_err = e
                if attempt >= retries:
                    break
            except httpx.HTTPError as e:
                last_err = e
                await self._circuit.on_failure()
                if attempt >= retries:
                    break
                backoff = self.config.backoff_factor * (2 ** attempt)
                await asyncio.sleep(backoff)

        assert last_err is not None
        _LOG.error(_j({"event": "request_failed", "path": path, "error": repr(last_err)}))
        if self.metrics:
            self.metrics.increment("casb.request_failed", {"path": path})
        raise last_err

    # --------------------- Public API ---------------------

    async def health_check(self) -> bool:
        try:
            data = await self._request("GET", "/health", cache_key="health")
            ok = bool(data.get("ok", False))
            if self.metrics:
                self.metrics.gauge("casb.health", 1.0 if ok else 0.0)
            return ok
        except Exception as e:
            if self.metrics:
                self.metrics.gauge("casb.health", 0.0)
            _LOG.warning(_j({"event": "health_check_failed", "error": repr(e)}))
            return False

    async def evaluate_access(self, req: AccessRequest) -> AccessDecision:
        payload = req.model_dump(mode="json")
        data = await self._request("POST", "/access/evaluate", json_body=payload)
        try:
            decision = AccessDecision(**data)
        except ValidationError as ve:
            _LOG.error(_j({"event": "decision_validation_failed", "error": str(ve)}))
            raise CASBError("Invalid decision payload from CASB") from ve
        # Safe audit log
        _LOG.info(_j({
            "event": "access_decision",
            "resource": req.resource,
            "action": req.action,
            "user_id": req.context.user_id,
            "device_id": _redact(req.context.device_id),
            "allow": decision.allow,
            "reason": decision.reason,
        }))
        if decision.ttl_sec and decision.ttl_sec > 0:
            # optional cache (per resource/action/user)
            key = f"decision:{req.context.user_id}:{req.resource}:{req.action}"
            await self._cache.set(key, decision.model_dump(mode="json"))
        return decision

    async def push_policy(self, policy: Policy) -> Policy:
        payload = policy.model_dump(mode="json")
        data = await self._request("POST", "/policies", json_body=payload)
        try:
            return Policy(**data)
        except ValidationError as ve:
            raise CASBError("Invalid policy payload returned by CASB") from ve

    async def fetch_policies(self, updated_after: Optional[datetime] = None) -> Sequence[Policy]:
        params: Dict[str, Any] = {}
        if updated_after:
            params["updated_after"] = updated_after.astimezone(timezone.utc).isoformat()
        data = await self._request("GET", "/policies", params=params, cache_key="policies")
        items = data.get("items", [])
        policies: list[Policy] = []
        for raw in items:
            try:
                policies.append(Policy(**raw))
            except ValidationError:
                _LOG.warning(_j({"event": "policy_skip_invalid"}))
        return policies

    async def get_user_sessions(self, user_id: str) -> Sequence[Session]:
        params = {"user_id": user_id}
        data = await self._request("GET", "/sessions", params=params)
        items = data.get("items", [])
        sessions: list[Session] = []
        for raw in items:
            try:
                sessions.append(Session(**raw))
            except ValidationError:
                _LOG.warning(_j({"event": "session_skip_invalid"}))
        return sessions

    async def block_session(self, session_id: str, reason: str) -> None:
        await self._request("POST", f"/sessions/{session_id}:block", json_body={"reason": reason})

    async def allow_session(self, session_id: str) -> None:
        await self._request("POST", f"/sessions/{session_id}:allow")

    async def fetch_incidents(self, severity: Optional[str] = None, limit: int = 100) -> Sequence[Incident]:
        params: Dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        data = await self._request("GET", "/incidents", params=params)
        items = data.get("items", [])
        incidents: list[Incident] = []
        for raw in items:
            try:
                incidents.append(Incident(**raw))
            except ValidationError:
                _LOG.warning(_j({"event": "incident_skip_invalid"}))
        return incidents

    async def submit_device_posture(self, posture: DevicePosture) -> None:
        await self._request("POST", "/devices/posture", json_body=posture.model_dump(mode="json"))

    # --------------------- Webhook ---------------------

    def handle_webhook(self, payload: bytes, headers: Mapping[str, str]) -> WebhookEvent:
        """
        Verify HMAC signature and parse event.
        Expect headers:
            X-CASB-Event-Id
            X-CASB-Event-Type
            X-CASB-Signature: sha256=<hex>
            X-CASB-Timestamp: RFC3339 or epoch
        """
        secret = self.config.webhook_secret
        if not secret:
            raise CASBConfigError("Missing webhook secret")
        sig = headers.get("X-CASB-Signature")
        if not sig or not sig.startswith("sha256="):
            raise CASBWebhookError("Missing/invalid signature header")

        expected = hmac.new(
            key=secret.encode("utf-8"),
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()

        provided = sig.split("=", 1)[1]
        if not hmac.compare_digest(expected, provided):
            raise CASBWebhookError("Signature verification failed")

        try:
            body = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise CASBWebhookError(f"Invalid JSON payload: {e}") from e

        event_id = headers.get("X-CASB-Event-Id") or body.get("id") or ""
        event_type = headers.get("X-CASB-Event-Type") or body.get("type") or "unknown"
        ts_hdr = headers.get("X-CASB-Timestamp")
        created_at = datetime.now(timezone.utc)
        if ts_hdr:
            try:
                if ts_hdr.isdigit():
                    created_at = datetime.fromtimestamp(int(ts_hdr), tz=timezone.utc)
                else:
                    created_at = datetime.fromisoformat(ts_hdr.replace("Z", "+00:00"))
            except Exception:
                # keep current time if parsing fails
                pass

        evt = WebhookEvent(id=event_id or f"evt_{int(time.time()*1000)}", type=event_type, created_at=created_at, payload=body)

        # Safe audit log
        _LOG.info(_j({
            "event": "webhook_received",
            "id": evt.id,
            "type": evt.type,
            "ts": evt.created_at.isoformat(),
        }))
        if self.metrics:
            self.metrics.increment("casb.webhook_received", {"type": evt.type})
        return evt

    # --------------------- Utilities ---------------------

    def _tenantize(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = dict(params or {})
        if self.config.tenant_id and "tenant_id" not in p:
            p["tenant_id"] = self.config.tenant_id
        return p
