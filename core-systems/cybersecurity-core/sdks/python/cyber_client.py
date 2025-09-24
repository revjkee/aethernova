# cybersecurity-core/sdks/python/cyber_client.py
# -*- coding: utf-8 -*-
"""
Industrial-grade asynchronous SDK client for Aethernova cybersecurity-core.

Features:
- Async HTTP client (httpx) with robust timeouts
- Pluggable authentication strategies (API key / Bearer token / custom)
- Structured JSON logging, correlation IDs
- Optional OpenTelemetry tracing (auto-detected)
- Exponential backoff with jitter (retry policy)
- Circuit breaker (rolling) to protect upstream
- Local token-bucket rate limiting
- Idempotency keys for mutating requests
- Pydantic models (v2 with graceful fallback to v1) for strict typing
- Unified error model with rich context
- Cursor/page pagination helpers
- Extensible resource clients: ThreatIntel, Incidents, IDS, EDR

Dependencies:
    httpx>=0.25
    pydantic>=1.10 (v2 preferred; v1 fallback supported)
Optional:
    opentelemetry-api, opentelemetry-sdk (auto-detected)

This file is self-contained and production-ready.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import httpx

# --- Pydantic import with v2/v1 compatibility --------------------------------
try:
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
    from pydantic import __version__ as _pyd_ver  # type: ignore

    PydanticV2 = _pyd_ver.startswith("2.")
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, ValidationError  # type: ignore

    PydanticV2 = False

# --- Optional OpenTelemetry ---------------------------------------------------
try:
    from opentelemetry import trace  # type: ignore

    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore


# --- Logging ------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach extra fields if present
        for key in ("correlation_id", "component", "event", "http_status", "retry_in_ms"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str = "cyber_sdk") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(os.getenv("CYBER_SDK_LOG_LEVEL", "INFO"))
    return logger


logger = get_logger()


# --- Errors -------------------------------------------------------------------
class CyberError(Exception):
    """Base error for the SDK."""

    def __init__(self, message: str, *, context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message)
        self.context = dict(context or {})


class AuthError(CyberError):
    pass


class HTTPError(CyberError):
    def __init__(self, message: str, status_code: int, *, response_text: str = "", context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message, context=context)
        self.status_code = status_code
        self.response_text = response_text


class CircuitOpenError(CyberError):
    pass


class RateLimitError(CyberError):
    pass


class ModelValidationError(CyberError):
    def __init__(self, message: str, *, validation_error: Optional[ValidationError] = None, context: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(message, context=context)
        self.validation_error = validation_error


# --- Auth strategies ----------------------------------------------------------
class AuthStrategy:
    """Apply auth to headers in-place."""

    def apply(self, headers: MutableMapping[str, str]) -> None:
        raise NotImplementedError


class ApiKeyAuth(AuthStrategy):
    def __init__(self, api_key: str, header_name: str = "X-API-Key") -> None:
        if not api_key:
            raise AuthError("API key is empty")
        self.api_key = api_key
        self.header_name = header_name

    def apply(self, headers: MutableMapping[str, str]) -> None:
        headers[self.header_name] = self.api_key


class BearerTokenAuth(AuthStrategy):
    def __init__(self, token: str) -> None:
        if not token:
            raise AuthError("Bearer token is empty")
        self.token = token

    def apply(self, headers: MutableMapping[str, str]) -> None:
        headers["Authorization"] = f"Bearer {self.token}"


class CompositeAuth(AuthStrategy):
    """Chain multiple strategies."""

    def __init__(self, strategies: Sequence[AuthStrategy]) -> None:
        self._strategies = list(strategies)

    def apply(self, headers: MutableMapping[str, str]) -> None:
        for s in self._strategies:
            s.apply(headers)


# --- Retry policy -------------------------------------------------------------
@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 100
    max_delay_ms: int = 5_000
    multiplier: float = 2.0
    jitter_ms: int = 50
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)

    def compute_delay_ms(self, attempt: int) -> int:
        from random import randint

        if attempt <= 1:
            backoff = self.base_delay_ms
        else:
            backoff = min(int(self.base_delay_ms * (self.multiplier ** (attempt - 1))), self.max_delay_ms)
        return backoff + randint(0, self.jitter_ms)

    def should_retry(self, attempt: int, status_code: Optional[int], exc: Optional[Exception]) -> bool:
        if attempt >= self.max_attempts:
            return False
        if exc is not None:
            return True
        if status_code is None:
            return False
        return status_code in self.retry_on_status


# --- Circuit breaker ----------------------------------------------------------
class CircuitBreaker:
    """Simple rolling circuit breaker."""

    def __init__(self, failure_threshold: int = 5, recovery_time_s: int = 30, success_threshold: int = 2) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_time_s = recovery_time_s
        self.success_threshold = success_threshold
        self._state = "closed"  # closed, open, half-open
        self._failures = 0
        self._successes = 0
        self._opened_at: Optional[float] = None

    def allow(self) -> bool:
        now = time.time()
        if self._state == "open":
            if self._opened_at is not None and now - self._opened_at >= self.recovery_time_s:
                self._state = "half-open"
                self._successes = 0
                self._failures = 0
                return True
            return False
        return True

    def record_success(self) -> None:
        if self._state == "half-open":
            self._successes += 1
            if self._successes >= self.success_threshold:
                self._state = "closed"
                self._failures = 0
                self._successes = 0
        else:
            self._failures = 0

    def record_failure(self) -> None:
        if self._state == "half-open":
            self._state = "open"
            self._opened_at = time.time()
            self._failures = 1
            self._successes = 0
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._state = "open"
            self._opened_at = time.time()

    @property
    def state(self) -> str:
        return self._state


# --- Token bucket rate limiter ------------------------------------------------
class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            # need to wait
            deficit = tokens - self._tokens
            wait_s = deficit / self.rate
            await asyncio.sleep(wait_s)
            await self._refill()
            self._tokens -= tokens

    async def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)


# --- Core config --------------------------------------------------------------
class TLSConfig(BaseModel):
    verify: bool = True
    ca_bundle: Optional[str] = None  # path to custom CA bundle
    # Note: httpx does not expose SPKI pinning hooks directly; certificate pinning is out of scope here.
    # Provide ca_bundle for private PKI or mTLS context externally if required.


class ClientConfig(BaseModel):
    base_url: str
    timeout_s: float = 15.0
    user_agent: str = "Aethernova-CyberSDK/1.0"
    default_headers: Dict[str, str] = Field(default_factory=dict)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    circuit_breaker: Optional[Dict[str, int]] = Field(default_factory=lambda: {"failure_threshold": 5, "recovery_time_s": 30, "success_threshold": 2})
    rate_limit: Optional[Dict[str, float]] = Field(default_factory=lambda: {"rate_per_sec": 10.0, "burst": 20})
    tls: TLSConfig = Field(default_factory=TLSConfig)
    proxies: Optional[Mapping[str, str]] = None
    enable_tracing: bool = True

    @classmethod
    def from_env(cls) -> "ClientConfig":
        base = os.getenv("CYBER_BASE_URL", "").strip()
        if not base:
            raise ValueError("CYBER_BASE_URL is not set")
        return cls(
            base_url=base,
            timeout_s=float(os.getenv("CYBER_TIMEOUT_S", "15")),
            user_agent=os.getenv("CYBER_USER_AGENT", "Aethernova-CyberSDK/1.0"),
        )


# --- Models (minimal, extensible) --------------------------------------------
class ProblemDetails(BaseModel):
    type: Optional[str] = None
    title: Optional[str] = None
    status: Optional[int] = None
    detail: Optional[str] = None
    instance: Optional[str] = None
    trace_id: Optional[str] = None


class PageMeta(BaseModel):
    next_cursor: Optional[str] = None
    prev_cursor: Optional[str] = None
    total: Optional[int] = None


class ListResponse(BaseModel):
    items: List[Any]
    page: Optional[PageMeta] = None


# Threat intelligence indicator example
class TIIndicator(BaseModel):
    id: Optional[str] = None
    type: str
    value: str
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class Incident(BaseModel):
    id: Optional[str] = None
    title: str
    severity: str  # e.g., low, medium, high, critical
    status: str  # e.g., open, in_progress, resolved
    description: Optional[str] = None
    assignee: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class IDSAlert(BaseModel):
    id: Optional[str] = None
    rule: str
    src_ip: str
    dst_ip: str
    severity: str
    ts: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EDRAction(BaseModel):
    id: Optional[str] = None
    host: str
    action: str  # e.g., isolate, kill_process, quarantine
    status: Optional[str] = None
    requested_by: Optional[str] = None
    created_at: Optional[str] = None


# --- Utilities ----------------------------------------------------------------
T = TypeVar("T", bound=BaseModel)


def _gen_idempotency_key() -> str:
    return str(uuid.uuid4())


def _merge_headers(base: Mapping[str, str], extra: Optional[Mapping[str, str]]) -> Dict[str, str]:
    merged = dict(base)
    if extra:
        merged.update({k: v for k, v in extra.items() if v is not None})
    return merged


# --- AsyncCyberClient ---------------------------------------------------------
class AsyncCyberClient:
    """
    Core async client with resilience, logging and tracing.
    """

    def __init__(
        self,
        config: ClientConfig,
        auth: Optional[AuthStrategy] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        self.config = config
        self.auth = auth
        self.correlation_id = correlation_id or str(uuid.uuid4())

        # Timeouts
        timeouts = httpx.Timeout(timeout=config.timeout_s)

        # SSL context if custom CA
        verify: Union[bool, str, ssl.SSLContext]
        if config.tls.ca_bundle:
            verify = config.tls.ca_bundle
        else:
            verify = config.tls.verify

        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=timeouts,
            headers={"User-Agent": config.user_agent, **config.default_headers},
            verify=verify,
            proxies=config.proxies,  # type: ignore
        )

        # Circuit breaker
        self._cb = None  # type: Optional[CircuitBreaker]
        if config.circuit_breaker:
            self._cb = CircuitBreaker(
                failure_threshold=int(config.circuit_breaker.get("failure_threshold", 5)),
                recovery_time_s=int(config.circuit_breaker.get("recovery_time_s", 30)),
                success_threshold=int(config.circuit_breaker.get("success_threshold", 2)),
            )

        # Rate limiter
        self._rl = None  # type: Optional[TokenBucket]
        if config.rate_limit:
            self._rl = TokenBucket(
                rate_per_sec=float(config.rate_limit.get("rate_per_sec", 10.0)),
                burst=int(config.rate_limit.get("burst", 20)),
            )

        # Tracing flag
        self._tracing_enabled = bool(config.enable_tracing and _tracer is not None)

    # --- Context management ---------------------------------------------------
    async def __aenter__(self) -> "AsyncCyberClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- Public request API ---------------------------------------------------
    async def get(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        expect: Tuple[int, ...] = (200,),
    ) -> httpx.Response:
        return await self._request("GET", path, params=params, headers=headers, expect=expect)

    async def delete(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        expect: Tuple[int, ...] = (200, 204),
    ) -> httpx.Response:
        return await self._request("DELETE", path, params=params, headers=headers, expect=expect)

    async def post(
        self,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        expect: Tuple[int, ...] = (200, 201, 202),
    ) -> httpx.Response:
        return await self._request(
            "POST",
            path,
            json=json_body,
            data=data,
            headers=headers,
            idempotency_key=idempotency_key,
            expect=expect,
        )

    async def put(
        self,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        expect: Tuple[int, ...] = (200, 201),
    ) -> httpx.Response:
        return await self._request(
            "PUT",
            path,
            json=json_body,
            headers=headers,
            idempotency_key=idempotency_key,
            expect=expect,
        )

    async def patch(
        self,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        expect: Tuple[int, ...] = (200, 204),
    ) -> httpx.Response:
        return await self._request(
            "PATCH",
            path,
            json=json_body,
            headers=headers,
            idempotency_key=idempotency_key,
            expect=expect,
        )

    # --- Low-level request with resilience -----------------------------------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        expect: Tuple[int, ...] = (200,),
    ) -> httpx.Response:
        retry = self.config.retry

        # apply auth and common headers
        req_headers: Dict[str, str] = {}
        if self.auth:
            self.auth.apply(req_headers)
        req_headers["X-Correlation-ID"] = self.correlation_id
        if idempotency_key is None and method in ("POST", "PUT", "PATCH"):
            req_headers["Idempotency-Key"] = _gen_idempotency_key()
        elif idempotency_key:
            req_headers["Idempotency-Key"] = idempotency_key

        req_headers = _merge_headers(req_headers, headers)

        # Circuit breaker gate
        if self._cb and not self._cb.allow():
            logger.warning(
                "Circuit breaker open; request blocked",
                extra={"correlation_id": self.correlation_id, "event": "circuit_block"},
            )
            raise CircuitOpenError("Circuit breaker is open")

        attempt = 0
        last_exc: Optional[Exception] = None
        last_status: Optional[int] = None

        # Rate limiting
        if self._rl:
            await self._rl.acquire()

        # Tracing
        span = None
        if self._tracing_enabled:
            span = _tracer.start_as_current_span(f"HTTP {method} {path}")  # type: ignore

        try:
            if span:  # pragma: no cover
                span.__enter__()  # type: ignore

            while True:
                attempt += 1
                try:
                    response = await self._client.request(
                        method,
                        path,
                        params=params,
                        json=json,
                        data=data,
                        headers=req_headers,
                    )
                    last_status = response.status_code

                    if last_status in expect:
                        if self._cb:
                            self._cb.record_success()
                        return response

                    # Handle retryable statuses
                    if retry.should_retry(attempt, last_status, None):
                        delay_ms = retry.compute_delay_ms(attempt)
                        logger.warning(
                            f"Retrying after status {last_status}",
                            extra={
                                "correlation_id": self.correlation_id,
                                "event": "retry_status",
                                "http_status": last_status,
                                "retry_in_ms": delay_ms,
                            },
                        )
                        await asyncio.sleep(delay_ms / 1000.0)
                        continue

                    # Not retryable: raise HTTPError with details
                    body = response.text
                    detail = None
                    try:
                        parsed = response.json()
                        if isinstance(parsed, dict):
                            detail = ProblemDetails(**parsed)
                    except Exception:
                        detail = None

                    if self._cb:
                        self._cb.record_failure()

                    raise HTTPError(
                        f"Unexpected status {last_status}",
                        status_code=last_status,
                        response_text=body,
                        context={"problem": detail.dict() if detail else None},  # type: ignore
                    )

                except httpx.RequestError as exc:
                    last_exc = exc
                    if retry.should_retry(attempt, None, exc):
                        delay_ms = retry.compute_delay_ms(attempt)
                        logger.warning(
                            f"Network error: {exc}; retrying",
                            extra={
                                "correlation_id": self.correlation_id,
                                "event": "retry_exception",
                                "retry_in_ms": delay_ms,
                            },
                        )
                        await asyncio.sleep(delay_ms / 1000.0)
                        continue
                    if self._cb:
                        self._cb.record_failure()
                    raise CyberError("Network error") from exc
        finally:
            if span:  # pragma: no cover
                try:
                    span.__exit__(None, None, None)  # type: ignore
                except Exception:
                    pass

    # --- Helpers for typed responses -----------------------------------------
    async def _json(self, response: httpx.Response) -> Any:
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise CyberError("Invalid JSON response") from exc

    async def _parse_model(self, response: httpx.Response, model: Type[T]) -> T:
        payload = await self._json(response)
        try:
            return model.model_validate(payload) if PydanticV2 else model.parse_obj(payload)  # type: ignore
        except ValidationError as ve:
            raise ModelValidationError("Response validation failed", validation_error=ve)

    async def _parse_model_list(self, response: httpx.Response, model: Type[T]) -> List[T]:
        payload = await self._json(response)
        items = payload.get("items") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise ModelValidationError("Expected list response")
        out: List[T] = []
        for it in items:
            try:
                out.append(model.model_validate(it) if PydanticV2 else model.parse_obj(it))  # type: ignore
            except ValidationError as ve:
                raise ModelValidationError("Item validation failed", validation_error=ve)
        return out

    # --- Pagination helpers ---------------------------------------------------
    async def paginate(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        page_param: str = "cursor",
        limit_param: str = "limit",
        limit: int = 100,
        model: Optional[Type[T]] = None,
    ) -> AsyncIterator[Union[Dict[str, Any], T]]:
        """
        Cursor-based pagination.
        """
        cursor: Optional[str] = None
        params = dict(params or {})
        params[limit_param] = limit
        while True:
            if cursor:
                params[page_param] = cursor
            resp = await self.get(path, params=params)
            payload = await self._json(resp)
            items = payload.get("items", [])
            for item in items:
                if model is not None:
                    try:
                        yield model.model_validate(item) if PydanticV2 else model.parse_obj(item)  # type: ignore
                    except ValidationError as ve:
                        raise ModelValidationError("Item validation failed", validation_error=ve)
                else:
                    yield item
            cursor = (payload.get("page") or {}).get("next_cursor")
            if not cursor:
                break


# --- Resource clients ---------------------------------------------------------
class ThreatIntelClient:
    def __init__(self, core: AsyncCyberClient, base_path: str = "/api/ti/indicators") -> None:
        self.core = core
        self.base_path = base_path

    async def create_indicator(self, indicator: TIIndicator) -> TIIndicator:
        resp = await self.core.post(self.base_path, json_body=indicator.model_dump() if PydanticV2 else indicator.dict())  # type: ignore
        return await self.core._parse_model(resp, TIIndicator)

    async def get_indicator(self, indicator_id: str) -> TIIndicator:
        resp = await self.core.get(f"{self.base_path}/{indicator_id}")
        return await self.core._parse_model(resp, TIIndicator)

    async def delete_indicator(self, indicator_id: str) -> None:
        await self.core.delete(f"{self.base_path}/{indicator_id}")

    async def list_indicators(self, limit: int = 100) -> List[TIIndicator]:
        resp = await self.core.get(self.base_path, params={"limit": limit})
        return await self.core._parse_model_list(resp, TIIndicator)

    async def search(self, query: Mapping[str, Any], limit: int = 100) -> List[TIIndicator]:
        resp = await self.core.post(f"{self.base_path}:search", json_body={"query": dict(query), "limit": limit})
        return await self.core._parse_model_list(resp, TIIndicator)


class IncidentsClient:
    def __init__(self, core: AsyncCyberClient, base_path: str = "/api/incidents") -> None:
        self.core = core
        self.base_path = base_path

    async def create(self, incident: Incident) -> Incident:
        resp = await self.core.post(self.base_path, json_body=incident.model_dump() if PydanticV2 else incident.dict())  # type: ignore
        return await self.core._parse_model(resp, Incident)

    async def get(self, incident_id: str) -> Incident:
        resp = await self.core.get(f"{self.base_path}/{incident_id}")
        return await self.core._parse_model(resp, Incident)

    async def update(self, incident_id: str, patch: Mapping[str, Any]) -> Incident:
        resp = await self.core.patch(f"{self.base_path}/{incident_id}", json_body=dict(patch))
        return await self.core._parse_model(resp, Incident)

    async def delete(self, incident_id: str) -> None:
        await self.core.delete(f"{self.base_path}/{incident_id}")

    async def list(self, limit: int = 100) -> List[Incident]:
        resp = await self.core.get(self.base_path, params={"limit": limit})
        return await self.core._parse_model_list(resp, Incident)


class IDSClient:
    def __init__(self, core: AsyncCyberClient, base_path: str = "/api/ids/alerts") -> None:
        self.core = core
        self.base_path = base_path

    async def ingest(self, alert: IDSAlert) -> IDSAlert:
        resp = await self.core.post(self.base_path, json_body=alert.model_dump() if PydanticV2 else alert.dict())  # type: ignore
        return await self.core._parse_model(resp, IDSAlert)

    async def get(self, alert_id: str) -> IDSAlert:
        resp = await self.core.get(f"{self.base_path}/{alert_id}")
        return await self.core._parse_model(resp, IDSAlert)

    async def list(self, limit: int = 100) -> List[IDSAlert]:
        resp = await self.core.get(self.base_path, params={"limit": limit})
        return await self.core._parse_model_list(resp, IDSAlert)


class EDRClient:
    def __init__(self, core: AsyncCyberClient, base_path: str = "/api/edr/actions") -> None:
        self.core = core
        self.base_path = base_path

    async def request_action(self, action: EDRAction) -> EDRAction:
        resp = await self.core.post(self.base_path, json_body=action.model_dump() if PydanticV2 else action.dict())  # type: ignore
        return await self.core._parse_model(resp, EDRAction)

    async def get(self, action_id: str) -> EDRAction:
        resp = await self.core.get(f"{self.base_path}/{action_id}")
        return await self.core._parse_model(resp, EDRAction)

    async def list(self, host: Optional[str] = None, limit: int = 100) -> List[EDRAction]:
        params: Dict[str, Any] = {"limit": limit}
        if host:
            params["host"] = host
        resp = await self.core.get(self.base_path, params=params)
        return await self.core._parse_model_list(resp, EDRAction)


# --- High-level facade --------------------------------------------------------
class CyberSDK:
    """
    High-level facade exposing resource clients under one namespace.

    Example (async):
        config = ClientConfig.from_env()
        auth = ApiKeyAuth(os.getenv("CYBER_API_KEY", ""))
        async with CyberSDK(config=config, auth=auth) as sdk:
            indicators = await sdk.ti.list_indicators(limit=50)
    """

    def __init__(self, config: ClientConfig, auth: Optional[AuthStrategy] = None) -> None:
        self._core = AsyncCyberClient(config, auth=auth)
        self.ti = ThreatIntelClient(self._core)
        self.incidents = IncidentsClient(self._core)
        self.ids = IDSClient(self._core)
        self.edr = EDRClient(self._core)

    async def __aenter__(self) -> "CyberSDK":
        await self._core.__aenter__()  # type: ignore
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._core.__aexit__(exc_type, exc, tb)

    async def aclose(self) -> None:
        await self._core.aclose()

    @property
    def core(self) -> AsyncCyberClient:
        return self._core


__all__ = [
    # Core
    "AsyncCyberClient",
    "CyberSDK",
    "ClientConfig",
    "TLSConfig",
    "RetryPolicy",
    "CircuitBreaker",
    "TokenBucket",
    # Auth
    "AuthStrategy",
    "ApiKeyAuth",
    "BearerTokenAuth",
    "CompositeAuth",
    # Models
    "ProblemDetails",
    "ListResponse",
    "PageMeta",
    "TIIndicator",
    "Incident",
    "IDSAlert",
    "EDRAction",
    # Resources
    "ThreatIntelClient",
    "IncidentsClient",
    "IDSClient",
    "EDRClient",
    # Errors
    "CyberError",
    "AuthError",
    "HTTPError",
    "CircuitOpenError",
    "RateLimitError",
    "ModelValidationError",
]
