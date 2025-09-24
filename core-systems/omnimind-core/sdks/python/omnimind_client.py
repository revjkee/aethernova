# -*- coding: utf-8 -*-
"""
Omnimind Core — Industrial Python SDK client.

Features:
- Sync and Async clients (httpx-based)
- Timeouts, connection pooling, TLS verification, proxy support
- Exponential backoff with jitter; honors Retry-After
- Safe retry policy for idempotent methods + opt-in for POST/PUT with Idempotency-Key
- Token-bucket rate limiting (sync and async)
- Robust error mapping into typed exceptions
- Pluggable JSON serializer (orjson if available, fallback to json)
- Structured logging with correlation (X-Request-Id)
- SSE streaming helper
- Trace ingestion helpers (JSON dicts or Avro bytes)
- Health endpoint convenience

Python: 3.11+
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import json
import logging
import math
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Tuple, Union

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError("httpx is required: pip install httpx>=0.27") from e

try:
    import orjson  # type: ignore

    def _json_dumps(obj: Any) -> bytes:
        return orjson.dumps(obj)

    def _json_loads(data: Union[str, bytes, bytearray]) -> Any:
        return orjson.loads(data)

    JSON_BINARY = True
except Exception:  # pragma: no cover
    import json as _stdlib_json

    def _json_dumps(obj: Any) -> bytes:
        return _stdlib_json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _json_loads(data: Union[str, bytes, bytearray]) -> Any:
        if isinstance(data, (bytes, bytearray)):
            data = data.decode("utf-8")
        return _stdlib_json.loads(data)

    JSON_BINARY = False


# ---------------------------
# Exceptions
# ---------------------------

class OmnimindError(Exception):
    """Base exception for Omnimind SDK."""

    def __init__(self, message: str, *, status: Optional[int] = None, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload


class NetworkError(OmnimindError):
    """Network or transport-level error."""


class TimeoutError(OmnimindError):
    """Request timeout."""


class AuthError(OmnimindError):
    """401 Unauthorized or auth failure."""


class PermissionDeniedError(OmnimindError):
    """403 Forbidden."""


class NotFoundError(OmnimindError):
    """404 Not Found."""


class ConflictError(OmnimindError):
    """409 Conflict."""


class ValidationError(OmnimindError):
    """400/422 semantic or validation error."""


class RateLimitError(OmnimindError):
    """429 Too Many Requests."""


class ServerError(OmnimindError):
    """5xx server-side error."""


# ---------------------------
# Retry policy & rate limiting
# ---------------------------

@dataclass(slots=True)
class RetryPolicy:
    """Retry configuration with exponential backoff and jitter."""

    max_retries: int = 4
    backoff_base: float = 0.2  # seconds
    backoff_factor: float = 2.0
    max_backoff: float = 10.0
    retry_on_statuses: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    retry_on_methods: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "TRACE")
    retry_on_post_with_idempotency: bool = True
    # Exceptions to retry
    retry_on_exceptions: Tuple[type[BaseException], ...] = (httpx.TransportError,)

    def compute_backoff(self, attempt: int, *, retry_after: Optional[float] = None) -> float:
        if retry_after is not None:
            return max(0.0, min(retry_after, self.max_backoff))
        delay = self.backoff_base * (self.backoff_factor ** max(0, attempt - 1))
        # Full jitter: random in [0, min(delay, max_backoff)]
        return random.uniform(0.0, min(delay, self.max_backoff))


class _TokenBucket:
    """Simple token bucket for rate limiting (sync)."""

    def __init__(self, rate_per_sec: float, burst: int) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be > 0")
        self.rate = float(rate_per_sec)
        self.burst = int(burst)
        self.tokens = float(burst)
        self._last = time.monotonic()

    def acquire(self) -> None:
        now = time.monotonic()
        # Refill
        elapsed = now - self._last
        self._last = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens < 1.0:
            # Need to wait
            need = 1.0 - self.tokens
            delay = need / self.rate
            time.sleep(delay)
            # After sleeping, account tokens
            now2 = time.monotonic()
            elapsed2 = now2 - self._last
            self._last = now2
            self.tokens = min(self.burst, self.tokens + elapsed2 * self.rate)
        # Consume
        self.tokens -= 1.0


class _AsyncTokenBucket:
    """Async token bucket for rate limiting (async)."""

    def __init__(self, rate_per_sec: float, burst: int) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be > 0")
        self.rate = float(rate_per_sec)
        self.burst = int(burst)
        self.tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            if self.tokens < 1.0:
                need = 1.0 - self.tokens
                delay = need / self.rate
                await asyncio.sleep(delay)
                now2 = time.monotonic()
                elapsed2 = now2 - self._last
                self._last = now2
                self.tokens = min(self.burst, self.tokens + elapsed2 * self.rate)
            self.tokens -= 1.0


# ---------------------------
# Configuration
# ---------------------------

def _default_user_agent(version: str = "0.1.0") -> str:
    return f"omnimind-python/{version}"


@dataclass(slots=True)
class ClientConfig:
    base_url: str = field(default_factory=lambda: os.getenv("OMNIMIND_BASE_URL", "http://localhost:8000"))
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("OMNIMIND_API_KEY"))
    timeout: float = float(os.getenv("OMNIMIND_TIMEOUT", "30"))
    connect_timeout: float = float(os.getenv("OMNIMIND_CONNECT_TIMEOUT", "10"))
    verify_ssl: bool = os.getenv("OMNIMIND_VERIFY_SSL", "true").lower() != "false"
    proxies: Optional[Union[str, Mapping[str, str]]] = None
    organization: Optional[str] = field(default_factory=lambda: os.getenv("OMNIMIND_ORG"))
    default_headers: Mapping[str, str] = field(default_factory=dict)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    # Rate limiting: disabled by default
    rate_limit_per_sec: Optional[float] = None
    rate_limit_burst: int = 10
    # SDK identity
    sdk_version: str = "0.1.0"
    user_agent: str = field(default_factory=lambda: _default_user_agent("0.1.0"))

    def merged_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self.user_agent or _default_user_agent(self.sdk_version),
        }
        if self.organization:
            headers["X-Org"] = self.organization
        headers.update(self.default_headers)
        return headers


# ---------------------------
# Utilities
# ---------------------------

def _normalize_base(url: str) -> str:
    return url.rstrip("/")


def _join_url(base: str, path: str) -> str:
    base = _normalize_base(base)
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _as_idempotency_key(key: Optional[str]) -> str:
    return key or str(uuid.uuid4())


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        # RFC: either seconds or HTTP-date. We support seconds.
        return float(value)
    except Exception:
        return None


def _build_client_timeout(cfg: ClientConfig) -> httpx.Timeout:
    return httpx.Timeout(timeout=cfg.timeout, connect=cfg.connect_timeout)


def _headers_with_auth(cfg: ClientConfig, headers: Optional[Mapping[str, str]], api_key: Optional[str]) -> Dict[str, str]:
    merged = dict(cfg.merged_headers())
    if headers:
        merged.update(headers)
    token = api_key if api_key is not None else cfg.api_key
    if token:
        merged["Authorization"] = f"Bearer {token}"
    return merged


def _ensure_json_body(data: Any) -> Tuple[bytes, str]:
    body = _json_dumps(data)
    return body, "application/json"


def _ensure_sse(headers: Mapping[str, str]) -> Mapping[str, str]:
    if "accept" not in {k.lower(): v for k, v in headers.items()}:
        h = dict(headers)
        h["Accept"] = "text/event-stream"
        return h
    return headers


def _log_response(logger: logging.Logger, resp: httpx.Response) -> None:
    logger.debug("HTTP %s %s -> %s", resp.request.method, str(resp.request.url), resp.status_code)


# ---------------------------
# Base client
# ---------------------------

class _BaseClient:
    def __init__(self, config: ClientConfig, *, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("omnimind.sdk")
        self._retry = config.retry_policy
        self._rate: Optional[_TokenBucket] = None

        if config.rate_limit_per_sec:
            self._rate = _TokenBucket(config.rate_limit_per_sec, config.rate_limit_burst)

        self._client = httpx.Client(
            base_url=_normalize_base(config.base_url),
            timeout=_build_client_timeout(config),
            verify=config.verify_ssl,
            proxies=config.proxies,
            headers=config.merged_headers(),
            transport=httpx.HTTPTransport(retries=0),  # we manage retries ourselves
        )

    # ------------- lifecycle -------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "_BaseClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------- request core -------------

    def _should_retry(self, method: str, status: Optional[int], exc: Optional[BaseException], has_idem_key: bool) -> bool:
        if exc is not None:
            return isinstance(exc, self._retry.retry_on_exceptions)

        if status is None:
            return False

        if status in self._retry.retry_on_statuses:
            if method.upper() in self._retry.retry_on_methods:
                return True
            if method.upper() in ("POST", "PUT") and has_idem_key and self._retry.retry_on_post_with_idempotency:
                return True
        return False

    def _raise_for_status(self, resp: httpx.Response) -> None:
        status = resp.status_code
        payload: Any = None
        with contextlib.suppress(Exception):
            if resp.headers.get("content-type", "").lower().startswith("application/json"):
                payload = resp.json()
            else:
                payload = resp.text

        msg = f"HTTP {status}"
        if isinstance(payload, dict):
            detail = payload.get("error") or payload.get("message") or payload.get("detail")
            if detail:
                msg = f"{msg} — {detail}"

        if status == 401:
            raise AuthError(msg, status=status, payload=payload)
        if status == 403:
            raise PermissionDeniedError(msg, status=status, payload=payload)
        if status == 404:
            raise NotFoundError(msg, status=status, payload=payload)
        if status in (400, 422):
            raise ValidationError(msg, status=status, payload=payload)
        if status == 409:
            raise ConflictError(msg, status=status, payload=payload)
        if status == 429:
            raise RateLimitError(msg, status=status, payload=payload)
        if 500 <= status <= 599:
            raise ServerError(msg, status=status, payload=payload)
        # default
        raise OmnimindError(msg, status=status, payload=payload)

    def _maybe_rate_limit(self) -> None:
        if self._rate:
            self._rate.acquire()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> httpx.Response:
        url = path if path.startswith("http") else _join_url(self.config.base_url, path)
        method_up = method.upper()

        # Build headers
        req_headers = _headers_with_auth(self.config, headers, api_key)
        request_body: Optional[bytes] = None

        if json is not None and data is not None:
            raise ValueError("Provide either json or data, not both")

        if json is not None:
            request_body, ctype = _ensure_json_body(json)
            req_headers.setdefault("Content-Type", ctype)
        elif data is not None:
            request_body = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            if content_type:
                req_headers.setdefault("Content-Type", content_type)

        # Idempotency for POST/PUT when not provided
        has_idem_key = False
        if method_up in ("POST", "PUT"):
            key = idempotency_key or os.getenv("OMNIMIND_IDEMPOTENCY_KEY")
            if key:
                req_headers.setdefault("Idempotency-Key", _as_idempotency_key(key))
                has_idem_key = True

        # Correlation id
        req_headers.setdefault("X-Request-Id", str(uuid.uuid4()))

        attempt = 0
        while True:
            attempt += 1
            self._maybe_rate_limit()

            try:
                resp = self._client.request(
                    method_up,
                    url,
                    params=params,
                    content=request_body,
                    headers=req_headers,
                )
                _log_response(self.logger, resp)

                if resp.is_success:
                    return resp

                if not self._should_retry(method_up, resp.status_code, None, has_idem_key):
                    self._raise_for_status(resp)

                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                delay = self._retry.compute_backoff(attempt, retry_after=retry_after)

            except httpx.TimeoutException as e:
                if not self._should_retry(method_up, None, e, has_idem_key) or attempt > self._retry.max_retries:
                    raise TimeoutError(str(e)) from e
                delay = self._retry.compute_backoff(attempt)

            except httpx.TransportError as e:
                if not self._should_retry(method_up, None, e, has_idem_key) or attempt > self._retry.max_retries:
                    raise NetworkError(str(e)) from e
                delay = self._retry.compute_backoff(attempt)

            if attempt > self._retry.max_retries:
                # last response would have been raised already for status; for exceptions we reach here
                raise OmnimindError("Max retries exceeded")

            time.sleep(delay)

    # ------------- convenience -------------

    def get(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> Any:
        resp = self.request("GET", path, params=params, headers=headers, api_key=api_key)
        return self._json_or_text(resp)

    def post(
        self,
        path: str,
        *,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        resp = self.request(
            "POST",
            path,
            params=params,
            json=json,
            data=data,
            headers=headers,
            idempotency_key=idempotency_key,
            api_key=api_key,
            content_type=content_type,
        )
        return self._json_or_text(resp)

    def put(
        self,
        path: str,
        *,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        resp = self.request(
            "PUT",
            path,
            params=params,
            json=json,
            data=data,
            headers=headers,
            idempotency_key=idempotency_key,
            api_key=api_key,
            content_type=content_type,
        )
        return self._json_or_text(resp)

    def delete(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> Any:
        resp = self.request("DELETE", path, params=params, headers=headers, api_key=api_key)
        return self._json_or_text(resp)

    @staticmethod
    def _json_or_text(resp: httpx.Response) -> Any:
        ctype = resp.headers.get("content-type", "").lower()
        if ctype.startswith("application/json"):
            return resp.json()
        return resp.text

    # ------------- domain helpers -------------

    def health(self) -> Dict[str, Any]:
        """GET /health"""
        return self.get("/health")

    def ingest_traces_json(
        self,
        batch: Mapping[str, Any],
        *,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """POST /v1/traces with JSON payload."""
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        return self.post("/v1/traces", json=batch, headers=hdrs, idempotency_key=idempotency_key)

    def ingest_traces_avro(
        self,
        avro_payload: Union[bytes, bytearray, memoryview],
        *,
        schema_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        POST /v1/traces with Avro binary payload.
        If schema_id is provided, it will be sent as X-Avro-Schema-Id header.
        """
        hdrs: Dict[str, str] = {"Content-Type": "avro/binary", "Accept": "application/json"}
        if schema_id:
            hdrs["X-Avro-Schema-Id"] = schema_id
        if headers:
            hdrs.update(headers)
        return self.post("/v1/traces", data=bytes(avro_payload), headers=hdrs, idempotency_key=idempotency_key)

    def stream_sse(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
        retry: Optional[RetryPolicy] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Stream Server-Sent Events as dicts with keys: event, id, data, retry (if present).
        Automatically reconnects respecting Retry-After and Retry policy.
        """
        policy = retry or self._retry
        url = path if path.startswith("http") else _join_url(self.config.base_url, path)
        req_headers = _headers_with_auth(self.config, headers, api_key)
        req_headers = dict(req_headers)
        req_headers = _ensure_sse(req_headers)

        attempt = 0
        while True:
            attempt += 1
            try:
                with self._client.stream("GET", url, params=params, headers=req_headers, timeout=None) as r:
                    if r.status_code != 200:
                        if not self._should_retry("GET", r.status_code, None, False) or attempt > policy.max_retries:
                            self._raise_for_status(r)
                        delay = policy.compute_backoff(attempt, retry_after=_parse_retry_after(r.headers.get("Retry-After")))
                        time.sleep(delay)
                        continue

                    buffer = ""
                    for chunk in r.iter_text():
                        if chunk is None:
                            continue
                        buffer += chunk
                        while "\n\n" in buffer:
                            raw, buffer = buffer.split("\n\n", 1)
                            event: Dict[str, Any] = {}
                            for line in raw.splitlines():
                                if not line.strip() or line.startswith(":"):
                                    continue
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    event.setdefault(k.strip(), "")
                                    event[k.strip()] = v.lstrip()
                                else:
                                    event.setdefault("data", "")
                                    event["data"] += line
                            # Attempt to parse data as JSON if looks like JSON
                            data = event.get("data")
                            if data:
                                dt = data.strip()
                                if (dt.startswith("{") and dt.endswith("}")) or (dt.startswith("[") and dt.endswith("]")):
                                    with contextlib.suppress(Exception):
                                        event["data"] = _json_loads(dt)
                            yield event
                    # Normal end-of-stream: stop reconnecting
                    return
            except httpx.TimeoutException as e:
                if attempt > policy.max_retries:
                    raise TimeoutError(str(e)) from e
                time.sleep(policy.compute_backoff(attempt))
            except httpx.TransportError as e:
                if attempt > policy.max_retries:
                    raise NetworkError(str(e)) from e
                time.sleep(policy.compute_backoff(attempt))


# ---------------------------
# Async client
# ---------------------------

class _AsyncBaseClient:
    def __init__(self, config: ClientConfig, *, logger: Optional[logging.Logger] = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("omnimind.sdk")
        self._retry = config.retry_policy
        self._rate: Optional[_AsyncTokenBucket] = None

        if config.rate_limit_per_sec:
            self._rate = _AsyncTokenBucket(config.rate_limit_per_sec, config.rate_limit_burst)

        self._client = httpx.AsyncClient(
            base_url=_normalize_base(config.base_url),
            timeout=_build_client_timeout(config),
            verify=config.verify_ssl,
            proxies=config.proxies,
            headers=config.merged_headers(),
            transport=httpx.AsyncHTTPTransport(retries=0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "_AsyncBaseClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    def _should_retry(self, method: str, status: Optional[int], exc: Optional[BaseException], has_idem_key: bool) -> bool:
        rp = self._retry
        if exc is not None:
            return isinstance(exc, rp.retry_on_exceptions)

        if status is None:
            return False

        if status in rp.retry_on_statuses:
            if method.upper() in rp.retry_on_methods:
                return True
            if method.upper() in ("POST", "PUT") and has_idem_key and rp.retry_on_post_with_idempotency:
                return True
        return False

    def _raise_for_status(self, resp: httpx.Response) -> None:
        status = resp.status_code
        payload: Any = None
        with contextlib.suppress(Exception):
            if resp.headers.get("content-type", "").lower().startswith("application/json"):
                payload = resp.json()
            else:
                payload = resp.text

        msg = f"HTTP {status}"
        if isinstance(payload, dict):
            detail = payload.get("error") or payload.get("message") or payload.get("detail")
            if detail:
                msg = f"{msg} — {detail}"

        if status == 401:
            raise AuthError(msg, status=status, payload=payload)
        if status == 403:
            raise PermissionDeniedError(msg, status=status, payload=payload)
        if status == 404:
            raise NotFoundError(msg, status=status, payload=payload)
        if status in (400, 422):
            raise ValidationError(msg, status=status, payload=payload)
        if status == 409:
            raise ConflictError(msg, status=status, payload=payload)
        if status == 429:
            raise RateLimitError(msg, status=status, payload=payload)
        if 500 <= status <= 599:
            raise ServerError(msg, status=status, payload=payload)
        raise OmnimindError(msg, status=status, payload=payload)

    async def _maybe_rate_limit(self) -> None:
        if self._rate:
            await self._rate.acquire()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> httpx.Response:
        url = path if path.startswith("http") else _join_url(self.config.base_url, path)
        method_up = method.upper()

        req_headers = _headers_with_auth(self.config, headers, api_key)
        request_body: Optional[bytes] = None

        if json is not None and data is not None:
            raise ValueError("Provide either json or data, not both")

        if json is not None:
            request_body, ctype = _ensure_json_body(json)
            req_headers.setdefault("Content-Type", ctype)
        elif data is not None:
            request_body = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            if content_type:
                req_headers.setdefault("Content-Type", content_type)

        has_idem_key = False
        if method_up in ("POST", "PUT"):
            key = idempotency_key or os.getenv("OMNIMIND_IDEMPOTENCY_KEY")
            if key:
                req_headers.setdefault("Idempotency-Key", _as_idempotency_key(key))
                has_idem_key = True

        req_headers.setdefault("X-Request-Id", str(uuid.uuid4()))

        attempt = 0
        while True:
            attempt += 1
            await self._maybe_rate_limit()

            try:
                resp = await self._client.request(
                    method_up,
                    url,
                    params=params,
                    content=request_body,
                    headers=req_headers,
                )
                _log_response(self.logger, resp)

                if resp.is_success:
                    return resp

                if not self._should_retry(method_up, resp.status_code, None, has_idem_key):
                    self._raise_for_status(resp)

                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                delay = self._retry.compute_backoff(attempt, retry_after=retry_after)

            except httpx.TimeoutException as e:
                if not self._should_retry(method_up, None, e, has_idem_key) or attempt > self._retry.max_retries:
                    raise TimeoutError(str(e)) from e
                delay = self._retry.compute_backoff(attempt)

            except httpx.TransportError as e:
                if not self._should_retry(method_up, None, e, has_idem_key) or attempt > self._retry.max_retries:
                    raise NetworkError(str(e)) from e
                delay = self._retry.compute_backoff(attempt)

            if attempt > self._retry.max_retries:
                raise OmnimindError("Max retries exceeded")

            await asyncio.sleep(delay)

    # convenience

    async def get(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> Any:
        resp = await self.request("GET", path, params=params, headers=headers, api_key=api_key)
        return self._json_or_text(resp)

    async def post(
        self,
        path: str,
        *,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        resp = await self.request(
            "POST",
            path,
            params=params,
            json=json,
            data=data,
            headers=headers,
            idempotency_key=idempotency_key,
            api_key=api_key,
            content_type=content_type,
        )
        return self._json_or_text(resp)

    async def put(
        self,
        path: str,
        *,
        json: Optional[Any] = None,
        data: Optional[Union[bytes, bytearray, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        api_key: Optional[str] = None,
        content_type: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        resp = await self.request(
            "PUT",
            path,
            params=params,
            json=json,
            data=data,
            headers=headers,
            idempotency_key=idempotency_key,
            api_key=api_key,
            content_type=content_type,
        )
        return self._json_or_text(resp)

    async def delete(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> Any:
        resp = await self.request("DELETE", path, params=params, headers=headers, api_key=api_key)
        return self._json_or_text(resp)

    @staticmethod
    def _json_or_text(resp: httpx.Response) -> Any:
        ctype = resp.headers.get("content-type", "").lower()
        if ctype.startswith("application/json"):
            return resp.json()
        return resp.text

    # domain

    async def health(self) -> Dict[str, Any]:
        return await self.get("/health")

    async def ingest_traces_json(
        self,
        batch: Mapping[str, Any],
        *,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        return await self.post("/v1/traces", json=batch, headers=hdrs, idempotency_key=idempotency_key)

    async def ingest_traces_avro(
        self,
        avro_payload: Union[bytes, bytearray, memoryview],
        *,
        schema_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        hdrs: Dict[str, str] = {"Content-Type": "avro/binary", "Accept": "application/json"}
        if schema_id:
            hdrs["X-Avro-Schema-Id"] = schema_id
        if headers:
            hdrs.update(headers)
        return await self.post("/v1/traces", data=bytes(avro_payload), headers=hdrs, idempotency_key=idempotency_key)

    async def stream_sse(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        api_key: Optional[str] = None,
        retry: Optional[RetryPolicy] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        policy = retry or self._retry
        url = path if path.startswith("http") else _join_url(self.config.base_url, path)
        req_headers = _headers_with_auth(self.config, headers, api_key)
        req_headers = _ensure_sse(dict(req_headers))

        attempt = 0
        while True:
            attempt += 1
            try:
                async with self._client.stream("GET", url, params=params, headers=req_headers, timeout=None) as r:
                    if r.status_code != 200:
                        if not self._should_retry("GET", r.status_code, None, False) or attempt > policy.max_retries:
                            self._raise_for_status(r)
                        delay = policy.compute_backoff(attempt, retry_after=_parse_retry_after(r.headers.get("Retry-After")))
                        await asyncio.sleep(delay)
                        continue

                    buffer = ""
                    async for chunk in r.aiter_text():
                        if chunk is None:
                            continue
                        buffer += chunk
                        while "\n\n" in buffer:
                            raw, buffer = buffer.split("\n\n", 1)
                            event: Dict[str, Any] = {}
                            for line in raw.splitlines():
                                if not line.strip() or line.startswith(":"):
                                    continue
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    event.setdefault(k.strip(), "")
                                    event[k.strip()] = v.lstrip()
                                else:
                                    event.setdefault("data", "")
                                    event["data"] += line
                            data = event.get("data")
                            if data:
                                dt = data.strip()
                                if (dt.startswith("{") and dt.endswith("}")) or (dt.startswith("[") and dt.endswith("]")):
                                    with contextlib.suppress(Exception):
                                        event["data"] = _json_loads(dt)
                            yield event
                    return
            except httpx.TimeoutException as e:
                if attempt > policy.max_retries:
                    raise TimeoutError(str(e)) from e
                await asyncio.sleep(policy.compute_backoff(attempt))
            except httpx.TransportError as e:
                if attempt > policy.max_retries:
                    raise NetworkError(str(e)) from e
                await asyncio.sleep(policy.compute_backoff(attempt))


# ---------------------------
# Public API
# ---------------------------

class OmnimindClient(_BaseClient):
    """Synchronous Omnimind client."""


class AsyncOmnimindClient(_AsyncBaseClient):
    """Asynchronous Omnimind client."""


# ---------------------------
# Example usage (manual smoke)
# ---------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = ClientConfig()
    with OmnimindClient(cfg) as c:
        try:
            print("Health:", c.health())
        except OmnimindError as err:
            logging.error("Health check failed: %s", err)
