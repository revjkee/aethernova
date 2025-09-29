# backend/src/utils/http_client.py
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Dict, Iterable, Literal, Mapping, MutableMapping, Optional, Tuple, Union

import httpx

# -----------------------------
# Optional integrations (no-ops if not installed)
# -----------------------------
try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *_, **__): ...
        def labels(self, *_, **__): return self
        def observe(self, *_: Any, **__: Any): ...
        def inc(self, *_: Any, **__: Any): ...

    Counter = Histogram = _Noop  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _otel_tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _otel_tracer = None  # type: ignore


logger = logging.getLogger(__name__)

# -----------------------------
# Metrics
# -----------------------------
_HTTP_REQUESTS = Counter(
    "http_client_requests_total",
    "Total HTTP client requests",
    ["method", "host", "status", "outcome"],
)
_HTTP_LATENCY = Histogram(
    "http_client_request_duration_seconds",
    "HTTP client request latency",
    ["method", "host", "status", "outcome"],
)

# -----------------------------
# Config & helpers
# -----------------------------

IdempotentMethod = Literal["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"]
AnyMethod = Literal["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "POST", "PATCH"]

DEFAULT_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "x-auth-token", "cookie", "set-cookie"}
DEFAULT_SENSITIVE_QUERY_PARAMS = {"token", "access_token", "api_key", "key", "signature"}

def _redact_mapping(src: Optional[Mapping[str, Any]], sensitive_keys: Iterable[str]) -> Dict[str, Any]:
    if not src:
        return {}
    sens = {k.lower() for k in sensitive_keys}
    out: Dict[str, Any] = {}
    for k, v in src.items():
        if k.lower() in sens:
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out

def _now() -> float:
    return time.monotonic()

def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        # Seconds form
        seconds = int(value)
        return float(seconds) if seconds >= 0 else None
    except ValueError:
        try:
            # HTTP-date
            dt = parsedate_to_datetime(value)
            delay = (dt - datetime.utcnow()).total_seconds()
            return max(0.0, delay)
        except Exception:
            return None

def _hash_cache_key(method: str, url: str, params: Optional[Mapping[str, Any]], headers: Optional[Mapping[str, Any]]) -> str:
    h = hashlib.sha256()
    h.update(method.encode())
    h.update(b"|")
    h.update(url.encode())
    h.update(b"|")
    if params:
        # sort for stability
        serialized = json.dumps(sorted(params.items()), separators=(",", ":"), ensure_ascii=False)
        h.update(serialized.encode())
    h.update(b"|")
    if headers:
        # only safe headers (exclude typical sensitive)
        safe_headers = {k: v for k, v in headers.items() if k.lower() not in DEFAULT_SENSITIVE_HEADERS}
        serialized = json.dumps(sorted(safe_headers.items()), separators=(",", ":"), ensure_ascii=False)
        h.update(serialized.encode())
    return h.hexdigest()

@dataclass(frozen=True)
class PoolLimits:
    max_keepalive: int = 20
    max_connections: int = 100
    keepalive_expiry: float = 15.0

@dataclass
class RetryPolicy:
    retries: int = 3
    backoff_base: float = 0.2
    backoff_max: float = 5.0
    jitter: float = 0.1  # +/- percentage of delay (0.1 => 10%)
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    retry_all_methods: bool = False  # otherwise only idempotent
    respect_retry_after: bool = True

@dataclass
class CircuitBreakerPolicy:
    failure_threshold: int = 5          # consecutive failures to open
    recovery_timeout: float = 30.0      # seconds in open before half-open
    half_open_max_calls: int = 1        # trial calls allowed in half-open

@dataclass
class RateLimitPolicy:
    rate_per_sec: float = 50.0
    burst: int = 50

@dataclass
class CachePolicy:
    enabled: bool = True
    ttl_seconds: float = 2.0  # small TTL for hot GETs
    cacheable_methods: Tuple[str, ...] = ("GET", "HEAD")

@dataclass
class HttpClientConfig:
    base_url: Optional[str] = None
    timeout: float = 10.0
    verify_ssl: bool = True
    follow_redirects: bool = True
    default_headers: Dict[str, str] = field(default_factory=dict)
    pool: PoolLimits = field(default_factory=PoolLimits)
    retries: RetryPolicy = field(default_factory=RetryPolicy)
    circuit_breaker: CircuitBreakerPolicy = field(default_factory=CircuitBreakerPolicy)
    rate_limit: Optional[RateLimitPolicy] = field(default_factory=lambda: RateLimitPolicy())
    cache: CachePolicy = field(default_factory=CachePolicy)
    proxies: Optional[Union[str, Mapping[str, str]]] = None  # httpx proxy format
    http2: bool = True
    # HMAC signing
    hmac_key: Optional[bytes] = None
    hmac_header: str = "X-Signature"
    hmac_algo: str = "sha256"
    # Redaction
    redact_headers: Iterable[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_HEADERS)
    redact_query_params: Iterable[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_QUERY_PARAMS)

# -----------------------------
# Rate limiter (async token bucket)
# -----------------------------
class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = float(rate)
        self.capacity = int(burst)
        self.tokens = float(burst)
        self.updated = _now()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = _now()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                # time until next token
                wait_for = (1.0 - self.tokens) / self.rate if self.rate > 0 else 0.01
                await asyncio.sleep(max(0.001, wait_for))

# -----------------------------
# Circuit breaker
# -----------------------------
class _CircuitState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class _CircuitBreaker:
    def __init__(self, policy: CircuitBreakerPolicy):
        self.policy = policy
        self._state = _CircuitState.CLOSED
        self._consec_failures = 0
        self._opened_at = 0.0
        self._half_open_calls = 0

    def _transition(self, new_state: str) -> None:
        self._state = new_state
        if new_state == _CircuitState.OPEN:
            self._opened_at = _now()
            self._half_open_calls = 0
        elif new_state == _CircuitState.CLOSED:
            self._consec_failures = 0
            self._opened_at = 0.0
            self._half_open_calls = 0
        elif new_state == _CircuitState.HALF_OPEN:
            self._half_open_calls = 0

    def allow(self) -> bool:
        if self._state == _CircuitState.CLOSED:
            return True
        if self._state == _CircuitState.OPEN:
            if _now() - self._opened_at >= self.policy.recovery_timeout:
                self._transition(_CircuitState.HALF_OPEN)
                return True
            return False
        # HALF_OPEN
        if self._half_open_calls < self.policy.half_open_max_calls:
            self._half_open_calls += 1
            return True
        return False

    def on_success(self) -> None:
        if self._state in (_CircuitState.HALF_OPEN, _CircuitState.OPEN):
            self._transition(_CircuitState.CLOSED)
        else:
            self._consec_failures = 0

    def on_failure(self) -> None:
        if self._state == _CircuitState.HALF_OPEN:
            self._transition(_CircuitState.OPEN)
            return
        self._consec_failures += 1
        if self._consec_failures >= self.policy.failure_threshold:
            self._transition(_CircuitState.OPEN)

    @property
    def state(self) -> str:
        return self._state

# -----------------------------
# Async HTTP Client
# -----------------------------
class AsyncHTTPClient:
    """
    Industrial async HTTP client based on httpx with:
    - timeouts, connection pooling, HTTP/2
    - retries with exponential backoff, jitter, Retry-After handling
    - circuit breaker
    - rate limiting (token bucket)
    - small in-memory TTL cache for GET/HEAD
    - secure logging with secret redaction
    - optional HMAC signing, X-Request-Id propagation
    - optional Prometheus and OpenTelemetry instrumentation (if installed)
    """

    def __init__(self, config: Optional[HttpClientConfig] = None) -> None:
        self.config = config or HttpClientConfig()
        limits = httpx.Limits(
            max_keepalive_connections=self.config.pool.max_keepalive,
            max_connections=self.config.pool.max_connections,
            keepalive_expiry=self.config.pool.keepalive_expiry,
        )
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url or "",
            timeout=httpx.Timeout(self.config.timeout),
            verify=self.config.verify_ssl,
            follow_redirects=self.config.follow_redirects,
            limits=limits,
            proxies=self.config.proxies,
            http2=self.config.http2,
            headers=self.config.default_headers or {},
        )
        self._bucket = _TokenBucket(self.config.rate_limit.rate_per_sec, self.config.rate_limit.burst) if self.config.rate_limit else None
        self._breaker = _CircuitBreaker(self.config.circuit_breaker)
        self._cache: Dict[str, Tuple[float, httpx.Response]] = {}
        self._cache_lock = asyncio.Lock()

    # ------------- Public API -------------

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: AnyMethod,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Union[Mapping[str, Any], bytes, str]] = None,
        content: Optional[bytes] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        allow_redirects: Optional[bool] = None,
        idempotent_override: Optional[bool] = None,
        request_id: Optional[str] = None,
    ) -> httpx.Response:
        """
        Core request with retries, circuit breaker, rate limiting, caching, safe logging, and instrumentation.

        Notes:
        - Retries are applied only to idempotent methods unless `retry_all_methods=True` in config or idempotent_override=True.
        - Cache applies to GET/HEAD with small TTL; bypassed on explicit headers like Cache-Control: no-cache if provided by caller.
        - HMAC signature is applied if config.hmac_key is set; header name and algo are configurable.
        """
        # Circuit breaker
        if not self._breaker.allow():
            raise httpx.HTTPError("Circuit breaker is OPEN")

        # Rate limiting
        if self._bucket:
            await self._bucket.acquire()

        # Merge headers & request-id
        req_headers: Dict[str, str] = {}
        req_headers.update(self.config.default_headers or {})
        if headers:
            req_headers.update(headers)
        rid = request_id or req_headers.get("X-Request-Id") or str(uuid.uuid4())
        req_headers["X-Request-Id"] = rid

        # HMAC signing (over URL+body)
        if self.config.hmac_key:
            signature = self._sign_hmac(method, url, params, json_body if json_body is not None else data if data is not None else content)
            req_headers[self.config.hmac_header] = signature

        # Cache lookup (GET/HEAD only)
        cache_key = None
        if self._cache_enabled(method, req_headers):
            cache_key = _hash_cache_key(method, str(self._client.base_url.join(url) if self._client.base_url else url), params, req_headers)
            cached = await self._cache_get(cache_key)
            if cached is not None:
                return cached

        # Prepare request kwargs
        kwargs: Dict[str, Any] = {"params": params, "headers": req_headers}
        if json_body is not None:
            kwargs["json"] = json_body
        if data is not None:
            kwargs["data"] = data
        if content is not None:
            kwargs["content"] = content
        if files is not None:
            kwargs["files"] = files
        if timeout is not None:
            kwargs["timeout"] = timeout
        if allow_redirects is not None:
            kwargs["follow_redirects"] = allow_redirects

        # Retry loop
        policy = self.config.retries
        attempts = max(0, int(policy.retries)) + 1
        idempotent = method in ("GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE")
        may_retry = policy.retry_all_methods or idempotent or (idempotent_override is True)
        last_exc: Optional[Exception] = None
        response: Optional[httpx.Response] = None

        # OTel span
        if _otel_tracer:
            span_ctx = _otel_tracer.start_as_current_span(f"http.client {method}")
        else:
            # dummy context manager
            class _NoopSpan:
                def __enter__(self): return None
                def __exit__(self, *args): return False
            span_ctx = _NoopSpan()

        with span_ctx:
            for attempt in range(1, attempts + 1):
                start = _now()
                outcome = "success"
                status_label = "0"
                host_label = self._client.base_url.host if self._client.base_url else (httpx.URL(url).host or "unknown")

                try:
                    self._log_request(method, url, params, req_headers)
                    response = await self._client.request(method, url, **kwargs)
                    status_label = str(response.status_code)

                    if self._should_retry_response(response) and may_retry and attempt < attempts:
                        outcome = "retry"
                        delay = self._compute_delay(attempt, response)
                        self._metrics(method, host_label, status_label, outcome, start)
                        await asyncio.sleep(delay)
                        continue

                    # Success path
                    if 200 <= response.status_code < 400:
                        self._breaker.on_success()
                        self._metrics(method, host_label, status_label, outcome, start)
                        if cache_key is not None:
                            await self._cache_put(cache_key, response)
                        return response

                    # Non-retriable error
                    self._breaker.on_failure()
                    outcome = "error"
                    self._metrics(method, host_label, status_label, outcome, start)
                    return response

                except (httpx.TransportError, httpx.ReadError, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                    last_exc = exc
                    status_label = "transport_error"
                    if may_retry and attempt < attempts:
                        outcome = "retry"
                        self._metrics(method, host_label, status_label, outcome, start)
                        delay = self._compute_delay(attempt, None)
                        await asyncio.sleep(delay)
                        continue
                    outcome = "error"
                    self._breaker.on_failure()
                    self._metrics(method, host_label, status_label, outcome, start)
                    raise

                finally:
                    # Attach OTel attributes if available
                    if _otel_tracer:
                        span = trace.get_current_span()
                        try:
                            span.set_attribute("http.request.method", method)
                            span.set_attribute("http.url", str(self._client.base_url.join(url) if self._client.base_url else url))
                            if response is not None:
                                span.set_attribute("http.response.status_code", response.status_code)
                        except Exception:
                            pass

        # If we are here and no response returned
        if last_exc:
            raise last_exc
        raise httpx.HTTPError("Request failed without further details")

    # Convenience shortcuts
    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)
    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)
    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)
    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)
    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)
    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    # ------------- Internals -------------

    def _metrics(self, method: str, host: str, status: str, outcome: str, started: float) -> None:
        try:
            _HTTP_REQUESTS.labels(method=method, host=host, status=status, outcome=outcome).inc()
            _HTTP_LATENCY.labels(method=method, host=host, status=status, outcome=outcome).observe(_now() - started)
        except Exception:
            pass

    def _log_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]],
        headers: Optional[Mapping[str, str]],
    ) -> None:
        if not logger.isEnabledFor(logging.DEBUG):
            return
        safe_headers = _redact_mapping(headers, self.config.redact_headers)
        safe_params = _redact_mapping(params, self.config.redact_query_params)
        logger.debug("HTTP %s %s params=%s headers=%s", method, url, safe_params, safe_headers)

    def _should_retry_response(self, response: httpx.Response) -> bool:
        if response.status_code in self.config.retries.retry_on_status:
            return True
        return False

    def _compute_delay(self, attempt: int, response: Optional[httpx.Response]) -> float:
        rp = self.config.retries
        if rp.respect_retry_after and response is not None:
            ra = _parse_retry_after(response.headers.get("Retry-After"))
            if ra is not None:
                return float(min(max(0.0, ra), rp.backoff_max))
        # exponential backoff with jitter
        base = min(rp.backoff_max, rp.backoff_base * (2 ** (attempt - 1)))
        jitter_range = base * rp.jitter
        return max(0.0, base + random.uniform(-jitter_range, jitter_range))

    def _cache_enabled(self, method: str, headers: Mapping[str, str]) -> bool:
        if not self.config.cache.enabled:
            return False
        if method.upper() not in self.config.cache.cacheable_methods:
            return False
        # allow bypass if caller sets no-cache
        cache_control = headers.get("Cache-Control", "") if headers else ""
        pragma = headers.get("Pragma", "") if headers else ""
        if "no-cache" in cache_control.lower() or "no-store" in cache_control.lower() or "no-cache" in pragma.lower():
            return False
        return True

    async def _cache_get(self, key: str) -> Optional[httpx.Response]:
        async with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            ts, resp = item
            if (_now() - ts) <= self.config.cache.ttl_seconds:
                # Return a copy to avoid consumed content issues
                return self._clone_response(resp)
            # expired
            self._cache.pop(key, None)
            return None

    async def _cache_put(self, key: str, response: httpx.Response) -> None:
        async with self._cache_lock:
            # store a copy
            self._cache[key] = (_now(), self._clone_response(response))

    def _clone_response(self, response: httpx.Response) -> httpx.Response:
        # materialize content
        content = response.content
        new = httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=content,
            request=response.request,
            extensions=response.extensions,
            reason_phrase=response.reason_phrase,
        )
        return new

    def _sign_hmac(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]],
        body: Optional[Any],
    ) -> str:
        assert self.config.hmac_key is not None
        algo = self.config.hmac_algo.lower()
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported HMAC algo: {self.config.hmac_algo}")
        m = hashlib.new(algo)
        # canonical string: METHOD\nURL\nsorted_query\nbody_sha256
        # Note: URL should be absolute when base_url present
        absolute = str(self._client.base_url.join(url) if self._client.base_url else url)
        qry = ""
        if params:
            qry = json.dumps(sorted(params.items()), separators=(",", ":"), ensure_ascii=False)
        body_bytes: bytes
        if body is None:
            body_bytes = b""
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        elif isinstance(body, str):
            body_bytes = body.encode()
        elif isinstance(body, Mapping) or isinstance(body, list):
            body_bytes = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        else:
            body_bytes = str(body).encode()

        body_sha = hashlib.sha256(body_bytes).hexdigest().encode()

        canonical = "\n".join([method.upper(), absolute, qry]).encode() + b"\n" + body_sha
        digest = hmac.new(self.config.hmac_key, canonical, algo).hexdigest()
        return digest

# -----------------------------
# Factory from environment
# -----------------------------
def build_client_from_env(prefix: str = "HTTP_CLIENT_") -> AsyncHTTPClient:
    """
    Build AsyncHTTPClient from environment variables.

    Supported variables:
    - {prefix}BASE_URL
    - {prefix}TIMEOUT
    - {prefix}VERIFY_SSL (true/false)
    - {prefix}FOLLOW_REDIRECTS (true/false)
    - {prefix}MAX_CONNECTIONS
    - {prefix}MAX_KEEPALIVE
    - {prefix}KEEPALIVE_EXPIRY
    - {prefix}RETRIES
    - {prefix}BACKOFF_BASE
    - {prefix}BACKOFF_MAX
    - {prefix}RETRY_ALL_METHODS
    - {prefix}HTTP2 (true/false)
    - {prefix}RATE (tokens per second)
    - {prefix}BURST
    - {prefix}CACHE_TTL
    - {prefix}HMAC_KEY (hex)
    - {prefix}HMAC_HEADER
    - {prefix}HMAC_ALGO
    - {prefix}PROXIES (httpx format, single string)
    """
    def _b(name: str, default: bool) -> bool:
        return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}
    def _f(name: str, default: float) -> float:
        try: return float(os.getenv(name, str(default)))
        except Exception: return default
    def _i(name: str, default: int) -> int:
        try: return int(os.getenv(name, str(default)))
        except Exception: return default
    def _s(name: str, default: Optional[str] = None) -> Optional[str]:
        return os.getenv(name, default)

    base_url = _s(f"{prefix}BASE_URL")
    timeout = _f(f"{prefix}TIMEOUT", 10.0)
    verify_ssl = _b(f"{prefix}VERIFY_SSL", True)
    follow_redirects = _b(f"{prefix}FOLLOW_REDIRECTS", True)
    http2 = _b(f"{prefix}HTTP2", True)

    max_conns = _i(f"{prefix}MAX_CONNECTIONS", 100)
    max_keepalive = _i(f"{prefix}MAX_KEEPALIVE", 20)
    keepalive_expiry = _f(f"{prefix}KEEPALIVE_EXPIRY", 15.0)

    retries = _i(f"{prefix}RETRIES", 3)
    backoff_base = _f(f"{prefix}BACKOFF_BASE", 0.2)
    backoff_max = _f(f"{prefix}BACKOFF_MAX", 5.0)
    retry_all = _b(f"{prefix}RETRY_ALL_METHODS", False)

    rate = _f(f"{prefix}RATE", 50.0)
    burst = _i(f"{prefix}BURST", 50)

    cache_ttl = _f(f"{prefix}CACHE_TTL", 2.0)

    hmac_key_hex = _s(f"{prefix}HMAC_KEY")
    hmac_key = bytes.fromhex(hmac_key_hex) if hmac_key_hex else None
    hmac_header = _s(f"{prefix}HMAC_HEADER", "X-Signature") or "X-Signature"
    hmac_algo = _s(f"{prefix}HMAC_ALGO", "sha256") or "sha256"

    proxies = _s(f"{prefix}PROXIES")

    cfg = HttpClientConfig(
        base_url=base_url,
        timeout=timeout,
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        pool=PoolLimits(max_keepalive=max_keepalive, max_connections=max_conns, keepalive_expiry=keepalive_expiry),
        retries=RetryPolicy(retries=retries, backoff_base=backoff_base, backoff_max=backoff_max, retry_all_methods=retry_all),
        rate_limit=RateLimitPolicy(rate_per_sec=rate, burst=burst),
        cache=CachePolicy(enabled=True, ttl_seconds=cache_ttl),
        proxies=proxies,
        http2=http2,
        hmac_key=hmac_key,
        hmac_header=hmac_header,
        hmac_algo=hmac_algo,
    )
    return AsyncHTTPClient(cfg)

# -----------------------------
# Example safe JSON helper (optional usage)
# -----------------------------
async def get_json(client: AsyncHTTPClient, url: str, **kwargs: Any) -> Any:
    """
    Convenience helper to GET+parse JSON with proper error propagation.
    """
    resp = await client.get(url, **kwargs)
    resp.raise_for_status()
    # httpx decodes json safely and raises if invalid by default
    return resp.json()
