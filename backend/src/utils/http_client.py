# backend/src/utils/http_client.py
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import httpx

try:
    # Опциональная телеметрия: не является обязательной зависимостью
    from opentelemetry import trace  # type: ignore
    _OTEL_AVAILABLE = True
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False
    _tracer = None  # type: ignore

try:
    # Опциональные метрики Prometheus
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

__all__ = [
    "HttpClientConfig",
    "AsyncCircuitBreaker",
    "AsyncHttpClient",
    "build_default_client",
]

logger = logging.getLogger("utils.http_client")


@dataclass(frozen=True)
class HttpClientConfig:
    # Базовые настройки
    base_url: Optional[str] = None
    verify_ssl: bool = True
    http2: bool = True

    # Таймауты
    connect_timeout: float = 3.0
    read_timeout: float = 15.0
    write_timeout: float = 10.0
    pool_timeout: float = 3.0

    # Пула соединений
    pool_max_keepalive: int = 100
    pool_max_connections: int = 100

    # Ретраи
    retries: int = 3
    backoff_base: float = 0.2           # базовая задержка
    backoff_max: float = 5.0            # максимум между ретраями
    backoff_factor: float = 2.0         # экспонента
    jitter: Tuple[float, float] = (0.1, 0.4)
    retry_methods: Sequence[str] = field(default_factory=lambda: ("GET", "HEAD", "PUT", "DELETE", "OPTIONS"))
    retry_statuses: Sequence[int] = field(default_factory=lambda: (408, 425, 429, 500, 502, 503, 504))
    retry_exceptions: Tuple[type, ...] = (
        httpx.ConnectError,
        httpx.ReadError,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.NetworkError,
    )

    # Circuit Breaker
    cb_fail_threshold: int = 5           # сколько последовательных сбоев, чтобы открыть
    cb_half_open_after: float = 15.0     # через сколько секунд перейти в half-open
    cb_half_open_max_calls: int = 3      # сколько пробных вызовов в half-open
    cb_name: str = "default"

    # Прокси (опционально)
    proxies: Optional[Union[str, Mapping[str, str]]] = None

    # Доп. заголовки по умолчанию
    default_headers: Mapping[str, str] = field(default_factory=dict)

    # Ограничение на размер содержимого ответа (байты) — 0 означает без ограничения
    max_response_bytes: int = 0

    # Идентификатор клиента (для логов/метрик)
    client_name: str = "http"


class AsyncCircuitBreaker:
    """
    Простой асинхронный circuit breaker с тремя состояниями:
    - CLOSED: обычная работа, считаем ошибки; при пороге -> OPEN
    - OPEN: сразу отклоняем запросы до истечения окна cb_half_open_after
    - HALF_OPEN: допускаем ограниченное число проб (cb_half_open_max_calls); при успехе -> CLOSED, при ошибке -> OPEN
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, name: str, fail_threshold: int, half_open_after: float, half_open_max_calls: int) -> None:
        self._name = name
        self._fail_threshold = max(1, fail_threshold)
        self._half_open_after = max(1.0, half_open_after)
        self._half_open_max_calls = max(1, half_open_max_calls)

        self._state = self.CLOSED
        self._fail_count = 0
        self._opened_at = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def allow(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            if self._state == self.OPEN:
                if now - self._opened_at >= self._half_open_after:
                    self._state = self.HALF_OPEN
                    self._half_open_calls = 0
                    return True
                return False
            if self._state == self.HALF_OPEN:
                if self._half_open_calls < self._half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                # превышен лимит проб — удерживаем OPEN до следующего окна
                self._state = self.OPEN
                self._opened_at = now
                return False
            return True  # CLOSED

    async def record_success(self) -> None:
        async with self._lock:
            self._fail_count = 0
            if self._state in (self.OPEN, self.HALF_OPEN):
                self._state = self.CLOSED
                self._opened_at = 0.0
                self._half_open_calls = 0

    async def record_failure(self) -> None:
        async with self._lock:
            if self._state == self.HALF_OPEN:
                # любая ошибка в half-open — открыть
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                self._fail_count = self._fail_threshold  # для диагностик
                return

            # CLOSED
            self._fail_count += 1
            if self._fail_count >= self._fail_threshold:
                self._state = self.OPEN
                self._opened_at = time.monotonic()


# Метрики Prometheus (опционально)
if _PROM_AVAILABLE:  # pragma: no cover
    HTTP_REQUESTS_TOTAL = Counter(
        "http_client_requests_total",
        "Total HTTP client requests",
        ["client", "method", "host", "status"],
    )
    HTTP_REQUEST_EXCEPTIONS_TOTAL = Counter(
        "http_client_request_exceptions_total",
        "Total HTTP client request exceptions",
        ["client", "method", "host", "exception"],
    )
    HTTP_REQUEST_LATENCY_SECONDS = Histogram(
        "http_client_request_latency_seconds",
        "HTTP client request latency in seconds",
        ["client", "method", "host"],
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    )
else:  # pragma: no cover
    HTTP_REQUESTS_TOTAL = None
    HTTP_REQUEST_EXCEPTIONS_TOTAL = None
    HTTP_REQUEST_LATENCY_SECONDS = None


class AsyncHttpClient:
    """
    Производственный асинхронный HTTP-клиент с:
      - httpx.AsyncClient (HTTP/1.1 и HTTP/2)
      - Пулы соединений и таймауты
      - Экспоненциальные ретраи с джиттером (по методам/статусам/исключениям)
      - Асинхронный circuit breaker
      - Структурное логирование
      - Опциональные OpenTelemetry и Prometheus
      - Потоковые ответы (stream)
      - Ограничение размера ответа (safeguard)
    """

    def __init__(self, config: HttpClientConfig) -> None:
        self._cfg = config
        limits = httpx.Limits(
            max_keepalive_connections=self._cfg.pool_max_keepalive,
            max_connections=self._cfg.pool_max_connections,
            keepalive_expiry=30.0,
        )
        timeout = httpx.Timeout(
            connect=self._cfg.connect_timeout,
            read=self._cfg.read_timeout,
            write=self._cfg.write_timeout,
            pool=self._cfg.pool_timeout,
        )
        self._client = httpx.AsyncClient(
            base_url=self._cfg.base_url or "",
            verify=self._cfg.verify_ssl,
            http2=self._cfg.http2,
            limits=limits,
            timeout=timeout,
            headers=self._cfg.default_headers,  # применяются как default
            proxies=self._cfg.proxies,
        )
        self._cb = AsyncCircuitBreaker(
            name=self._cfg.cb_name,
            fail_threshold=self._cfg.cb_fail_threshold,
            half_open_after=self._cfg.cb_half_open_after,
            half_open_max_calls=self._cfg.cb_half_open_max_calls,
        )
        self._closed = False

    # ----------------- Публичный API -----------------

    async def aclose(self) -> None:
        if not self._closed:
            await self._client.aclose()
            self._closed = True

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request("GET", url, headers=headers, params=params, timeout=timeout, idempotency_key=idempotency_key)

    async def post(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[Mapping[str, Any], bytes]] = None,
        json_: Optional[Any] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request(
            "POST",
            url,
            headers=headers,
            params=params,
            data=data,
            json=json_,
            files=files,
            timeout=timeout,
            idempotency_key=idempotency_key,
        )

    async def put(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[Mapping[str, Any], bytes]] = None,
        json_: Optional[Any] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request(
            "PUT",
            url,
            headers=headers,
            params=params,
            data=data,
            json=json_,
            files=files,
            timeout=timeout,
            idempotency_key=idempotency_key,
        )

    async def delete(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request("DELETE", url, headers=headers, params=params, timeout=timeout, idempotency_key=idempotency_key)

    async def head(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request("HEAD", url, headers=headers, params=params, timeout=timeout, idempotency_key=idempotency_key)

    async def patch(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[Mapping[str, Any], bytes]] = None,
        json_: Optional[Any] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        return await self.request(
            "PATCH",
            url,
            headers=headers,
            params=params,
            data=data,
            json=json_,
            files=files,
            timeout=timeout,
            idempotency_key=idempotency_key,
        )

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[Mapping[str, Any], bytes]] = None,
        json: Optional[Any] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> AsyncIterator[httpx.Response]:
        """
        Стриминговые ответы. Ретраи применяются к установлению соединения.
        """
        async with self._request_internal(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            json=json,
            files=files,
            timeout=timeout,
            idempotency_key=idempotency_key,
            stream=True,
        ) as resp:
            yield resp

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[Mapping[str, Any], bytes]] = None,
        json: Optional[Any] = None,
        files: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> httpx.Response:
        async with self._request_internal(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            json=json,
            files=files,
            timeout=timeout,
            idempotency_key=idempotency_key,
            stream=False,
        ) as resp:
            # Ограничение размера ответа (если задано)
            if self._cfg.max_response_bytes and resp.headers.get("Content-Length"):
                try:
                    size = int(resp.headers["Content-Length"])
                    if size > self._cfg.max_response_bytes:
                        await resp.aclose()
                        raise httpx.HTTPError(
                            f"Response too large: {size} bytes > limit {self._cfg.max_response_bytes}"
                        )
                except ValueError:
                    pass
            return resp

    # ----------------- Внутренняя логика -----------------

    @asynccontextmanager
    async def _request_internal(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]],
        params: Optional[Mapping[str, Any]],
        data: Optional[Union[Mapping[str, Any], bytes]],
        json: Optional[Any],
        files: Optional[Mapping[str, Any]],
        timeout: Optional[float],
        idempotency_key: Optional[str],
        stream: bool,
    ) -> AsyncIterator[httpx.Response]:
        method_u = method.upper()
        hdrs: Dict[str, str] = {}
        if headers:
            hdrs.update(headers)

        # Idempotency-Key для безопасных повторов write-операций (по желанию)
        if idempotency_key and method_u in ("POST", "PATCH", "PUT", "DELETE"):
            hdrs.setdefault("Idempotency-Key", idempotency_key)

        # OpenTelemetry span
        span_cm = _tracer.start_as_current_span("http.client.request") if _OTEL_AVAILABLE else _noop_cm()
        async with span_cm as span:  # type: ignore
            start = time.perf_counter()
            host_label = self._host_label(url)

            # метрики: таймер
            timer_cm = _metrics_timer(self._cfg.client_name, method_u, host_label)
            with timer_cm:
                attempt = 0
                last_exc: Optional[BaseException] = None
                while True:
                    attempt += 1
                    allowed = await self._cb.allow()
                    if not allowed:
                        exc = httpx.HTTPError(f"CircuitBreaker[{self._cfg.cb_name}] is OPEN")
                        self._record_exception(method_u, host_label, exc)
                        if _OTEL_AVAILABLE and span is not None:
                            span.set_attribute("cb.state", "open")
                        raise exc

                    try:
                        if _OTEL_AVAILABLE and span is not None:
                            span.set_attribute("http
