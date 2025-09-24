# automation-core/src/automation_core/http_client/base.py
# -*- coding: utf-8 -*-
"""
Асинхронный промышленный HTTP-клиент поверх httpx.

Ключевые свойства:
- Таймауты и лимиты соединений на уровне клиента (httpx.Timeout/limits).
- Экспоненциальный бэкоф с полным джиттером и верхней «шляпой» (cap).
- Уважение Retry-After (HTTP-date или delta-seconds) согласно RFC 9110 §10.2.3.
- Политика повторов: по статусам, исключениям и идемпотентным методам (RFC 9110 §9.2.2).
- Circuit breaker (threshold, cooldown, half-open).
- Хуки для метрик/логирования/трейсинга без жёстких зависимостей.
- Безопасные значения по умолчанию: ограниченные таймауты, лимиты пула, запрет повторов для неидемпотентных методов (кроме явной настройки).

Зависимости: httpx (async). Стандартная библиотека для остального.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

import httpx

__all__ = [
    "RetryPolicy",
    "CircuitBreakerConfig",
    "HTTPClientConfig",
    "AsyncHTTPClient",
    "RequestHook",
    "ResponseHook",
    "RetryHook",
    "ErrorHook",
    "CircuitState",
]

# -----------------------------------------------------------------------------
# Типы хуков
# -----------------------------------------------------------------------------

RequestHook = Callable[[httpx.Request], Awaitable[None]]
ResponseHook = Callable[[httpx.Request, httpx.Response], Awaitable[None]]
RetryHook = Callable[[httpx.Request, Optional[httpx.Response], BaseException | None, int, float], Awaitable[None]]
ErrorHook = Callable[[httpx.Request, BaseException], Awaitable[None]]

# -----------------------------------------------------------------------------
# Полезные константы
# -----------------------------------------------------------------------------

# RFC 9110 §9.2.2: идемпотентны PUT, DELETE и все "safe" (GET, HEAD, OPTIONS, TRACE)
IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})

DEFAULT_RETRY_STATUSES: frozenset[int] = frozenset({408, 413, 429, 500, 502, 503, 504})
DEFAULT_RETRY_EXC_TYPES: Tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
)

# -----------------------------------------------------------------------------
# Политика повторов и circuit breaker
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    backoff_base: float = 0.25          # секунд
    backoff_cap: float = 8.0            # максимум задержки
    jitter: bool = True                 # полный джиттер
    respect_retry_after: bool = True    # уважать Retry-After для 429/503/413
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES
    retry_exc_types: Tuple[type[BaseException], ...] = DEFAULT_RETRY_EXC_TYPES
    retry_on_methods: frozenset[str] = IDEMPOTENT_METHODS  # по умолчанию — только идемпотентные

    def compute_sleep(self, attempt: int) -> float:
        """Экспоненциальный бэкоф с полным джиттером."""
        raw = min(self.backoff_cap, self.backoff_base * (2 ** max(0, attempt - 1)))
        return random.uniform(0, raw) if self.jitter else raw

    def method_allowed(self, method: str) -> bool:
        return method.upper() in self.retry_on_methods

    def status_retryable(self, status: int) -> bool:
        return status in self.retry_statuses or 500 <= status < 600

    def exc_retryable(self, exc: BaseException) -> bool:
        return isinstance(exc, self.retry_exc_types)


@dataclass(frozen=True)
class CircuitBreakerConfig:
    failure_threshold: int = 10          # сколько подряд неудач перед "open"
    recovery_cooldown: float = 30.0      # сколько держать "open" (сек)
    half_open_max_calls: int = 1         # сколько пробных вызовов в half-open


class CircuitState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# -----------------------------------------------------------------------------
# Конфигурация клиента
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class HTTPClientConfig:
    base_url: Optional[str] = None
    headers: Optional[Mapping[str, str]] = None
    timeout_connect: float = 5.0
    timeout_read: float = 10.0
    timeout_write: float = 10.0
    timeout_pool: float = 5.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry: float = 5.0
    http2: bool = True
    verify: bool | str = True
    proxies: Optional[Mapping[str, str]] = None
    trust_env: bool = True
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    circuit: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    user_agent: str = "automation-core-http/1.0"

# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

def _parse_retry_after(value: str) -> Optional[float]:
    """
    Парсинг Retry-After (delta-seconds или HTTP-date) -> задержка в секундах.
    RFC 9110 §10.2.3.
    """
    if not value:
        return None
    value = value.strip()
    # delta-seconds
    if value.isdigit():
        try:
            return max(0.0, float(int(value)))
        except Exception:
            return None
    # HTTP-date
    try:
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delay = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delay)
    except Exception:
        return None


async def _await_hook(hook: Optional[Callable], *args):
    if hook is None:
        return
    res = hook(*args)
    if asyncio.iscoroutine(res):
        await res

# -----------------------------------------------------------------------------
# Клиент
# -----------------------------------------------------------------------------

class AsyncHTTPClient:
    """
    Асинхронный HTTP-клиент с повторами, уважением Retry-After и circuit breaker.

    Использует httpx.AsyncClient с управляемыми таймаутами и лимитами пула.
    Документы по таймаутам/лимитам/AsyncClient см. источники.
    """

    def __init__(
        self,
        config: HTTPClientConfig,
        *,
        on_request: Optional[RequestHook] = None,
        on_response: Optional[ResponseHook] = None,
        on_retry: Optional[RetryHook] = None,
        on_error: Optional[ErrorHook] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._cfg = config
        self._on_request = on_request
        self._on_response = on_response
        self._on_retry = on_retry
        self._on_error = on_error
        self._log = logger or logging.getLogger(__name__)

        self._client: Optional[httpx.AsyncClient] = None

        # circuit breaker state
        self._cb_state = CircuitState.CLOSED
        self._cb_failures = 0
        self._cb_open_until: float = 0.0
        self._cb_half_open_calls = 0

    # --------------- контекстный менеджер ----------------

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def start(self) -> None:
        if self._client is not None:
            return
        timeout = httpx.Timeout(
            connect=self._cfg.timeout_connect,
            read=self._cfg.timeout_read,
            write=self._cfg.timeout_write,
            pool=self._cfg.timeout_pool,
        )
        limits = httpx.Limits(
            max_connections=self._cfg.max_connections,
            max_keepalive_connections=self._cfg.max_keepalive_connections,
            keepalive_expiry=self._cfg.keepalive_expiry,
        )
        headers = {"user-agent": self._cfg.user_agent}
        if self._cfg.headers:
            headers.update(self._cfg.headers)

        self._client = httpx.AsyncClient(
            base_url=self._cfg.base_url or "",
            timeout=timeout,
            limits=limits,
            http2=self._cfg.http2,
            verify=self._cfg.verify,
            proxies=self._cfg.proxies,
            trust_env=self._cfg.trust_env,
            headers=headers,
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # --------------- circuit breaker ----------------

    def _cb_now(self) -> float:
        return time.monotonic()

    def _cb_allow(self) -> bool:
        now = self._cb_now()
        if self._cb_state == CircuitState.OPEN:
            if now >= self._cb_open_until:
                self._cb_state = CircuitState.HALF_OPEN
                self._cb_half_open_calls = 0
            else:
                return False
        if self._cb_state == CircuitState.HALF_OPEN:
            return self._cb_half_open_calls < self._cfg.circuit.half_open_max_calls
        return True

    def _cb_on_success(self) -> None:
        if self._cb_state in (CircuitState.OPEN, CircuitState.HALF_OPEN):
            self._log.debug("Circuit closed after successful probe")
        self._cb_state = CircuitState.CLOSED
        self._cb_failures = 0
        self._cb_open_until = 0.0
        self._cb_half_open_calls = 0

    def _cb_on_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_state == CircuitState.HALF_OPEN:
            # возврат в OPEN
            self._cb_state = CircuitState.OPEN
            self._cb_open_until = self._cb_now() + self._cfg.circuit.recovery_cooldown
            self._log.warning("Circuit re-opened after failed half-open probe")
            return
        if self._cb_failures >= self._cfg.circuit.failure_threshold:
            self._cb_state = CircuitState.OPEN
            self._cb_open_until = self._cb_now() + self._cfg.circuit.recovery_cooldown
            self._log.warning("Circuit opened (failures=%d)", self._cb_failures)

    # --------------- публичный API ----------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        json: Any = None,
        data: Any = None,
        content: Any = None,
        files: Any = None,
        timeout: Optional[httpx.Timeout] = None,
    ) -> httpx.Response:
        """
        Выполняет запрос с повторами/бэкофом/Retry-After и circuit breaker.
        """
        if self._client is None:
            await self.start()

        assert self._client is not None  # для type checker
        method_u = method.upper()

        # circuit check
        if not self._cb_allow():
            raise httpx.HTTPError("Circuit breaker is OPEN")

        attempts = 0
        last_exc: Optional[BaseException] = None
        last_resp: Optional[httpx.Response] = None

        while True:
            if self._cb_state == CircuitState.HALF_OPEN:
                self._cb_half_open_calls += 1

            req = self._client.build_request(
                method_u, url, params=params, headers=headers, json=json, data=data, content=content, files=files
            )

            # пользовательский хук "перед отправкой"
            await _await_hook(self._on_request, req)

            try:
                attempts += 1
                resp = await self._client.send(req, timeout=timeout)
                last_resp = resp

                # пользовательский хук "после ответа"
                await _await_hook(self._on_response, req, resp)

                if self._should_retry_response(method_u, resp, attempts):
                    sleep_s = self._sleep_for_response(resp, attempts)
                    await _await_hook(self._on_retry, req, resp, None, attempts, sleep_s)
                    self._log.debug("Retryable response %s %s -> %d, sleep %.3fs", method_u, url, resp.status_code, sleep_s)
                    await asyncio.sleep(sleep_s)
                    continue

                # успешная ветка
                if 200 <= resp.status_code < 400:
                    self._cb_on_success()
                else:
                    # неуспешно, но неретрайбл: учитываем в circuit
                    self._cb_on_failure()
                return resp

            except BaseException as exc:
                last_exc = exc
                await _await_hook(self._on_error, req, exc)

                if not self._should_retry_exception(method_u, exc, attempts):
                    # ошибка неретрайбл — учитываем и выкидываем
                    self._cb_on_failure()
                    raise

                sleep_s = self._cfg.retry.compute_sleep(attempts)
                await _await_hook(self._on_retry, req, None, exc, attempts, sleep_s)
                self._log.debug("Retryable exception %s %s -> %s, sleep %.3fs", method_u, url, type(exc).__name__, sleep_s)
                await asyncio.sleep(sleep_s)
                continue

    # Удобные шорткаты
    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    # --------------- внутренняя логика ретраев ----------------

    def _should_retry_response(self, method: str, resp: httpx.Response, attempts: int) -> bool:
        pol = self._cfg.retry
        if attempts >= pol.max_attempts:
            return False
        if not pol.method_allowed(method):
            return False
        status = resp.status_code
        if not pol.status_retryable(status):
            return False
        # Если есть Retry-After и он разрешён политикой — повторим (даже если status не 5xx)
        if pol.respect_retry_after:
            ra = resp.headers.get("retry-after")
            if ra:
                return True
        return True

    def _should_retry_exception(self, method: str, exc: BaseException, attempts: int) -> bool:
        pol = self._cfg.retry
        if attempts >= pol.max_attempts:
            return False
        if not pol.method_allowed(method):
            return False
        return pol.exc_retryable(exc)

    def _sleep_for_response(self, resp: httpx.Response, attempts: int) -> float:
        pol = self._cfg.retry
        if pol.respect_retry_after and resp.status_code in (429, 503, 413):
            ra = resp.headers.get("retry-after")
            if ra:
                parsed = _parse_retry_after(ra)
                if parsed is not None:
                    return min(parsed, pol.backoff_cap)
        return pol.compute_sleep(attempts)
