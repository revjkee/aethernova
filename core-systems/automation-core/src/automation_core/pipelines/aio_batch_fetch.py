"""
automation_core.pipelines.aio_batch_fetch
-----------------------------------------

Высоконагруженный асинхронный батч-фетчер HTTP-ресурсов на базе httpx.

Возможности:
- Управление конкурентностью (asyncio.Semaphore) и глобальный rate-limit (token bucket).
- Экспоненциальные ретраи с джиттером, уважение Retry-After/RateLimit-* заголовков.
- Circuit Breaker с half-open фазой, авто-восстановление.
- Безопасное логирование (маскирование токенов), подсчёт байтов/латентности.
- Потоковая выдача результатов через async-генератор и/или on_result callback.
- Грейсфул shutdown, отмена и дедупликация запросов (опц.).
- Плагинообразные хуки: before_send / after_result / on_error.
- Не тянет фреймворки; зависимости: httpx (>=0.27).

Пример (док. комментарий):
    urls = ["https://example.com", ...]
    reqs = [FetchRequest(url=u) for u in urls]
    fetcher = BatchFetcher(concurrency=50, rate_per_sec=100)
    async for res in fetcher.run_iter(reqs):
        if res.ok:
            ...
        else:
            ...

Автор: automation-core
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from types import TracebackType
from typing import (
    Any,
    AsyncGenerator,
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
    Union,
)

import httpx


# ------------------------------------------------------------------------------
# Логирование
# ------------------------------------------------------------------------------

logger = logging.getLogger("automation_core.pipelines.aio_batch_fetch")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# ------------------------------------------------------------------------------
# Утилиты
# ------------------------------------------------------------------------------

def _now_ts() -> float:
    return time.time()

def _mask_secret(value: Optional[str], keep: int = 3) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "***"
    return f"{value[:keep]}…{value[-keep:]}"


# ------------------------------------------------------------------------------
# Rate limiter — Token Bucket
# ------------------------------------------------------------------------------

class TokenBucket:
    """
    Асинхронный токен-бакет. Поддерживает дробные токены.
    capacity — максимальное число токенов в бакете.
    rate_per_sec — скорость пополнения (токенов/сек).
    """

    def __init__(self, *, capacity: float, rate_per_sec: float) -> None:
        if capacity <= 0 or rate_per_sec <= 0:
            raise ValueError("capacity и rate_per_sec должны быть > 0")
        self._capacity = float(capacity)
        self._rate = float(rate_per_sec)
        self._tokens = float(capacity)
        self._updated = _now_ts()
        self._cond = asyncio.Condition()

    def _refill(self) -> None:
        now = _now_ts()
        delta = max(0.0, now - self._updated)
        if delta > 0:
            self._tokens = min(self._capacity, self._tokens + delta * self._rate)
            self._updated = now

    async def acquire(self) -> None:
        async with self._cond:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Сколько ждать до появления 1 токена
                need = 1.0 - self._tokens
                wait = need / self._rate if self._rate > 0 else 0.01
                await asyncio.sleep(min(max(wait, 0.001), 1.0))

    async def __aenter__(self) -> "TokenBucket":
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> Optional[bool]:
        # Ничего, токен уже потрачен
        return None


# ------------------------------------------------------------------------------
# Circuit Breaker
# ------------------------------------------------------------------------------

class CircuitOpen(Exception):
    pass


class CircuitBreaker:
    """
    Простой circuit breaker:
      - closed: пропускает все запросы
      - open: отклоняет до истечения recovery_timeout
      - half-open: ограниченное число проб, при успехе -> closed, при провале -> open
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 10,
        recovery_timeout_sec: float = 30.0,
        half_open_max_calls: int = 5,
    ) -> None:
        self._state = "closed"  # closed|open|half-open
        self._failures = 0
        self._last_opened = 0.0
        self._recovery = float(recovery_timeout_sec)
        self._threshold = int(failure_threshold)
        self._half_open_max = int(half_open_max_calls)
        self._half_open_inflight = 0
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            now = _now_ts()
            if self._state == "open":
                if (now - self._last_opened) >= self._recovery:
                    self._state = "half-open"
                    self._half_open_inflight = 0
                else:
                    raise CircuitOpen("circuit is open")
            if self._state == "half-open":
                if self._half_open_inflight >= self._half_open_max:
                    raise CircuitOpen("circuit half-open capacity exhausted")
                self._half_open_inflight += 1

    async def record_success(self) -> None:
        async with self._lock:
            if self._state == "half-open":
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                # Успех переводит в closed, сбрасывает счётчики
                self._state = "closed"
                self._failures = 0
            elif self._state == "closed":
                self._failures = 0

    async def record_failure(self) -> None:
        async with self._lock:
            if self._state == "half-open":
                # Немедленно открыть при неудаче
                self._state = "open"
                self._last_opened = _now_ts()
                self._failures = 0
                self._half_open_inflight = 0
            elif self._state == "closed":
                self._failures += 1
                if self._failures >= self._threshold:
                    self._state = "open"
                    self._last_opened = _now_ts()
                    self._failures = 0

    @property
    def state(self) -> str:
        return self._state


# ------------------------------------------------------------------------------
# Типы запросов/результатов
# ------------------------------------------------------------------------------

HttpMethod = Union[
    str
]  # допустим любой метод, но обычно "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"

@dataclass(frozen=True)
class FetchRequest:
    url: str
    method: HttpMethod = "GET"
    params: Optional[Mapping[str, Any]] = None
    headers: Optional[Mapping[str, str]] = None
    json: Optional[Any] = None
    data: Optional[Union[Mapping[str, Any], bytes]] = None
    content: Optional[bytes] = None
    timeout: Optional[float] = None
    id: Optional[str] = None
    allow_redirects: bool = True
    retries: Optional[int] = None  # override глобальной политики ретраев


@dataclass
class ErrorInfo:
    type: str
    message: str
    retryable: bool = False


@dataclass
class FetchResult:
    request: FetchRequest
    ok: bool
    status_code: Optional[int]
    url: str
    started_at: float
    finished_at: float
    elapsed_ms: int
    bytes_read: int
    headers: Mapping[str, str] = field(default_factory=dict)
    data: Optional[Any] = None
    error: Optional[ErrorInfo] = None

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at


# ------------------------------------------------------------------------------
# BatchFetcher
# ------------------------------------------------------------------------------

BeforeSendHook = Callable[[FetchRequest], Awaitable[None]]
AfterResultHook = Callable[[FetchResult], Awaitable[None]]
OnErrorHook = Callable[[FetchRequest, ErrorInfo], Awaitable[None]]
TransformFn = Callable[[httpx.Response], Awaitable[Any]]


class BatchFetcher:
    """
    Промышленный батч-фетчер с управляемой конкурентностью, rate-limit, ретраями и CB.

    Параметры:
      - concurrency: максимум одновременных запросов.
      - rate_per_sec: глобальный лимит RPS (token-bucket). None — без лимита.
      - timeout: базовый таймаут на запрос.
      - retries: число повторов при временных ошибках/429/5xx.
      - backoff_base: старт задержки, backoff_factor — множитель, backoff_cap — максимум.
      - jitter: добавлять случайный джиттер к задержке.
      - client: необязательный httpx.AsyncClient (если не передать — будет создан).
      - transform: async-функция обработки ответа (например, response.json()).
      - on_result/on_error/before_send: хуки-уведомления (метрики/логика).
      - circuit_breaker: внешний или внутренний CB.

    Замечания:
      - Уважает Retry-After (секунды или дату); при конфликтах берёт максимум(заголовок, backoff).
      - Полностью читает контент через response.aread() для освобождения соединения.
      - Поддерживает переопределение retry-политики на уровне FetchRequest.retries.
    """

    def __init__(
        self,
        *,
        concurrency: int = 64,
        rate_per_sec: Optional[float] = None,
        timeout: float = 20.0,
        retries: int = 3,
        backoff_base: float = 0.25,
        backoff_factor: float = 2.0,
        backoff_cap: float = 10.0,
        jitter: bool = True,
        client: Optional[httpx.AsyncClient] = None,
        transform: Optional[TransformFn] = None,
        before_send: Optional[BeforeSendHook] = None,
        on_result: Optional[AfterResultHook] = None,
        on_error: Optional[OnErrorHook] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        dedupe: bool = False,
    ) -> None:
        if concurrency <= 0:
            raise ValueError("concurrency должен быть > 0")

        self._sem = asyncio.Semaphore(concurrency)
        self._rate = TokenBucket(capacity=rate_per_sec, rate_per_sec=rate_per_sec) if rate_per_sec else None
        self._timeout = timeout
        self._retries = retries
        self._backoff_base = backoff_base
        self._backoff_factor = backoff_factor
        self._backoff_cap = backoff_cap
        self._jitter = jitter
        self._client = client
        self._own_client = client is None
        self._transform = transform
        self._before_send = before_send
        self._on_result = on_result
        self._on_error = on_error
        self._cb = circuit_breaker or CircuitBreaker()
        self._dedupe = dedupe
        self._seen: set[str] = set()
        self._closed = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Делегируем опции TLS/прокси/limits пользователю при необходимости
            limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
            self._client = httpx.AsyncClient(timeout=self._timeout, limits=limits, headers={})
        return self._client

    def _delay(self, attempt: int) -> float:
        # delay = min(base * factor^attempt, cap) + jitter
        delay = min(self._backoff_base * (self._backoff_factor ** attempt), self._backoff_cap)
        if self._jitter:
            delay += random.uniform(0, self._backoff_base)
        return max(0.0, delay)

    @staticmethod
    def _is_retryable_status(code: int) -> bool:
        # 429 и 5xx — кандидаты на ретрай
        return code == 429 or 500 <= code <= 599

    @staticmethod
    def _retry_after_delay(resp: httpx.Response) -> Optional[float]:
        h = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
        if not h:
            return None
        try:
            # RFC: может быть секундное число
            return float(h)
        except ValueError:
            # Попытаться распарсить HTTP-date (упрощённо: httpx не парсит тут сам)
            try:
                import email.utils as eut
                dt = eut.parsedate_to_datetime(h)
                if dt is not None:
                    return max(0.0, (dt.timestamp() - _now_ts()))
            except Exception:
                return None
        return None

    async def _emit_result(self, res: FetchResult) -> None:
        if self._on_result:
            try:
                await self._on_result(res)
            except Exception as e:
                logger.debug("on_result hook raised: %s", e)

    async def _emit_error(self, req: FetchRequest, err: ErrorInfo) -> None:
        if self._on_error:
            try:
                await self._on_error(req, err)
            except Exception as e:
                logger.debug("on_error hook raised: %s", e)

    async def _single(self, req: FetchRequest) -> FetchResult:
        # Дедупликация по (method,url,params) — опционально
        if self._dedupe:
            key = f"{req.method}:{req.url}:{tuple(sorted((req.params or {}).items()))}"
            if key in self._seen:
                # Возвращаем синтетический результат OK=false с error=duplicate
                now = _now_ts()
                return FetchResult(
                    request=req,
                    ok=False,
                    status_code=None,
                    url=req.url,
                    started_at=now,
                    finished_at=now,
                    elapsed_ms=0,
                    bytes_read=0,
                    error=ErrorInfo(type="Duplicate", message="duplicate suppressed", retryable=False),
                )
            self._seen.add(key)

        await self._cb.allow()  # может бросить CircuitOpen

        if self._before_send:
            try:
                await self._before_send(req)
            except Exception as e:
                logger.debug("before_send hook raised: %s", e)

        attempt = 0
        max_attempts = (req.retries if isinstance(req.retries, int) else self._retries) + 1

        client = await self._ensure_client()
        started = _now_ts()
        last_error: Optional[ErrorInfo] = None

        while attempt < max_attempts:
            attempt_started = _now_ts()
            # Rate-limit + concurrency
            async with self._sem:
                if self._rate:
                    await self._rate.acquire()
                try:
                    timeout = req.timeout if req.timeout is not None else self._timeout
                    resp = await client.request(
                        req.method,
                        req.url,
                        params=req.params,
                        headers=req.headers,
                        json=req.json,
                        data=req.data,
                        content=req.content,
                        timeout=timeout,
                        follow_redirects=req.allow_redirects,
                    )
                except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
                    # сетевые/временные ошибки — ретраим
                    last_error = ErrorInfo(type=type(e).__name__, message=str(e), retryable=True)
                    should_retry = attempt + 1 < max_attempts
                    if not should_retry:
                        finished = _now_ts()
                        await self._cb.record_failure()
                        res = FetchResult(
                            request=req,
                            ok=False,
                            status_code=None,
                            url=req.url,
                            started_at=started,
                            finished_at=finished,
                            elapsed_ms=int((finished - started) * 1000),
                            bytes_read=0,
                            error=last_error,
                        )
                        await self._emit_error(req, last_error)
                        return res
                else:
                    # Убедимся, что тело прочитано — это освобождает соединение.
                    # Даём возможность transform прочитать заранее загруженное содержимое.
                    content = await resp.aread()
                    bytes_read = len(content)
                    status = resp.status_code

                    if status < 400:
                        # Успех
                        data: Optional[Any] = None
                        if self._transform:
                            try:
                                data = await self._transform(resp)
                            except Exception as tr_err:
                                # Трансформация — неуспех, но без ретрая
                                finished = _now_ts()
                                await self._cb.record_failure()
                                err = ErrorInfo(type="TransformError", message=str(tr_err), retryable=False)
                                res = FetchResult(
                                    request=req,
                                    ok=False,
                                    status_code=status,
                                    url=str(resp.url),
                                    started_at=started,
                                    finished_at=finished,
                                    elapsed_ms=int((finished - started) * 1000),
                                    bytes_read=bytes_read,
                                    headers=dict(resp.headers),
                                    error=err,
                                )
                                await self._emit_error(req, err)
                                return res

                        finished = _now_ts()
                        await self._cb.record_success()
                        res = FetchResult(
                            request=req,
                            ok=True,
                            status_code=status,
                            url=str(resp.url),
                            started_at=started,
                            finished_at=finished,
                            elapsed_ms=int((finished - started) * 1000),
                            bytes_read=bytes_read,
                            headers=dict(resp.headers),
                            data=data,
                        )
                        return res

                    # Ошибка HTTP
                    retryable = self._is_retryable_status(status)
                    last_error = ErrorInfo(
                        type=f"HTTP{status}",
                        message=resp.text[:512] if resp.text else "",
                        retryable=retryable,
                    )
                    if retryable and (attempt + 1) < max_attempts:
                        # Учитываем Retry-After
                        ra = self._retry_after_delay(resp) or 0.0
                        delay = max(ra, self._delay(attempt))
                        await asyncio.sleep(delay)
                        attempt += 1
                        continue

                    # Не ретраим — отдаём результат
                    finished = _now_ts()
                    # Для 4xx обычно не портим CB; для 5xx/429 — failure
                    if retryable:
                        await self._cb.record_failure()
                    else:
                        await self._cb.record_success()
                    res = FetchResult(
                        request=req,
                        ok=False,
                        status_code=status,
                        url=str(resp.url),
                        started_at=started,
                        finished_at=finished,
                        elapsed_ms=int((finished - started) * 1000),
                        bytes_read=bytes_read,
                        headers=dict(resp.headers),
                        error=last_error,
                    )
                    await self._emit_error(req, last_error)
                    return res

            # Дойдём сюда только после сетевой ошибки (исключение) с планом ретрая
            attempt += 1
            if attempt < max_attempts and last_error and last_error.retryable:
                delay = self._delay(attempt - 1)
                await asyncio.sleep(delay)

        # Если вышли из цикла — отдадим последнее состояние
        finished = _now_ts()
        await self._cb.record_failure()
        res = FetchResult(
            request=req,
            ok=False,
            status_code=None,
            url=req.url,
            started_at=started,
            finished_at=finished,
            elapsed_ms=int((finished - started) * 1000),
            bytes_read=0,
            error=last_error or ErrorInfo(type="Unknown", message="exhausted retries", retryable=False),
        )
        await self._emit_error(req, res.error)  # type: ignore[arg-type]
        return res

    async def _guarded_single(self, req: FetchRequest) -> FetchResult:
        try:
            return await self._single(req)
        except CircuitOpen as e:
            now = _now_ts()
            res = FetchResult(
                request=req,
                ok=False,
                status_code=None,
                url=req.url,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                bytes_read=0,
                error=ErrorInfo(type="CircuitOpen", message=str(e), retryable=True),
            )
            await self._emit_error(req, res.error)  # type: ignore[arg-type]
            return res
        except asyncio.CancelledError:
            now = _now_ts()
            res = FetchResult(
                request=req,
                ok=False,
                status_code=None,
                url=req.url,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                bytes_read=0,
                error=ErrorInfo(type="Cancelled", message="request cancelled", retryable=False),
            )
            await self._emit_error(req, res.error)  # type: ignore[arg-type]
            raise
        except Exception as e:
            now = _now_ts()
            err = ErrorInfo(type=type(e).__name__, message=str(e), retryable=False)
            res = FetchResult(
                request=req,
                ok=False,
                status_code=None,
                url=req.url,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                bytes_read=0,
                error=err,
            )
            await self._emit_error(req, err)
            return res

    async def run_iter(
        self,
        requests: Iterable[FetchRequest],
        *,
        yield_ok: bool = True,
        yield_failed: bool = True,
    ) -> AsyncGenerator[FetchResult, None]:
        """
        Основной потоковый режим: возвращает async-генератор результатов по мере готовности.
        """
        if self._closed:
            raise RuntimeError("BatchFetcher уже закрыт")

        client = await self._ensure_client()
        # Планируем задачи сразу, но ограничиваем по семафору внутри _single
        pending: set[asyncio.Task[FetchResult]] = set()

        loop = asyncio.get_event_loop()
        for req in requests:
            task = loop.create_task(self._guarded_single(req))
            pending.add(task)

        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    res = t.result()
                    # Внешний хук
                    await self._emit_result(res)
                    if (res.ok and yield_ok) or ((not res.ok) and yield_failed):
                        yield res
        finally:
            # Ничего дополнительно не делаем; клиент закрывается в close()
            ...

    async def run_collect(
        self,
        requests: Iterable[FetchRequest],
        *,
        include_failed: bool = True,
    ) -> List[FetchResult]:
        """
        Сбор всех результатов в память (для небольших батчей).
        """
        results: List[FetchResult] = []
        async for r in self.run_iter(requests, yield_ok=True, yield_failed=include_failed):
            results.append(r)
        return results

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._client and self._own_client:
            await self._client.aclose()

    async def __aenter__(self) -> "BatchFetcher":
        await self._ensure_client()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> Optional[bool]:
        await self.close()
        return None


# ------------------------------------------------------------------------------
# Публичный интерфейс
# ------------------------------------------------------------------------------

__all__ = [
    "FetchRequest",
    "FetchResult",
    "ErrorInfo",
    "BatchFetcher",
    "CircuitBreaker",
    "CircuitOpen",
    "TokenBucket",
]
