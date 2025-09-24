# chronowatch-core/chronowatch/adapters/resilience_adapter.py
# Production-grade resilience adapter for ChronoWatch Core.
# Python 3.11+. No required third-party deps (Prometheus metrics optional).

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import dataclasses
import functools
import logging
import os
import random
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Deque, Dict, Generic, Iterable, Optional, Tuple, Type, TypeVar, Union

T = TypeVar("T")
R = TypeVar("R")

# ------------------------------------------------------------------------------
# Optional Prometheus metrics
# ------------------------------------------------------------------------------
HAS_PROM = False
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    HAS_PROM = True
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

if HAS_PROM:
    METRIC_CALLS = Counter(
        "cw_resilience_calls_total",
        "Resilience wrapped calls",
        ["name", "result"],
    )
    METRIC_LATENCY = Histogram(
        "cw_resilience_latency_seconds",
        "Latency of wrapped calls",
        ["name"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
else:
    METRIC_CALLS = METRIC_LATENCY = None  # type: ignore

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
LOG = logging.getLogger("chronowatch.resilience")
if not LOG.handlers:
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )

corr_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("corr", default=None)


# ------------------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------------------
class ResilienceError(Exception):
    pass


class CircuitOpenError(ResilienceError):
    pass


class TimeoutExceededError(ResilienceError):
    pass


class BulkheadFullError(ResilienceError):
    pass


class RateLimitExceededError(ResilienceError):
    pass


# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
@dataclass(slots=True)
class CircuitConfig:
    failure_ratio_threshold: float = 0.5        # доля неуспехов в окне
    min_samples: int = 20                      # мин. событий до триггера
    window_seconds: float = 30.0               # скользящее окно
    open_seconds: float = 30.0                 # длительность OPEN
    half_open_max_calls: int = 5               # тестовые вызовы в HALF_OPEN


@dataclasses.dataclass(slots=True)
class RetryConfig:
    max_attempts: int = 4                       # всего попыток (включая первую)
    base_delay: float = 0.05                    # сек (экспонента)
    max_delay: float = 2.0
    max_elapsed: float | None = None            # общий лимит времени ретраев
    jitter: str = "full"                        # none|full|equal
    retry_on: Tuple[Type[BaseException], ...] = (
        TimeoutError, ConnectionError, OSError
    )


@dataclass(slots=True)
class TimeoutConfig:
    seconds: float = 5.0


@dataclass(slots=True)
class BulkheadConfig:
    max_concurrent_async: int = 64
    max_concurrent_sync: int = 32
    queue_warn_threshold: int = 100             # только для наблюдаемости


@dataclass(slots=True)
class RateLimitConfig:
    rate_per_sec: float = 0.0                   # 0 = выключено
    burst: int = 1


@dataclass(slots=True)
class HedgingConfig:
    enabled: bool = False
    delay_seconds: float = 0.05                 # через сколько подать дубль
    max_hedges: int = 1                         # сколько дублей максимум
    idempotent: bool = True                     # применять только к идемпотентным операциям


@dataclass(slots=True)
class CacheConfig:
    success_ttl_seconds: float = 0.0            # 0 = выключено
    max_entries: int = 1000


@dataclass(slots=True)
class ResilienceConfig:
    name: str = "default"
    timeout: TimeoutConfig = TimeoutConfig()
    retry: RetryConfig = RetryConfig()
    circuit: CircuitConfig = CircuitConfig()
    bulkhead: BulkheadConfig = BulkheadConfig()
    ratelimit: RateLimitConfig = RateLimitConfig()
    hedging: HedgingConfig = HedgingConfig()
    cache: CacheConfig = CacheConfig()


# ------------------------------------------------------------------------------
# Circuit Breaker
# ------------------------------------------------------------------------------
class CircuitState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, cfg: CircuitConfig, time_fn: Callable[[], float] = time.monotonic) -> None:
        self._cfg = cfg
        self._time = time_fn
        self._state = CircuitState.CLOSED
        self._opened_at = 0.0
        self._half_open_inflight = 0
        self._events: Deque[Tuple[float, bool]] = deque()  # (ts, success)
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        w = self._cfg.window_seconds
        while self._events and now - self._events[0][0] > w:
            self._events.popleft()

    def _stats(self, now: float) -> Tuple[int, int, float]:
        self._prune(now)
        total = len(self._events)
        failures = sum(1 for _, ok in self._events if not ok)
        ratio = (failures / total) if total else 0.0
        return total, failures, ratio

    def allow(self) -> None:
        with self._lock:
            now = self._time()
            if self._state == CircuitState.OPEN:
                if now - self._opened_at >= self._cfg.open_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_inflight = 0
                else:
                    raise CircuitOpenError("Circuit is OPEN")
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_inflight >= self._cfg.half_open_max_calls:
                    raise CircuitOpenError("Circuit is HALF_OPEN capacity reached")
                self._half_open_inflight += 1

    def on_result(self, success: bool) -> None:
        with self._lock:
            now = self._time()
            self._events.append((now, success))
            if self._state == CircuitState.CLOSED:
                total, _fail, ratio = self._stats(now)
                if total >= self._cfg.min_samples and ratio >= self._cfg.failure_ratio_threshold:
                    self._state = CircuitState.OPEN
                    self._opened_at = now
                    LOG.warning("Circuit opened (ratio=%.2f, total=%d)", ratio, total)
                return

            if self._state == CircuitState.HALF_OPEN:
                if not success:
                    self._state = CircuitState.OPEN
                    self._opened_at = now
                    self._half_open_inflight = 0
                    LOG.warning("Circuit re-opened due to failure in HALF_OPEN")
                else:
                    # если все тестовые прошли — закрываем
                    # допускаем закрытие, когда нет параллельных тестов
                    if self._half_open_inflight > 0:
                        self._half_open_inflight -= 1
                    if self._half_open_inflight == 0:
                        # Проверим, что в окне приемлемая доля ошибок
                        total, _fail, ratio = self._stats(now)
                        if ratio < self._cfg.failure_ratio_threshold:
                            self._state = CircuitState.CLOSED
                            LOG.info("Circuit closed after HALF_OPEN success")
            elif self._state == CircuitState.OPEN:
                # игнорируем результаты (запросы не должны доходить)
                pass

    @property
    def state(self) -> str:
        with self._lock:
            return self._state


# ------------------------------------------------------------------------------
# Bulkhead
# ------------------------------------------------------------------------------
class AsyncBulkhead:
    def __init__(self, permits: int) -> None:
        self._sem = asyncio.Semaphore(permits)

    async def acquire(self) -> None:
        await self._sem.acquire()

    def release(self) -> None:
        self._sem.release()


class SyncBulkhead:
    def __init__(self, permits: int) -> None:
        self._sem = threading.Semaphore(permits)

    def __enter__(self) -> None:
        if not self._sem.acquire(blocking=False):
            raise BulkheadFullError("Bulkhead is full")

    def __exit__(self, exc_type, exc, tb) -> None:
        self._sem.release()


# ------------------------------------------------------------------------------
# Rate Limiter (token bucket)
# ------------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int, time_fn: Callable[[], float] = time.monotonic) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self._time = time_fn
        self._ts = self._time()
        self._lock = threading.Lock()

    def _refill(self, now: float) -> None:
        if self.rate <= 0.0:
            return
        delta = max(0.0, now - self._ts)
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self._ts = now

    def try_consume(self, tokens: float = 1.0) -> bool:
        if self.rate <= 0.0:
            return True
        with self._lock:
            now = self._time()
            self._refill(now)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_time(self, tokens: float = 1.0) -> float:
        if self.rate <= 0.0:
            return 0.0
        with self._lock:
            now = self._time()
            self._refill(now)
            deficit = max(0.0, tokens - self.tokens)
            return deficit / self.rate if self.rate > 0 else float("inf")


# ------------------------------------------------------------------------------
# In-flight dedup/cache
# ------------------------------------------------------------------------------
class TTLCache:
    def __init__(self, ttl: float, max_entries: int) -> None:
        self.ttl = ttl
        self.max = max_entries
        self._data: Dict[Any, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Tuple[bool, Any | None]:
        if self.ttl <= 0:
            return False, None
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if not item:
                return False, None
            ts, val = item
            if now - ts > self.ttl:
                self._data.pop(key, None)
                return False, None
            return True, val

    def set(self, key: Any, val: Any) -> None:
        if self.ttl <= 0:
            return
        now = time.monotonic()
        with self._lock:
            if len(self._data) >= self.max:
                # простая эвикция: удалить самый старый
                oldest = min(self._data.items(), key=lambda kv: kv[1][0])[0]
                self._data.pop(oldest, None)
            self._data[key] = (now, val)


# ------------------------------------------------------------------------------
# Adapter
# ------------------------------------------------------------------------------
class ResilienceAdapter:
    """
    Универсальный адаптер устойчивости: декоратор с retry/timeout/circuit/bulkhead/ratelimit/hedging/fallback.
    """

    def __init__(
        self,
        cfg: ResilienceConfig,
        *,
        fallback: Callable[..., Any] | None = None,
        idempotency_key_fn: Callable[[Tuple[Any, ...], Dict[str, Any]], Any] | None = None,
    ) -> None:
        self.cfg = cfg
        self.fallback = fallback
        self.idempotency_key_fn = idempotency_key_fn
        self._circuit = CircuitBreaker(cfg.circuit)
        self._bulk_async = AsyncBulkhead(cfg.bulkhead.max_concurrent_async)
        self._bulk_sync = SyncBulkhead(cfg.bulkhead.max_concurrent_sync)
        self._bucket = TokenBucket(cfg.ratelimit.rate_per_sec, cfg.ratelimit.burst)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(4, cfg.bulkhead.max_concurrent_sync)
        )
        self._cache = TTLCache(cfg.cache.success_ttl_seconds, cfg.cache.max_entries)
        self._inflight_lock = threading.Lock()
        self._inflight: Dict[Any, asyncio.Future] = {}

    # --------------------------
    # Public API
    # --------------------------
    def decorator(self, fn: Callable[..., R | Awaitable[R]]) -> Callable[..., Awaitable[R] | R]:
        """
        Декоратор, распознающий async/sync функции. Возвращает функцию того же типа.
        """
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def wrapper_async(*args: Any, **kwargs: Any) -> R:
                return await self._call_async(fn, args, kwargs)
            return wrapper_async  # type: ignore[return-value]
        else:
            @functools.wraps(fn)
            def wrapper_sync(*args: Any, **kwargs: Any) -> R:
                return self._call_sync(fn, args, kwargs)
            return wrapper_sync  # type: ignore[return-value]

    # alias
    __call__ = decorator

    # --------------------------
    # Core pipeline
    # --------------------------
    async def _call_async(self, fn: Callable[..., Awaitable[R]], args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> R:
        name = self.cfg.name
        start_ts = time.perf_counter()

        # Rate limit
        await self._rl_wait_async()

        # Bulkhead
        await self._bulk_async.acquire()
        try:
            # Circuit allow
            self._circuit.allow()
            try:
                res = await self._retry_async(lambda: self._with_timeout_async(fn, *args, **kwargs))
                self._circuit.on_result(True)
                self._observe(name, "ok", start_ts)
                self._cache_store(args, kwargs, res)
                return res
            except Exception as e:
                self._circuit.on_result(False)
                if self.fallback is not None:
                    LOG.warning("Fallback after failure: %s", e)
                    res = await _maybe_await(self.fallback(*args, **kwargs))
                    self._observe(name, "fallback", start_ts)
                    return res  # type: ignore[return-value]
                self._observe(name, "error", start_ts)
                raise
        except CircuitOpenError:
            if self.fallback is not None:
                res = await _maybe_await(self.fallback(*args, **kwargs))
                self._observe(name, "fallback", start_ts)
                return res  # type: ignore[return-value]
            self._observe(name, "circuit_open", start_ts)
            raise
        finally:
            self._bulk_async.release()

    def _call_sync(self, fn: Callable[..., R], args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> R:
        name = self.cfg.name
        start_ts = time.perf_counter()

        # Cache hit
        ok, cached = self._cache_get(args, kwargs)
        if ok:
            self._observe(name, "cache", start_ts)
            return cached  # type: ignore[return-value]

        # Rate limit
        self._rl_wait_sync()

        # Bulkhead
        with self._bulk_sync:
            # Circuit allow
            self._circuit.allow()
            try:
                res = self._retry_sync(lambda: self._with_timeout_sync(fn, *args, **kwargs))
                self._circuit.on_result(True)
                self._observe(name, "ok", start_ts)
                self._cache_store(args, kwargs, res)
                return res
            except Exception as e:
                self._circuit.on_result(False)
                if self.fallback is not None:
                    LOG.warning("Fallback after failure: %s", e)
                    res = self.fallback(*args, **kwargs)
                    self._observe(name, "fallback", start_ts)
                    return res  # type: ignore[return-value]
                self._observe(name, "error", start_ts)
                raise

    # --------------------------
    # Retry with backoff + jitter
    # --------------------------
    async def _retry_async(self, call: Callable[[], Awaitable[R]]) -> R:
        cfg = self.cfg.retry
        attempt = 0
        first_ts = time.monotonic()

        # Hedging: запускаем дубль после задержки
        if self.cfg.hedging.enabled and self.cfg.hedging.idempotent:
            return await self._hedge_async(call)

        while True:
            try:
                # In-flight dedup (async) — ключ опционален
                key = self._idempotency_key()
                if key is not None:
                    result = await self._dedup_inflight_async(key, call)
                else:
                    result = await call()
                return result
            except Exception as e:
                attempt += 1
                if not _should_retry(e, cfg.retry_on):
                    raise
                if attempt >= cfg.max_attempts:
                    raise
                if cfg.max_elapsed is not None and (time.monotonic() - first_ts) > cfg.max_elapsed:
                    raise
                delay = _backoff_delay(attempt, cfg.base_delay, cfg.max_delay, cfg.jitter)
                await asyncio.sleep(delay)

    def _retry_sync(self, call: Callable[[], R]) -> R:
        cfg = self.cfg.retry
        attempt = 0
        first_ts = time.monotonic()
        while True:
            try:
                return call()
            except Exception as e:
                attempt += 1
                if not _should_retry(e, cfg.retry_on):
                    raise
                if attempt >= cfg.max_attempts:
                    raise
                if cfg.max_elapsed is not None and (time.monotonic() - first_ts) > cfg.max_elapsed:
                    raise
                delay = _backoff_delay(attempt, cfg.base_delay, cfg.max_delay, cfg.jitter)
                time.sleep(delay)

    # --------------------------
    # Timeout
    # --------------------------
    async def _with_timeout_async(self, fn: Callable[..., Awaitable[R]], *args: Any, **kwargs: Any) -> R:
        timeout = self.cfg.timeout.seconds
        # Cache hit before фактического вызова
        ok, cached = self._cache_get(args, kwargs)
        if ok:
            return cached  # type: ignore[return-value]
        try:
            return await asyncio.wait_for(fn(*args, **kwargs), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutExceededError(f"Timeout {timeout}s") from e

    def _with_timeout_sync(self, fn: Callable[..., R], *args: Any, **kwargs: Any) -> R:
        timeout = self.cfg.timeout.seconds

        def _call() -> R:
            return fn(*args, **kwargs)

        future = self._executor.submit(_call)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as e:
            future.cancel()
            raise TimeoutExceededError(f"Timeout {timeout}s") from e

    # --------------------------
    # Rate limit wait
    # --------------------------
    def _rl_wait_sync(self) -> None:
        wait = self._bucket.wait_time(1.0)
        if wait > 0:
            time.sleep(wait)
        if not self._bucket.try_consume(1.0):
            # в высококонкурентной гонке может не хватить токена
            raise RateLimitExceededError("Rate limit exceeded")

    async def _rl_wait_async(self) -> None:
        wait = self._bucket.wait_time(1.0)
        if wait > 0:
            await asyncio.sleep(wait)
        if not self._bucket.try_consume(1.0):
            # в высококонкурентной гонке может не хватить токена
            raise RateLimitExceededError("Rate limit exceeded")

    # --------------------------
    # Hedging (async)
    # --------------------------
    async def _hedge_async(self, call: Callable[[], Awaitable[R]]) -> R:
        cfg = self.cfg.hedging
        if not cfg.enabled:
            return await call()
        tasks = [asyncio.create_task(call())]
        await asyncio.sleep(cfg.delay_seconds)
        for _ in range(cfg.max_hedges):
            tasks.append(asyncio.create_task(call()))
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for d in done:
                try:
                    result = d.result()
                    for p in pending:
                        p.cancel()
                    return result
                except Exception:
                    # если первый завершился ошибкой — даём еще одному шанс
                    tasks = list(pending)
                    break
        # если все закончили ошибкой
        results = await asyncio.gather(*tasks, return_exceptions=True)
        last_exc = next((r for r in results if isinstance(r, Exception)), RuntimeError("All hedged calls failed"))
        if isinstance(last_exc, Exception):
            raise last_exc
        return results[-1]  # pragma: no cover

    # --------------------------
    # Cache helpers
    # --------------------------
    def _cache_key(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any | None:
        if self.cfg.cache.success_ttl_seconds <= 0:
            return None
        if self.idempotency_key_fn:
            try:
                return self.idempotency_key_fn(args, kwargs)
            except Exception:
                return None
        # дефолтный ключ: позиционные/именованные аргументы
        try:
            return (args, tuple(sorted(kwargs.items())))
        except Exception:
            return None

    def _cache_get(self, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Tuple[bool, Any | None]:
        key = self._cache_key(args, kwargs)
        if key is None:
            return False, None
        return self._cache.get(key)

    def _cache_store(self, args: Tuple[Any, ...], kwargs: Dict[str, Any], value: Any) -> None:
        key = self._cache_key(args, kwargs)
        if key is None:
            return
        self._cache.set(key, value)

    # --------------------------
    # In-flight dedup (async)
    # --------------------------
    def _idempotency_key(self) -> Any | None:
        if not self.cfg.hedging.idempotent:
            return None
        # применяем тот же ключ, что и для cache
        return object()  # по умолчанию отключено, только при явном ключе через idempotency_key_fn
        # Примечание: оставлено отключенным по умолчанию, чтобы не дедуплицировать разные вызовы без явного ключа.

    async def _dedup_inflight_async(self, key: Any, call: Callable[[], Awaitable[R]]) -> R:
        # Если уже есть запрос с таким ключом — возвращаем его результат
        with self._inflight_lock:
            fut = self._inflight.get(key)
            if fut is None:
                loop = asyncio.get_running_loop()
                fut = loop.create_future()
                self._inflight[key] = fut
                leader = True
            else:
                leader = False

        if leader:
            try:
                res = await call()
                fut.set_result(res)
                return res
            except Exception as e:
                fut.set_exception(e)
                raise
            finally:
                with self._inflight_lock:
                    self._inflight.pop(key, None)
        else:
            return await fut  # type: ignore[return-value]

    # --------------------------
    # Metrics
    # --------------------------
    def _observe(self, name: str, result: str, start_ts: float) -> None:
        if HAS_PROM and METRIC_CALLS and METRIC_LATENCY:
            try:
                METRIC_CALLS.labels(name=name, result=result).inc()
                METRIC_LATENCY.labels(name=name).observe(time.perf_counter() - start_ts)
            except Exception:  # pragma: no cover
                pass


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _should_retry(exc: BaseException, whitelist: Tuple[Type[BaseException], ...]) -> bool:
    return isinstance(exc, whitelist)


def _backoff_delay(attempt: int, base: float, mx: float, jitter: str) -> float:
    # экспонента: base * 2^(attempt-1), начиная со 2-й попытки
    raw = base * (2 ** max(0, attempt - 1))
    raw = min(raw, mx)
    if jitter == "none":
        return raw
    if jitter == "equal":
        return raw / 2 + random.random() * (raw / 2)
    # full jitter
    return random.random() * raw


async def _maybe_await(val: Any) -> Any:
    if asyncio.iscoroutine(val):
        return await val
    return val


# ------------------------------------------------------------------------------
# Public factory
# ------------------------------------------------------------------------------
def make_adapter(
    *,
    name: str = "external_call",
    timeout_s: float = 5.0,
    retry_attempts: int = 4,
    retry_base: float = 0.05,
    retry_max: float = 2.0,
    circuit_fail_ratio: float = 0.5,
    circuit_min_samples: int = 20,
    circuit_window_s: float = 30.0,
    circuit_open_s: float = 30.0,
    half_open_max_calls: int = 5,
    bulk_async: int = 64,
    bulk_sync: int = 32,
    rate_per_sec: float = 0.0,
    burst: int = 1,
    hedging_enabled: bool = False,
    hedge_delay_s: float = 0.05,
    cache_ttl_s: float = 0.0,
    cache_max: int = 1000,
    fallback: Callable[..., Any] | None = None,
    idempotency_key_fn: Callable[[Tuple[Any, ...], Dict[str, Any]], Any] | None = None,
) -> ResilienceAdapter:
    cfg = ResilienceConfig(
        name=name,
        timeout=TimeoutConfig(seconds=timeout_s),
        retry=RetryConfig(max_attempts=retry_attempts, base_delay=retry_base, max_delay=retry_max),
        circuit=CircuitConfig(
            failure_ratio_threshold=circuit_fail_ratio,
            min_samples=circuit_min_samples,
            window_seconds=circuit_window_s,
            open_seconds=circuit_open_s,
            half_open_max_calls=half_open_max_calls,
        ),
        bulkhead=BulkheadConfig(max_concurrent_async=bulk_async, max_concurrent_sync=bulk_sync),
        ratelimit=RateLimitConfig(rate_per_sec=rate_per_sec, burst=burst),
        hedging=HedgingConfig(enabled=hedging_enabled, delay_seconds=hedge_delay_s, idempotent=True),
        cache=CacheConfig(success_ttl_seconds=cache_ttl_s, max_entries=cache_max),
    )
    return ResilienceAdapter(cfg, fallback=fallback, idempotency_key_fn=idempotency_key_fn)


__all__ = [
    "ResilienceAdapter",
    "ResilienceConfig",
    "CircuitConfig",
    "RetryConfig",
    "TimeoutConfig",
    "BulkheadConfig",
    "RateLimitConfig",
    "HedgingConfig",
    "CacheConfig",
    "CircuitOpenError",
    "TimeoutExceededError",
    "BulkheadFullError",
    "RateLimitExceededError",
    "make_adapter",
]
