# physical_integration/adapters/resilience_adapter.py
from __future__ import annotations

import abc
import asyncio
import concurrent.futures
import contextlib
import dataclasses
import enum
import logging
import math
import os
import random
import threading
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generic,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

__all__ = [
    "ResilienceConfig",
    "ResilienceMetrics",
    "CircuitBreakerState",
    "CircuitOpenError",
    "RateLimitExceededError",
    "OperationTimeoutError",
    "FatalOperationError",
    "ResilienceAdapter",
]

T = TypeVar("T")


# =========================
# Exceptions
# =========================

class CircuitOpenError(RuntimeError):
    pass

class RateLimitExceededError(RuntimeError):
    pass

class OperationTimeoutError(TimeoutError):
    pass

class FatalOperationError(RuntimeError):
    pass


# =========================
# Config and Metrics
# =========================

@dataclass(frozen=True)
class ResilienceConfig:
    # Retry
    max_retries: int = 3
    backoff_initial_s: float = 0.05
    backoff_max_s: float = 2.0
    backoff_multiplier: float = 2.0
    backoff_jitter_s: float = 0.02  # добавляется равномерный джиттер ±j

    # Timeout
    call_timeout_s: Optional[float] = 3.0  # None = без таймаута

    # Circuit Breaker
    cb_failure_threshold: int = 5            # сколько подряд неудач до OPEN
    cb_recovery_timeout_s: float = 10.0      # пауза до HALF_OPEN
    cb_half_open_probe_count: int = 2        # сколько успешных проб для CLOSE

    # Bulkhead (ограничение параллелизма)
    bulkhead_limit: int = 8                  # 0/None = без ограничения

    # Rate Limiting (token bucket)
    rate_limit_per_sec: Optional[float] = None  # средняя скорость (токен/сек)
    rate_burst: int = 1                          # емкость бака

    # Ошибки: пользовательский классификатор, True = ретраится
    # сигнатура: (exc: BaseException) -> bool
    error_classifier: Optional[Callable[[BaseException], bool]] = None

    # Лейблы для метрик/логов
    service_name: str = "device"
    resource_id: Optional[str] = None

    # Таймаут для попытки Acquire у лимитеров (rate/bulkhead)
    guard_acquire_timeout_s: float = 5.0


@dataclass
class ResilienceMetrics:
    # Счётчики
    calls_total: int = 0
    calls_succeeded: int = 0
    calls_failed: int = 0
    calls_timed_out: int = 0
    calls_retried: int = 0
    rate_limited: int = 0
    bulkhead_blocked: int = 0
    breaker_open_rejects: int = 0

    # Времена
    last_latency_s: Optional[float] = None
    sum_latency_s: float = 0.0

    # Circuit
    cb_state: "CircuitBreakerState" = field(default_factory=lambda: CircuitBreakerState.CLOSED)
    cb_failures: int = 0

    # Пользовательский экспорт
    on_export: Optional[Callable[[Mapping[str, Any]], None]] = None

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def export(self) -> Dict[str, Any]:
        with self._lock:
            data = dataclasses.asdict(self)
        if self.on_export:
            try:
                self.on_export(data)
            except Exception:
                # не ломаем рабочий поток из‑за экспорта метрик
                pass
        return data

    def record_latency(self, value: float) -> None:
        with self._lock:
            self.last_latency_s = value
            self.sum_latency_s += value

    def inc(self, field_name: str, inc_by: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + inc_by)


# =========================
# Retry policy
# =========================

class _RetryPolicy:
    def __init__(self, cfg: ResilienceConfig) -> None:
        self.cfg = cfg
        self._is_retriable = cfg.error_classifier or self._default_transient

    @staticmethod
    def _default_transient(exc: BaseException) -> bool:
        # Консервативный набор временных ошибок
        transient_types: Tuple[Type[BaseException], ...] = (
            TimeoutError,
            ConnectionError,
            InterruptedError,
            OSError,
        )
        return isinstance(exc, transient_types)

    def should_retry(self, exc: BaseException, attempt: int) -> bool:
        if attempt >= self.cfg.max_retries:
            return False
        try:
            return bool(self._is_retriable(exc))
        except Exception:
            return False

    def delay_for(self, attempt: int) -> float:
        # экспоненциальный рост с ограничением и симметричным джиттером
        base = min(
            self.cfg.backoff_initial_s * (self.cfg.backoff_multiplier ** max(0, attempt - 1)),
            self.cfg.backoff_max_s,
        )
        j = self.cfg.backoff_jitter_s
        if j > 0:
            base += random.uniform(-j, j)
        return max(0.0, base)


# =========================
# Circuit Breaker
# =========================

class CircuitBreakerState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class _CircuitBreaker:
    def __init__(self, cfg: ResilienceConfig, metrics: ResilienceMetrics, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self.logger = logger

        self._state = CircuitBreakerState.CLOSED
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_successes = 0
        self._lock = threading.Lock()

    def state(self) -> CircuitBreakerState:
        with self._lock:
            return self._state

    def on_success(self) -> None:
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.cfg.cb_half_open_probe_count:
                    self._close_locked()
            else:
                # в CLOSED любая удача сбрасывает счётчик ошибок
                self._failures = 0
                self.metrics.cb_failures = 0
        self.metrics.cb_state = self.state()

    def on_failure(self, exc: BaseException) -> None:
        with self._lock:
            if self._state == CircuitBreakerState.CLOSED:
                self._failures += 1
                self.metrics.cb_failures = self._failures
                if self._failures >= self.cfg.cb_failure_threshold:
                    self._open_locked()
            elif self._state == CircuitBreakerState.HALF_OPEN:
                # в HALF_OPEN любой фэйл снова открывает
                self._open_locked()
        self.metrics.cb_state = self.state()

    def guard(self) -> None:
        now = time.time()
        with self._lock:
            if self._state == CircuitBreakerState.OPEN:
                if self._opened_at is not None and (now - self._opened_at) >= self.cfg.cb_recovery_timeout_s:
                    self._to_half_open_locked()
                else:
                    raise CircuitOpenError("circuit breaker open")
            # CLOSED и HALF_OPEN разрешают выполнение

    def _open_locked(self) -> None:
        self._state = CircuitBreakerState.OPEN
        self._opened_at = time.time()
        self._half_open_successes = 0
        self.logger.warning("Circuit breaker OPEN for %s/%s", self.cfg.service_name, self.cfg.resource_id)

    def _to_half_open_locked(self) -> None:
        self._state = CircuitBreakerState.HALF_OPEN
        self._half_open_successes = 0
        self.logger.info("Circuit breaker HALF_OPEN for %s/%s", self.cfg.service_name, self.cfg.resource_id)

    def _close_locked(self) -> None:
        self._state = CircuitBreakerState.CLOSED
        self._failures = 0
        self._opened_at = None
        self._half_open_successes = 0
        self.logger.info("Circuit breaker CLOSED for %s/%s", self.cfg.service_name, self.cfg.resource_id)


# =========================
# Bulkhead and Rate limiter
# =========================

class _Bulkhead:
    def __init__(self, limit: Optional[int]) -> None:
        self._sem_sync: Optional[threading.Semaphore] = None
        self._sem_async: Optional[asyncio.Semaphore] = None
        if limit and limit > 0:
            self._sem_sync = threading.Semaphore(limit)
            self._sem_async = asyncio.Semaphore(limit)

    # sync
    def acquire(self, timeout: Optional[float]) -> bool:
        if self._sem_sync is None:
            return True
        return self._sem_sync.acquire(timeout=timeout if timeout and timeout > 0 else None)

    def release(self) -> None:
        if self._sem_sync is not None:
            self._sem_sync.release()

    # async
    async def acquire_async(self, timeout: Optional[float]) -> bool:
        if self._sem_async is None:
            return True
        if timeout is None or timeout <= 0:
            await self._sem_async.acquire()
            return True
        try:
            await asyncio.wait_for(self._sem_async.acquire(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def release_async(self) -> None:
        if self._sem_async is not None:
            self._sem_async.release()


class _TokenBucket:
    def __init__(self, rate_per_sec: Optional[float], burst: int) -> None:
        self.rate = rate_per_sec
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        if not self.rate:
            return
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed <= 0:
            return
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    # sync
    def acquire(self, timeout: Optional[float]) -> bool:
        if not self.rate:
            return True
        deadline = None if not timeout or timeout <= 0 else (time.monotonic() + timeout)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.001)

    # async
    async def acquire_async(self, timeout: Optional[float]) -> bool:
        if not self.rate:
            return True
        deadline = None if not timeout or timeout <= 0 else (asyncio.get_running_loop().time() + timeout)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if deadline is not None and asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.001)


# =========================
# Core Adapter
# =========================

class ResilienceAdapter(Generic[T]):
    """
    Универсальный адаптер устойчивости для вызовов к физическим устройствам/драйверам.

    Поддержка:
      - Circuit Breaker (CLOSED/OPEN/HALF_OPEN)
      - Retry с экспоненциальным backoff и джиттером
      - Таймаут исполнения (sync: Future.result(timeout), async: asyncio.wait_for)
      - Bulkhead (ограничение параллельности)
      - Token Bucket Rate Limiter
      - Настраиваемый классификатор ошибок (transient vs. fatal)
      - Fallback-функция
      - Метрики и логирование

    Пример использования (sync):

        adapter = ResilienceAdapter(ResilienceConfig(service_name="modbus", resource_id="inv-01"))
        def read_registers():
            return modbus.read_input_registers(addr=100, count=4)
        value = adapter.execute(read_registers, op_name="read_registers")

    Пример использования (async):

        adapter = ResilienceAdapter(ResilienceConfig(service_name="opcua", resource_id="robot-02"))
        async def read_node():
            return await opcua.read("ns=2;s=Temp")
        value = await adapter.aexecute(read_node, op_name="read_node")
    """

    def __init__(
        self,
        cfg: ResilienceConfig,
        logger: Optional[logging.Logger] = None,
        metrics: Optional[ResilienceMetrics] = None,
        executor: Optional[concurrent.futures.ThreadPoolExecutor] = None,
    ) -> None:
        self.cfg = cfg
        self.logger = logger or logging.getLogger(f"resilience.{cfg.service_name}.{cfg.resource_id or 'default'}")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
            self.logger.addHandler(h)
            self.logger.setLevel(logging.INFO)

        self.metrics = metrics or ResilienceMetrics()
        self._retry = _RetryPolicy(cfg)
        self._breaker = _CircuitBreaker(cfg, self.metrics, self.logger)
        self._bulkhead = _Bulkhead(cfg.bulkhead_limit)
        self._bucket = _TokenBucket(cfg.rate_limit_per_sec, cfg.rate_burst)
        self._executor_external = executor is not None
        self._executor = executor or concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 4) * 2),
            thread_name_prefix="resilience-exec",
        )

    # ========== Public API (sync) ==========

    def execute(
        self,
        fn: Callable[[], T],
        *,
        op_name: str = "operation",
        fallback: Optional[Callable[[BaseException], T]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> T:
        """Синхронный вызов с устойчивостью."""
        self.metrics.inc("calls_total")
        start = time.monotonic()

        # Rate limit
        if not self._bucket.acquire(self.cfg.guard_acquire_timeout_s):
            self.metrics.inc("rate_limited")
            self.logger.warning("Rate limited: %s", op_name)
            raise RateLimitExceededError(f"rate limit exceeded for {op_name}")

        # Bulkhead
        if not self._bulkhead.acquire(self.cfg.guard_acquire_timeout_s):
            self.metrics.inc("bulkhead_blocked")
            self.logger.warning("Bulkhead blocked: %s", op_name)
            raise FatalOperationError(f"bulkhead limit exceeded for {op_name}")

        try:
            # Circuit check
            try:
                self._breaker.guard()
            except CircuitOpenError:
                self.metrics.inc("breaker_open_rejects")
                self.logger.warning("Circuit open reject: %s", op_name)
                raise

            attempt = 0
            while True:
                attempt += 1
                try:
                    result = self._run_with_timeout_sync(fn, self.cfg.call_timeout_s)
                    self._breaker.on_success()
                    latency = time.monotonic() - start
                    self.metrics.record_latency(latency)
                    self.metrics.inc("calls_succeeded")
                    self._log_ok(op_name, latency, attempt, context)
                    return result
                except OperationTimeoutError as e:
                    self.metrics.inc("calls_timed_out")
                    self._breaker.on_failure(e)
                    if self._retry.should_retry(e, attempt):
                        self.metrics.inc("calls_retried")
                        delay = self._retry.delay_for(attempt)
                        self._log_retry(op_name, attempt, delay, e)
                        time.sleep(delay)
                        continue
                    self._log_fail(op_name, attempt, e)
                    if fallback:
                        return fallback(e)
                    raise
                except BaseException as e:
                    # Классификация ошибок
                    is_retry = self._retry.should_retry(e, attempt)
                    if is_retry:
                        self.metrics.inc("calls_retried")
                        self._breaker.on_failure(e)
                        delay = self._retry.delay_for(attempt)
                        self._log_retry(op_name, attempt, delay, e)
                        time.sleep(delay)
                        continue
                    else:
                        self._breaker.on_failure(e)
                        self._log_fail(op_name, attempt, e)
                        if fallback:
                            return fallback(e)
                        raise
        finally:
            self._bulkhead.release()
            self.metrics.export()

    # ========== Public API (async) ==========

    async def aexecute(
        self,
        fn: Callable[[], Awaitable[T]],
        *,
        op_name: str = "operation",
        fallback: Optional[Callable[[BaseException], T | Awaitable[T]]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> T:
        """Асинхронный вызов с устойчивостью."""
        self.metrics.inc("calls_total")
        start = time.monotonic()

        # Rate limit
        if not await self._bucket.acquire_async(self.cfg.guard_acquire_timeout_s):
            self.metrics.inc("rate_limited")
            self.logger.warning("Rate limited: %s", op_name)
            raise RateLimitExceededError(f"rate limit exceeded for {op_name}")

        # Bulkhead
        if not await self._bulkhead.acquire_async(self.cfg.guard_acquire_timeout_s):
            self.metrics.inc("bulkhead_blocked")
            self.logger.warning("Bulkhead blocked: %s", op_name)
            raise FatalOperationError(f"bulkhead limit exceeded for {op_name}")

        try:
            # Circuit check
            try:
                self._breaker.guard()
            except CircuitOpenError:
                self.metrics.inc("breaker_open_rejects")
                self.logger.warning("Circuit open reject: %s", op_name)
                raise

            attempt = 0
            while True:
                attempt += 1
                try:
                    result = await self._run_with_timeout_async(fn, self.cfg.call_timeout_s)
                    self._breaker.on_success()
                    latency = time.monotonic() - start
                    self.metrics.record_latency(latency)
                    self.metrics.inc("calls_succeeded")
                    self._log_ok(op_name, latency, attempt, context)
                    return result
                except OperationTimeoutError as e:
                    self.metrics.inc("calls_timed_out")
                    self._breaker.on_failure(e)
                    if self._retry.should_retry(e, attempt):
                        self.metrics.inc("calls_retried")
                        delay = self._retry.delay_for(attempt)
                        self._log_retry(op_name, attempt, delay, e)
                        await asyncio.sleep(delay)
                        continue
                    self._log_fail(op_name, attempt, e)
                    if fallback:
                        if asyncio.iscoroutinefunction(fallback):  # type: ignore
                            return await fallback(e)  # type: ignore
                        return fallback(e)  # type: ignore
                    raise
                except BaseException as e:
                    is_retry = self._retry.should_retry(e, attempt)
                    if is_retry:
                        self.metrics.inc("calls_retried")
                        self._breaker.on_failure(e)
                        delay = self._retry.delay_for(attempt)
                        self._log_retry(op_name, attempt, delay, e)
                        await asyncio.sleep(delay)
                        continue
                    else:
                        self._breaker.on_failure(e)
                        self._log_fail(op_name, attempt, e)
                        if fallback:
                            if asyncio.iscoroutinefunction(fallback):  # type: ignore
                                return await fallback(e)  # type: ignore
                            return fallback(e)  # type: ignore
                        raise
        finally:
            self._bulkhead.release_async()
            self.metrics.export()

    # ========== Convenience wrappers ==========

    def read(self, fn: Callable[[], T], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return self.execute(fn, op_name="read", context=context)

    async def aread(self, fn: Callable[[], Awaitable[T]], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return await self.aexecute(fn, op_name="read", context=context)

    def write(self, fn: Callable[[], T], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return self.execute(fn, op_name="write", context=context)

    async def awrite(self, fn: Callable[[], Awaitable[T]], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return await self.aexecute(fn, op_name="write", context=context)

    def command(self, fn: Callable[[], T], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return self.execute(fn, op_name="command", context=context)

    async def acommand(self, fn: Callable[[], Awaitable[T]], *, context: Optional[Mapping[str, Any]] = None) -> T:
        return await self.aexecute(fn, op_name="command", context=context)

    # ========== Internals (timeouts) ==========

    def _run_with_timeout_sync(self, fn: Callable[[], T], timeout: Optional[float]) -> T:
        if timeout is None or timeout <= 0:
            return fn()
        future = self._executor.submit(fn)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # отменяем выполнение; в общем случае отмена не гарантируется
            self._cancel_future(future)
            raise OperationTimeoutError("operation timed out")

    async def _run_with_timeout_async(self, fn: Callable[[], Awaitable[T]], timeout: Optional[float]) -> T:
        coro = fn()
        if timeout is None or timeout <= 0:
            return await coro
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            raise OperationTimeoutError("operation timed out")

    @staticmethod
    def _cancel_future(fut: concurrent.futures.Future) -> None:
        try:
            fut.cancel()
        except Exception:
            pass

    # ========== Logging helpers ==========

    def _log_ok(self, op_name: str, latency: float, attempt: int, context: Optional[Mapping[str, Any]]) -> None:
        self.logger.info(
            "OK op=%s svc=%s res=%s attempt=%d latency_s=%.6f",
            op_name, self.cfg.service_name, self.cfg.resource_id, attempt, latency,
        )

    def _log_retry(self, op_name: str, attempt: int, delay: float, exc: BaseException) -> None:
        self.logger.warning(
            "RETRY op=%s svc=%s res=%s attempt=%d delay_s=%.3f exc=%s",
            op_name, self.cfg.service_name, self.cfg.resource_id, attempt, delay, repr(exc),
        )

    def _log_fail(self, op_name: str, attempt: int, exc: BaseException) -> None:
        self.logger.error(
            "FAIL op=%s svc=%s res=%s attempt=%d exc=%s",
            op_name, self.cfg.service_name, self.cfg.resource_id, attempt, repr(exc),
        )

    # ========== Lifecycle ==========

    def close(self) -> None:
        if not self._executor_external:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> "ResilienceAdapter[T]":
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        self.close()
