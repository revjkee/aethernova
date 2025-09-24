# neuroforge-core/neuroforge/adapters/resilience_adapter.py
from __future__ import annotations

import abc
import asyncio
import concurrent.futures
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)

# ========================= Исключения уровня адаптера =========================

class ResilienceError(Exception):
    pass

class TimeoutExceeded(ResilienceError):
    def __init__(self, attempt_timeout_ms: int) -> None:
        super().__init__(f"Attempt timed out after {attempt_timeout_ms} ms")
        self.attempt_timeout_ms = attempt_timeout_ms

class CircuitOpen(ResilienceError):
    pass

class RateLimited(ResilienceError):
    pass

# ========================= Политики и типы =========================

class JitterMode(str, Enum):
    NONE = "none"
    FULL = "full"            # delay * U(0,1)
    EQUAL = "equal"          # delay * U(0.5, 1.5)
    DECORRELATED = "decorrelated"  # AWS backoff

@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay_ms: int = 200
    backoff_factor: float = 2.0
    max_delay_ms: int = 5000
    jitter: JitterMode = JitterMode.EQUAL
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (TimeoutError, ConnectionError, OSError)
    # Возврат True означает "нужно повторить" на основании результата
    retry_on_result: Optional[Callable[[Any], bool]] = None
    # Если функция возвращает "код" (например HTTP), можно дать предикат по коду
    retry_on_status: Optional[Callable[[Any], bool]] = None
    # Индивидуальный таймаут на попытку
    attempt_timeout_ms: int = 30_000
    # Общий таймаут на все попытки (0 = без общего)
    overall_timeout_ms: int = 0

@dataclass
class CircuitBreakerOptions:
    failure_threshold: int = 5              # подряд неуспехов до OPEN
    recovery_timeout_ms: int = 15_000       # время в OPEN перед HALF-OPEN
    half_open_max_calls: int = 2            # пробных вызова в HALF-OPEN
    success_threshold: int = 1              # успехов для возврата в CLOSED

class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass
class BulkheadOptions:
    max_concurrent: int = 100

@dataclass
class TokenBucketOptions:
    rate_per_sec: float = 50.0    # скорость пополнения
    burst: int = 100              # ёмкость

# Набор хуков телеметрии
@dataclass
class TelemetryHooks:
    on_start: Optional[Callable[[Dict[str, Any]], None]] = None
    on_finish: Optional[Callable[[Dict[str, Any]], None]] = None
    on_retry: Optional[Callable[[Dict[str, Any]], None]] = None
    on_circuit_change: Optional[Callable[[Dict[str, Any]], None]] = None
    on_hedge_spawn: Optional[Callable[[Dict[str, Any]], None]] = None

@dataclass
class ResilienceConfig:
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    circuit: CircuitBreakerOptions = field(default_factory=CircuitBreakerOptions)
    bulkhead: BulkheadOptions = field(default_factory=BulkheadOptions)
    rate_limiter: Optional[TokenBucketOptions] = None
    telemetry: TelemetryHooks = field(default_factory=TelemetryHooks)
    # Hedging: запускаем доп. попытки по таймеру, уменьшая p95/99
    hedging_enabled: bool = False
    hedge_delays_ms: Tuple[int, ...] = ()  # например (100, 300) — две ставки
    # Пользовательские метки (пойдут в телеметрию)
    tags: Dict[str, Any] = field(default_factory=dict)

# ========================= Вспомогательные таймеры и джиттер =========================

def _now_ms() -> int:
    return int(time.time() * 1000)

def _sleep_sync(ms: int) -> None:
    time.sleep(max(0.0, ms / 1000.0))

async def _sleep_async(ms: int) -> None:
    await asyncio.sleep(max(0.0, ms / 1000.0))

def _apply_jitter(delay_ms: int, mode: JitterMode, prev_delay_ms: int) -> int:
    if delay_ms <= 0:
        return 0
    if mode == JitterMode.NONE:
        return delay_ms
    if mode == JitterMode.FULL:
        return int(random.random() * delay_ms)
    if mode == JitterMode.EQUAL:
        return int(delay_ms * (0.5 + random.random()))
    if mode == JitterMode.DECORRELATED:
        # decorrelated jitter (AWS)
        low = delay_ms / 2
        high = max(delay_ms, prev_delay_ms * 3)
        return int(min(high, max(0, low + random.random() * (high - low))))
    return delay_ms

# ========================= Circuit Breaker =========================

class CircuitBreaker:
    def __init__(self, opts: CircuitBreakerOptions, telemetry: TelemetryHooks) -> None:
        self._opts = opts
        self._state = CircuitState.CLOSED
        self._lock = threading.Lock()
        self._opened_at = 0
        self._consec_failures = 0
        self._half_open_inflight = 0
        self._half_open_success = 0
        self._telemetry = telemetry

    def state(self) -> CircuitState:
        with self._lock:
            return self._state

    def _emit(self) -> None:
        if self._telemetry.on_circuit_change:
            self._telemetry.on_circuit_change({
                "state": self._state.value,
                "failures": self._consec_failures,
                "opened_at": self._opened_at,
            })

    def pre_check(self) -> None:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if _now_ms() - self._opened_at >= self._opts.recovery_timeout_ms:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_inflight = 0
                    self._half_open_success = 0
                    self._emit()
                else:
                    raise CircuitOpen("Circuit is open")
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_inflight >= self._opts.half_open_max_calls:
                    raise CircuitOpen("Circuit half-open: probe limit reached")
                self._half_open_inflight += 1

    def on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                self._half_open_success += 1
                if self._half_open_success >= self._opts.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._consec_failures = 0
                    self._emit()
                return
            self._consec_failures = 0

    def on_failure(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = _now_ms()
                self._half_open_inflight = 0
                self._emit()
                return
            self._consec_failures += 1
            if self._consec_failures >= self._opts.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = _now_ms()
                self._emit()

# ========================= Bulkhead (semaphore) =========================

class Bulkhead:
    def __init__(self, opts: BulkheadOptions) -> None:
        self._sem = threading.Semaphore(opts.max_concurrent)

    def acquire(self, timeout_ms: int = 0) -> bool:
        if timeout_ms <= 0:
            return self._sem.acquire(blocking=True)
        return self._sem.acquire(timeout=max(0.0, timeout_ms / 1000.0))

    def release(self) -> None:
        self._sem.release()

class AsyncBulkhead:
    def __init__(self, opts: BulkheadOptions) -> None:
        self._sem = asyncio.Semaphore(opts.max_concurrent)

    async def acquire(self) -> None:
        await self._sem.acquire()

    def release(self) -> None:
        self._sem.release()

# ========================= Token Bucket =========================

class TokenBucket:
    def __init__(self, opts: TokenBucketOptions) -> None:
        self._rate = float(opts.rate_per_sec)
        self._capacity = float(opts.burst)
        self._tokens = float(opts.burst)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            delta = now - self._updated
            self._updated = now
            self._tokens = min(self._capacity, self._tokens + delta * self._rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

class AsyncTokenBucket:
    def __init__(self, opts: TokenBucketOptions) -> None:
        self._tb = TokenBucket(opts)

    async def allow(self, tokens: float = 1.0) -> bool:
        # асинхронная сигнатура для симметрии
        return self._tb.allow(tokens)

# ========================= Результат вызова =========================

@dataclass
class CallResult(Generic[T]):
    ok: bool
    value: Optional[T]
    error: Optional[BaseException]
    attempts: int
    duration_ms: int
    hedged: bool = False
    # Дополнительно можно проложить треск: список попыток, задержек, причин
    trace: List[Dict[str, Any]] = field(default_factory=list)

# ========================= Исполнитель (sync/async) =========================

class _ExecutorBase(abc.ABC):
    def __init__(self, cfg: ResilienceConfig) -> None:
        self.cfg = cfg
        self.cb = CircuitBreaker(cfg.circuit, cfg.telemetry)
        self.bulkhead = Bulkhead(cfg.bulkhead)
        self.rate = TokenBucket(cfg.rate_limiter) if cfg.rate_limiter else None
        self._tp: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._tp_lock = threading.Lock()

    def _threadpool(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._tp_lock:
            if self._tp is None:
                # Размер — приблизительный: вдвое больше bulkhead, минимум 4
                max_workers = max(4, self.cfg.bulkhead.max_concurrent * 2)
                self._tp = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="resilience")
            return self._tp

    def _should_retry(self, attempt: int, err: Optional[BaseException], result: Any) -> Tuple[bool, str]:
        pol = self.cfg.retry
        if attempt >= pol.max_retries:
            return False, "max_retries_reached"
        if err is not None:
            if isinstance(err, pol.retry_on_exceptions):
                return True, f"exception:{err.__class__.__name__}"
            # Внутренний таймаут адаптера
            if isinstance(err, TimeoutExceeded):
                return True, "timeout"
            return False, f"non_retryable_exception:{err.__class__.__name__}"
        if pol.retry_on_result and pol.retry_on_result(result):
            return True, "retry_on_result"
        if pol.retry_on_status and pol.retry_on_status(result):
            return True, "retry_on_status"
        return False, "ok"

    def _next_delay(self, attempt: int, prev_delay: int) -> int:
        pol = self.cfg.retry
        base = int(min(pol.max_delay_ms, pol.base_delay_ms * (pol.backoff_factor ** max(0, attempt - 1))))
        return _apply_jitter(base, pol.jitter, prev_delay)

    def _start_event(self) -> Dict[str, Any]:
        ctx = {
            "ts": _now_ms(),
            "tags": dict(self.cfg.tags),
        }
        if self.cfg.telemetry.on_start:
            self.cfg.telemetry.on_start(ctx)
        return ctx

    def _finish_event(self, ctx: Dict[str, Any], result: CallResult[Any]) -> None:
        if self.cfg.telemetry.on_finish:
            ev = dict(ctx)
            ev.update({"duration_ms": result.duration_ms, "attempts": result.attempts, "ok": result.ok, "hedged": result.hedged})
            self.cfg.telemetry.on_finish(ev)

class SyncExecutor(_ExecutorBase):
    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> CallResult[T]:
        if self.rate and not self.rate.allow(1.0):
            return CallResult(False, None, RateLimited("Rate limited"), 0, 0)
        ctx = self._start_event()

        start_all = _now_ms()
        attempts = 0
        delay_prev = 0
        trace: List[Dict[str, Any]] = []

        # Bulkhead
        self.bulkhead.acquire()
        try:
            if self.cb.state() == CircuitState.OPEN:
                return CallResult(False, None, CircuitOpen("Circuit is open"), 0, 0)

            deadline_all = start_all + (self.cfg.retry.overall_timeout_ms or 10**12)

            while True:
                # Circuit pre-check
                try:
                    self.cb.pre_check()
                except CircuitOpen as e:
                    return CallResult(False, None, e, attempts, _now_ms() - start_all, trace=trace)

                attempts += 1
                t0 = _now_ms()
                err: Optional[BaseException] = None
                val: Any = None

                # Выполняем в пуле с таймаутом попытки
                fut = self._threadpool().submit(fn, *args, **kwargs)
                try:
                    val = fut.result(timeout=max(0.001, self.cfg.retry.attempt_timeout_ms / 1000.0))
                    self.cb.on_success()
                except concurrent.futures.TimeoutError:
                    err = TimeoutExceeded(self.cfg.retry.attempt_timeout_ms)
                    self.cb.on_failure()
                except BaseException as e:
                    err = e
                    self.cb.on_failure()

                # Оценка retry
                should, reason = self._should_retry(attempts - 1, err, val)
                tr = {"attempt": attempts, "reason": reason, "elapsed_ms": _now_ms() - t0}
                trace.append(tr)

                if not should:
                    dur = _now_ms() - start_all
                    res = CallResult(err is None, None if err else val, err, attempts, dur, trace=trace)
                    self._finish_event(ctx, res)
                    return res

                # Общий таймаут?
                if _now_ms() >= deadline_all:
                    dur = _now_ms() - start_all
                    res = CallResult(False, None, TimeoutExceeded(self.cfg.retry.overall_timeout_ms or 0), attempts, dur, trace=trace)
                    self._finish_event(ctx, res)
                    return res

                # Задержка с джиттером
                delay_ms = self._next_delay(attempts, delay_prev)
                delay_prev = delay_ms
                if self.cfg.telemetry.on_retry:
                    self.cfg.telemetry.on_retry({"attempt": attempts, "delay_ms": delay_ms, "reason": reason})
                _sleep_sync(delay_ms)
        finally:
            self.bulkhead.release()

class AsyncExecutor(_ExecutorBase):
    def __init__(self, cfg: ResilienceConfig) -> None:
        super().__init__(cfg)
        self.bulkhead_async = AsyncBulkhead(cfg.bulkhead)
        self.rate_async = AsyncTokenBucket(cfg.rate_limiter) if cfg.rate_limiter else None

    async def call(self, fn: Union[Callable[..., Awaitable[T]], Callable[..., T]], *args: Any, **kwargs: Any) -> CallResult[T]:
        if self.rate_async and not await self.rate_async.allow(1.0):
            return CallResult(False, None, RateLimited("Rate limited"), 0, 0)
        ctx = self._start_event()

        start_all = _now_ms()
        attempts = 0
        delay_prev = 0
        trace: List[Dict[str, Any]] = []

        await self.bulkhead_async.acquire()
        try:
            if self.cb.state() == CircuitState.OPEN:
                return CallResult(False, None, CircuitOpen("Circuit is open"), 0, 0)

            deadline_all = start_all + (self.cfg.retry.overall_timeout_ms or 10**12)

            while True:
                try:
                    self.cb.pre_check()
                except CircuitOpen as e:
                    return CallResult(False, None, e, attempts, _now_ms() - start_all, trace=trace)

                attempts += 1
                t0 = _now_ms()
                err: Optional[BaseException] = None
                val: Any = None

                async def _run_async() -> Any:
                    maybe = fn(*args, **kwargs)
                    if asyncio.iscoroutine(maybe):
                        return await maybe
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(self._threadpool(), lambda: maybe)

                try:
                    val = await asyncio.wait_for(_run_async(), timeout=max(0.001, self.cfg.retry.attempt_timeout_ms / 1000.0))
                    self.cb.on_success()
                except asyncio.TimeoutError:
                    err = TimeoutExceeded(self.cfg.retry.attempt_timeout_ms)
                    self.cb.on_failure()
                except BaseException as e:
                    err = e
                    self.cb.on_failure()

                should, reason = self._should_retry(attempts - 1, err, val)
                trace.append({"attempt": attempts, "reason": reason, "elapsed_ms": _now_ms() - t0})

                if not should:
                    dur = _now_ms() - start_all
                    res = CallResult(err is None, None if err else val, err, attempts, dur, trace=trace)
                    self._finish_event(ctx, res)
                    return res

                if _now_ms() >= deadline_all:
                    dur = _now_ms() - start_all
                    res = CallResult(False, None, TimeoutExceeded(self.cfg.retry.overall_timeout_ms or 0), attempts, dur, trace=trace)
                    self._finish_event(ctx, res)
                    return res

                delay_ms = self._next_delay(attempts, delay_prev)
                delay_prev = delay_ms
                if self.cfg.telemetry.on_retry:
                    self.cfg.telemetry.on_retry({"attempt": attempts, "delay_ms": delay_ms, "reason": reason})
                await _sleep_async(delay_ms)
        finally:
            self.bulkhead_async.release()

    async def hedged_call(self, fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> CallResult[T]:
        """
        Hedging: запускает основную попытку + дополнительные через задержки hedge_delays_ms.
        Возвращает первый успешный результат; остальные отменяются best-effort.
        Поведение retry внутри каждой попытки сохраняется (обычно max_retries=0 для hedging).
        """
        if not self.cfg.hedging_enabled or not self.cfg.hedge_delays_ms:
            return await self.call(fn, *args, **kwargs)

        if self.cfg.telemetry.on_hedge_spawn:
            self.cfg.telemetry.on_hedge_spawn({"count": 1 + len(self.cfg.hedge_delays_ms)})

        async def single_attempt(start_delay: int) -> CallResult[T]:
            if start_delay > 0:
                await _sleep_async(start_delay)
            # Внутри hedging запускаем без дополнительных попыток (копия конфигурации)
            sub_cfg = ResilienceConfig(
                retry=RetryPolicy(
                    max_retries=0,
                    base_delay_ms=self.cfg.retry.base_delay_ms,
                    backoff_factor=self.cfg.retry.backoff_factor,
                    max_delay_ms=self.cfg.retry.max_delay_ms,
                    jitter=self.cfg.retry.jitter,
                    retry_on_exceptions=self.cfg.retry.retry_on_exceptions,
                    retry_on_result=self.cfg.retry.retry_on_result,
                    retry_on_status=self.cfg.retry.retry_on_status,
                    attempt_timeout_ms=self.cfg.retry.attempt_timeout_ms,
                    overall_timeout_ms=self.cfg.retry.overall_timeout_ms,
                ),
                circuit=self.cfg.circuit,
                bulkhead=self.cfg.bulkhead,
                rate_limiter=self.cfg.rate_limiter,
                telemetry=self.cfg.telemetry,
                hedging_enabled=False,
                hedge_delays_ms=(),
                tags=self.cfg.tags,
            )
            exec2 = AsyncExecutor(sub_cfg)
            return await exec2.call(fn, *args, **kwargs)

        start_all = _now_ms()
        tasks = [asyncio.create_task(single_attempt(0))]
        for d in self.cfg.hedge_delays_ms:
            tasks.append(asyncio.create_task(single_attempt(d)))

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        winner: Optional[CallResult[T]] = None
        for t in done:
            try:
                res = t.result()
                winner = res
            except BaseException as e:
                winner = CallResult(False, None, e, 1, _now_ms() - start_all)
        for p in pending:
            p.cancel()
        if winner is None:
            return CallResult(False, None, ResilienceError("No winner"), len(tasks), _now_ms() - start_all, hedged=True)
        winner.hedged = True
        return winner

# ========================= Высокоуровневый адаптер =========================

class ResilienceAdapter:
    """
    Универсальный адаптер устойчивости.
    Поддерживает sync/async вызовы, ретраи, таймауты, circuit breaker, bulkhead,
    rate limiting и hedging. Возвращает CallResult и не скрывает итоговую ошибку.
    """

    def __init__(self, cfg: Optional[ResilienceConfig] = None) -> None:
        self.cfg = cfg or ResilienceConfig()
        self.sync = SyncExecutor(self.cfg)
        self.async_ = AsyncExecutor(self.cfg)

    # --------- Синхронный вызов ---------
    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> CallResult[T]:
        return self.sync.call(fn, *args, **kwargs)

    # --------- Асинхронный вызов ---------
    async def call_async(self, fn: Union[Callable[..., Awaitable[T]], Callable[..., T]], *args: Any, **kwargs: Any) -> CallResult[T]:
        # Если включено hedging и fn — coroutine-функция, используем hedged_call
        if self.cfg.hedging_enabled and asyncio.iscoroutinefunction(fn):  # type: ignore[arg-type]
            return await self.async_.hedged_call(fn, *args, **kwargs)  # type: ignore[arg-type]
        return await self.async_.call(fn, *args, **kwargs)

# ========================= Примеры использования (docstring) =========================

"""
Пример 1: обёртка вокруг requests (sync)

    import requests
    adapter = ResilienceAdapter(ResilienceConfig(
        retry=RetryPolicy(
            max_retries=4,
            base_delay_ms=200,
            backoff_factor=2.0,
            max_delay_ms=3000,
            jitter=JitterMode.DECORRELATED,
            retry_on_exceptions=(requests.Timeout, requests.ConnectionError),
            retry_on_status=lambda r: getattr(r, "status_code", 0) in {408, 409, 425, 429, 500, 502, 503, 504},
            attempt_timeout_ms=5000,
            overall_timeout_ms=15000,
        ),
        circuit=CircuitBreakerOptions(failure_threshold=5, recovery_timeout_ms=15000, half_open_max_calls=2),
        bulkhead=BulkheadOptions(max_concurrent=64),
        rate_limiter=TokenBucketOptions(rate_per_sec=100, burst=200),
    ))

    def fetch():
        return requests.get("https://api.example.com/data", timeout=4)

    result = adapter.call(fetch)
    if result.ok:
        print(result.value.text)
    else:
        print("error:", result.error)

Пример 2: aiohttp (async) + hedging

    import aiohttp, asyncio

    async def get_json(session, url):
        async with session.get(url, timeout=5) as resp:
            data = await resp.json()
            # переретрай по бизнес-условию: если нет нужного поля
            return data

    cfg = ResilienceConfig(
        retry=RetryPolicy(
            max_retries=2,
            attempt_timeout_ms=3000,
            retry_on_result=lambda data: "items" not in data
        ),
        hedging_enabled=True,
        hedge_delays_ms=(100, 300),   # две дополнительные ставки через 100 и 300 мс
        bulkhead=BulkheadOptions(max_concurrent=128),
    )
    adapter = ResilienceAdapter(cfg)

    async def main():
        async with aiohttp.ClientSession() as s:
            res = await adapter.call_async(lambda: get_json(s, "https://api.example.com/list"))
            if res.ok:
                print(len(res.value.get("items", [])))
            else:
                print(res.error)

    asyncio.run(main())

Пример 3: интеграция с вашим SDK-клиентом

    client = NeuroForgeClient({...})
    adapter = ResilienceAdapter()

    # Синхронный путь (через threadpool)
    def list_datasets():
        # допустим, у клиента есть sync-метод
        return client.request_sync("GET", "/v1/datasets")

    result = adapter.call(list_datasets)

    # Асинхронный путь
    async def list_datasets_async():
        return await client.request("GET", "/v1/datasets")

    result2 = asyncio.run(adapter.call_async(list_datasets_async))

Замечания:
- Таймаут синхронных функций прерывает ожидание результата, но не гарантирует остановку работы внутри функции (ограничение Python). Для сетевых клиентов указывайте собственные таймауты тоже.
- Hedging рекомендуется включать, когда инфраструктура выдерживает «лишние» попытки и важна p95/99 латентность.
- Circuit breaker разделяйте по критическим внешним зависимостям (создавайте отдельные экземпляры адаптера на endpoint/сервис).
"""
