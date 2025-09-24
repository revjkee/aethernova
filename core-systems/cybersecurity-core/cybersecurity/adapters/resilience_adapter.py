# cybersecurity-core/cybersecurity/adapters/resilience_adapter.py
"""
Resilience Adapter for cybersecurity-core.

Features (sync + async):
- Retries: exponential backoff, full jitter, retry-on-exception and retry-on-result predicates
- Circuit Breaker: CLOSED/OPEN/HALF_OPEN, failure thresholds, recovery timeout, half-open probe limit
- Bulkhead: concurrency caps (threading.Semaphore / asyncio.Semaphore)
- Timeout: asyncio.wait_for for async; thread-pool wrapper for sync (soft cancel, safe cross-platform)
- Rate Limiter: token-bucket with monotonic clock (sync + async acquire)
- Idempotency Cache: in-memory LRU with TTL; stores success results and selected exceptions
- Fallbacks: ordered list of alternate callables used on ultimate failure
- Events & Metrics: dataclass events, counters/histograms; hook callbacks
- Fully typed, stdlib-only, thread-safe with RLock

Intended order of application:
    RateLimit -> Bulkhead -> CircuitBreaker -> (Idempotency check) -> Retry{ Timeout -> Call -> Evaluate } -> Fallback

Usage:
    adapter = ResilienceAdapter(policy=ResiliencePolicy.default())
    # Decorator for sync
    @adapter.wrap()
    def fetch_user(uid: str) -> dict: ...
    # Decorator for async
    @adapter.wrap_async()
    async def get_page(url: str) -> bytes: ...
    # Or direct
    result = adapter.call(func, *args, ctx={"idempotency_key": "..."} , **kwargs)
    result = await adapter.acall(afunc, *args, ctx={"idempotency_key": "..."} , **kwargs)

Note:
- Sync timeout uses ThreadPoolExecutor with future.result(timeout). Work inside thread will continue if it ignores cancellation.
  Design your callables to be side-effect safe or combine with idempotency and circuit breaker.
"""

from __future__ import annotations

import abc
import concurrent.futures
import functools
import heapq
import logging
import random
import threading
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generic,
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
    overload,
)

import asyncio

logger = logging.getLogger("cybersecurity.resilience")

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)

# -----------------------------
# Configuration dataclasses
# -----------------------------

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_base: float = 0.2         # seconds
    backoff_factor: float = 2.0       # exponential factor
    max_backoff: float = 10.0         # cap per-attempt delay
    jitter: float = 0.8               # 0..1 full jitter portion: delay = exp * (1 - jitter) + rand(0, exp*jitter)
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (Exception,)
    retry_on_result: Optional[Callable[[Any], bool]] = None  # return True to retry
    give_up_on_exceptions: Tuple[Type[BaseException], ...] = ()  # do not retry if these are raised

    def compute_delay(self, attempt_index: int) -> float:
        # attempt_index starts at 1 for first retry
        exp = self.backoff_base * (self.backoff_factor ** max(0, attempt_index - 1))
        exp = min(self.max_backoff, exp)
        jitter_span = max(0.0, min(1.0, self.jitter))
        delay = exp * (1.0 - jitter_span) + random.random() * (exp * jitter_span)
        return max(0.0, delay)


@dataclass(frozen=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 5          # consecutive failures to OPEN
    recovery_timeout: float = 30.0      # seconds in OPEN before HALF_OPEN
    half_open_max_calls: int = 2        # allowed concurrent probes in HALF_OPEN
    success_threshold: int = 2          # consecutive successes in HALF_OPEN to CLOSE
    track_exceptions: Tuple[Type[BaseException], ...] = (Exception,)  # which exceptions count as failure
    track_result: Optional[Callable[[Any], bool]] = None  # True -> count as failure


@dataclass(frozen=True)
class BulkheadPolicy:
    max_concurrent: int = 50


@dataclass(frozen=True)
class TimeoutPolicy:
    seconds: Optional[float] = 5.0  # None to disable


@dataclass(frozen=True)
class RateLimitPolicy:
    rate_per_sec: float = 100.0  # fill rate
    capacity: int = 200          # bucket size
    acquire_timeout: float = 1.0 # max wait to acquire token; <=0 -> non-blocking


@dataclass(frozen=True)
class IdempotencyPolicy:
    enabled: bool = True
    cache_capacity: int = 10_000
    ttl_seconds: float = 300.0
    cache_exceptions: Tuple[Type[BaseException], ...] = ()  # store selected exception outcomes if desired (rare)
    key_from_ctx: str = "idempotency_key"


@dataclass(frozen=True)
class FallbackPolicy:
    fallbacks: Tuple[Callable[..., Any], ...] = ()  # sync fallbacks
    fallbacks_async: Tuple[Callable[..., Awaitable[Any]], ...] = ()  # async fallbacks


@dataclass(frozen=True)
class ResiliencePolicy:
    retry: Optional[RetryPolicy] = field(default_factory=RetryPolicy)
    breaker: Optional[CircuitBreakerPolicy] = field(default_factory=CircuitBreakerPolicy)
    bulkhead: Optional[BulkheadPolicy] = field(default_factory=BulkheadPolicy)
    timeout: Optional[TimeoutPolicy] = field(default_factory=TimeoutPolicy)
    ratelimit: Optional[RateLimitPolicy] = field(default_factory=RateLimitPolicy)
    idempotency: Optional[IdempotencyPolicy] = field(default_factory=IdempotencyPolicy)
    fallback: Optional[FallbackPolicy] = field(default_factory=FallbackPolicy)

    @staticmethod
    def default() -> "ResiliencePolicy":
        return ResiliencePolicy()


# -----------------------------
# Events and metrics
# -----------------------------

class EventType(str, Enum):
    RATE_LIMIT_ACQUIRE = "rate_limit_acquire"
    BULKHEAD_ENTER = "bulkhead_enter"
    BULKHEAD_REJECT = "bulkhead_reject"
    BREAKER_OPEN = "breaker_open"
    BREAKER_HALF_OPEN = "breaker_half_open"
    BREAKER_CLOSE = "breaker_close"
    RETRY = "retry"
    TIMEOUT = "timeout"
    SUCCESS = "success"
    FAILURE = "failure"
    FALLBACK = "fallback"
    IDEMPOTENT_HIT = "idempotent_hit"


@dataclass
class ResilienceEvent:
    type: EventType
    at: float
    attempt: int = 0
    message: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ResilienceMetrics:
    counters: MutableMapping[str, int] = field(default_factory=lambda: defaultdict(int))
    timings: MutableMapping[str, List[float]] = field(default_factory=lambda: defaultdict(list))
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def incr(self, name: str, value: int = 1) -> None:
        with self._lock:
            self.counters[name] += value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self.timings[name].append(value)

    def snapshot(self) -> Tuple[Mapping[str, int], Mapping[str, Tuple[float, float, float]]]:
        # returns counters and (min, avg, max) for timings
        with self._lock:
            c = dict(self.counters)
            t: Dict[str, Tuple[float, float, float]] = {}
            for k, arr in self.timings.items():
                if arr:
                    mn = min(arr)
                    mx = max(arr)
                    avg = sum(arr) / len(arr)
                    t[k] = (mn, avg, mx)
                else:
                    t[k] = (0.0, 0.0, 0.0)
            return c, t


# -----------------------------
# Token Bucket (sync + async)
# -----------------------------

class TokenBucket:
    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = max(0.0, rate)
        self.capacity = max(1, capacity)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def try_acquire(self, n: int = 1, timeout: float = 0.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            now = time.monotonic()
            with self._lock:
                self._refill(now)
                if self._tokens >= n:
                    self._tokens -= n
                    return True
            if timeout <= 0.0 or now >= deadline:
                return False
            time.sleep(min(0.005, deadline - now))

    async def acquire_async(self, n: int = 1, timeout: float = 0.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            now = time.monotonic()
            async with self._async_lock:
                self._refill(now)
                if self._tokens >= n:
                    self._tokens -= n
                    return True
            if timeout <= 0.0 or now >= deadline:
                return False
            await asyncio.sleep(0.005)


# -----------------------------
# Bulkhead (sync + async)
# -----------------------------

class Bulkhead:
    def __init__(self, limit: int) -> None:
        self._sem = threading.Semaphore(max(1, limit))

    def try_enter(self) -> bool:
        return self._sem.acquire(blocking=False)

    def exit(self) -> None:
        self._sem.release()


class BulkheadAsync:
    def __init__(self, limit: int) -> None:
        self._sem = asyncio.Semaphore(max(1, limit))

    async def try_enter(self) -> bool:
        if self._sem.locked() and self._sem._value <= 0:  # type: ignore[attr-defined]
            return False
        # non-blocking acquire
        return self._sem.acquire_nowait() if hasattr(self._sem, "acquire_nowait") else await self._sem.acquire()  # py<3.11 fallback

    def exit(self) -> None:
        self._sem.release()


# -----------------------------
# Circuit Breaker (sync + async safe)
# -----------------------------

class BreakerState(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


class CircuitBreaker:
    def __init__(self, p: CircuitBreakerPolicy) -> None:
        self.p = p
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._successes_half_open = 0
        self._opened_at = 0.0
        self._lock = threading.RLock()
        self._half_open_inflight = 0

    def allow(self) -> bool:
        with self._lock:
            if self._state == BreakerState.CLOSED:
                return True
            if self._state == BreakerState.OPEN:
                if (time.monotonic() - self._opened_at) >= self.p.recovery_timeout:
                    self._state = BreakerState.HALF_OPEN
                    self._successes_half_open = 0
                    self._half_open_inflight = 0
                else:
                    return False
            if self._state == BreakerState.HALF_OPEN:
                if self._half_open_inflight < self.p.half_open_max_calls:
                    self._half_open_inflight += 1
                    return True
                return False
            return False

    def on_success(self, emit: Callable[[ResilienceEvent], None]) -> None:
        with self._lock:
            if self._state == BreakerState.CLOSED:
                self._failures = 0
                return
            if self._state == BreakerState.HALF_OPEN:
                self._successes_half_open += 1
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                if self._successes_half_open >= self.p.success_threshold:
                    self._state = BreakerState.CLOSED
                    self._failures = 0
                    emit(ResilienceEvent(EventType.BREAKER_CLOSE, time.monotonic(), message="breaker closed"))
            # If OPEN shouldn't receive success; ignore

    def on_failure(self, exc: BaseException, emit: Callable[[ResilienceEvent], None]) -> None:
        with self._lock:
            if self._state == BreakerState.CLOSED:
                if isinstance(exc, self.p.track_exceptions):
                    self._failures += 1
                    if self._failures >= self.p.failure_threshold:
                        self._state = BreakerState.OPEN
                        self._opened_at = time.monotonic()
                        emit(ResilienceEvent(EventType.BREAKER_OPEN, self._opened_at, message="breaker opened"))
            elif self._state == BreakerState.HALF_OPEN:
                self._state = BreakerState.OPEN
                self._opened_at = time.monotonic()
                self._half_open_inflight = max(0, self._half_open_inflight - 1)
                emit(ResilienceEvent(EventType.BREAKER_OPEN, self._opened_at, message="breaker re-opened from half-open"))

    def current_state(self) -> BreakerState:
        with self._lock:
            return self._state


# -----------------------------
# Idempotency store (LRU + TTL)
# -----------------------------

@dataclass
class _CacheEntry:
    value: Any
    created: float
    is_exception: bool = False
    exc_type: Optional[str] = None
    exc_args: Tuple[Any, ...] = ()


class LruTtlCache:
    def __init__(self, capacity: int, ttl: float) -> None:
        self.capacity = max(1, capacity)
        self.ttl = max(0.0, ttl)
        self._store: "OrderedDict[str, _CacheEntry]" = OrderedDict()
        self._lock = threading.RLock()

    def _evict(self) -> None:
        while len(self._store) > self.capacity:
            self._store.popitem(last=False)

    def get(self, key: str) -> Optional[_CacheEntry]:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            if (now - entry.created) > self.ttl:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key, last=True)
            return entry

    def put(self, key: str, entry: _CacheEntry) -> None:
        with self._lock:
            self._store[key] = entry
            self._store.move_to_end(key, last=True)
            self._evict()


# -----------------------------
# Resilience Adapter
# -----------------------------

EventHook = Callable[[ResilienceEvent], None]

@dataclass
class ResilienceComponents:
    bucket: Optional[TokenBucket] = None
    bulkhead: Optional[Bulkhead] = None
    bulkhead_async: Optional[BulkheadAsync] = None
    breaker: Optional[CircuitBreaker] = None
    idem_cache: Optional[LruTtlCache] = None


class ResilienceAdapter:
    def __init__(self, policy: Optional[ResiliencePolicy] = None, on_event: Optional[EventHook] = None, metrics: Optional[ResilienceMetrics] = None) -> None:
        self.policy = policy or ResiliencePolicy.default()
        self.on_event = on_event or (lambda e: None)
        self.metrics = metrics or ResilienceMetrics()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=128, thread_name_prefix="resilience-sync")
        # components
        self.c = ResilienceComponents()
        if self.policy.ratelimit:
            self.c.bucket = TokenBucket(rate=self.policy.ratelimit.rate_per_sec, capacity=self.policy.ratelimit.capacity)
        if self.policy.bulkhead:
            self.c.bulkhead = Bulkhead(limit=self.policy.bulkhead.max_concurrent)
            self.c.bulkhead_async = BulkheadAsync(limit=self.policy.bulkhead.max_concurrent)
        if self.policy.breaker:
            self.c.breaker = CircuitBreaker(self.policy.breaker)
        if self.policy.idempotency and self.policy.idempotency.enabled:
            self.c.idem_cache = LruTtlCache(capacity=self.policy.idempotency.cache_capacity, ttl=self.policy.idempotency.ttl_seconds)

    # ------------- Decorators -------------

    def wrap(self, *, ctx_provider: Optional[Callable[..., Mapping[str, Any]]] = None):
        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> T:
                ctx = {}
                if ctx_provider:
                    try:
                        ctx = dict(ctx_provider(*args, **kwargs) or {})
                    except Exception:
                        ctx = {}
                return self.call(func, *args, ctx=ctx, **kwargs)
            return wrapper
        return decorator

    def wrap_async(self, *, ctx_provider: Optional[Callable[..., Mapping[str, Any]]] = None):
        def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> T:
                ctx = {}
                if ctx_provider:
                    try:
                        ctx = dict(ctx_provider(*args, **kwargs) or {})
                    except Exception:
                        ctx = {}
                return await self.acall(func, *args, ctx=ctx, **kwargs)
            return wrapper
        return decorator

    # ------------- Public call API -------------

    def call(self, func: Callable[..., T], *args: Any, ctx: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> T:
        start_total = time.monotonic()
        try:
            return self._call_impl_sync(func, args, kwargs, ctx or {})
        finally:
            self.metrics.observe("call.total_time", time.monotonic() - start_total)

    async def acall(self, func: Callable[..., Awaitable[T]], *args: Any, ctx: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> T:
        start_total = time.monotonic()
        try:
            return await self._call_impl_async(func, args, kwargs, ctx or {})
        finally:
            self.metrics.observe("call.total_time_async", time.monotonic() - start_total)

    # ------------- Internal: sync --------------

    def _call_impl_sync(self, func: Callable[..., T], args: Tuple[Any, ...], kwargs: Dict[str, Any], ctx: Mapping[str, Any]) -> T:
        # Rate limit
        if self.c.bucket and self.policy.ratelimit:
            ok = self.c.bucket.try_acquire(timeout=max(0.0, self.policy.ratelimit.acquire_timeout))
            if not ok:
                self.metrics.incr("ratelimit.reject")
                self.on_event(ResilienceEvent(EventType.RATE_LIMIT_ACQUIRE, time.monotonic(), message="ratelimit reject"))
                raise TimeoutError("Rate limit exceeded")

        # Bulkhead
        bh_token = None
        if self.c.bulkhead:
            if not self.c.bulkhead.try_enter():
                self.metrics.incr("bulkhead.reject")
                self.on_event(ResilienceEvent(EventType.BULKHEAD_REJECT, time.monotonic()))
                raise RuntimeError("Bulkhead limit reached")
            bh_token = True
            self.on_event(ResilienceEvent(EventType.BULKHEAD_ENTER, time.monotonic()))

        try:
            # Circuit breaker gate
            if self.c.breaker and not self.c.breaker.allow():
                self.metrics.incr("breaker.block")
                raise RuntimeError("Circuit breaker OPEN")

            # Idempotency check (before execution)
            cache_key = None
            if self.c.idem_cache and self.policy.idempotency:
                key_field = self.policy.idempotency.key_from_ctx
                cache_key = str(ctx.get(key_field)) if key_field in ctx else None
                if cache_key:
                    ent = self.c.idem_cache.get(cache_key)
                    if ent:
                        self.metrics.incr("idem.hit")
                        self.on_event(ResilienceEvent(EventType.IDEMPOTENT_HIT, time.monotonic()))
                        if ent.is_exception:
                            # reconstruct simple exception
                            ex = RuntimeError(ent.exc_type or "cached_exception")
                            ex.args = ent.exc_args
                            raise ex
                        return ent.value  # type: ignore[return-value]

            # Retry loop
            attempts = max(1, (self.policy.retry.max_attempts if self.policy.retry else 1))
            last_exc: Optional[BaseException] = None
            for attempt in range(1, attempts + 1):
                t0 = time.monotonic()
                try:
                    result = self._run_with_timeout_sync(func, args, kwargs)
                    # Retry on result?
                    if self.policy.retry and self.policy.retry.retry_on_result and self.policy.retry.retry_on_result(result):
                        raise _RetrySignal("retry_on_result")
                    # Success path
                    self.metrics.incr("success")
                    self.metrics.observe("call.latency", time.monotonic() - t0)
                    if cache_key and self.c.idem_cache and self.policy.idempotency.enabled:
                        self.c.idem_cache.put(cache_key, _CacheEntry(value=result, created=time.monotonic()))
                    if self.c.breaker:
                        self.c.breaker.on_success(self.on_event)
                    self.on_event(ResilienceEvent(EventType.SUCCESS, time.monotonic(), attempt=attempt))
                    return result  # type: ignore[return-value]
                except BaseException as exc:  # noqa: BLE001
                    # Timeout accounting
                    if isinstance(exc, asyncio.TimeoutError) or isinstance(exc, TimeoutError):
                        self.metrics.incr("timeout")
                        self.on_event(ResilienceEvent(EventType.TIMEOUT, time.monotonic(), attempt=attempt, message=str(exc)))
                    # Breaker failure tracking
                    if self.c.breaker:
                        self.c.breaker.on_failure(exc, self.on_event)
                    # Retry decision
                    last_exc = exc
                    if not self.policy.retry or attempt >= attempts:
                        break
                    if isinstance(exc, self.policy.retry.give_up_on_exceptions):
                        break
                    if not isinstance(exc, self.policy.retry.retry_on_exceptions):
                        break
                    delay = self.policy.retry.compute_delay(attempt)
                    self.metrics.incr("retry")
                    self.on_event(ResilienceEvent(EventType.RETRY, time.monotonic(), attempt=attempt, message=str(exc), extra={"delay": delay}))
                    time.sleep(delay)
                    continue
            # After retries exhausted
            if cache_key and self.c.idem_cache and self.policy.idempotency and self.policy.idempotency.cache_exceptions:
                if last_exc and isinstance(last_exc, self.policy.idempotency.cache_exceptions):
                    self.c.idem_cache.put(cache_key, _CacheEntry(value=None, created=time.monotonic(), is_exception=True, exc_type=type(last_exc).__name__, exc_args=tuple(last_exc.args)))
            self.metrics.incr("failure")
            self.on_event(ResilienceEvent(EventType.FAILURE, time.monotonic(), message=str(last_exc or "unknown")))
            # Fallbacks
            if self.policy.fallback and self.policy.fallback.fallbacks:
                for fb in self.policy.fallback.fallbacks:
                    try:
                        self.on_event(ResilienceEvent(EventType.FALLBACK, time.monotonic(), message=f"fallback:{getattr(fb, '__name__', 'call')}"))
                        return fb(*args, **kwargs)  # type: ignore[return-value]
                    except Exception:
                        continue
            if last_exc:
                raise last_exc
            raise RuntimeError("Call failed without exception")
        finally:
            if bh_token and self.c.bulkhead:
                self.c.bulkhead.exit()

    def _run_with_timeout_sync(self, func: Callable[..., T], args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> T:
        # No timeout configured
        if not self.policy.timeout or self.policy.timeout.seconds is None:
            return func(*args, **kwargs)
        # Execute in thread pool and wait with timeout
        future = self._executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=max(0.0, self.policy.timeout.seconds))
        except concurrent.futures.TimeoutError:
            # We cannot kill the running thread; best effort cancel flag:
            # future.cancel() only cancels if not started. We mark timeout.
            raise TimeoutError(f"Operation timed out after {self.policy.timeout.seconds:.3f}s")

    # ------------- Internal: async -------------

    async def _call_impl_async(self, func: Callable[..., Awaitable[T]], args: Tuple[Any, ...], kwargs: Dict[str, Any], ctx: Mapping[str, Any]) -> T:
        # Rate limit
        if self.c.bucket and self.policy.ratelimit:
            ok = await self.c.bucket.acquire_async(timeout=max(0.0, self.policy.ratelimit.acquire_timeout))
            if not ok:
                self.metrics.incr("ratelimit.reject")
                self.on_event(ResilienceEvent(EventType.RATE_LIMIT_ACQUIRE, time.monotonic(), message="ratelimit reject"))
                raise asyncio.TimeoutError("Rate limit exceeded")

        # Bulkhead
        bh_entered = False
        if self.c.bulkhead_async:
            acquired = await self.c.bulkhead_async.try_enter()
            if not acquired:
                self.metrics.incr("bulkhead.reject")
                self.on_event(ResilienceEvent(EventType.BULKHEAD_REJECT, time.monotonic()))
                raise RuntimeError("Bulkhead limit reached")
            bh_entered = True
            self.on_event(ResilienceEvent(EventType.BULKHEAD_ENTER, time.monotonic()))

        try:
            # Circuit breaker gate
            if self.c.breaker and not self.c.breaker.allow():
                self.metrics.incr("breaker.block")
                raise RuntimeError("Circuit breaker OPEN")

            # Idempotency check
            cache_key = None
            if self.c.idem_cache and self.policy.idempotency:
                key_field = self.policy.idempotency.key_from_ctx
                cache_key = str(ctx.get(key_field)) if key_field in ctx else None
                if cache_key:
                    ent = self.c.idem_cache.get(cache_key)
                    if ent:
                        self.metrics.incr("idem.hit")
                        self.on_event(ResilienceEvent(EventType.IDEMPOTENT_HIT, time.monotonic()))
                        if ent.is_exception:
                            ex = RuntimeError(ent.exc_type or "cached_exception")
                            ex.args = ent.exc_args
                            raise ex
                        return ent.value  # type: ignore[return-value]

            attempts = max(1, (self.policy.retry.max_attempts if self.policy.retry else 1))
            last_exc: Optional[BaseException] = None
            for attempt in range(1, attempts + 1):
                t0 = time.monotonic()
                try:
                    coro = func(*args, **kwargs)
                    # Timeout
                    if self.policy.timeout and self.policy.timeout.seconds is not None:
                        result = await asyncio.wait_for(coro, timeout=self.policy.timeout.seconds)
                    else:
                        result = await coro
                    if self.policy.retry and self.policy.retry.retry_on_result and self.policy.retry.retry_on_result(result):
                        raise _RetrySignal("retry_on_result")
                    # Success
                    self.metrics.incr("success_async")
                    self.metrics.observe("call.latency_async", time.monotonic() - t0)
                    if cache_key and self.c.idem_cache and self.policy.idempotency.enabled:
                        self.c.idem_cache.put(cache_key, _CacheEntry(value=result, created=time.monotonic()))
                    if self.c.breaker:
                        self.c.breaker.on_success(self.on_event)
                    self.on_event(ResilienceEvent(EventType.SUCCESS, time.monotonic(), attempt=attempt))
                    return result  # type: ignore[return-value]
                except BaseException as exc:  # noqa: BLE001
                    if isinstance(exc, asyncio.TimeoutError):
                        self.metrics.incr("timeout_async")
                        self.on_event(ResilienceEvent(EventType.TIMEOUT, time.monotonic(), attempt=attempt, message=str(exc)))
                    if self.c.breaker:
                        self.c.breaker.on_failure(exc, self.on_event)
                    last_exc = exc
                    if not self.policy.retry or attempt >= attempts:
                        break
                    if isinstance(exc, self.policy.retry.give_up_on_exceptions):
                        break
                    if not isinstance(exc, self.policy.retry.retry_on_exceptions):
                        break
                    delay = self.policy.retry.compute_delay(attempt)
                    self.metrics.incr("retry_async")
                    self.on_event(ResilienceEvent(EventType.RETRY, time.monotonic(), attempt=attempt, message=str(exc), extra={"delay": delay}))
                    await asyncio.sleep(delay)
                    continue
            if cache_key and self.c.idem_cache and self.policy.idempotency and self.policy.idempotency.cache_exceptions:
                if last_exc and isinstance(last_exc, self.policy.idempotency.cache_exceptions):
                    self.c.idem_cache.put(cache_key, _CacheEntry(value=None, created=time.monotonic(), is_exception=True, exc_type=type(last_exc).__name__, exc_args=tuple(last_exc.args)))
            self.metrics.incr("failure_async")
            self.on_event(ResilienceEvent(EventType.FAILURE, time.monotonic(), message=str(last_exc or "unknown")))
            # Fallbacks
            if self.policy.fallback and self.policy.fallback.fallbacks_async:
                for fb in self.policy.fallback.fallbacks_async:
                    try:
                        self.on_event(ResilienceEvent(EventType.FALLBACK, time.monotonic(), message=f"fallback_async:{getattr(fb, '__name__,', 'call')}"))
                        return await fb(*args, **kwargs)  # type: ignore[return-value]
                    except Exception:
                        continue
            if last_exc:
                raise last_exc
            raise RuntimeError("Async call failed without exception")
        finally:
            if bh_entered and self.c.bulkhead_async:
                self.c.bulkhead_async.exit()


# -----------------------------
# Internal helpers
# -----------------------------

class _RetrySignal(RuntimeError):
    pass


# -----------------------------
# Minimal self-test example (not executed)
# -----------------------------
# if __name__ == "__main__":
#     logging.basicConfig(level=logging.INFO)
#     pol = ResiliencePolicy.default()
#     adapter = ResilienceAdapter(policy=pol, on_event=lambda e: logger.info("event %s (%s)", e.type, e.message))
#     @adapter.wrap()
#     def flaky(x):
#         if random.random() < 0.7:
#             raise ValueError("boom")
#         return x * 2
#     print(flaky(21))
#
#     async def main():
#         @adapter.wrap_async()
#         async def aflaky(x):
#             await asyncio.sleep(0.05)
#             if random.random() < 0.7:
#                 raise ValueError("boom")
#             return x * 2
#         print(await aflaky(21))
#     asyncio.run(main())
