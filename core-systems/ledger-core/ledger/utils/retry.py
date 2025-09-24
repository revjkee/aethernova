# ledger/utils/retry.py
# -*- coding: utf-8 -*-
"""
Industrial-grade retry utilities for ledger-core.

Features:
- Sync and Async retry with uniform API.
- Backoff strategies: constant, exponential, exponential+full jitter, decorrelated jitter.
- Attempt timeout (sync via ThreadPoolExecutor, async via asyncio.wait_for).
- Global deadline, max attempts, and retry budget (token-bucket style).
- Custom should_retry over exceptions and/or results.
- Circuit Breaker with half-open probes.
- Metrics/Tracing hooks via lightweight Protocols.
- Structured logging with attempt telemetry.
- Idempotency context token for downstreams.

No external dependencies.
"""

from __future__ import annotations

import concurrent.futures
import functools
import logging
import random
import threading
import time
import types
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable, Optional, Protocol, Tuple, Type, TypeVar, Union, runtime_checkable

try:
    import asyncio
except Exception:  # pragma: no cover
    asyncio = None  # type: ignore

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ledger.utils.retry")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Observability Protocols
# ---------------------------------------------------------------------------

@runtime_checkable
class MetricSink(Protocol):
    def incr(self, name: str, value: int = 1, *, tags: Optional[dict] = None) -> None: ...
    def timing(self, name: str, ms: float, *, tags: Optional[dict] = None) -> None: ...

@runtime_checkable
class TraceSink(Protocol):
    def span(self, name: str, **kwargs) -> "TraceSpan": ...

class TraceSpan:
    def __init__(self, name: str):
        self.name = name
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_tag(self, key: str, value: Any): return self

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RetryError(Exception):
    """Base retry error."""

class RetryBudgetExhausted(RetryError):
    """Retry budget depleted."""

class RetryDeadlineExceeded(RetryError):
    """Global deadline exceeded."""

class RetryAttemptTimeout(RetryError):
    """Single attempt timed out."""

class CircuitOpen(RetryError):
    """Circuit breaker is open."""

# ---------------------------------------------------------------------------
# Backoff
# ---------------------------------------------------------------------------

class Backoff(str, Enum):
    CONSTANT = "constant"
    EXP = "exponential"
    EXP_FULL_JITTER = "exp_full_jitter"
    DECORRELATED_JITTER = "decorrelated_jitter"  # AWS-style

def _backoff_delays(
    strategy: Backoff,
    base_ms: int,
    max_ms: int,
    attempts: int,
    *,
    factor: float = 2.0,
) -> Iterable[int]:
    """
    Yield 'attempts' delay values in milliseconds according to strategy.
    """
    if attempts <= 0:
        return []
    a = base_ms
    if strategy == Backoff.CONSTANT:
        for _ in range(attempts):
            yield min(max_ms, max(0, a))
    elif strategy == Backoff.EXP:
        d = a
        for _ in range(attempts):
            yield min(max_ms, max(0, int(d)))
            d = d * factor
    elif strategy == Backoff.EXP_FULL_JITTER:
        d = a
        for _ in range(attempts):
            cap = min(max_ms, int(d))
            yield random.randint(0, max(0, cap))
            d = d * factor
    elif strategy == Backoff.DECORRELATED_JITTER:
        sleep = a
        for _ in range(attempts):
            sleep = int(min(max_ms, max(a, random.randint(a, int(sleep * factor)))))
            yield sleep
    else:  # pragma: no cover
        for _ in range(attempts):
            yield a

# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_seconds: float = 30.0
    half_open_probes: int = 1

    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _opened_at: Optional[float] = field(default=None, init=False, repr=False)
    _failures: int = field(default=0, init=False, repr=False)
    _half_open_left: int = field(default=0, init=False, repr=False)

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if time.time() - self._opened_at >= self.recovery_seconds:
                # Half-open
                if self._half_open_left <= 0:
                    self._half_open_left = max(1, self.half_open_probes)
                return True
            return False

    def on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._half_open_left = 0

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._opened_at is None and self._failures >= self.failure_threshold:
                self._opened_at = time.time()
                logger.warning("Retry circuit opened (failures=%d)", self._failures)

    def consume_half_open(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if self._half_open_left > 0:
                self._half_open_left -= 1
                return True
            return False

# ---------------------------------------------------------------------------
# Retry Budget (token bucket)
# ---------------------------------------------------------------------------

@dataclass
class RetryBudget:
    capacity: int = 20
    refill_rate_per_sec: float = 1.0  # tokens per second
    _tokens: float = field(default=0.0, init=False, repr=False)
    _last_refill: float = field(default_factory=lambda: time.time(), init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._last_refill = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate_per_sec)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

# ---------------------------------------------------------------------------
# Policy & Config
# ---------------------------------------------------------------------------

T = TypeVar("T")
ExcPredicate = Callable[[BaseException], bool]
ResPredicate = Callable[[Any], bool]

@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 50
    max_delay_ms: int = 2_000
    backoff: Backoff = Backoff.EXP_FULL_JITTER
    factor: float = 2.0
    attempt_timeout_s: Optional[float] = None      # per-attempt timeout
    deadline_s: Optional[float] = None             # global deadline (wall clock)
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (TimeoutError, ConnectionError)  # baseline
    retry_on_exception_pred: Optional[ExcPredicate] = None
    retry_on_result_pred: Optional[ResPredicate] = None
    give_up_on_exceptions: Tuple[Type[BaseException], ...] = (ValueError,)  # examples of non-retriable
    metric_sink: Optional[MetricSink] = None
    trace_sink: Optional[TraceSink] = None
    circuit: Optional[CircuitBreaker] = None
    budget: Optional[RetryBudget] = None
    idempotency_key_header: str = "x-idempotency-key"  # for ctx propagation

    def clone_for_attempts(self, attempts: int) -> "RetryPolicy":
        p = RetryPolicy(**{**self.__dict__})
        p.max_attempts = attempts
        return p

# ---------------------------------------------------------------------------
# Runtime helpers
# ---------------------------------------------------------------------------

def _timing(sink: Optional[MetricSink], name: str, ms: float, tags: Optional[dict] = None) -> None:
    if sink:
        try: sink.timing(name, ms, tags=tags)
        except Exception: logger.debug("metric timing failed", exc_info=True)

def _incr(sink: Optional[MetricSink], name: str, value: int = 1, tags: Optional[dict] = None) -> None:
    if sink:
        try: sink.incr(name, value=value, tags=tags)
        except Exception: logger.debug("metric incr failed", exc_info=True)

def _span(tracer: Optional[TraceSink], name: str):
    if tracer:
        try: return tracer.span(name)
        except Exception: pass
    return TraceSpan(name)

# ---------------------------------------------------------------------------
# Core Engine
# ---------------------------------------------------------------------------

class RetryEngine:
    """
    Unified sync/async retry executor with backoff, deadlines and circuit breaker.
    """

    def __init__(self, policy: RetryPolicy):
        if policy.max_attempts < 1:
            raise RetryError("max_attempts must be >= 1")
        self.policy = policy
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._executor_lock = threading.RLock()

    # ---------------------- Public API: sync ----------------------

    def run(self, fn: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute callable with retry/backoff. Returns result or raises last error.
        """
        return self._run_impl(sync_callable=fn, args=args, kwargs=kwargs)

    # ---------------------- Public API: async ---------------------

    async def arun(self, fn: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """
        Execute async callable with retry/backoff. Returns result or raises last error.
        """
        if asyncio is None:
            raise RetryError("asyncio is not available in this runtime")
        return await self._run_impl_async(async_callable=fn, args=args, kwargs=kwargs)

    # ---------------------- Internal: sync ------------------------

    def _run_impl(self, *, sync_callable: Callable[..., T], args: Tuple[Any, ...], kwargs: dict) -> T:
        pol = self.policy
        backoffs = list(_backoff_delays(pol.backoff, pol.base_delay_ms, pol.max_delay_ms, pol.max_attempts - 1, factor=pol.factor))
        start = time.time()
        ido = str(uuid.uuid4())

        with _span(pol.trace_sink, "retry.run") as span:
            span.set_tag("attempts", pol.max_attempts)
            span.set_tag("idempotency_key", ido)
            last_exc: Optional[BaseException] = None

            for attempt in range(1, pol.max_attempts + 1):
                if pol.budget and not pol.budget.allow():
                    _incr(pol.metric_sink, "retry.budget.exhausted")
                    raise RetryBudgetExhausted("retry budget exhausted")

                if pol.deadline_s is not None and time.time() - start > pol.deadline_s:
                    _incr(pol.metric_sink, "retry.deadline.exceeded")
                    raise RetryDeadlineExceeded("retry deadline exceeded")

                if pol.circuit and not pol.circuit.allow():
                    _incr(pol.metric_sink, "retry.circuit.open")
                    raise CircuitOpen("circuit is open")

                if pol.circuit and not pol.circuit.consume_half_open():
                    _incr(pol.metric_sink, "retry.circuit.half_open.throttle")
                    raise CircuitOpen("circuit half-open throttle")

                t0 = time.time()
                try:
                    # Inject idempotency key if callee accepts 'retry_ctx'
                    if "retry_ctx" in fn_params(sync_callable):
                        kwargs = dict(kwargs)  # shallow copy
                        kwargs["retry_ctx"] = {"idempotency_key": ido, "attempt": attempt}

                    res = self._call_with_timeout(sync_callable, pol.attempt_timeout_s, *args, **kwargs)
                    _timing(pol.metric_sink, "retry.attempt.ms", (time.time() - t0) * 1000.0, tags={"attempt": attempt})

                    if pol.retry_on_result_pred and pol.retry_on_result_pred(res):
                        _incr(pol.metric_sink, "retry.on_result.triggered")
                        raise _ResultRetrySignal()

                    if pol.circuit: pol.circuit.on_success()
                    return res

                except _ResultRetrySignal:
                    last_exc = None
                except pol.give_up_on_exceptions as e:
                    _incr(pol.metric_sink, "retry.give_up")
                    raise
                except BaseException as e:
                    last_exc = e
                    if isinstance(e, concurrent.futures.TimeoutError):
                        last_exc = RetryAttemptTimeout("attempt timed out")
                    if not _should_retry_exception(e, pol):
                        raise

                # Decide sleep or finish
                if attempt >= pol.max_attempts:
                    _incr(pol.metric_sink, "retry.exhausted")
                    if pol.circuit and last_exc: pol.circuit.on_failure()
                    if last_exc: raise last_exc
                    raise RetryError("retry exhausted without exception")

                delay_ms = backoffs[attempt - 1] if attempt - 1 < len(backoffs) else pol.max_delay_ms
                _incr(pol.metric_sink, "retry.sleep", tags={"ms": delay_ms})
                logger.debug("Retry attempt %d failed; sleeping %d ms", attempt, delay_ms)
                time.sleep(delay_ms / 1000.0)
                if pol.circuit and last_exc: pol.circuit.on_failure()

    # ---------------------- Internal: async -----------------------

    async def _run_impl_async(self, *, async_callable: Callable[..., Awaitable[T]], args: Tuple[Any, ...], kwargs: dict) -> T:
        pol = self.policy
        backoffs = list(_backoff_delays(pol.backoff, pol.base_delay_ms, pol.max_delay_ms, pol.max_attempts - 1, factor=pol.factor))
        start = time.time()
        ido = str(uuid.uuid4())

        with _span(pol.trace_sink, "retry.arun") as span:
            span.set_tag("attempts", pol.max_attempts)
            span.set_tag("idempotency_key", ido)
            last_exc: Optional[BaseException] = None

            for attempt in range(1, pol.max_attempts + 1):
                if pol.budget and not pol.budget.allow():
                    _incr(pol.metric_sink, "retry.budget.exhausted")
                    raise RetryBudgetExhausted("retry budget exhausted")

                if pol.deadline_s is not None and time.time() - start > pol.deadline_s:
                    _incr(pol.metric_sink, "retry.deadline.exceeded")
                    raise RetryDeadlineExceeded("retry deadline exceeded")

                if pol.circuit and not pol.circuit.allow():
                    _incr(pol.metric_sink, "retry.circuit.open")
                    raise CircuitOpen("circuit is open")

                if pol.circuit and not pol.circuit.consume_half_open():
                    _incr(pol.metric_sink, "retry.circuit.half_open.throttle")
                    raise CircuitOpen("circuit half-open throttle")

                t0 = time.time()
                try:
                    if "retry_ctx" in fn_params(async_callable):
                        kwargs = dict(kwargs)
                        kwargs["retry_ctx"] = {"idempotency_key": ido, "attempt": attempt}

                    coro = async_callable(*args, **kwargs)
                    if not asyncio.iscoroutine(coro):
                        raise RetryError("async callable did not return coroutine")

                    if pol.attempt_timeout_s:
                        res = await asyncio.wait_for(coro, timeout=pol.attempt_timeout_s)
                    else:
                        res = await coro

                    _timing(pol.metric_sink, "retry.attempt.ms", (time.time() - t0) * 1000.0, tags={"attempt": attempt})

                    if pol.retry_on_result_pred and pol.retry_on_result_pred(res):
                        _incr(pol.metric_sink, "retry.on_result.triggered")
                        raise _ResultRetrySignal()

                    if pol.circuit: pol.circuit.on_success()
                    return res

                except _ResultRetrySignal:
                    last_exc = None
                except pol.give_up_on_exceptions as e:
                    _incr(pol.metric_sink, "retry.give_up")
                    raise
                except BaseException as e:
                    last_exc = e
                    if asyncio and isinstance(e, asyncio.TimeoutError):
                        last_exc = RetryAttemptTimeout("attempt timed out")
                    if not _should_retry_exception(e, pol):
                        raise

                if attempt >= pol.max_attempts:
                    _incr(pol.metric_sink, "retry.exhausted")
                    if pol.circuit and last_exc: pol.circuit.on_failure()
                    if last_exc: raise last_exc
                    raise RetryError("retry exhausted without exception")

                delay_ms = backoffs[attempt - 1] if attempt - 1 < len(backoffs) else pol.max_delay_ms
                _incr(pol.metric_sink, "retry.sleep", tags={"ms": delay_ms})
                logger.debug("Async retry attempt %d failed; sleeping %d ms", attempt, delay_ms)
                if asyncio:
                    await asyncio.sleep(delay_ms / 1000.0)
                else:
                    time.sleep(delay_ms / 1000.0)
                if pol.circuit and last_exc: pol.circuit.on_failure()

    # ---------------------- Helpers -----------------------------

    def _call_with_timeout(self, fn: Callable[..., T], timeout_s: Optional[float], *args, **kwargs) -> T:
        if timeout_s is None:
            return fn(*args, **kwargs)
        # Run in a worker to enforce timeout
        with self._ensure_executor() as ex:
            fut = ex.submit(fn, *args, **kwargs)
            try:
                return fut.result(timeout=timeout_s)  # raises concurrent.futures.TimeoutError
            finally:
                # Best-effort cancel if still running
                if not fut.done():
                    fut.cancel()

    def _ensure_executor(self):
        class _Mgr:
            def __init__(self, outer: RetryEngine):
                self.outer = outer
            def __enter__(self):
                with self.outer._executor_lock:
                    if self.outer._executor is None:
                        self.outer._executor = concurrent.futures.ThreadPoolExecutor(max_workers=64, thread_name_prefix="retry")
                    return self.outer._executor
            def __exit__(self, exc_type, exc, tb):
                # Keep executor for reuse; not shutting down to amortize cost
                return False
        return _Mgr(self)

# Internal signal to trigger retry based on result predicate
class _ResultRetrySignal(Exception):
    pass

def _should_retry_exception(exc: BaseException, pol: RetryPolicy) -> bool:
    if isinstance(exc, pol.give_up_on_exceptions):
        return False
    if isinstance(exc, pol.retry_on_exceptions):
        return True
    if pol.retry_on_exception_pred:
        try:
            return bool(pol.retry_on_exception_pred(exc))
        except Exception:
            logger.debug("retry_on_exception_pred failed", exc_info=True)
            return False
    # Unknown exceptions: by default do not retry
    return False

def fn_params(fn: Callable[..., Any]) -> Tuple[str, ...]:
    """
    Safe, fast way to check parameter names (for injecting retry_ctx).
    """
    code = getattr(fn, "__code__", None)
    if code is None:
        return tuple()
    return tuple(code.co_varnames[: code.co_argcount])

# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])

def retry(policy: RetryPolicy) -> Callable[[F], F]:
    """
    Sync decorator. Example:

        @retry(RetryPolicy(max_attempts=4, attempt_timeout_s=1.0))
        def fetch(): ...
    """
    engine = RetryEngine(policy)
    def _wrap(fn: F) -> F:
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            return engine.run(fn, *args, **kwargs)
        return inner  # type: ignore
    return _wrap

def aretry(policy: RetryPolicy) -> Callable[[F], F]:
    """
    Async decorator. Example:

        @aretry(RetryPolicy(max_attempts=4, attempt_timeout_s=1.0))
        async def fetch(): ...
    """
    engine = RetryEngine(policy)
    def _wrap(fn: F) -> F:
        @functools.wraps(fn)
        async def inner(*args, **kwargs):
            return await engine.arun(fn, *args, **kwargs)
        return inner  # type: ignore
    return _wrap

# ---------------------------------------------------------------------------
# Sensible defaults for common scenarios
# ---------------------------------------------------------------------------

def default_network_policy() -> RetryPolicy:
    """
    Baseline for network calls: exp full jitter, transient network errors, attempt timeout.
    """
    return RetryPolicy(
        max_attempts=5,
        base_delay_ms=100,
        max_delay_ms=3_000,
        backoff=Backoff.EXP_FULL_JITTER,
        factor=2.0,
        attempt_timeout_s=5.0,
        deadline_s=15.0,
        retry_on_exceptions=(TimeoutError, ConnectionError, RetryAttemptTimeout),
        give_up_on_exceptions=(ValueError, KeyError),
        circuit=CircuitBreaker(failure_threshold=6, recovery_seconds=20.0, half_open_probes=2),
        budget=RetryBudget(capacity=50, refill_rate_per_sec=2.0),
    )

def default_idempotent_write_policy() -> RetryPolicy:
    """
    For idempotent writes to external services (PUT/UPSERT).
    """
    return RetryPolicy(
        max_attempts=6,
        base_delay_ms=150,
        max_delay_ms=5_000,
        backoff=Backoff.DECORRELATED_JITTER,
        factor=1.5,
        attempt_timeout_s=3.0,
        deadline_s=20.0,
        retry_on_exceptions=(TimeoutError, ConnectionError, RetryAttemptTimeout),
        give_up_on_exceptions=(ValueError,),
        circuit=CircuitBreaker(failure_threshold=5, recovery_seconds=30.0, half_open_probes=1),
        budget=RetryBudget(capacity=40, refill_rate_per_sec=1.0),
    )

# ---------------------------------------------------------------------------
# Minimal examples (non-executing sketches)
# ---------------------------------------------------------------------------

def _example_sync():
    pol = default_network_policy()
    eng = RetryEngine(pol)

    def flaky_call(retry_ctx=None):
        # retry_ctx: {"idempotency_key": "...", "attempt": n}
        raise ConnectionError("transient")

    # eng.run(flaky_call)

async def _example_async():  # pragma: no cover
    pol = default_network_policy()
    eng = RetryEngine(pol)

    async def flaky_call(retry_ctx=None):
        await asyncio.sleep(0.01)
        return "ok"

    # await eng.arun(flaky_call)

__all__ = [
    "RetryError",
    "RetryBudgetExhausted",
    "RetryDeadlineExceeded",
    "RetryAttemptTimeout",
    "CircuitOpen",
    "Backoff",
    "CircuitBreaker",
    "RetryBudget",
    "RetryPolicy",
    "RetryEngine",
    "retry",
    "aretry",
    "default_network_policy",
    "default_idempotent_write_policy",
]
