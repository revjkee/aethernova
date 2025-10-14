# datafabric/datafabric/utils/retry.py
# Industrial-grade retry utility for sync/async call paths with exponential backoff, jitter,
# deadline/attempt timeouts, result/exception predicates, hooks, and a soft circuit breaker.

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import math
import os
import random
import signal
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Iterable,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
)

# -------- Optional logging integration (fallback to stdlib) --------
try:
    from datafabric.observability.logging import get_logger  # type: ignore
    _log = get_logger("datafabric.retry")
except Exception:
    import logging
    _log = logging.getLogger("datafabric.retry")
    if not _log.handlers:
        _log.addHandler(logging.StreamHandler(sys.stdout))
    _log.setLevel(getattr(logging, os.getenv("DF_LOG_LEVEL", "INFO").upper(), 20))

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)

# =========================
# Exceptions
# =========================
class RetryError(RuntimeError):
    def __init__(self, message: str, last_exception: Optional[BaseException], attempts: int, elapsed: float):
        super().__init__(message)
        self.last_exception = last_exception
        self.attempts = attempts
        self.elapsed = elapsed

class CircuitOpenError(RuntimeError):
    pass

# =========================
# Hooks (metrics/tracing)
# =========================
BeforeHook = Callable[[str, int], None]
AfterHook = Callable[[str, int, Optional[BaseException], Optional[float]], None]
SleepHook = Callable[[float, int], None]

def _noop_before(_name: str, _attempt: int) -> None: ...
def _noop_after(_name: str, _attempt: int, _exc: Optional[BaseException], _sleep: Optional[float]) -> None: ...
def _noop_sleep(_delay: float, _attempt: int) -> None: ...

# =========================
# Policy
# =========================
@dataclass(frozen=True)
class RetryPolicy:
    # attempts
    max_attempts: int = int(os.getenv("DF_RETRY_MAX_ATTEMPTS", "6"))
    # backoff
    backoff_base: float = float(os.getenv("DF_RETRY_BACKOFF_BASE", "0.2"))  # seconds
    backoff_multiplier: float = float(os.getenv("DF_RETRY_BACKOFF_MULTIPLIER", "2.0"))
    backoff_max: float = float(os.getenv("DF_RETRY_BACKOFF_MAX", "20.0"))
    # jitter: full (0..d), half (±d/2), or none
    jitter: str = os.getenv("DF_RETRY_JITTER", "full")  # "full" | "half" | "none"
    # deadline (wall-clock, seconds) for the whole operation
    deadline: Optional[float] = None
    # per-attempt timeout (seconds)
    attempt_timeout: Optional[float] = None
    # retry-able exceptions
    retry_on_exceptions: Tuple[Type[BaseException], ...] = (TimeoutError, ConnectionError)
    # optional predicate to retry by result
    retry_on_result: Optional[Callable[[Any], bool]] = None
    # stop if predicate says so (even if exceptions match)
    giveup_on_exception: Optional[Callable[[BaseException], bool]] = None
    # name for metrics/logs
    name: str = "operation"
    # cancel checker (returns True -> abort immediately)
    cancel_check: Optional[Callable[[], bool]] = None
    # hooks
    before_hook: BeforeHook = _noop_before
    after_hook: AfterHook = _noop_after
    sleep_hook: SleepHook = _noop_sleep
    # soft circuit breaker
    breaker_fail_threshold: int = int(os.getenv("DF_RETRY_BREAKER_FAILS", "0"))  # 0 disables
    breaker_reset_timeout: float = float(os.getenv("DF_RETRY_BREAKER_RESET", "30.0"))  # seconds
    breaker_half_open_trials: int = int(os.getenv("DF_RETRY_BREAKER_HALF", "1"))

    # run sync call in thread to enforce per-attempt timeout (costly but safe)
    run_sync_in_thread: bool = True
    thread_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None

# =========================
# Circuit Breaker (soft)
# =========================
@dataclass
class _BreakerState:
    failures: int = 0
    opened_at: Optional[float] = None
    half_open_trials_left: int = 0

class _Breaker:
    def __init__(self, policy: RetryPolicy):
        self._policy = policy
        self._lock = threading.Lock()
        self._st = _BreakerState()

    def try_enter(self) -> None:
        if self._policy.breaker_fail_threshold <= 0:
            return
        with self._lock:
            if self._st.opened_at is None:
                return
            elapsed = time.monotonic() - self._st.opened_at
            if elapsed < self._policy.breaker_reset_timeout and self._st.half_open_trials_left <= 0:
                raise CircuitOpenError("circuit is open")
            # Enter half-open window
            if elapsed >= self._policy.breaker_reset_timeout:
                self._st.half_open_trials_left = max(1, self._policy.breaker_half_open_trials)

            if self._st.half_open_trials_left <= 0:
                raise CircuitOpenError("circuit is open")
            self._st.half_open_trials_left -= 1

    def on_success(self) -> None:
        if self._policy.breaker_fail_threshold <= 0:
            return
        with self._lock:
            self._st = _BreakerState()  # close/reset

    def on_failure(self) -> None:
        if self._policy.breaker_fail_threshold <= 0:
            return
        with self._lock:
            self._st.failures += 1
            if self._st.failures >= self._policy.breaker_fail_threshold and self._st.opened_at is None:
                self._st.opened_at = time.monotonic()

# =========================
# Backoff utils
# =========================
def _jittered(delay: float, mode: str) -> float:
    if delay <= 0:
        return 0.0
    if mode == "none":
        return delay
    if mode == "half":
        return max(0.0, delay * (1.0 + (random.random() - 0.5)))
    # full
    return random.random() * delay

def _backoff(policy: RetryPolicy, attempt: int) -> float:
    # attempt starts at 1
    d = policy.backoff_base * (policy.backoff_multiplier ** (attempt - 1))
    d = min(d, policy.backoff_max)
    return _jittered(d, policy.jitter)

# =========================
# Core engine
# =========================
def _should_retry_by_exc(exc: BaseException, policy: RetryPolicy) -> bool:
    if policy.giveup_on_exception and policy.giveup_on_exception(exc):
        return False
    return isinstance(exc, policy.retry_on_exceptions)

def _should_retry_by_result(res: Any, policy: RetryPolicy) -> bool:
    if policy.retry_on_result is None:
        return False
    try:
        return bool(policy.retry_on_result(res))
    except Exception:
        # if predicate fails, better to NOT loop forever
        return False

def _check_deadline(start_ts: float, policy: RetryPolicy) -> None:
    if policy.deadline is None:
        return
    if (time.monotonic() - start_ts) >= policy.deadline:
        raise RetryError(f"deadline exceeded for {policy.name}", None, 0, time.monotonic() - start_ts)

def _sleep(delay: float, attempt: int, policy: RetryPolicy) -> None:
    if delay <= 0:
        return
    policy.sleep_hook(delay, attempt)
    time.sleep(delay)

async def _asleep(delay: float, attempt: int, policy: RetryPolicy) -> None:
    if delay <= 0:
        return
    policy.sleep_hook(delay, attempt)
    await asyncio.sleep(delay)

# =========================
# Sync execution
# =========================
def _call_with_timeout_sync(fn: Callable[..., T], attempt_timeout: Optional[float], run_in_thread: bool,
                            pool: Optional[concurrent.futures.ThreadPoolExecutor],
                            *args: Any, **kwargs: Any) -> T:
    if attempt_timeout is None:
        return fn(*args, **kwargs)
    if not run_in_thread:
        # best-effort: no hard cancel, but we can raise after the fact — not safe; avoid
        raise TimeoutError("attempt_timeout set but run_sync_in_thread=False")

    exec_pool = pool or _DEFAULT_POOL
    fut = exec_pool.submit(fn, *args, **kwargs)
    return fut.result(timeout=attempt_timeout)

# =========================
# Async execution
# =========================
async def _call_with_timeout_async(afn: Callable[..., Awaitable[T]], attempt_timeout: Optional[float],
                                   *args: Any, **kwargs: Any) -> T:
    if attempt_timeout is None:
        return cast(T, await afn(*args, **kwargs))
    return cast(T, await asyncio.wait_for(afn(*args, **kwargs), timeout=attempt_timeout))

# =========================
# Public call APIs
# =========================
_DEFAULT_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=int(os.getenv("DF_RETRY_THREADPOOL", "16")))

def retry_call(fn: Callable[..., T], *, policy: Optional[RetryPolicy] = None, **kwargs: Any) -> T:
    """
    Execute sync function with retry according to policy.
    """
    p = policy or RetryPolicy()
    breaker = _Breaker(p)
    attempts = 0
    start_ts = time.monotonic()
    last_exc: Optional[BaseException] = None

    while True:
        _check_deadline(start_ts, p)
        if p.cancel_check and p.cancel_check():
            raise RetryError(f"cancelled before attempt for {p.name}", last_exc, attempts, time.monotonic() - start_ts)
        attempts += 1

        try:
            breaker.try_enter()
            p.before_hook(p.name, attempts)
            res = _call_with_timeout_sync(fn, p.attempt_timeout, p.run_sync_in_thread, p.thread_pool, **kwargs)
            if _should_retry_by_result(res, p):
                raise RuntimeError("result_marked_for_retry")
            breaker.on_success()
            p.after_hook(p.name, attempts, None, None)
            return res
        except CircuitOpenError as ce:
            p.after_hook(p.name, attempts, ce, None)
            raise
        except BaseException as exc:
            last_exc = exc
            retryable = _should_retry_by_exc(exc, p) or (isinstance(exc, RuntimeError) and str(exc) == "result_marked_for_retry")
            done = attempts >= p.max_attempts
            if not retryable or done:
                p.after_hook(p.name, attempts, exc, None)
                breaker.on_failure()
                raise RetryError(f"retry failed for {p.name} after {attempts} attempts", exc, attempts, time.monotonic() - start_ts) from exc
            delay = _backoff(p, attempts)
            p.after_hook(p.name, attempts, exc, delay)
            _log.debug("retry(%s): attempt=%s failed=%s; sleep=%.3fs", p.name, attempts, type(exc).__name__, delay)
            breaker.on_failure()
            _sleep(delay, attempts, p)

async def aretry_call(afn: Callable[..., Awaitable[T]], *, policy: Optional[RetryPolicy] = None, **kwargs: Any) -> T:
    """
    Execute async function with retry according to policy.
    """
    p = policy or RetryPolicy()
    breaker = _Breaker(p)
    attempts = 0
    start_ts = time.monotonic()
    last_exc: Optional[BaseException] = None

    while True:
        _check_deadline(start_ts, p)
        if p.cancel_check and p.cancel_check():
            raise RetryError(f"cancelled before attempt for {p.name}", last_exc, attempts, time.monotonic() - start_ts)
        attempts += 1

        try:
            breaker.try_enter()
            p.before_hook(p.name, attempts)
            res = await _call_with_timeout_async(afn, p.attempt_timeout, **kwargs)
            if _should_retry_by_result(res, p):
                raise RuntimeError("result_marked_for_retry")
            breaker.on_success()
            p.after_hook(p.name, attempts, None, None)
            return res
        except CircuitOpenError as ce:
            p.after_hook(p.name, attempts, ce, None)
            raise
        except BaseException as exc:
            last_exc = exc
            retryable = _should_retry_by_exc(exc, p) or (isinstance(exc, RuntimeError) and str(exc) == "result_marked_for_retry")
            done = attempts >= p.max_attempts
            if not retryable or done:
                p.after_hook(p.name, attempts, exc, None)
                breaker.on_failure()
                raise RetryError(f"retry failed for {p.name} after {attempts} attempts", exc, attempts, time.monotonic() - start_ts) from exc
            delay = _backoff(p, attempts)
            p.after_hook(p.name, attempts, exc, delay)
            _log.debug("aretry(%s): attempt=%s failed=%s; sleep=%.3fs", p.name, attempts, type(exc).__name__, delay)
            breaker.on_failure()
            await _asleep(delay, attempts, p)

# =========================
# Decorators
# =========================
def _mk_policy(name: Optional[str], overrides: dict) -> RetryPolicy:
    base = RetryPolicy()
    # dataclasses.replace to apply overrides
    if name:
        overrides = dict(overrides or {})
        overrides.setdefault("name", name)
    return dataclasses.replace(base, **overrides)

def retry(**policy_overrides: Any) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for sync functions.

    Example:
        @retry(max_attempts=5, backoff_base=0.1, retry_on_exceptions=(TimeoutError,))
        def fetch():
            ...
    """
    p = _mk_policy(policy_overrides.get("name"), policy_overrides)

    def wrapper(fn: Callable[..., T]) -> Callable[..., T]:
        def inner(*args: Any, **kwargs: Any) -> T:
            return retry_call(lambda **kw: fn(*args, **kw), policy=p, **kwargs)
        inner.__name__ = getattr(fn, "__name__", "retry_wrapped")
        inner.__doc__ = fn.__doc__
        return inner
    return wrapper

def aretry(**policy_overrides: Any) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator for async functions.

    Example:
        @aretry(max_attempts=7, retry_on_result=lambda r: r is None)
        async def rpc():
            ...
    """
    p = _mk_policy(policy_overrides.get("name"), policy_overrides)

    def wrapper(afn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def inner(*args: Any, **kwargs: Any) -> T:
            return await aretry_call(lambda **kw: afn(*args, **kw), policy=p, **kwargs)
        inner.__name__ = getattr(afn, "__name__", "aretry_wrapped")
        inner.__doc__ = afn.__doc__
        return inner
    return wrapper

# =========================
# Utilities
# =========================
@contextmanager
def cancel_on_signal(policy: RetryPolicy, *signals: int) -> None:
    """
    Convert POSIX signals to cancel_check() via side-effect. Use in CLI/batch jobs.
    """
    cancelled = {"v": False}

    def handler(_signum, _frame):
        cancelled["v"] = True

    old = {}
    try:
        for s in signals or (signal.SIGINT, signal.SIGTERM):
            old[s] = signal.signal(s, handler)
        object.__setattr__(policy, "cancel_check", lambda: cancelled["v"])  # type: ignore[attr-defined]
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)

def default_http_retry_policy(name: str = "http") -> RetryPolicy:
    return RetryPolicy(
        name=name,
        max_attempts=int(os.getenv("DF_RETRY_HTTP_ATTEMPTS", "6")),
        backoff_base=float(os.getenv("DF_RETRY_HTTP_BASE", "0.1")),
        backoff_multiplier=float(os.getenv("DF_RETRY_HTTP_MULT", "2.0")),
        backoff_max=float(os.getenv("DF_RETRY_HTTP_MAX", "10.0")),
        jitter=os.getenv("DF_RETRY_HTTP_JITTER", "full"),
        attempt_timeout=float(os.getenv("DF_RETRY_HTTP_ATTEMPT_TIMEOUT", "10.0")),
        retry_on_exceptions=(TimeoutError, ConnectionError, OSError),
        retry_on_result=lambda r: getattr(r, "status", 200) >= 500 if hasattr(r, "status") else False,
        breaker_fail_threshold=int(os.getenv("DF_RETRY_HTTP_BREAKER_FAILS", "5")),
        breaker_reset_timeout=float(os.getenv("DF_RETRY_HTTP_BREAKER_RESET", "30.0")),
        breaker_half_open_trials=int(os.getenv("DF_RETRY_HTTP_BREAKER_HALF", "1")),
    )

def default_db_retry_policy(name: str = "db") -> RetryPolicy:
    return RetryPolicy(
        name=name,
        max_attempts=int(os.getenv("DF_RETRY_DB_ATTEMPTS", "8")),
        backoff_base=float(os.getenv("DF_RETRY_DB_BASE", "0.05")),
        backoff_multiplier=float(os.getenv("DF_RETRY_DB_MULT", "2.0")),
        backoff_max=float(os.getenv("DF_RETRY_DB_MAX", "5.0")),
        retry_on_exceptions=(TimeoutError, ConnectionError, OSError),
        attempt_timeout=float(os.getenv("DF_RETRY_DB_ATTEMPT_TIMEOUT", "5.0")),
        jitter=os.getenv("DF_RETRY_DB_JITTER", "half"),
        breaker_fail_threshold=int(os.getenv("DF_RETRY_DB_BREAKER_FAILS", "8")),
        breaker_reset_timeout=float(os.getenv("DF_RETRY_DB_BREAKER_RESET", "60.0")),
        breaker_half_open_trials=int(os.getenv("DF_RETRY_DB_BREAKER_HALF", "2")),
    )

# =========================
# Self-test (run directly)
# =========================
if __name__ == "__main__":
    # Demo sync
    cnt = {"n": 0}

    @retry(name="demo_sync", max_attempts=3, backoff_base=0.05, retry_on_exceptions=(ValueError,))
    def flaky(x: int) -> int:
        cnt["n"] += 1
        if cnt["n"] < 3:
            raise ValueError("boom")
        return x * 2

    print("flaky ->", flaky(21))

    # Demo async
    attempts = {"n": 0}

    @aretry(name="demo_async", max_attempts=4, backoff_base=0.05, retry_on_result=lambda r: r is None)
    async def aflaky(y: int) -> Optional[int]:
        attempts["n"] += 1
        if attempts["n"] < 3:
            return None
        return y + 1

    async def main():
        print("aflaky ->", await aflaky(41))

    asyncio.run(main())
