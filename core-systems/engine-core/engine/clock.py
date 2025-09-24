# engine-core/engine/clock.py
"""
Industrial-grade time utilities for engine-core.

Features:
- Clock abstraction (Protocol-like): now(), monotonic(), sleep()
- SystemClock (asyncio-based) and Deterministic TestClock (manual advance)
- Deadline and Timeout handling with monotonic base
- Stopwatch (context manager) for precise measurements
- Drift-corrected AsyncTicker (stable interval scheduling)
- Exponential backoff with full jitter and cap
- Async TokenBucket rate limiter with fairness and max_delay
- UTC-aware datetime helpers

Design notes:
- All timeouts and scheduling are based on time.monotonic() to avoid wall-clock jumps.
- Sleep operations are cancellation-safe: cancellation propagates, internal helpers
  ensure Deadline semantics are preserved.
- No external dependencies.

Copyright:
- MIT-like; adapt to project policy if needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Optional,
    Protocol,
    Union,
    Iterable,
)

# =========================
# Clock Abstraction
# =========================

class Clock(Protocol):
    """Minimal clock protocol to support testability."""

    def now(self) -> datetime:
        """Current UTC time as timezone-aware datetime."""
        ...

    def monotonic(self) -> float:
        """Monotonic seconds with high resolution."""
        ...

    async def sleep(self, seconds: float) -> None:
        """Asynchronous sleep that can be cancelled."""
        ...


class SystemClock:
    """Production clock implementation backed by system time and asyncio."""

    __slots__ = ()

    def now(self) -> datetime:
        # Use time.time_ns to minimize rounding, then convert to aware datetime.
        return datetime.fromtimestamp(time.time_ns() / 1_000_000_000, tz=timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            # Yield control to event loop if non-positive
            await asyncio.sleep(0)
            return
        await asyncio.sleep(seconds)


class TestClock:
    """
    Deterministic, manually-advanced clock for tests.

    - monotonic() returns a controlled value.
    - now() is derived from an initial wall time plus monotonic offset.
    - sleep() waits until advance() moves time forward accordingly.
    """

    def __init__(self, start_utc: Optional[datetime] = None) -> None:
        self._mono: float = 0.0
        # Default anchor is current real UTC to keep sensible timestamps in logs.
        self._anchor_utc = (start_utc or utc_now()).astimezone(timezone.utc)
        self._cv = asyncio.Condition()

    def now(self) -> datetime:
        return self._anchor_utc + timedelta(seconds=self._mono)

    def monotonic(self) -> float:
        return self._mono

    async def sleep(self, seconds: float) -> None:
        target = self._mono + max(0.0, seconds)
        async with self._cv:
            # Wait until time has advanced past target
            while self._mono < target:
                await self._cv.wait()

    async def until(self, target_mono: float) -> None:
        async with self._cv:
            while self._mono < target_mono:
                await self._cv.wait()

    def advance(self, seconds: float) -> None:
        """Advance time and wake sleepers."""
        if seconds < 0:
            raise ValueError("cannot go back in time")
        self._mono += seconds
        # Notify all waiters
        async def _notify() -> None:
            async with self._cv:
                self._cv.notify_all()
        # Schedule notify in loop if running; otherwise ignore (tests may call within loop)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_notify())
        except RuntimeError:
            # No running loop; ignored for non-async test scenarios
            pass


# Singletons (optional convenience)
SYSTEM_CLOCK = SystemClock()

# =========================
# Time helpers
# =========================

def utc_now() -> datetime:
    """Current UTC time as timezone-aware datetime."""
    return datetime.now(tz=timezone.utc)

def to_unix(dt: datetime) -> float:
    """UTC-aware datetime -> UNIX seconds float."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.timestamp()

def from_unix(ts: float) -> datetime:
    """UNIX seconds -> UTC-aware datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)

# =========================
# Deadline & Timeout
# =========================

class TimeoutError(asyncio.TimeoutError):
    """Engine-core timeout error with remaining time info."""

    def __init__(self, message: str, *, deadline: Optional["Deadline"] = None) -> None:
        super().__init__(message)
        self.deadline = deadline


@dataclass(frozen=True)
class Deadline:
    """Represents a time limit measured in monotonic seconds."""
    when: float

    @staticmethod
    def after(seconds: float, *, clock: Clock = SYSTEM_CLOCK) -> "Deadline":
        return Deadline(clock.monotonic() + max(0.0, seconds))

    def remaining(self, *, clock: Clock = SYSTEM_CLOCK) -> float:
        return max(0.0, self.when - clock.monotonic())

    def expired(self, *, clock: Clock = SYSTEM_CLOCK) -> bool:
        return self.remaining(clock=clock) <= 0.0

    async def sleep_until(self, *, clock: Clock = SYSTEM_CLOCK) -> None:
        rem = self.remaining(clock=clock)
        if rem > 0:
            await clock.sleep(rem)

    def __str__(self) -> str:
        return f"Deadline(when={self.when:.6f})"


async def sleep_with_deadline(
    timeout: Optional[float],
    *,
    clock: Clock = SYSTEM_CLOCK,
    interrupt: Optional[asyncio.Event] = None,
) -> None:
    """
    Sleep up to timeout seconds or until interrupt event is set.
    If timeout is None, wait only for interrupt (if provided) or yield.
    """
    if timeout is not None and timeout <= 0:
        # Yield control but do not block
        await clock.sleep(0)
        return

    if interrupt is None:
        if timeout is None:
            # Nothing to wait on
            await clock.sleep(0)
            return
        await clock.sleep(timeout)
        return

    # Wait for either interrupt or timeout using wait_for logic with monotonic base
    dl = Deadline.after(timeout if timeout is not None else 365 * 24 * 3600, clock=clock)
    while True:
        if interrupt.is_set():
            return
        rem = dl.remaining(clock=clock)
        if rem <= 0.0:
            return
        # Use smaller slice to be responsive to interrupt
        await clock.sleep(min(0.1, rem))


async def wait_for_deadline(
    coro: Awaitable[Any],
    timeout: Optional[float],
    *,
    clock: Clock = SYSTEM_CLOCK,
) -> Any:
    """
    Await coroutine with Deadline semantics based on monotonic clock.
    Raises TimeoutError on expiration.
    """
    if timeout is None or timeout == float("inf"):
        return await coro

    dl = Deadline.after(timeout, clock=clock)
    task = asyncio.create_task(coro)
    try:
        while True:
            rem = dl.remaining(clock=clock)
            if rem <= 0:
                raise TimeoutError("operation timed out", deadline=dl)
            done, _ = await asyncio.wait({task}, timeout=min(rem, 0.1))
            if done:
                return task.result()
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

# =========================
# Stopwatch
# =========================

class Stopwatch:
    """High-resolution stopwatch, usable as context manager."""

    __slots__ = ("_start", "_elapsed", "_running", "_clock")

    def __init__(self, *, clock: Clock = SYSTEM_CLOCK) -> None:
        self._clock = clock
        self._start: Optional[float] = None
        self._elapsed: float = 0.0
        self._running: bool = False

    def start(self) -> "Stopwatch":
        if self._running:
            return self
        self._start = self._clock.monotonic()
        self._running = True
        return self

    def stop(self) -> float:
        if not self._running or self._start is None:
            return self._elapsed
        self._elapsed += (self._clock.monotonic() - self._start)
        self._start = None
        self._running = False
        return self._elapsed

    def reset(self) -> None:
        self._start = None
        self._elapsed = 0.0
        self._running = False

    @property
    def elapsed(self) -> float:
        if self._running and self._start is not None:
            return self._elapsed + (self._clock.monotonic() - self._start)
        return self._elapsed

    def __enter__(self) -> "Stopwatch":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

# =========================
# Ticker (drift-corrected)
# =========================

class AsyncTicker:
    """
    Drift-corrected periodic ticker yielding ticks at a fixed interval.

    - Uses monotonic schedule (t_{n+1} = t_0 + (n+1)*interval)
    - If the loop is late, it catches up without accumulating drift.
    """

    def __init__(self, interval: float, *, clock: Clock = SYSTEM_CLOCK) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")
        self._interval = float(interval)
        self._clock = clock
        self._running = False
        self._start_mono: Optional[float] = None
        self._n = 0

    async def __aiter__(self) -> AsyncIterator[float]:
        await self.start()
        try:
            while self._running:
                target = self._start_mono + self._n * self._interval  # type: ignore
                now = self._clock.monotonic()
                delay = target - now
                if delay > 0:
                    await self._clock.sleep(delay)
                else:
                    # If we're late by > one interval, skip ahead
                    if -delay > self._interval:
                        missed = math.floor((-delay) / self._interval)
                        self._n += missed
                yield self._clock.monotonic()
                self._n += 1
        finally:
            await self.stop()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._start_mono = self._clock.monotonic()
        self._n = 1  # first tick scheduled at start + interval

    async def stop(self) -> None:
        self._running = False

# =========================
# Backoff with Jitter
# =========================

def add_full_jitter(value: float, *, rng: Callable[[], float] = None) -> float:
    """
    Full jitter in [0, value]. rng returns uniform [0,1).
    """
    if value <= 0:
        return 0.0
    if rng is None:
        rng = time.random  # type: ignore[attr-defined]
    # Fallback if time.random is unavailable (Py <3.11 on some envs)
    try:
        r = rng()
    except Exception:
        r = _fallback_random()
    return r * value

def _fallback_random() -> float:
    # Simple LCG based on monotonic_ns for environments without random
    ns = time.monotonic_ns()
    # Constants from Numerical Recipes
    a = 1664525
    c = 1013904223
    m = 2**32
    x = (a * (ns & 0xFFFFFFFF) + c) % m
    return (x / m)

def exponential_backoff(
    attempt: int,
    *,
    base: float = 0.1,
    factor: float = 2.0,
    cap: float = 30.0,
    jitter: bool = True,
) -> float:
    """
    Compute backoff delay for given attempt (1-based).
    """
    if attempt <= 0:
        return 0.0
    raw = min(cap, base * (factor ** (attempt - 1)))
    return add_full_jitter(raw) if jitter else raw

async def backoff_sleep(
    attempt: int,
    *,
    base: float = 0.1,
    factor: float = 2.0,
    cap: float = 30.0,
    jitter: bool = True,
    max_delay: Optional[float] = None,
    clock: Clock = SYSTEM_CLOCK,
) -> float:
    """Sleep for computed backoff delay and return actual delay."""
    delay = exponential_backoff(attempt, base=base, factor=factor, cap=cap, jitter=jitter)
    if max_delay is not None:
        delay = min(delay, max_delay)
    await clock.sleep(delay)
    return delay

# =========================
# Async Token Bucket Rate Limiter
# =========================

class TokenBucket:
    """
    Async token bucket with fairness and max_delay.

    - capacity: max tokens (burst)
    - refill_rate: tokens per second
    - acquire(n): waits until n tokens available or raises TimeoutError if max_delay exceeded
    """

    def __init__(self, capacity: float, refill_rate: float, *, clock: Clock = SYSTEM_CLOCK) -> None:
        if capacity <= 0 or refill_rate < 0:
            raise ValueError("invalid capacity or refill_rate")
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._tokens = self.capacity
        self._last = clock.monotonic()
        self._clock = clock
        self._cv = asyncio.Condition()

    def _refill(self) -> None:
        now = self._clock.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            self._last = now

    async def acquire(self, n: float = 1.0, *, max_delay: Optional[float] = None) -> None:
        if n <= 0:
            return
        dl = Deadline.after(max_delay, clock=self._clock) if max_delay is not None else None
        async with self._cv:
            while True:
                self._refill()
                if self._tokens >= n:
                    self._tokens -= n
                    self._cv.notify_all()
                    return
                # Not enough tokens; wait a slice or until deadline
                if dl is not None and dl.expired(clock=self._clock):
                    raise TimeoutError("rate limit acquire timed out", deadline=dl)
                # Predict time to availability
                need = n - self._tokens
                tta = need / max(self.refill_rate, 1e-12)  # time-to-available
                slice_sleep = min(0.05, tta)
                if dl is not None:
                    slice_sleep = min(slice_sleep, dl.remaining(clock=self._clock))
                await self._cv.wait_for(lambda: False, timeout=max(slice_sleep, 0.0))  # timed wait

    def tokens(self) -> float:
        self._refill()
        return self._tokens

# =========================
# Convenience helpers
# =========================

async def retry_with_backoff(
    func: Callable[[], Awaitable[Any]],
    *,
    max_attempts: int = 5,
    base: float = 0.1,
    factor: float = 2.0,
    cap: float = 10.0,
    jitter: bool = True,
    clock: Clock = SYSTEM_CLOCK,
    should_retry: Callable[[BaseException], bool] = lambda e: True,
) -> Any:
    """
    Execute func with bounded retries and backoff. Raises last error if all attempts fail.
    """
    attempt = 1
    while True:
        try:
            return await func()
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            if attempt >= max_attempts or not should_retry(e):
                raise
            await backoff_sleep(
                attempt,
                base=base,
                factor=factor,
                cap=cap,
                jitter=jitter,
                clock=clock,
            )
            attempt += 1

# =========================
# Safe timeout wrapper
# =========================

@contextlib.asynccontextmanager
async def timeout_after(seconds: Optional[float], *, clock: Clock = SYSTEM_CLOCK):
    """
    Context manager that cancels on deadline and raises TimeoutError.
    """
    if seconds is None or seconds == float("inf"):
        yield
        return

    dl = Deadline.after(seconds, clock=clock)
    task = asyncio.current_task()
    cancelled = False

    async def _watchdog():
        nonlocal cancelled
        while True:
            rem = dl.remaining(clock=clock)
            if rem <= 0:
                cancelled = True
                if task:
                    task.cancel()
                return
            await clock.sleep(min(rem, 0.05))

    watchdog = asyncio.create_task(_watchdog())
    try:
        yield
    except asyncio.CancelledError:
        if cancelled:
            raise TimeoutError("operation timed out", deadline=dl)
        raise
    finally:
        watchdog.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watchdog

# =========================
# __all__
# =========================

__all__ = [
    # Clocks
    "Clock",
    "SystemClock",
    "TestClock",
    "SYSTEM_CLOCK",
    # Time utils
    "utc_now",
    "to_unix",
    "from_unix",
    # Deadline/timeout
    "Deadline",
    "TimeoutError",
    "sleep_with_deadline",
    "wait_for_deadline",
    "timeout_after",
    # Stopwatch
    "Stopwatch",
    # Ticker
    "AsyncTicker",
    # Backoff
    "add_full_jitter",
    "exponential_backoff",
    "backoff_sleep",
    # Rate limiter
    "TokenBucket",
    # Retry
    "retry_with_backoff",
]
