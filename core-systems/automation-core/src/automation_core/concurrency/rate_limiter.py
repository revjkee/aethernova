# -*- coding: utf-8 -*-
"""
Industrial-grade rate limiters (token bucket) for sync and async Python.

Verified sources referenced by this module:
- Token bucket as a standard metering/limiting mechanism:
  * RFC 2697 (Single Rate Three Color Marker) — token buckets, rate and burst.  # :contentReference[oaicite:3]{index=3}
  * RFC 2698 (Two Rate Three Color Marker) — token buckets with PIR/CIR.        # :contentReference[oaicite:4]{index=4}
- Use of monotonic clocks for measuring intervals (won't go backwards):
  * Python time.monotonic(): official docs.                                     # :contentReference[oaicite:5]{index=5}
- Synchronous coordination primitives:
  * Python threading module overview/Condition usage.                           # :contentReference[oaicite:6]{index=6}
- Asynchronous coordination primitives:
  * asyncio high-level APIs and sleeping; asyncio.Condition.                    # :contentReference[oaicite:7]{index=7}

Unverified (environment-specific): your exact Python runtime version and workload
patterns. Defaults target Python 3.10+ but rely only on stdlib.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections import OrderedDict
from contextlib import AbstractAsyncContextManager, AbstractContextManager
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Hashable,
    Iterable,
    Optional,
    Tuple,
    TypeVar,
)

__all__ = [
    "RateLimitExceeded",
    "TokenBucketConfig",
    "AsyncTokenBucket",
    "SyncTokenBucket",
    "rate_limited_async",
    "rate_limited_sync",
    "AsyncMultiKeyTokenBucket",
]

T = TypeVar("T")


# ---------------------------- Exceptions -----------------------------

class RateLimitExceeded(RuntimeError):
    """Raised when waiting would exceed max_delay or limiter is closed."""


# ---------------------------- Config model ---------------------------

@dataclass(frozen=True)
class TokenBucketConfig:
    """
    Configuration for token bucket rate limiting.

    rate: tokens per second (float > 0).
    capacity: maximum bucket size (burst). If None, defaults to `rate` (1-second burst).
    jitter: optional additive jitter (seconds) to spread wakeups.
    max_delay: optional hard cap on how long acquire() may wait.
    """
    rate: float
    capacity: Optional[float] = None
    jitter: float = 0.0
    max_delay: Optional[float] = None

    def normalized(self) -> "TokenBucketConfig":
        cap = self.capacity if self.capacity and self.capacity > 0 else self.rate
        if self.rate <= 0:
            raise ValueError("rate must be > 0")
        if cap <= 0:
            raise ValueError("capacity must be > 0")
        if self.jitter < 0:
            raise ValueError("jitter must be >= 0")
        if self.max_delay is not None and self.max_delay < 0:
            raise ValueError("max_delay must be >= 0")
        return TokenBucketConfig(rate=float(self.rate), capacity=float(cap), jitter=float(self.jitter), max_delay=self.max_delay)


# ------------------------ Common token logic -------------------------

def _refill(tokens: float, last_ts: float, now_ts: float, rate: float, capacity: float) -> Tuple[float, float]:
    """Compute new token count using elapsed = now - last_ts, capped at capacity."""
    if now_ts <= last_ts:
        # Monotonic clocks should not go backwards; treat as zero elapsed.  # :contentReference[oaicite:8]{index=8}
        return min(tokens, capacity), last_ts
    elapsed = now_ts - last_ts
    new_tokens = min(capacity, tokens + elapsed * rate)
    return new_tokens, now_ts


def _wait_seconds_needed(tokens: float, cost: float, rate: float) -> float:
    """Seconds to wait until there are >= cost tokens; 0 if already enough."""
    if tokens >= cost:
        return 0.0
    needed = cost - tokens
    return needed / rate


# -------------------------- Async token bucket -----------------------

class AsyncTokenBucket(AbstractAsyncContextManager):
    """
    Asyncio token-bucket rate limiter (FIFO fairness via asyncio.Condition).

    Uses time.monotonic() for time measurement, as recommended for intervals.   # :contentReference[oaicite:9]{index=9}
    Waiting uses asyncio primitives/task sleeping per official docs.            # :contentReference[oaicite:10]{index=10}
    """

    def __init__(self, cfg: TokenBucketConfig) -> None:
        self.cfg = cfg.normalized()
        self._tokens = float(self.cfg.capacity)  # start full (typical for token bucket)
        self._last_ts = time.monotonic()
        self._closed = False
        self._cond = asyncio.Condition()
        self._queue_pos = 0  # increasing ticket for FIFO
        self._next_to_serve = 0

    async def __aenter__(self) -> "AsyncTokenBucket":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        # Wake all waiters (if any)
        if self._cond.locked():  # not strictly required; guard to avoid noise
            pass

    def _refill_locked(self, now_ts: float) -> None:
        self._tokens, self._last_ts = _refill(
            self._tokens, self._last_ts, now_ts, self.cfg.rate, self.cfg.capacity  # type: ignore[arg-type]
        )

    async def acquire(self, cost: float = 1.0, *, max_delay: Optional[float] = None) -> None:
        """
        Acquire tokens, waiting if necessary. Raises RateLimitExceeded if waiting
        would exceed max_delay (from arg or config). Fair to arrival order.
        """
        if cost <= 0:
            return
        max_wait = self.cfg.max_delay if max_delay is None else max_delay
        start = time.monotonic()
        jitter = self.cfg.jitter

        async with self._cond:
            my_ticket = self._queue_pos
            self._queue_pos += 1

            while True:
                if self._closed:
                    raise RateLimitExceeded("Limiter is closed")

                now = time.monotonic()
                self._refill_locked(now)

                # Serve strictly in FIFO order
                if my_ticket == self._next_to_serve and self._tokens >= cost:
                    self._tokens -= cost
                    self._next_to_serve += 1
                    self._cond.notify_all()
                    return

                # Compute remaining wait including rate refill prediction
                wait_needed = _wait_seconds_needed(self._tokens if my_ticket == self._next_to_serve else 0.0, cost, self.cfg.rate)
                # Add small jitter to reduce thundering herd
                wait_time = max(0.0, wait_needed + (jitter if jitter > 0 else 0.0))

                if max_wait is not None:
                    elapsed = now - start
                    if elapsed + wait_time > max_wait + 1e-12:
                        raise RateLimitExceeded(f"Would exceed max_delay={max_wait:.6f}s (elapsed={elapsed:.6f}s, extra={wait_time:.6f}s)")

                # Wait until enough tokens (or our turn) or timeout/cancel
                # asyncio.Condition.wait() suspends the task cooperatively.     # :contentReference[oaicite:11]{index=11}
                try:
                    if wait_time == 0.0:
                        await self._cond.wait()
                    else:
                        # sleep without holding the lock to not block others
                        self._cond.release()
                        try:
                            await asyncio.sleep(wait_time)  # non-blocking sleep  # :contentReference[oaicite:12]{index=12}
                        finally:
                            await self._cond.acquire()
                except asyncio.CancelledError:
                    # Preserve FIFO counter for others and propagate
                    raise

    async def try_acquire(self, cost: float = 1.0) -> bool:
        """Attempt to acquire without waiting; return True on success."""
        if cost <= 0:
            return True
        async with self._cond:
            if self._closed:
                return False
            now = time.monotonic()
            self._refill_locked(now)
            if self._next_to_serve != self._queue_pos:
                # someone is ahead in queue — do not steal
                return False
            if self._tokens >= cost:
                self._tokens -= cost
                self._next_to_serve += 1
                self._cond.notify_all()
                return True
            return False


# -------------------------- Sync token bucket ------------------------

class SyncTokenBucket(AbstractContextManager):
    """
    Thread-safe token-bucket limiter (FIFO fairness via threading.Condition).

    Uses time.monotonic() for intervals; `Condition` coordinates waiters.       # :contentReference[oaicite:13]{index=13}
    """

    def __init__(self, cfg: TokenBucketConfig) -> None:
        self.cfg = cfg.normalized()
        self._tokens = float(self.cfg.capacity)
        self._last_ts = time.monotonic()
        self._closed = False
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._queue_pos = 0
        self._next_to_serve = 0

    def __enter__(self) -> "SyncTokenBucket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _refill_locked(self, now_ts: float) -> None:
        self._tokens, self._last_ts = _refill(
            self._tokens, self._last_ts, now_ts, self.cfg.rate, self.cfg.capacity  # type: ignore[arg-type]
        )

    def acquire(self, cost: float = 1.0, *, max_delay: Optional[float] = None) -> None:
        """Blocking acquire; raises RateLimitExceeded if wait > max_delay."""
        if cost <= 0:
            return
        max_wait = self.cfg.max_delay if max_delay is None else max_delay
        start = time.monotonic()
        jitter = self.cfg.jitter

        with self._cond:
            my_ticket = self._queue_pos
            self._queue_pos += 1

            while True:
                if self._closed:
                    raise RateLimitExceeded("Limiter is closed")

                now = time.monotonic()
                self._refill_locked(now)

                if my_ticket == self._next_to_serve and self._tokens >= cost:
                    self._tokens -= cost
                    self._next_to_serve += 1
                    self._cond.notify_all()
                    return

                wait_needed = _wait_seconds_needed(self._tokens if my_ticket == self._next_to_serve else 0.0, cost, self.cfg.rate)
                wait_time = max(0.0, wait_needed + (jitter if jitter > 0 else 0.0))

                if max_wait is not None:
                    elapsed = now - start
                    if elapsed + wait_time > max_wait + 1e-12:
                        raise RateLimitExceeded(f"Would exceed max_delay={max_wait:.6f}s (elapsed={elapsed:.6f}s, extra={wait_time:.6f}s)")

                # Condition.wait(timeout) releases lock and blocks current thread; see docs.  # :contentReference[oaicite:14]{index=14}
                self._cond.wait(timeout=wait_time if wait_time > 0 else None)

    def try_acquire(self, cost: float = 1.0) -> bool:
        """Non-blocking acquire; return True if tokens were taken."""
        if cost <= 0:
            return True
        with self._cond:
            if self._closed:
                return False
            now = time.monotonic()
            self._refill_locked(now)
            if self._next_to_serve != self._queue_pos:
                return False
            if self._tokens >= cost:
                self._tokens -= cost
                self._next_to_serve += 1
                self._cond.notify_all()
                return True
            return False


# ------------------------- Async per-key limiter ---------------------

class AsyncMultiKeyTokenBucket:
    """
    Manages per-key AsyncTokenBucket instances with LRU eviction and TTL.

    Use cases: per-tenant/user/endpoint rate limits. All operations are async.
    """

    def __init__(
        self,
        cfg_factory: Callable[[Hashable], TokenBucketConfig],
        *,
        max_buckets: int = 1024,
        ttl_seconds: float = 300.0,
    ) -> None:
        if max_buckets <= 0:
            raise ValueError("max_buckets must be > 0")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")

        self._cfg_factory = cfg_factory
        self._max_buckets = max_buckets
        self._ttl = ttl_seconds
        self._buckets: OrderedDict[Hashable, Tuple[AsyncTokenBucket, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def _get_bucket(self, key: Hashable) -> AsyncTokenBucket:
        now = time.monotonic()
        async with self._lock:
            # Evict expired
            to_delete: Iterable[Hashable] = []
            for k, (_, last_used) in list(self._buckets.items()):
                if now - last_used > self._ttl:
                    to_delete.append(k)
            for k in to_delete:
                bucket, _ = self._buckets.pop(k, (None, 0.0))  # type: ignore[assignment]
                if bucket:
                    bucket.close()

            # Return or create
            if key in self._buckets:
                bucket, _ = self._buckets.pop(key)  # move to end (LRU)
                self._buckets[key] = (bucket, now)
                return bucket

            if len(self._buckets) >= self._max_buckets:
                # Evict least-recently used
                old_key, (old_bucket, _) = self._buckets.popitem(last=False)
                old_bucket.close()

            cfg = self._cfg_factory(key).normalized()
            bucket = AsyncTokenBucket(cfg)
            self._buckets[key] = (bucket, now)
            return bucket

    async def acquire(self, key: Hashable, cost: float = 1.0, *, max_delay: Optional[float] = None) -> None:
        bucket = await self._get_bucket(key)
        await bucket.acquire(cost=cost, max_delay=max_delay)

    async def try_acquire(self, key: Hashable, cost: float = 1.0) -> bool:
        bucket = await self._get_bucket(key)
        return await bucket.try_acquire(cost=cost)


# ------------------------------ Decorators ---------------------------

def rate_limited_async(limiter: AsyncTokenBucket, *, cost: float = 1.0) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Decorator for async functions to acquire before calling."""

    def _wrap(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def _inner(*args: Any, **kwargs: Any) -> T:
            await limiter.acquire(cost=cost)
            return await fn(*args, **kwargs)
        return _inner

    return _wrap


def rate_limited_sync(limiter: SyncTokenBucket, *, cost: float = 1.0) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for sync functions to acquire before calling."""

    def _wrap(fn: Callable[..., T]) -> Callable[..., T]:
        def _inner(*args: Any, **kwargs: Any) -> T:
            limiter.acquire(cost=cost)
            return fn(*args, **kwargs)
        return _inner

    return _wrap
