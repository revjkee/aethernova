# datafabric-core/datafabric/utils/backpressure.py
# Industrial-grade backpressure utilities for DataFabric
# Features:
# - TokenBucket & LeakyBucket rate limiters (thread-safe)
# - ConcurrencyLimiter (sync/async) with adaptive controller (AIMD + PID-like smoothing)
# - Overload detection via moving latency window, error rate, queue depth
# - Exponential backoff with decorrelated jitter
# - Retry-After aware sleeping
# - Context managers & decorators (sync/async)
# - Lightweight metrics snapshot for observability/audit
# - No external deps

from __future__ import annotations

import asyncio
import math
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar, Awaitable, Union, Iterable

T = TypeVar("T")

# ========= Helpers =========

def _now() -> float:
    return time.monotonic()

def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def _exp_backoff_with_jitter(base: float, cap: float, attempt: int) -> float:
    # "Decorrelated jitter" per AWS architecture blogs
    import random
    sleep = min(cap, base * (2 ** attempt))
    return random.uniform(sleep / 2.0, sleep)

def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        # Seconds form
        return float(value)
    except Exception:
        return None

# ========= Sliding window stats =========

class EWMA:
    """Exponentially Weighted Moving Average for latency."""
    def __init__(self, alpha: float = 0.2, initial: Optional[float] = None):
        self.alpha = alpha
        self.value = initial
    def update(self, x: float) -> float:
        if self.value is None:
            self.value = x
        else:
            self.value = self.alpha * x + (1 - self.alpha) * self.value
        return self.value or x

class CounterWindow:
    """Rolling counters over coarse windows to approximate error rate."""
    def __init__(self, window_sec: float = 10.0):
        self.window = window_sec
        self._data: list[Tuple[float, int, int]] = []  # (t, ok, err)
        self._lock = threading.Lock()
    def add(self, ok: int, err: int) -> None:
        with self._lock:
            self._data.append((_now(), ok, err))
            self._prune()
    def _prune(self) -> None:
        cutoff = _now() - self.window
        while self._data and self._data[0][0] < cutoff:
            self._data.pop(0)
    def snapshot(self) -> Tuple[int, int, float]:
        with self._lock:
            self._prune()
            ok = sum(x[1] for x in self._data)
            err = sum(x[2] for x in self._data)
            rate = err / max(1, ok + err)
            return ok, err, rate

# ========= TokenBucket / LeakyBucket =========

class TokenBucket:
    """
    Thread-safe token bucket.
    capacity: max tokens
    rate: tokens per second added
    """
    def __init__(self, rate: float, capacity: Optional[float] = None):
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else rate)
        self.tokens = self.capacity
        self.ts = _now()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = _now()
        delta = now - self.ts
        if delta > 0:
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            self.ts = now

    def try_consume(self, amount: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def wait(self, amount: float = 1.0) -> None:
        # Blocking wait until tokens available
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                needed = (amount - self.tokens) / self.rate if self.rate > 0 else 0.01
            time.sleep(max(0.0, needed))

class LeakyBucket:
    """
    Thread-safe leaky bucket approximating constant drain (good for smoothing bursts).
    """
    def __init__(self, rate: float, capacity: float):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.level = 0.0
        self.ts = _now()
        self._lock = threading.Lock()

    def _drain(self) -> None:
        now = _now()
        delta = now - self.ts
        drained = delta * self.rate
        self.level = max(0.0, self.level - drained)
        self.ts = now

    def try_add(self, amount: float = 1.0) -> bool:
        with self._lock:
            self._drain()
            if self.level + amount <= self.capacity:
                self.level += amount
                return True
            return False

# ========= ConcurrencyLimiter (sync/async) =========

class ConcurrencyLimiter:
    """Semaphore-based concurrency limiter with queue size bound."""
    def __init__(self, max_concurrency: int, max_queue: int = 0):
        self._sem = threading.Semaphore(max(1, int(max_concurrency)))
        self._queue_bound = int(max_queue)

    def acquire(self, block: bool = True, timeout: Optional[float] = None) -> bool:
        if self._queue_bound > 0 and threading.active_count() > self._queue_bound:
            return False
        return self._sem.acquire(blocking=block, timeout=timeout if timeout is not None else -1)

    def release(self) -> None:
        self._sem.release()

class AsyncConcurrencyLimiter:
    def __init__(self, max_concurrency: int):
        self._sem = asyncio.Semaphore(max(1, int(max_concurrency)))
    async def acquire(self) -> None:
        await self._sem.acquire()
    def release(self) -> None:
        self._sem.release()

# ========= Adaptive Controller =========

@dataclass
class AdaptiveConfig:
    min_parallel: int = 1
    max_parallel: int = 512
    start_parallel: int = 8
    target_latency_ms: float = 200.0
    high_error_rate: float = 0.05
    # AIMD parameters
    add_step: int = 1
    mul_factor: float = 0.5
    # PID-like smoothing (on latency error)
    kp: float = 0.02
    ki: float = 0.001
    kd: float = 0.01
    integral_limit: float = 100.0
    # backoff bounds
    sleep_cap_s: float = 1.0
    # sampling windows
    latency_alpha: float = 0.2
    error_window_s: float = 10.0

@dataclass
class AdaptiveState:
    parallel: int
    ewma_latency_ms: EWMA
    counter: CounterWindow
    integral: float = 0.0
    last_error: float = 0.0
    last_update_ts: float = field(default_factory=_now)
    overload: bool = False

class AdaptiveBackpressure:
    """
    Adaptive controller managing concurrency and delays based on latency & error rate.
    Designed to sit above TokenBucket/ConcurrencyLimiter.
    """
    def __init__(self, cfg: Optional[AdaptiveConfig] = None):
        self.cfg = cfg or AdaptiveConfig()
        self.state = AdaptiveState(
            parallel=int(self.cfg.start_parallel),
            ewma_latency_ms=EWMA(alpha=self.cfg.latency_alpha),
            counter=CounterWindow(window_sec=self.cfg.error_window_s),
        )
        self._lock = threading.Lock()

    def record(self, latency_ms: float, ok: bool, queue_depth: Optional[int] = None) -> None:
        with self._lock:
            e = self.state.ewma_latency_ms.update(latency_ms)
            self.state.counter.add(1 if ok else 0, 0 if ok else 1)
            _, _, err_rate = self.state.counter.snapshot()
            # Determine overload
            overload = (e > self.cfg.target_latency_ms) or (err_rate >= self.cfg.high_error_rate) or (queue_depth is not None and queue_depth > 0)
            self.state.overload = overload
            # Update parallelism via AIMD + PID-like correction
            dt_s = max(1e-3, _now() - self.state.last_update_ts)
            self.state.last_update_ts = _now()
            error = (e - self.cfg.target_latency_ms)
            # PID terms
            self.state.integral = _clamp(self.state.integral + error * dt_s, -self.cfg.integral_limit, self.cfg.integral_limit)
            derivative = (error - self.state.last_error) / dt_s if dt_s > 0 else 0.0
            self.state.last_error = error
            pid_correction = self.cfg.kp * error + self.cfg.ki * self.state.integral + self.cfg.kd * derivative

            if overload:
                new_parallel = int(math.floor(self.state.parallel * self.cfg.mul_factor))
            else:
                new_parallel = int(self.state.parallel + self.cfg.add_step)

            # Apply PID correction as small additive clamp
            new_parallel = int(_clamp(new_parallel - pid_correction, self.cfg.min_parallel, self.cfg.max_parallel))
            if new_parallel != self.state.parallel:
                self.state.parallel = new_parallel

    def recommend_sleep(self, attempt: int = 0, retry_after: Optional[str] = None) -> float:
        ra = _parse_retry_after(retry_after)
        if ra is not None:
            return _clamp(ra, 0.0, self.cfg.sleep_cap_s)
        # If overloaded, add jittered backoff; otherwise 0
        if self.state.overload:
            return _exp_backoff_with_jitter(0.01, self.cfg.sleep_cap_s, attempt)
        return 0.0

    def snapshot(self) -> Dict[str, Any]:
        ok, err, er = self.state.counter.snapshot()
        return {
            "parallel": self.state.parallel,
            "ewma_latency_ms": self.state.ewma_latency_ms.value,
            "ok": ok,
            "err": err,
            "error_rate": er,
            "overload": self.state.overload,
            "ts": _now(),
        }

# ========= High-level Controller =========

class BackpressureController:
    """
    Combines TokenBucket + ConcurrencyLimiter + AdaptiveBackpressure.
    Typical usage:
        bp = BackpressureController(target_rps=500, max_parallel=128)
        with bp.limit_sync():
            # do work and report result
            ...
            bp.report(latency_ms, ok=True)
    """
    def __init__(
        self,
        target_rps: float = 100.0,
        burst: Optional[float] = None,
        max_parallel: int = 128,
        start_parallel: Optional[int] = None,
        adaptive_cfg: Optional[AdaptiveConfig] = None,
    ):
        self.bucket = TokenBucket(rate=target_rps, capacity=burst if burst is not None else target_rps)
        cfg = adaptive_cfg or AdaptiveConfig(max_parallel=max_parallel, start_parallel=start_parallel or min(max_parallel, 8))
        self.adaptive = AdaptiveBackpressure(cfg)
        self.conc = ConcurrencyLimiter(max_concurrency=cfg.start_parallel)
        self.async_conc = AsyncConcurrencyLimiter(max_concurrency=cfg.start_parallel)
        self._lock = threading.Lock()

    # ----- Acquisition APIs -----

    def limit_sync(self, tokens: float = 1.0, timeout: Optional[float] = None):
        """Context manager for sync code."""
        bucket = self.bucket
        conc = self.conc
        class _Ctx:
            def __enter__(self_nonlocal):
                bucket.wait(tokens)
                acquired = conc.acquire(timeout=timeout if timeout is not None else None)
                if not acquired:
                    # If cannot acquire, sleep small and retry once
                    time.sleep(0.005)
                    if not conc.acquire(timeout=timeout if timeout is not None else None):
                        raise TimeoutError("Backpressure concurrency acquire timeout")
                return self
            def __exit__(self_nonlocal, exc_type, exc, tb):
                conc.release()
                # On exception we still release
                return False
        return _Ctx()

    def limit_async(self, tokens: float = 1.0):
        """Async context manager for async code."""
        controller = self
        class _ACtx:
            async def __aenter__(self_nonlocal):
                # Busy-wait with small sleeps to mimic token wait
                while not controller.bucket.try_consume(tokens):
                    await asyncio.sleep(0.001)
                await controller.async_conc.acquire()
                return controller
            async def __aexit__(self_nonlocal, exc_type, exc, tb):
                controller.async_conc.release()
                return False
        return _ACtx()

    # ----- Reporting & Adaptation -----

    def report(self, latency_ms: float, ok: bool, queue_depth: Optional[int] = None) -> None:
        self.adaptive.record(latency_ms=latency_ms, ok=ok, queue_depth=queue_depth)
        snap = self.adaptive.snapshot()
        # Adjust concurrency limiters if needed
        desired = int(max(1, min(snap["parallel"], self.adaptive.cfg.max_parallel)))
        with self._lock:
            # Update sync limiter by replacing semaphore permits difference
            delta = desired - self._available_concurrency()
            if delta != 0:
                # Recreate semaphores to adjust permits atomically/safely
                self.conc = ConcurrencyLimiter(max_concurrency=desired)
                self.async_conc = AsyncConcurrencyLimiter(max_concurrency=desired)

    def _available_concurrency(self) -> int:
        # We cannot directly read Semaphore count; keep from adaptive state
        return int(self.adaptive.state.parallel)

    # ----- Decorators -----

    def guard(self, tokens: float = 1.0, timeout: Optional[float] = None):
        """Decorator for sync functions with auto-reporting based on duration and success."""
        def _wrap(fn: Callable[..., T]) -> Callable[..., T]:
            def _inner(*args, **kwargs) -> T:
                t0 = _now()
                with self.limit_sync(tokens=tokens, timeout=timeout):
                    try:
                        res = fn(*args, **kwargs)
                        ok = True
                        return res
                    except Exception:
                        ok = False
                        raise
                    finally:
                        self.report((_now() - t0) * 1000.0, ok=ok)
            _inner.__name__ = fn.__name__
            _inner.__doc__ = fn.__doc__
            return _inner
        return _wrap

    def aguard(self, tokens: float = 1.0):
        """Decorator for async functions with auto-reporting."""
        def _wrap(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            async def _inner(*args, **kwargs) -> T:
                t0 = _now()
                async with self.limit_async(tokens=tokens):
                    try:
                        res = await fn(*args, **kwargs)
                        ok = True
                        return res
                    except Exception:
                        ok = False
                        raise
                    finally:
                        self.report((_now() - t0) * 1000.0, ok=ok)
            _inner.__name__ = fn.__name__
            _inner.__doc__ = fn.__doc__
            return _inner
        return _wrap

    # ----- Retry helper -----

    def retry_with_backoff(
        self,
        fn: Callable[[], T],
        should_retry: Callable[[BaseException], bool],
        max_attempts: int = 5,
        retry_after_header: Optional[str] = None,
    ) -> T:
        attempt = 0
        while True:
            t0 = _now()
            with self.limit_sync():
                try:
                    res = fn()
                    self.report((_now() - t0) * 1000.0, ok=True)
                    return res
                except Exception as e:
                    self.report((_now() - t0) * 1000.0, ok=False)
                    if attempt >= max_attempts - 1 or not should_retry(e):
                        raise
                    ra = _parse_retry_after(retry_after_header)
                    sleep = ra if ra is not None else self.adaptive.recommend_sleep(attempt=attempt)
            time.sleep(sleep)
            attempt += 1

    async def aretry_with_backoff(
        self,
        fn: Callable[[], Awaitable[T]],
        should_retry: Callable[[BaseException], bool],
        max_attempts: int = 5,
        retry_after_header: Optional[str] = None,
    ) -> T:
        attempt = 0
        while True:
            t0 = _now()
            async with self.limit_async():
                try:
                    res = await fn()
                    self.report((_now() - t0) * 1000.0, ok=True)
                    return res
                except Exception as e:
                    self.report((_now() - t0) * 1000.0, ok=False)
                    if attempt >= max_attempts - 1 or not should_retry(e):
                        raise
                    ra = _parse_retry_after(retry_after_header)
                    sleep = ra if ra is not None else self.adaptive.recommend_sleep(attempt=attempt)
            await asyncio.sleep(sleep)
            attempt += 1

    # ----- Metrics -----

    def metrics(self) -> Dict[str, Any]:
        s = self.adaptive.snapshot()
        s.update({
            "token_bucket_tokens": self.bucket.tokens,
            "token_bucket_capacity": self.bucket.capacity,
            "controller_id": str(uuid.uuid4()),
        })
        return s

# ========= Integration notes (docstring style) =========
"""
Integration patterns:

1) Kafka consumer (python):
    bp = BackpressureController(target_rps=2000, max_parallel=64)
    for msg in consumer:
        t0 = _now()
        with bp.limit_sync():
            ok = True
            try:
                process(msg)
            except Exception:
                ok = False
                # dead-letter, etc.
            finally:
                bp.report((_now()-t0)*1000.0, ok)

2) Spark foreachBatch:
    # Use BP in driver to throttle external I/O (e.g., REST calls)
    bp = BackpressureController(target_rps=500, max_parallel=32)
    def writer(df, epoch_id):
        rows = df.collect()  # example; in practice, mapPartitions
        for r in rows:
            t0 = _now()
            with bp.limit_sync():
                ok = True
                try:
                    write_to_api(r)
                except Exception:
                    ok = False
                finally:
                    bp.report((_now()-t0)*1000.0, ok)
"""
# ========= Self-test =========

if __name__ == "__main__":
    bp = BackpressureController(target_rps=200.0, max_parallel=32)
    import random
    def work():
        # simulate variable latency and failures
        t = random.uniform(0.001, 0.02)
        time.sleep(t)
        if random.random() < 0.02:
            raise RuntimeError("boom")
    for i in range(1000):
        try:
            @bp.guard()
            def run():
                work()
            run()
        except Exception:
            pass
    print(bp.metrics())
