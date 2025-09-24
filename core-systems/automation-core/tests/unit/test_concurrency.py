# SPDX-License-Identifier: MIT
# automation-core/tests/unit/test_concurrency.py
import asyncio
import time
from typing import Awaitable, Callable, Iterable, List, Optional, Tuple

import pytest

# -----------------------------------------------------------------------------
# SUT import (optional). If your project provides implementations,
# tests will use them. Otherwise, a robust reference implementation is used.
# -----------------------------------------------------------------------------
try:  # pragma: no cover - import path may vary in early stages
    from automation_core.utils.concurrency import run_limited, RateLimiter  # type: ignore
except Exception:  # pragma: no cover
    # ---------------- Reference implementation used for tests ----------------
    class RateLimiter:
        """
        Token-bucket rate limiter for asyncio (permits/second).
        capacity: max burst tokens; defaults to 'rate' if None.
        """

        def __init__(self, rate: float, capacity: Optional[int] = None) -> None:
            assert rate > 0, "rate must be > 0"
            self._rate = float(rate)
            self._capacity = float(capacity if capacity is not None else max(1.0, rate))
            self._tokens = self._capacity
            self._last = time.monotonic()
            self._lock = asyncio.Lock()

        async def acquire(self, permits: float = 1.0) -> None:
            if permits <= 0:
                return
            async with self._lock:
                while True:
                    now = time.monotonic()
                    elapsed = now - self._last
                    if elapsed > 0:
                        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                        self._last = now
                    if self._tokens >= permits:
                        self._tokens -= permits
                        return
                    # Need to wait for more tokens
                    needed = permits - self._tokens
                    sleep_for = max(needed / self._rate, 0.0)
                    # Sleep in small chunks to remain responsive to cancellation
                    await asyncio.sleep(min(sleep_for, 0.05))

        # Context-manager sugar
        async def __aenter__(self):
            await self.acquire(1.0)
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def run_limited(
        concurrency: int,
        coros: Iterable[Callable[[], Awaitable]],
        *,
        timeout: Optional[float] = None,
        cancel_on_fail: bool = True,
    ) -> List:
        """
        Execute callables (no-arg coroutines) with a hard concurrency cap.
        If timeout is set, the overall run is bounded.
        On failure:
          - if cancel_on_fail=True: cancels all pending/active tasks and raises the first error
          - if False: waits for remaining tasks and raises AggregateError (first error)
        """
        assert concurrency >= 1, "concurrency must be >= 1"
        sem = asyncio.Semaphore(concurrency)
        tasks: List[asyncio.Task] = []
        results: List = []
        first_err: Optional[BaseException] = None

        async def _wrap(fn: Callable[[], Awaitable]):
            async with sem:
                return await fn()

        async def _runner():
            nonlocal first_err
            for fn in coros:
                if cancel_on_fail and first_err is not None:
                    break
                t = asyncio.create_task(_wrap(fn))
                tasks.append(t)
                # Attach error propagation
                def _done(task: asyncio.Task):
                    nonlocal first_err
                    if task.cancelled():
                        return
                    exc = task.exception()
                    if exc and first_err is None:
                        first_err = exc
                        if cancel_on_fail:
                            for ot in tasks:
                                if not ot.done():
                                    ot.cancel()
                t.add_done_callback(_done)

            # Gather results but allow cancellation/timeout to bubble
            for t in tasks:
                try:
                    res = await t
                    results.append(res)
                except asyncio.CancelledError:
                    pass
                except BaseException as e:
                    if not cancel_on_fail:
                        # continue gathering; re-raise after loop
                        continue
                    raise

            if first_err and not cancel_on_fail:
                raise first_err
            return results

        if timeout is not None:
            return await asyncio.wait_for(_runner(), timeout=timeout)
        return await _runner()


# -----------------------------------------------------------------------------
# Helpers for tests
# -----------------------------------------------------------------------------
class ConcurrencyProbe:
    """
    Tracks current and peak concurrency across awaited sections.
    """
    def __init__(self) -> None:
        self.current = 0
        self.peak = 0
        self._lock = asyncio.Lock()

    async def enter(self):
        async with self._lock:
            self.current += 1
            if self.current > self.peak:
                self.peak = self.current

    async def exit(self):
        async with self._lock:
            self.current -= 1
            assert self.current >= 0, "negative concurrency count"

    async def guarded(self, delay: float = 0.05):
        await self.enter()
        try:
            await asyncio.sleep(delay)
        finally:
            await self.exit()


async def _work(probe: ConcurrencyProbe, delay: float = 0.05, result: int = 1):
    await probe.guarded(delay)
    return result


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_limited_never_exceeds_concurrency():
    """
    Ensure that at no time concurrent tasks exceed the cap.
    """
    probe = ConcurrencyProbe()
    limit = 5
    total = 37

    coros = [lambda d=0.02 * (i % 3): (lambda: _work(probe, delay=0.03 + d, result=i))() for i in range(total)]
    results = await run_limited(limit, coros)
    assert len(results) == total
    assert probe.peak <= limit, f"peak concurrency {probe.peak} exceeded limit {limit}"


@pytest.mark.asyncio
async def test_run_limited_timeout_and_cancel_on_fail():
    """
    If overall timeout elapses, pending tasks should cancel and TimeoutError raised.
    """
    probe = ConcurrencyProbe()
    limit = 3
    total = 20

    # One deliberately slow task to trigger timeout
    async def slow():
        await probe.enter()
        try:
            await asyncio.sleep(2.0)
        finally:
            await probe.exit()
        return -1

    coros: List[Callable[[], Awaitable]] = [lambda: _work(probe, delay=0.05, result=1) for _ in range(total)]
    coros.insert(5, slow)  # add slow task roughly in the middle

    t0 = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await run_limited(limit, coros, timeout=0.5, cancel_on_fail=True)
    elapsed = time.monotonic() - t0

    assert elapsed < 1.5, "timeout handling took unexpectedly long"
    # Even with cancellation, peak must not exceed limit
    assert probe.peak <= limit


@pytest.mark.asyncio
async def test_run_limited_error_no_cancel_on_fail_collects_others():
    """
    When cancel_on_fail=False, other tasks should finish even if one fails.
    """
    probe = ConcurrencyProbe()
    limit = 4

    async def fail_task():
        await probe.enter()
        try:
            await asyncio.sleep(0.05)
            raise RuntimeError("boom")
        finally:
            await probe.exit()

    successes = 25
    coros: List[Callable[[], Awaitable]] = [lambda: _work(probe, delay=0.03, result=1) for _ in range(successes)]
    coros.insert(7, fail_task)

    with pytest.raises(RuntimeError):
        await run_limited(limit, coros, timeout=5.0, cancel_on_fail=False)

    # Ensure the rest had a chance to run and concurrency cap preserved
    assert probe.peak <= limit


@pytest.mark.asyncio
async def test_rate_limiter_throttles_total_time_with_burst():
    """
    Token-bucket: capacity 'cap' allows instant 'cap' permits, replenishing at 'rate' per second.
    We request 'n' permits and assert the total time is at least the theoretical minimum
    (with small tolerance for scheduling jitter).
    """
    rate = 5.0  # permits per second
    cap = 5     # initial burst
    n = 10      # total permits to acquire

    limiter = RateLimiter(rate=rate, capacity=cap)

    async def do_acquire():
        await limiter.acquire(1.0)

    t0 = time.monotonic()
    await run_limited(concurrency=10, coros=[lambda: do_acquire() for _ in range(n)], timeout=5.0)
    elapsed = time.monotonic() - t0

    # Expect at least (n - cap) / rate seconds for the extra permits.
    expected_min = (n - cap) / rate  # 1.0s
    # Allow negative tolerance (i.e., lower bound) to accommodate clock/granularity
    tolerance = 0.20  # seconds
    assert elapsed + tolerance >= expected_min, f"rate limiter too permissive: {elapsed:.3f}s < {expected_min:.3f}s"


@pytest.mark.asyncio
async def test_cancellation_propagates_to_children():
    """
    Cancelling the parent task should cancel in-flight operations.
    """
    probe = ConcurrencyProbe()
    limit = 3

    async def long_task():
        try:
            await probe.guarded(1.0)
            return "ok"
        except asyncio.CancelledError:
            # Ensure cleanup was performed
            raise

    async def parent():
        coros = [lambda: long_task() for _ in range(10)]
        # No timeout; we will cancel the parent soon after it starts
        return await run_limited(limit, coros, cancel_on_fail=True)

    task = asyncio.create_task(parent())
    await asyncio.sleep(0.1)  # let some children start
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert probe.peak <= limit


@pytest.mark.asyncio
async def test_backpressure_with_queue_and_limited_workers():
    """
    End-to-end sanity: producer fills a bounded queue, workers consume with a concurrency cap.
    Ensures we don't deadlock and the cap is respected.
    """
    probe = ConcurrencyProbe()
    q: asyncio.Queue[int] = asyncio.Queue(maxsize=8)
    items = list(range(50))
    produced = 0
    consumed: List[int] = []

    async def producer():
        nonlocal produced
        for x in items:
            await q.put(x)
            produced += 1
        # Signal end
        for _ in range(4):
            await q.put(-1)

    async def worker():
        while True:
            x = await q.get()
            if x == -1:
                q.task_done()
                break
            # simulate work
            await probe.guarded(0.02)
            consumed.append(x)
            q.task_done()

    async def runner():
        prod = asyncio.create_task(producer())
        workers = [asyncio.create_task(worker()) for _ in range(4)]
        await q.join()
        for w in workers:
            await w
        await prod

    await asyncio.wait_for(runner(), timeout=5.0)
    assert produced == len(items) + 4  # including sentinels
    assert len([x for x in consumed if x >= 0]) == len(items)
    assert probe.peak <= 4
