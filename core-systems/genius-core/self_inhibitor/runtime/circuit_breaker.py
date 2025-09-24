# path: core-systems/genius_core/security/self_inhibitor/runtime/circuit_breaker.py
# License: MIT
from __future__ import annotations

import asyncio
import random
import time
import typing as t
from dataclasses import dataclass, field
from enum import Enum, auto
from threading import BoundedSemaphore, Lock

# -------- Optional latency integration (best-effort) --------
try:
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:  # graceful fallback
    from contextlib import asynccontextmanager, contextmanager

    @asynccontextmanager
    async def track_latency(*_args, **_kwargs):
        yield

    @contextmanager
    def track_latency(*_args, **_kwargs):  # type: ignore
        yield


class State(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


class CallRejected(RuntimeError):
    """Raised when the breaker is OPEN and call is not allowed."""


@dataclass
class CBConfig:
    # Trip conditions
    consecutive_failures: int = 5
    error_rate_threshold: float = 0.5      # 0..1
    window_seconds: float = 30.0
    min_samples: int = 20

    # Open duration & backoff
    open_base_seconds: float = 2.0
    open_max_seconds: float = 60.0
    backoff_factor: float = 2.0
    jitter_fraction: float = 0.2           # +-20%

    # Half-open probing
    half_open_max_concurrent: int = 2
    half_open_successes_to_close: int = 2
    half_open_failures_to_open: int = 1

    # Exceptions policy
    ignored_exceptions: t.Tuple[t.Type[BaseException], ...] = (asyncio.CancelledError,)
    failure_exceptions: t.Tuple[t.Type[BaseException], ...] = (Exception,)

    # Telemetry
    name: str = "circuit"
    on_state_change: t.Optional[t.Callable[[str, State, State], None]] = None


def _now_monotonic() -> float:
    return time.monotonic()


def _jittered(v: float, frac: float) -> float:
    if frac <= 0:
        return v
    delta = v * frac
    return max(0.0, v + random.uniform(-delta, delta))


@dataclass
class _Window:
    # compact ring buffer (timestamps + outcome) for sliding window metrics
    times: t.List[float] = field(default_factory=list)
    ok: t.List[bool] = field(default_factory=list)

    def add(self, ts: float, success: bool, window_seconds: float) -> None:
        self.times.append(ts)
        self.ok.append(success)
        cutoff = ts - window_seconds
        # trim left
        while self.times and self.times[0] < cutoff:
            self.times.pop(0)
            self.ok.pop(0)

    def stats(self, now: float, window_seconds: float) -> t.Tuple[int, int, float]:
        cutoff = now - window_seconds
        total = 0
        fails = 0
        for t0, ok in zip(self.times, self.ok):
            if t0 >= cutoff:
                total += 1
                if not ok:
                    fails += 1
        rate = (fails / total) if total > 0 else 0.0
        return total, fails, rate


class _BaseBreaker:
    """
    Shared core: state machine, metrics, backoff; concurrency control is provided by subclasses.
    """
    def __init__(self, cfg: CBConfig) -> None:
        self.cfg = cfg
        self._state: State = State.CLOSED
        self._opened_until: float = 0.0
        self._streak_fail: int = 0
        self._streak_success: int = 0
        self._half_open_successes: int = 0
        self._half_open_failures: int = 0
        self._window = _Window()
        self._gen = 0  # state version

    # ----- state getters -----
    @property
    def state(self) -> State:
        return self._state

    @property
    def name(self) -> str:
        return self.cfg.name

    # ----- state transitions -----
    def _set_state(self, new_state: State) -> None:
        old = self._state
        if new_state is old:
            return
        self._state = new_state
        self._gen += 1
        if self.cfg.on_state_change:
            try:
                self.cfg.on_state_change(self.cfg.name, old, new_state)
            except Exception:
                pass

    def _compute_open_seconds(self) -> float:
        # exponential backoff bounded by max, based on consecutive failures
        base = self.cfg.open_base_seconds * (self.cfg.backoff_factor ** max(0, self._streak_fail - 1))
        return min(self.cfg.open_max_seconds, _jittered(base, self.cfg.jitter_fraction))

    def _trip_open(self) -> None:
        self._set_state(State.OPEN)
        self._opened_until = _now_monotonic() + self._compute_open_seconds()
        self._half_open_successes = 0
        self._half_open_failures = 0
        self._streak_success = 0

    def _try_half_open(self) -> None:
        # move from OPEN to HALF_OPEN if cooldown passed
        if self._state is State.OPEN and _now_monotonic() >= self._opened_until:
            self._set_state(State.HALF_OPEN)

    def _close(self) -> None:
        self._set_state(State.CLOSED)
        self._opened_until = 0.0
        self._streak_fail = 0
        self._streak_success = 0
        self._half_open_successes = 0
        self._half_open_failures = 0

    # ----- metrics updates -----
    def _record_success(self) -> None:
        self._streak_success += 1
        self._streak_fail = 0
        self._window.add(_now_monotonic(), True, self.cfg.window_seconds)

        if self._state is State.HALF_OPEN:
            self._half_open_successes += 1
            if self._half_open_successes >= self.cfg.half_open_successes_to_close:
                self._close()

    def _record_failure(self) -> None:
        self._streak_fail += 1
        self._streak_success = 0
        self._window.add(_now_monotonic(), False, self.cfg.window_seconds)

        # half-open immediate re-open if threshold hit
        if self._state is State.HALF_OPEN:
            self._half_open_failures += 1
            if self._half_open_failures >= self.cfg.half_open_failures_to_open:
                self._trip_open()
                return

        # closed: check trip conditions
        if self._state is State.CLOSED:
            if self._streak_fail >= self.cfg.consecutive_failures:
                self._trip_open()
                return
            total, fails, rate = self._window.stats(_now_monotonic(), self.cfg.window_seconds)
            if total >= self.cfg.min_samples and rate >= self.cfg.error_rate_threshold:
                self._trip_open()

    # ----- policy evaluation -----
    def _is_counted_failure(self, exc: BaseException) -> bool:
        # ignore whitelisted exceptions
        if isinstance(exc, self.cfg.ignored_exceptions):
            return False
        return isinstance(exc, self.cfg.failure_exceptions)


class CircuitBreaker(_BaseBreaker):
    """
    Thread-safe (sync) Circuit Breaker with optional async compatibility via AsyncCircuitBreaker.
    """
    def __init__(self, cfg: CBConfig) -> None:
        super().__init__(cfg)
        self._lock = Lock()
        self._probe_sem = BoundedSemaphore(max(1, int(cfg.half_open_max_concurrent)))

    # ---- public API (sync) ----
    def allow_call(self) -> bool:
        with self._lock:
            if self._state is State.OPEN:
                self._try_half_open()
                if self._state is State.OPEN:
                    return False
            if self._state is State.HALF_OPEN:
                # acquire non-blocking probe slot
                acquired = self._probe_sem.acquire(blocking=False)
                return acquired
            return True

    def on_after_call(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self._record_success()
            else:
                self._record_failure()
            # release probe slot if was half-open
            if self._state in (State.HALF_OPEN, State.CLOSED):
                # If HALF_OPEN: ensure semaphore is not over-released
                try:
                    if self._probe_sem._value < self.cfg.half_open_max_concurrent:  # type: ignore[attr-defined]
                        self._probe_sem.release()
                except Exception:
                    pass

    def call(self, fn: t.Callable[..., t.Any], *args, **kwargs) -> t.Any:
        if not self.allow_call():
            raise CallRejected(f"breaker_open:{self.cfg.name}")
        # Execute with latency metric
        ok = False
        with track_latency("circuit_call_ms", {"circuit": self.cfg.name}):
            try:
                res = fn(*args, **kwargs)
                ok = True
                return res
            except BaseException as e:
                ok = not self._is_counted_failure(e)
                if not ok:
                    raise
                # ignored exception counts as success for breaker perspective
                return None
            finally:
                self.on_after_call(ok)

    def protect(self, fn: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:
        def _wrap(*args, **kwargs):
            return self.call(fn, *args, **kwargs)
        _wrap.__name__ = getattr(fn, "__name__", "protected")
        return _wrap

    # ---- context manager (sync) ----
    def context(self):
        breaker = self
        class _Ctx:
            def __enter__(self_nonlocal):
                if not breaker.allow_call():
                    raise CallRejected(f"breaker_open:{breaker.cfg.name}")
                breaker._ctx_ok = True  # type: ignore
                return self_nonlocal
            def ok(self_nonlocal):
                breaker._ctx_ok = True  # type: ignore
            def fail(self_nonlocal):
                breaker._ctx_ok = False  # type: ignore
            def __exit__(self_nonlocal, exc_type, exc, tb):
                ok = True
                if exc is not None and breaker._is_counted_failure(exc):
                    ok = False
                elif getattr(breaker, "_ctx_ok", True) is False:  # explicit fail()
                    ok = False
                breaker.on_after_call(ok)
                # propagate original exception if any
                return False
        return _Ctx()


class AsyncCircuitBreaker(_BaseBreaker):
    """
    Asyncio-friendly Circuit Breaker.
    """
    def __init__(self, cfg: CBConfig) -> None:
        super().__init__(cfg)
        self._lock = asyncio.Lock()
        self._probe_sem = asyncio.Semaphore(max(1, int(cfg.half_open_max_concurrent)))

    # ---- public API (async) ----
    async def allow_call(self) -> bool:
        async with self._lock:
            if self._state is State.OPEN:
                self._try_half_open()
                if self._state is State.OPEN:
                    return False
            if self._state is State.HALF_OPEN:
                if self._probe_sem.locked() and self._probe_sem._value <= 0:  # type: ignore[attr-defined]
                    return False
                # acquire non-blocking
                got = self._probe_sem.locked() is False or self._probe_sem._value > 0  # type: ignore[attr-defined]
                if got:
                    try:
                        await asyncio.wait_for(self._probe_sem.acquire(), timeout=0.0)
                        return True
                    except Exception:
                        return False
                return False
            return True

    async def on_after_call(self, ok: bool) -> None:
        async with self._lock:
            if ok:
                self._record_success()
            else:
                self._record_failure()
            # release probe slot if half-open was active
            try:
                if self._state in (State.HALF_OPEN, State.CLOSED):
                    if self._probe_sem._value < self.cfg.half_open_max_concurrent:  # type: ignore[attr-defined]
                        self._probe_sem.release()
            except Exception:
                pass

    async def acall(self, fn: t.Callable[..., t.Awaitable[t.Any]], *args, **kwargs) -> t.Any:
        if not await self.allow_call():
            raise CallRejected(f"breaker_open:{self.cfg.name}")
        ok = False
        async with track_latency("circuit_call_ms", {"circuit": self.cfg.name}):  # type: ignore
            try:
                res = await fn(*args, **kwargs)
                ok = True
                return res
            except BaseException as e:
                ok = not self._is_counted_failure(e)
                if not ok:
                    raise
                return None
            finally:
                await self.on_after_call(ok)

    def aprotect(self, fn: t.Callable[..., t.Awaitable[t.Any]]) -> t.Callable[..., t.Awaitable[t.Any]]:
        async def _wrap(*args, **kwargs):
            return await self.acall(fn, *args, **kwargs)
        _wrap.__name__ = getattr(fn, "__name__", "aprotected")
        return _wrap

    # ---- context manager (async) ----
    def async_context(self):
        breaker = self
        class _AsyncCtx:
            async def __aenter__(self_nonlocal):
                if not await breaker.allow_call():
                    raise CallRejected(f"breaker_open:{breaker.cfg.name}")
                breaker._ctx_ok = True  # type: ignore
                return self_nonlocal
            def ok(self_nonlocal):
                breaker._ctx_ok = True  # type: ignore
            def fail(self_nonlocal):
                breaker._ctx_ok = False  # type: ignore
            async def __aexit__(self_nonlocal, exc_type, exc, tb):
                ok = True
                if exc is not None and breaker._is_counted_failure(exc):
                    ok = False
                elif getattr(breaker, "_ctx_ok", True) is False:
                    ok = False
                await breaker.on_after_call(ok)
                return False
        return _AsyncCtx()


# -------- Factory helpers --------

def make_circuit(
    *,
    name: str = "circuit",
    consecutive_failures: int = 5,
    error_rate_threshold: float = 0.5,
    window_seconds: float = 30.0,
    min_samples: int = 20,
    open_base_seconds: float = 2.0,
    open_max_seconds: float = 60.0,
    backoff_factor: float = 2.0,
    jitter_fraction: float = 0.2,
    half_open_max_concurrent: int = 2,
    half_open_successes_to_close: int = 2,
    half_open_failures_to_open: int = 1,
    ignored_exceptions: t.Tuple[t.Type[BaseException], ...] = (asyncio.CancelledError,),
    failure_exceptions: t.Tuple[t.Type[BaseException], ...] = (Exception,),
    on_state_change: t.Optional[t.Callable[[str, State, State], None]] = None,
) -> CircuitBreaker:
    cfg = CBConfig(
        consecutive_failures=consecutive_failures,
        error_rate_threshold=error_rate_threshold,
        window_seconds=window_seconds,
        min_samples=min_samples,
        open_base_seconds=open_base_seconds,
        open_max_seconds=open_max_seconds,
        backoff_factor=backoff_factor,
        jitter_fraction=jitter_fraction,
        half_open_max_concurrent=half_open_max_concurrent,
        half_open_successes_to_close=half_open_successes_to_close,
        half_open_failures_to_open=half_open_failures_to_open,
        ignored_exceptions=ignored_exceptions,
        failure_exceptions=failure_exceptions,
        name=name,
        on_state_change=on_state_change,
    )
    return CircuitBreaker(cfg)


def make_async_circuit(**kwargs) -> AsyncCircuitBreaker:
    return AsyncCircuitBreaker(make_circuit(**kwargs).cfg)  # reuse config


# -------- Usage examples (doctest-style) --------
if __name__ == "__main__":
    # Sync demo
    cb = make_circuit(name="sync-demo", consecutive_failures=2, min_samples=0)
    def may_fail(i):
        if i < 2:
            raise RuntimeError("boom")
        return "ok"
    for i in range(4):
        try:
            print("call", i, cb.call(may_fail, i))
        except CallRejected as e:
            print("rejected", e)

    # Async demo
    async def run_async():
        acb = make_async_circuit(name="async-demo", consecutive_failures=2, min_samples=0)
        call_no = 0
        async def task():
            nonlocal call_no
            call_no += 1
            if call_no < 2:
                raise RuntimeError("boom")
            return "ok"
        for _ in range(4):
            try:
                print("acall", await acb.acall(task))
            except CallRejected as e:
                print("rejected", e)
            await asyncio.sleep(0.2)
    asyncio.run(run_async())
