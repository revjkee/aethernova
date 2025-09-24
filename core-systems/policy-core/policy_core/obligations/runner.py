# policy-core/policy_core/obligations/runner.py
# Industrial async obligation runner for NeuroCity/TeslaAI policy-core.
# Features: registry, timeouts, retries (exp backoff + jitter), per-handler concurrency,
# circuit breaker, idempotency (TTL), structured audit logs, optional OpenTelemetry.
# No external hard dependencies.

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
    runtime_checkable,
)

# Optional OpenTelemetry (soft dependency)
try:
    from opentelemetry import trace as _ot_trace  # type: ignore
    _OTEL_TRACER = _ot_trace.get_tracer("policy_core.obligations.runner")
except Exception:  # pragma: no cover
    _OTEL_TRACER = None  # graceful fallback


__all__ = [
    "Obligation",
    "ObligationResult",
    "ObligationHandler",
    "ObligationRunner",
    "ObligationExecutionError",
    "HandlerAlreadyRegistered",
    "HandlerNotFound",
]


# ==========================
# Utilities and JSON logging
# ==========================

def _json_log(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    try:
        logger.log(level, json.dumps(payload, ensure_ascii=False))
    except Exception:
        logger.log(level, f"{event} {fields}")


@contextlib.asynccontextmanager
async def _maybe_async_context(cm: Any):
    """Accept sync or async context managers uniformly."""
    if hasattr(cm, "__aenter__") and hasattr(cm, "__aexit__"):
        async with cm:
            yield
    elif hasattr(cm, "__enter__") and hasattr(cm, "__exit__"):
        with cm:
            yield
    else:
        yield


def _otel_span(name: str):
    if not _OTEL_TRACER:
        return contextlib.nullcontext()
    return _OTEL_TRACER.start_as_current_span(name)


# ==============
# TTL Idempotency
# ==============

class _TTLCache:
    """Simple async-safe TTL cache for idempotency and memoization."""
    def __init__(self, capacity: int = 10000) -> None:
        self._cap = max(1, capacity)
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, val = item
            if exp and exp < time.time():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, val: Any, ttl_seconds: Optional[int]) -> None:
        if ttl_seconds is None or ttl_seconds <= 0:
            return
        exp = time.time() + ttl_seconds
        async with self._lock:
            if len(self._store) >= self._cap:
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (exp, val)

    async def purge(self) -> None:
        now = time.time()
        async with self._lock:
            dead = [k for k, (exp, _) in self._store.items() if exp and exp < now]
            for k in dead:
                self._store.pop(k, None)


# ===============
# Circuit Breaker
# ===============

class _CircuitBreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class _CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 15.0,
        half_open_max_calls: int = 3,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.reset_timeout = max(1.0, reset_timeout)
        self.half_open_max_calls = max(1, half_open_max_calls)

        self._state = _CircuitBreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            if self._state == _CircuitBreakerState.OPEN:
                if time.time() - self._opened_at >= self.reset_timeout:
                    self._state = _CircuitBreakerState.HALF_OPEN
                    self._half_open_calls = 0
                else:
                    return False

            if self._state == _CircuitBreakerState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    return False
                self._half_open_calls += 1
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            if self._state in (_CircuitBreakerState.HALF_OPEN, _CircuitBreakerState.OPEN):
                self._state = _CircuitBreakerState.CLOSED
                self._opened_at = 0.0
                self._half_open_calls = 0

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = _CircuitBreakerState.OPEN
                self._opened_at = time.time()
                self._half_open_calls = 0


# =========
# Exceptions
# =========

class HandlerAlreadyRegistered(RuntimeError):
    pass


class HandlerNotFound(KeyError):
    pass


class ObligationExecutionError(RuntimeError):
    """Raised when a critical obligation fails after retries."""
    def __init__(self, name: str, message: str, correlation_id: str, last_error: Optional[str] = None):
        super().__init__(f"obligation={name} message={message} correlation_id={correlation_id} last_error={last_error}")
        self.name = name
        self.correlation_id = correlation_id
        self.last_error = last_error or ""


# =====================
# Core data definitions
# =====================

@dataclass(frozen=True)
class Obligation:
    """Executable obligation item."""
    name: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    critical: bool = False
    timeout_seconds: Optional[float] = None
    max_attempts: Optional[int] = None
    base_backoff_seconds: Optional[float] = None
    max_backoff_seconds: Optional[float] = None
    jitter: Optional[float] = None   # 0..1
    retry_after_seconds: Optional[float] = None  # initial delay hint from upstream
    created_at: float = field(default_factory=lambda: time.time())


@dataclass
class ObligationResult:
    success: bool
    name: str
    attempts: int
    duration_ms: int
    output: Mapping[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def failed(self) -> bool:
        return not self.success


@runtime_checkable
class ObligationHandler(Protocol):
    """Handler must implement async handle(payload, context) -> Mapping | None.

    May raise exceptions; runner will retry according to policy.
    Optionally, handler can return dict with {"retry_after_seconds": float} hint for next retry.
    """
    async def handle(self, payload: Mapping[str, Any], context: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        ...


@dataclass
class _HandlerSpec:
    name: str
    handler: ObligationHandler
    # policy defaults for this handler
    timeout_seconds: float = 5.0
    max_attempts: int = 3
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 30.0
    jitter: float = 0.2
    concurrency_limit: int = 32
    failure_threshold: int = 5
    reset_timeout: float = 15.0
    half_open_max_calls: int = 3
    idempotency_ttl_seconds: int = 300
    enabled: bool = True

    # runtime
    semaphore: asyncio.Semaphore = field(init=False)
    breaker: _CircuitBreaker = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "semaphore", asyncio.Semaphore(max(1, self.concurrency_limit)))
        object.__setattr__(self, "breaker", _CircuitBreaker(
            failure_threshold=self.failure_threshold,
            reset_timeout=self.reset_timeout,
            half_open_max_calls=self.half_open_max_calls,
        ))


# =================
# Obligation Runner
# =================

class ObligationRunner:
    """Async obligation runner with per-handler policies and observability."""

    def __init__(
        self,
        *,
        logger: Optional[logging.Logger] = None,
        idempotency_cache_capacity: int = 10000,
        default_timeout_seconds: float = 5.0,
        default_max_attempts: int = 3,
        default_base_backoff_seconds: float = 0.5,
        default_max_backoff_seconds: float = 30.0,
        default_jitter: float = 0.2,
    ) -> None:
        self.logger = logger or logging.getLogger("policy_core.obligations.runner")
        self._registry: Dict[str, _HandlerSpec] = {}
        self._idempotency = _TTLCache(capacity=idempotency_cache_capacity)

        # global defaults
        self._g_timeout = default_timeout_seconds
        self._g_attempts = default_max_attempts
        self._g_base_backoff = default_base_backoff_seconds
        self._g_max_backoff = default_max_backoff_seconds
        self._g_jitter = default_jitter

    # ----------
    # Registry API
    # ----------

    def register(
        self,
        name: str,
        handler: ObligationHandler,
        *,
        timeout_seconds: Optional[float] = None,
        max_attempts: Optional[int] = None,
        base_backoff_seconds: Optional[float] = None,
        max_backoff_seconds: Optional[float] = None,
        jitter: Optional[float] = None,
        concurrency_limit: int = 32,
        failure_threshold: int = 5,
        reset_timeout: float = 15.0,
        half_open_max_calls: int = 3,
        idempotency_ttl_seconds: int = 300,
        enabled: bool = True,
    ) -> None:
        if name in self._registry:
            raise HandlerAlreadyRegistered(f"handler '{name}' already registered")
        spec = _HandlerSpec(
            name=name,
            handler=handler,
            timeout_seconds=(timeout_seconds if timeout_seconds is not None else self._g_timeout),
            max_attempts=(max_attempts if max_attempts is not None else self._g_attempts),
            base_backoff_seconds=(base_backoff_seconds if base_backoff_seconds is not None else self._g_base_backoff),
            max_backoff_seconds=(max_backoff_seconds if max_backoff_seconds is not None else self._g_max_backoff),
            jitter=(jitter if jitter is not None else self._g_jitter),
            concurrency_limit=concurrency_limit,
            failure_threshold=failure_threshold,
            reset_timeout=reset_timeout,
            half_open_max_calls=half_open_max_calls,
            idempotency_ttl_seconds=idempotency_ttl_seconds,
            enabled=enabled,
        )
        self._registry[name] = spec
        _json_log(self.logger, logging.INFO, "obligation.handler.registered", name=name)

    def enable(self, name: str, enabled: bool = True) -> None:
        spec = self._registry.get(name)
        if not spec:
            raise HandlerNotFound(name)
        spec.enabled = enabled
        _json_log(self.logger, logging.INFO, "obligation.handler.enabled", name=name, enabled=enabled)

    def get_names(self) -> Sequence[str]:
        return tuple(self._registry.keys())

    # ----------
    # Run API
    # ----------

    async def run_from_mapping(
        self,
        obligations: Mapping[str, Any],
        *,
        context: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Sequence[ObligationResult]:
        """Run obligations given as {name: payload} mapping (PDP-compatible)."""
        items: list[Obligation] = []
        for name, payload in obligations.items():
            if isinstance(payload, Mapping):
                idk = str(payload.get("idempotency_key")) if "idempotency_key" in payload else None
                critical = bool(payload.get("critical")) if "critical" in payload else False
                timeout = float(payload.get("timeout_seconds")) if "timeout_seconds" in payload else None
                items.append(Obligation(name=name, payload=payload, idempotency_key=idk, critical=critical, timeout_seconds=timeout))
            else:
                items.append(Obligation(name=name, payload={"value": payload}))
        return await self.run_many(items, context=context, correlation_id=correlation_id)

    async def run_many(
        self,
        obligations: Sequence[Obligation],
        *,
        context: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        max_parallel: Optional[int] = None,
    ) -> Sequence[ObligationResult]:
        """Run a batch of obligations concurrently."""
        if not obligations:
            return []
        correlation_id = correlation_id or str(uuid.uuid4())
        ctx = dict(context or {})
        ctx["correlation_id"] = correlation_id

        lim = max(1, int(max_parallel)) if max_parallel else None
        batch_semaphore = asyncio.Semaphore(lim) if lim else None

        results: list[ObligationResult] = []
        tasks: list[asyncio.Task[ObligationResult]] = []

        span_cm = _otel_span("obligations.run_many") if _OTEL_TRACER else contextlib.nullcontext()
        async with _maybe_async_context(span_cm):
            _json_log(self.logger, logging.INFO, "obligation.batch.start", count=len(obligations), correlation_id=correlation_id)

            async def _worker(item: Obligation) -> ObligationResult:
                if batch_semaphore:
                    async with batch_semaphore:
                        return await self._run_one(item, ctx)
                return await self._run_one(item, ctx)

            for item in obligations:
                tasks.append(asyncio.create_task(_worker(item)))

            for t in asyncio.as_completed(tasks):
                res = await t
                results.append(res)

            _json_log(self.logger, logging.INFO, "obligation.batch.done", count=len(results), correlation_id=correlation_id)

        # If any critical obligation failed — raise aggregated error (fail fast philosophy)
        critical_failed = [o for o, r in zip(obligations, results) if o.critical and r.failed]
        if critical_failed:
            names = ",".join(o.name for o in critical_failed)
            last = [r for r in results if r.name in {o.name for o in critical_failed} and r.failed]
            last_err = last[-1].error if last else ""
            raise ObligationExecutionError(names, "critical obligations failed", correlation_id, last_err)

        return results

    # ----------
    # Internals
    # ----------

    async def _run_one(self, item: Obligation, context: Mapping[str, Any]) -> ObligationResult:
        started = time.time()
        spec = self._registry.get(item.name)
        if not spec or not spec.enabled:
            msg = "handler_not_found" if not spec else "handler_disabled"
            _json_log(self.logger, logging.ERROR, "obligation.handler.missing", name=item.name, reason=msg, correlation_id=context.get("correlation_id"))
            return ObligationResult(success=False, name=item.name, attempts=0, duration_ms=int((time.time() - started) * 1000), error=msg, correlation_id=str(context.get("correlation_id")))

        # Idempotency check
        if item.idempotency_key:
            cached: Optional[ObligationResult] = await self._idempotency.get(self._idem_key(item))
            if cached:
                _json_log(self.logger, logging.DEBUG, "obligation.idempotent.hit", name=item.name, correlation_id=context.get("correlation_id"))
                return cached

        attempts = 0
        last_error: Optional[str] = None
        timeout = item.timeout_seconds if item.timeout_seconds is not None else spec.timeout_seconds
        max_attempts = max(1, item.max_attempts if item.max_attempts is not None else spec.max_attempts)
        base_backoff = item.base_backoff_seconds if item.base_backoff_seconds is not None else spec.base_backoff_seconds
        max_backoff = item.max_backoff_seconds if item.max_backoff_seconds is not None else spec.max_backoff_seconds
        jitter = item.jitter if item.jitter is not None else spec.jitter

        # Initial retry-after hint
        delay = max(0.0, float(item.retry_after_seconds)) if item.retry_after_seconds else 0.0

        # Circuit breaker gate
        if not await spec.breaker.allow():
            msg = "circuit_open"
            _json_log(self.logger, logging.WARNING, "obligation.circuit.open", name=item.name, correlation_id=context.get("correlation_id"))
            res = ObligationResult(success=False, name=item.name, attempts=attempts, duration_ms=int((time.time() - started) * 1000), error=msg, correlation_id=str(context.get("correlation_id")))
            await self._maybe_store_idem(item, spec, res)
            return res

        with_trace = _otel_span(f"obligation.{item.name}") if _OTEL_TRACER else contextlib.nullcontext()
        async with _maybe_async_context(with_trace):
            # Per-handler concurrency limit
            async with spec.semaphore:
                while attempts < max_attempts:
                    attempts += 1
                    if delay > 0:
                        await asyncio.sleep(delay)
                        delay = 0.0  # only once unless handler suggests again

                    try:
                        # Enforce timeout per attempt
                        run_coro = spec.handler.handle(item.payload, context)
                        output: Optional[Mapping[str, Any]] = await asyncio.wait_for(run_coro, timeout=timeout)
                        await spec.breaker.record_success()

                        res = ObligationResult(
                            success=True,
                            name=item.name,
                            attempts=attempts,
                            duration_ms=int((time.time() - started) * 1000),
                            output=output or {},
                            correlation_id=str(context.get("correlation_id")),
                        )
                        await self._maybe_store_idem(item, spec, res)
                        _json_log(self.logger, logging.INFO, "obligation.success", name=item.name, attempts=attempts, duration_ms=res.duration_ms, correlation_id=context.get("correlation_id"))
                        return res

                    except asyncio.TimeoutError:
                        last_error = "timeout"
                        await spec.breaker.record_failure()
                        _json_log(self.logger, logging.WARNING, "obligation.timeout", name=item.name, attempt=attempts, timeout_seconds=timeout, correlation_id=context.get("correlation_id"))

                    except Exception as exc:
                        last_error = str(exc)
                        await spec.breaker.record_failure()
                        _json_log(self.logger, logging.ERROR, "obligation.error", name=item.name, attempt=attempts, error=last_error, correlation_id=context.get("correlation_id"))

                    # Calculate backoff for next attempt
                    if attempts < max_attempts:
                        # Handler may hint retry_after_seconds in output-like form via context or known attribute
                        # Not standardized here; caller may embed dynamic hints in payload. Fallback to exp backoff.
                        backoff = min(max_backoff, base_backoff * (2 ** (attempts - 1)))
                        if jitter > 0:
                            # full jitter: random in [0, backoff] scaled by jitter coefficient
                            backoff = backoff * (1 - jitter) + random.random() * backoff * jitter
                        await asyncio.sleep(backoff)

                # Exhausted attempts
                res = ObligationResult(
                    success=False,
                    name=item.name,
                    attempts=attempts,
                    duration_ms=int((time.time() - started) * 1000),
                    error=last_error or "unknown_error",
                    correlation_id=str(context.get("correlation_id")),
                )
                await self._maybe_store_idem(item, spec, res)
                _json_log(self.logger, logging.ERROR, "obligation.failed", name=item.name, attempts=attempts, error=res.error, correlation_id=context.get("correlation_id"))
                return res

    async def _maybe_store_idem(self, item: Obligation, spec: _HandlerSpec, result: ObligationResult) -> None:
        if item.idempotency_key:
            await self._idempotency.set(self._idem_key(item), result, spec.idempotency_ttl_seconds)

    @staticmethod
    def _idem_key(item: Obligation) -> str:
        return f"{item.name}:{item.idempotency_key}"
