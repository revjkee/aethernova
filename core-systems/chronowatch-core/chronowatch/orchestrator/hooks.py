from __future__ import annotations

import asyncio
import importlib
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)
from uuid import UUID, uuid4

# ----------------------------- Логирование -----------------------------------

_LOG_LEVEL = os.getenv("CHRONOWATCH_LOG_LEVEL", "INFO").upper()
logger = logging.getLogger("chronowatch.hooks")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(_LOG_LEVEL)

# ----------------------------- OpenTelemetry (опц.) --------------------------

try:
    from opentelemetry import trace, metrics  # type: ignore
    from opentelemetry.trace import SpanKind  # type: ignore

    _tracer = trace.get_tracer(__name__)
    _meter = metrics.get_meter(__name__)
    _metric_hook_latency = _meter.create_histogram(
        "chronowatch_hook_latency_ms", unit="ms", description="Hook latency"
    )
    _metric_hook_results = _meter.create_counter(
        "chronowatch_hook_results", unit="1", description="Hook result counters"
    )
    _otel_enabled = True
except Exception:  # pragma: no cover - отсутствие OTEL не критично
    _tracer = None
    _meter = None
    _metric_hook_latency = None
    _metric_hook_results = None
    _otel_enabled = False

# ----------------------------- Типы событий ----------------------------------

EventName = Literal[
    "schedule.created",
    "schedule.updated",
    "schedule.deleted",
    "schedule.paused",
    "schedule.resumed",
    "run.enqueued",
    "run.started",
    "run.succeeded",
    "run.failed",
    "run.canceled",
    "run.timeout",
]

# --------------------------- Исключения/ошибки --------------------------------

class HookError(Exception):
    """Ошибка выполнения хука."""


class HookTimeout(HookError):
    """Таймаут выполнения хука."""


class HookCircuitOpen(HookError):
    """Circuit Breaker в состоянии OPEN."""


# --------------------------- Контекст и результат -----------------------------

@dataclass(slots=True)
class HookContext:
    event: EventName
    tenant_id: UUID
    schedule_id: Optional[UUID] = None
    run_id: Optional[UUID] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    def with_payload(self, extra: Dict[str, Any]) -> "HookContext":
        p = {**self.payload, **(extra or {})}
        return HookContext(
            event=self.event,
            tenant_id=self.tenant_id,
            schedule_id=self.schedule_id,
            run_id=self.run_id,
            payload=p,
            idempotency_key=self.idempotency_key,
            headers=self.headers,
            now=self.now,
            trace_id=self.trace_id,
            span_id=self.span_id,
        )


@dataclass(slots=True)
class HookResult:
    hook_name: str
    success: bool
    attempts: int
    duration_ms: float
    error: Optional[str] = None
    skipped: bool = False
    circuit_open: bool = False


# --------------------------- Протоколы для расширений -------------------------

class IdempotencyStore(Protocol):
    async def seen(self, key: str, ttl: int) -> bool: ...
    async def mark(self, key: str, ttl: int) -> None: ...


class CircuitBreakerStorage(Protocol):
    async def get_state(self, key: str) -> Tuple[str, float, int]:
        """
        Возвращает (state, open_until_ts, consecutive_failures)
        state: "CLOSED"|"OPEN"|"HALF_OPEN"
        open_until_ts: unix timestamp, когда можно перейти в HALF_OPEN
        consecutive_failures: счетчик подряд
        """
        ...

    async def set_state(self, key: str, state: str, open_until_ts: float, consecutive_failures: int) -> None: ...


# ------------------------ Дефолтные In-Memory реализации ----------------------

class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._cache: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def seen(self, key: str, ttl: int) -> bool:
        async with self._lock:
            now = time.time()
            exp = self._cache.get(key)
            if exp and exp > now:
                return True
            return False

    async def mark(self, key: str, ttl: int) -> None:
        async with self._lock:
            self._cache[key] = time.time() + ttl


class InMemoryCircuitBreakerStorage:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[str, float, int]] = {}
        self._lock = asyncio.Lock()

    async def get_state(self, key: str) -> Tuple[str, float, int]:
        async with self._lock:
            return self._data.get(key, ("CLOSED", 0.0, 0))

    async def set_state(self, key: str, state: str, open_until_ts: float, consecutive_failures: int) -> None:
        async with self._lock:
            self._data[key] = (state, open_until_ts, consecutive_failures)


# ------------------------------ Спецификация хука -----------------------------

Predicate = Callable[[HookContext], bool]
AnyHookFunc = Callable[[HookContext], Union[Awaitable[None], None]]


@dataclass(slots=True)
class HookSpec:
    event: EventName
    name: str
    func: AnyHookFunc
    priority: int = 100  # меньшая цифра — раньше
    timeout_s: float = 10.0
    retries: int = 0
    backoff_base_s: float = 0.5
    backoff_max_s: float = 10.0
    backoff_jitter: float = 0.1  # 10% джиттер
    stop_on_error: bool = False
    enabled: bool = True
    idempotent: bool = False
    idempotency_ttl_s: int = 300
    predicate: Optional[Predicate] = None
    circuit_breaker: bool = False
    cb_fail_threshold: int = 5
    cb_open_seconds: int = 60


# ------------------------------ Реестр хуков ----------------------------------

class HookRegistry:
    def __init__(self) -> None:
        self._hooks: Dict[EventName, List[HookSpec]] = {}

    def register(self, spec: HookSpec) -> None:
        hooks = self._hooks.setdefault(spec.event, [])
        # idempotent: уникальность по имени
        if any(h.name == spec.name for h in hooks):
            raise ValueError(f"Hook with name '{spec.name}' already registered for event {spec.event}")
        hooks.append(spec)
        hooks.sort(key=lambda h: h.priority)

    def list_for(self, event: EventName) -> List[HookSpec]:
        return list(self._hooks.get(event, []))

    def clear(self) -> None:
        self._hooks.clear()


REGISTRY = HookRegistry()


def hook(
    event: EventName,
    *,
    name: Optional[str] = None,
    priority: int = 100,
    timeout_s: float = 10.0,
    retries: int = 0,
    backoff_base_s: float = 0.5,
    backoff_max_s: float = 10.0,
    backoff_jitter: float = 0.1,
    stop_on_error: bool = False,
    enabled: bool = True,
    idempotent: bool = False,
    idempotency_ttl_s: int = 300,
    predicate: Optional[Predicate] = None,
    circuit_breaker: bool = False,
    cb_fail_threshold: int = 5,
    cb_open_seconds: int = 60,
) -> Callable[[AnyHookFunc], AnyHookFunc]:
    """
    Декоратор регистрации хука.
    """
    def decorator(func: AnyHookFunc) -> AnyHookFunc:
        spec = HookSpec(
            event=event,
            name=name or func.__name__,
            func=func,
            priority=priority,
            timeout_s=timeout_s,
            retries=retries,
            backoff_base_s=backoff_base_s,
            backoff_max_s=backoff_max_s,
            backoff_jitter=backoff_jitter,
            stop_on_error=stop_on_error,
            enabled=enabled,
            idempotent=idempotent,
            idempotency_ttl_s=idempotency_ttl_s,
            predicate=predicate,
            circuit_breaker=circuit_breaker,
            cb_fail_threshold=cb_fail_threshold,
            cb_open_seconds=cb_open_seconds,
        )
        REGISTRY.register(spec)
        return func
    return decorator


# ------------------------------ Circuit Breaker -------------------------------

class CircuitBreaker:
    def __init__(self, storage: CircuitBreakerStorage) -> None:
        self.storage = storage

    async def before_call(self, key: str) -> None:
        state, open_until, _ = await self.storage.get_state(key)
        now = time.time()
        if state == "OPEN":
            if now >= open_until:
                await self.storage.set_state(key, "HALF_OPEN", 0.0, 0)
            else:
                raise HookCircuitOpen(f"Circuit OPEN for {key}")

    async def on_success(self, key: str) -> None:
        await self.storage.set_state(key, "CLOSED", 0.0, 0)

    async def on_failure(self, key: str, threshold: int, open_seconds: int) -> None:
        state, _, fails = await self.storage.get_state(key)
        fails += 1
        if fails >= threshold:
            await self.storage.set_state(key, "OPEN", time.time() + open_seconds, fails)
        else:
            # в HALF_OPEN один фэйл снова открывает
            if state == "HALF_OPEN":
                await self.storage.set_state(key, "OPEN", time.time() + open_seconds, fails)
            else:
                await self.storage.set_state(key, "CLOSED", 0.0, fails)


# ------------------------------ Раннер хуков ----------------------------------

class OrchestratorHooks:
    def __init__(
        self,
        *,
        registry: HookRegistry = REGISTRY,
        idempotency: Optional[IdempotencyStore] = None,
        cb_storage: Optional[CircuitBreakerStorage] = None,
        max_concurrency: int = 8,
    ) -> None:
        self.registry = registry
        self.idempotency = idempotency or InMemoryIdempotencyStore()
        self.circuit_breaker = CircuitBreaker(cb_storage or InMemoryCircuitBreakerStorage())
        self._sem = asyncio.Semaphore(max_concurrency)

    async def emit(self, ctx: HookContext) -> List[HookResult]:
        """
        Выполнить все хуки для события ctx.event. Возвращает список результатов.
        """
        specs = [s for s in self.registry.list_for(ctx.event) if s.enabled]
        results: List[HookResult] = []

        for spec in specs:
            if spec.predicate and not _safe_predicate(spec, ctx):
                results.append(
                    HookResult(hook_name=spec.name, success=True, attempts=0, duration_ms=0.0, skipped=True)
                )
                continue

            try:
                res = await self._run_one(spec, ctx)
                results.append(res)
                if not res.success and spec.stop_on_error:
                    logger.error("Hook %s failed and stop_on_error=true; breaking chain", spec.name)
                    break
            except HookCircuitOpen:
                logger.warning("Circuit OPEN for hook %s; skipped", spec.name)
                results.append(
                    HookResult(
                        hook_name=spec.name,
                        success=False,
                        attempts=0,
                        duration_ms=0.0,
                        error="circuit_open",
                        circuit_open=True,
                        skipped=True,
                    )
                )
                if spec.stop_on_error:
                    break
            except Exception as e:
                logger.exception("Unexpected failure running hook %s", spec.name)
                results.append(
                    HookResult(hook_name=spec.name, success=False, attempts=1, duration_ms=0.0, error=str(e))
                )
                if spec.stop_on_error:
                    break

        return results

    async def _run_one(self, spec: HookSpec, ctx: HookContext) -> HookResult:
        idem_key = None
        if spec.idempotent and ctx.idempotency_key:
            idem_key = f"hook:{spec.name}:{ctx.idempotency_key}"
            if await self.idempotency.seen(idem_key, ttl=spec.idempotency_ttl_s):
                logger.info("Idempotent skip for hook %s with key %s", spec.name, idem_key)
                return HookResult(hook_name=spec.name, success=True, attempts=0, duration_ms=0.0, skipped=True)

        if spec.circuit_breaker:
            await self.circuit_breaker.before_call(f"hook:{spec.name}")

        attempts = 0
        t0 = time.perf_counter()
        last_err: Optional[str] = None

        # Трейс
        span_ctx = _tracer.start_as_current_span(spec.name, kind=SpanKind.CONSUMER) if _otel_enabled else None
        cm = span_ctx if span_ctx is not None else _nullcontext()

        async with self._sem:
            async with cm:  # type: ignore
                while True:
                    attempts += 1
                    try:
                        await _call_hook(spec.func, ctx, timeout=spec.timeout_s)
                        dur_ms = (time.perf_counter() - t0) * 1000.0
                        if idem_key:
                            await self.idempotency.mark(idem_key, ttl=spec.idempotency_ttl_s)
                        if spec.circuit_breaker:
                            await self.circuit_breaker.on_success(f"hook:{spec.name}")
                        _record_metrics(spec, True, dur_ms)
                        return HookResult(hook_name=spec.name, success=True, attempts=attempts, duration_ms=dur_ms)
                    except asyncio.TimeoutError:
                        last_err = f"timeout {spec.timeout_s}s"
                        logger.warning("Hook %s timeout after %.2fs", spec.name, spec.timeout_s)
                        err = HookTimeout(last_err)
                    except Exception as e:
                        last_err = str(e)
                        logger.warning("Hook %s failed (attempt %d/%d): %s", spec.name, attempts, spec.retries + 1, e)
                        err = e

                    if attempts > spec.retries:
                        dur_ms = (time.perf_counter() - t0) * 1000.0
                        if spec.circuit_breaker:
                            await self.circuit_breaker.on_failure(
                                f"hook:{spec.name}", spec.cb_fail_threshold, spec.cb_open_seconds
                            )
                        _record_metrics(spec, False, dur_ms, error=last_err or "unknown")
                        return HookResult(
                            hook_name=spec.name, success=False, attempts=attempts, duration_ms=dur_ms, error=last_err
                        )

                    # backoff
                    await asyncio.sleep(_compute_backoff(attempts, spec.backoff_base_s, spec.backoff_max_s, spec.backoff_jitter))


# ----------------------------- Утилиты раннера --------------------------------

async def _call_hook(func: AnyHookFunc, ctx: HookContext, *, timeout: float) -> None:
    async def _invoke() -> None:
        if asyncio.iscoroutinefunction(func):
            await func(ctx)  # type: ignore[arg-type]
        else:
            # безопасный запуск sync в thread pool
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, func, ctx)

    await asyncio.wait_for(_invoke(), timeout=timeout)


def _compute_backoff(attempt: int, base: float, max_s: float, jitter: float) -> float:
    # экспоненциальный рост без переполнений
    delay = min(max_s, base * math.pow(2.0, attempt - 1))
    # центрированный джиттер +/- jitter%
    noise = delay * jitter
    return max(0.0, delay + random.uniform(-noise, noise))


def _safe_predicate(spec: HookSpec, ctx: HookContext) -> bool:
    try:
        return bool(spec.predicate and spec.predicate(ctx))
    except Exception:
        logger.exception("Predicate raised for hook %s; treat as not matched", spec.name)
        return False


def _record_metrics(spec: HookSpec, success: bool, duration_ms: float, *, error: Optional[str] = None) -> None:
    if not _otel_enabled:
        return
    try:
        _metric_hook_latency.record(duration_ms, {"hook": spec.name, "event": spec.event})
        _metric_hook_results.add(1, {"hook": spec.name, "event": spec.event, "result": "ok" if success else "err", "err": error or ""})
    except Exception:  # pragma: no cover
        pass


class _nullcontext:
    async def __aenter__(self):  # noqa
        return None

    async def __aexit__(self, exc_type, exc, tb):  # noqa
        return False


# ----------------------------- Загрузка плагинов ------------------------------

def load_plugins(entrypoint_group: str = "chronowatch.hooks") -> int:
    """
    Загружает плагины, объявленные через entry points:
      [project.entry-points."chronowatch.hooks"]
      mypkg.hooks = "mypkg.hooks_module"
    Возврат: число успешно загруженных модулей.
    """
    count = 0
    try:
        # Python 3.11 style
        from importlib.metadata import entry_points  # type: ignore

        eps = entry_points().get(entrypoint_group, [])
        for ep in eps:
            try:
                importlib.import_module(ep.value)
                count += 1
                logger.info("Loaded hooks plugin: %s", ep.value)
            except Exception:
                logger.exception("Failed to load hooks plugin: %s", ep.value)
    except Exception:
        logger.debug("No entry points for %s", entrypoint_group)
    return count


# ----------------------------- Примеры встроенных хуков -----------------------

@hook(
    "run.succeeded",
    name="audit_success_log",
    priority=50,
    timeout_s=2.0,
    idempotent=True,
    idempotency_ttl_s=600,
)
def audit_success(ctx: HookContext) -> None:
    logger.info(
        "AUDIT success tenant=%s schedule=%s run=%s payload=%s",
        ctx.tenant_id,
        ctx.schedule_id,
        ctx.run_id,
        {k: v for k, v in ctx.payload.items() if k != "secret"},
    )


@hook(
    "run.failed",
    name="notify_ops_slack",
    priority=10,
    timeout_s=5.0,
    retries=3,
    backoff_base_s=0.5,
    backoff_max_s=5.0,
    circuit_breaker=True,
    cb_fail_threshold=4,
    cb_open_seconds=60,
    stop_on_error=False,
)
async def notify_ops(ctx: HookContext) -> None:
    # Здесь могла бы быть интеграция со Slack/PagerDuty
    # В примере просто лог.
    err = ctx.payload.get("error", "unknown")
    logger.error(
        "RUN FAILED tenant=%s schedule=%s run=%s error=%s",
        ctx.tenant_id,
        ctx.schedule_id,
        ctx.run_id,
        err,
    )


# ----------------------------- Пример использования ---------------------------
# Пример ниже может служить smoke-тестом в dev-среде.
if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        load_plugins()  # подхватим плагины, если объявлены
        orchestrator = OrchestratorHooks()
        ctx_ok = HookContext(
            event="run.succeeded",
            tenant_id=uuid4(),
            schedule_id=uuid4(),
            run_id=uuid4(),
            payload={"duration_ms": 1234},
            idempotency_key="run-1",
        )
        ctx_err = HookContext(
            event="run.failed",
            tenant_id=uuid4(),
            schedule_id=uuid4(),
            run_id=uuid4(),
            payload={"error": "Timeout while calling upstream"},
        )
        res1 = await orchestrator.emit(ctx_ok)
        res2 = await orchestrator.emit(ctx_err)
        print("results ok:", res1)
        print("results err:", res2)

    asyncio.run(_demo())
