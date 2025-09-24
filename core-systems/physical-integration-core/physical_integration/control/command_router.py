# physical-integration-core/physical_integration/control/command_router.py
from __future__ import annotations

import asyncio
import dataclasses
import heapq
import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger("physical_integration_core.control.command_router")

# ======================================================================================
# Модели и интерфейсы
# ======================================================================================

class CommandStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DEAD_LETTER = "DEAD_LETTER"


@dataclass(frozen=True)
class CommandEnvelope:
    tenant_id: uuid.UUID
    device_id: uuid.UUID
    command: str
    params: Dict[str, Any]
    command_id: uuid.UUID = field(default_factory=uuid.uuid4)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    scheduled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExecutionResult:
    success: bool
    detail: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)


class CommandHandler(Protocol):
    """
    Интерфейс обработчика команд.
    Реализация должна быть идемпотентной на уровне device_id+command+command_id.
    """
    async def handle(self, env: CommandEnvelope, *, timeout: float) -> ExecutionResult: ...


class AuditLogger(Protocol):
    async def log(self, event: str, data: Dict[str, Any]) -> None: ...


class MetricsSink(Protocol):
    def incr(self, name: str, tags: Optional[Dict[str, str]] = None, value: float = 1.0) -> None: ...
    def timing(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None: ...


# Совместимость с ранее показанным HTTP-слоем
@dataclass
class DispatchResult:
    command_id: uuid.UUID
    scheduled_at: datetime


class CommandDispatcher(Protocol):
    async def dispatch(
        self, *, tenant_id: uuid.UUID, device_id: uuid.UUID, command: str, params: Dict[str, Any]
    ) -> DispatchResult: ...


# ======================================================================================
# Конфигурация/ограничители
# ======================================================================================

@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_s: float = 0.5
    max_delay_s: float = 30.0
    jitter_s: float = 0.25  # добавочный джиттер при бэкоффе

    def next_delay(self, attempt: int) -> float:
        # экспоненциальный рост с ограничением и джиттером
        d = min(self.max_delay_s, self.base_delay_s * (2 ** (attempt - 1)))
        return d + random.uniform(0.0, self.jitter_s)


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5               # сколько последовательных ошибок до Open
    open_timeout_s: float = 30.0             # сколько держаться в Open
    half_open_probe: int = 1                 # сколько проб в Half-Open


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CircuitBreaker:
    cfg: CircuitBreakerConfig
    state: BreakerState = BreakerState.CLOSED
    failures: int = 0
    opened_at_monotonic: float = 0.0
    half_open_remaining: int = 0

    def allow(self) -> bool:
        now = time.monotonic()
        if self.state == BreakerState.OPEN:
            if now - self.opened_at_monotonic >= self.cfg.open_timeout_s:
                self.state = BreakerState.HALF_OPEN
                self.half_open_remaining = self.cfg.half_open_probe
                return True
            return False
        if self.state == BreakerState.HALF_OPEN:
            if self.half_open_remaining > 0:
                self.half_open_remaining -= 1
                return True
            return False
        return True

    def on_success(self) -> None:
        self.state = BreakerState.CLOSED
        self.failures = 0

    def on_failure(self) -> None:
        self.failures += 1
        if self.state in (BreakerState.CLOSED, BreakerState.HALF_OPEN):
            if self.failures >= self.cfg.failure_threshold:
                self.state = BreakerState.OPEN
                self.opened_at_monotonic = time.monotonic()


@dataclass
class RouterConfig:
    worker_concurrency: int = 8
    per_device_concurrency: int = 1
    queue_capacity: int = 10000
    op_timeout_s: float = 10.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    dead_letter_max_size: int = 1000
    tenant_rps: float = 100.0
    tenant_burst: int = 200


# ======================================================================================
# Простые ограничители скорости
# ======================================================================================

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = burst
        self.last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


# ======================================================================================
# Планировщик: приоритетная очередь по времени run_at
# ======================================================================================

@dataclass(order=True)
class _SchedItem:
    run_at: float
    seq: int
    env: CommandEnvelope = field(compare=False)
    attempt: int = field(default=1, compare=False)


# ======================================================================================
# CommandRouter
# ======================================================================================

class CommandRouter:
    """
    Асинхронный роутер команд:
      - очередь с планировщиком по времени (heap);
      - пер-устройство сериализация выполнения;
      - тайм-ауты, ретраи, circuit breaker;
      - backpressure и лимит скорости по арендатору;
      - аудит и метрики-хуки.
    """

    def __init__(
        self,
        cfg: RouterConfig = RouterConfig(),
        audit: Optional[AuditLogger] = None,
        metrics: Optional[MetricsSink] = None,
    ) -> None:
        self.cfg = cfg
        self.audit = audit
        self.metrics = metrics
        self._handlers: Dict[str, CommandHandler] = {}

        # планировщик
        self._heap: List[_SchedItem] = []
        self._sched_seq = 0
        self._sched_cv = asyncio.Condition()

        # состояние и воркеры
        self._closing = False
        self._workers: List[asyncio.Task] = []
        self._scheduler_task: Optional[asyncio.Task] = None

        # пер-девайс семафоры
        self._device_locks: Dict[uuid.UUID, asyncio.Semaphore] = {}

        # breaker per (device_id, command)
        self._breakers: Dict[Tuple[uuid.UUID, str], CircuitBreaker] = {}

        # хранилище статусов
        self._status: Dict[uuid.UUID, CommandStatus] = {}

        # dead-letter
        self._dlq: List[CommandEnvelope] = []
        # лимит скорости per-tenant
        self._tenant_rl: Dict[uuid.UUID, TokenBucket] = {}

    # -------------------------------------------------------------------------
    # Регистрация обработчиков и запуск
    # -------------------------------------------------------------------------

    def register(self, command: str, handler: CommandHandler) -> None:
        self._handlers[command.upper()] = handler

    async def start(self) -> None:
        if self._scheduler_task:
            return
        self._closing = False
        self._scheduler_task = asyncio.create_task(self._scheduler_loop(), name="cmd-scheduler")
        for i in range(self.cfg.worker_concurrency):
            self._workers.append(asyncio.create_task(self._worker_loop(i), name=f"cmd-worker-{i}"))
        logger.info("CommandRouter started: workers=%d", self.cfg.worker_concurrency)

    async def stop(self) -> None:
        self._closing = True
        async with self._sched_cv:
            self._sched_cv.notify_all()
        for t in self._workers:
            t.cancel()
        if self._scheduler_task:
            self._scheduler_task.cancel()
        for t in self._workers:
            with contextlib.suppress(Exception):
                await t
        if self._scheduler_task:
            with contextlib.suppress(Exception):
                await self._scheduler_task
        logger.info("CommandRouter stopped")

    # -------------------------------------------------------------------------
    # Подача команды
    # -------------------------------------------------------------------------

    def _tenant_bucket(self, tenant_id: uuid.UUID) -> TokenBucket:
        b = self._tenant_rl.get(tenant_id)
        if b is None:
            b = TokenBucket(self.cfg.tenant_rps, self.cfg.tenant_burst)
            self._tenant_rl[tenant_id] = b
        return b

    async def submit(self, env: CommandEnvelope) -> DispatchResult:
        # лимит нагрузки per-tenant
        if not self._tenant_bucket(env.tenant_id).allow():
            raise Rejected("tenant rate limit exceeded")

        # backpressure
        if len(self._heap) >= self.cfg.queue_capacity:
            raise Rejected("command queue is full")

        self._status[env.command_id] = CommandStatus.QUEUED
        await self._schedule(env, delay_s=0.0)
        await self._audit("command.queued", env, extra={})
        return DispatchResult(command_id=env.command_id, scheduled_at=env.scheduled_at)

    async def _schedule(self, env: CommandEnvelope, delay_s: float, attempt: int = 1) -> None:
        when = time.monotonic() + max(0.0, delay_s)
        async with self._sched_cv:
            self._sched_seq += 1
            heapq.heappush(self._heap, _SchedItem(run_at=when, seq=self._sched_seq, env=env, attempt=attempt))
            self._sched_cv.notify(1)

    # -------------------------------------------------------------------------
    # Мониторинг/запрос состояния (опционально)
    # -------------------------------------------------------------------------

    def get_status(self, command_id: uuid.UUID) -> Optional[CommandStatus]:
        return self._status.get(command_id)

    def dead_letter(self) -> List[CommandEnvelope]:
        return list(self._dlq)

    # -------------------------------------------------------------------------
    # Внутренние циклы
    # -------------------------------------------------------------------------

    async def _scheduler_loop(self) -> None:
        try:
            while not self._closing:
                async with self._sched_cv:
                    while not self._heap and not self._closing:
                        await self._sched_cv.wait()
                    if self._closing:
                        break
                    item = self._heap[0]
                    now = time.monotonic()
                    if item.run_at > now:
                        await asyncio.wait_for(self._sched_cv.wait(), timeout=item.run_at - now)
                        continue
                    heapq.heappop(self._heap)
                # Передаем на исполнение через общий канал
                await self._dispatch_item(item)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("scheduler loop failed")

    async def _dispatch_item(self, item: _SchedItem) -> None:
        # Выделяем воркер: просто кладем в общую очередь через таск
        asyncio.create_task(self._execute(item), name=f"cmd-exec-{item.env.command_id.hex}")

    async def _worker_loop(self, idx: int) -> None:
        # Рабочие корутины порождаются _dispatch_item; этот луп оставлен для совместимости
        try:
            while not self._closing:
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass

    # -------------------------------------------------------------------------
    # Исполнение команды: пер-девайс сериализация, breaker, тайм-ауты, ретраи
    # -------------------------------------------------------------------------

    def _device_lock(self, device_id: uuid.UUID) -> asyncio.Semaphore:
        sem = self._device_locks.get(device_id)
        if sem is None:
            sem = asyncio.Semaphore(self.cfg.per_device_concurrency)
            self._device_locks[device_id] = sem
        return sem

    def _breaker(self, device_id: uuid.UUID, command: str) -> CircuitBreaker:
        key = (device_id, command.upper())
        br = self._breakers.get(key)
        if br is None:
            br = CircuitBreaker(cfg=self.cfg.breaker)
            self._breakers[key] = br
        return br

    async def _execute(self, item: _SchedItem) -> None:
        env = item.env
        attempt = item.attempt
        lock = self._device_lock(env.device_id)
        breaker = self._breaker(env.device_id, env.command)

        # breaker gate
        if not breaker.allow():
            await self._audit("command.rejected_breaker", env, extra={"attempt": attempt})
            self._status[env.command_id] = CommandStatus.FAILED
            self._to_dead_letter(env)
            return

        async with lock:
            if self._status.get(env.command_id) not in (CommandStatus.QUEUED, CommandStatus.RUNNING):
                # команда уже перезаписана или завершена
                return
            self._status[env.command_id] = CommandStatus.RUNNING
            start_ts = time.monotonic()
            handler = self._handlers.get(env.command.upper())
            if handler is None:
                await self._audit("command.no_handler", env, extra={})
                self._status[env.command_id] = CommandStatus.FAILED
                self._to_dead_letter(env, reason="no handler")
                return

            try:
                # тайм-аут на выполнение
                res = await asyncio.wait_for(handler.handle(env, timeout=self.cfg.op_timeout_s), timeout=self.cfg.op_timeout_s)
                elapsed_ms = (time.monotonic() - start_ts) * 1000.0
                if res.success:
                    breaker.on_success()
                    self._status[env.command_id] = CommandStatus.SUCCEEDED
                    if self.metrics:
                        self.metrics.timing("command.exec_ms", elapsed_ms, tags={"command": env.command})
                    await self._audit("command.succeeded", env, extra={"attempt": attempt, "elapsed_ms": elapsed_ms, **res.attributes})
                    return
                # провал без исключения — считаем ошибкой
                raise RuntimeError(res.detail or "handler reported failure")
            except asyncio.TimeoutError:
                breaker.on_failure()
                await self._audit("command.timeout", env, extra={"attempt": attempt})
            except Exception as exc:
                breaker.on_failure()
                await self._audit("command.failed", env, extra={"attempt": attempt, "error": str(exc)})

        # неуспех: ретраи или DLQ
        if attempt < self.cfg.retry.max_attempts:
            delay = self.cfg.retry.next_delay(attempt)
            await self._schedule(env, delay_s=delay, attempt=attempt + 1)
            if self.metrics:
                self.metrics.incr("command.retry", tags={"command": env.command})
        else:
            self._status[env.command_id] = CommandStatus.DEAD_LETTER
            self._to_dead_letter(env)
            if self.metrics:
                self.metrics.incr("command.dead_letter", tags={"command": env.command})

    # -------------------------------------------------------------------------
    # DLQ и аудит
    # -------------------------------------------------------------------------

    def _to_dead_letter(self, env: CommandEnvelope, reason: Optional[str] = None) -> None:
        if len(self._dlq) >= self.cfg.dead_letter_max_size:
            self._dlq.pop(0)
        self._dlq.append(env)
        if reason:
            logger.warning("DLQ command=%s device=%s reason=%s", env.command, env.device_id, reason)

    async def _audit(self, event: str, env: CommandEnvelope, extra: Dict[str, Any]) -> None:
        if not self.audit:
            return
        data = {
            "tenant_id": str(env.tenant_id),
            "device_id": str(env.device_id),
            "command_id": str(env.command_id),
            "command": env.command,
            "correlation_id": env.correlation_id,
            "scheduled_at": env.scheduled_at.isoformat(),
            **extra,
        }
        with contextlib.suppress(Exception):
            await self.audit.log(event, data)


# ======================================================================================
# Реализация диспетчера для HTTP-слоя
# ======================================================================================

class RouterDispatcher(CommandDispatcher):
    def __init__(self, router: CommandRouter) -> None:
        self.router = router

    async def dispatch(
        self, *, tenant_id: uuid.UUID, device_id: uuid.UUID, command: str, params: Dict[str, Any]
    ) -> DispatchResult:
        env = CommandEnvelope(tenant_id=tenant_id, device_id=device_id, command=command, params=params)
        return await self.router.submit(env)


# ======================================================================================
# Примеры обработчиков и регистрация
# ======================================================================================

class AsyncFuncHandler(CommandHandler):
    """
    Обертка для простых асинхронных функций вида f(env) -> ExecutionResult.
    """
    def __init__(self, fn: Callable[[CommandEnvelope], Awaitable[ExecutionResult]]) -> None:
        self.fn = fn

    async def handle(self, env: CommandEnvelope, *, timeout: float) -> ExecutionResult:
        return await self.fn(env)


# Пример: заглушечные обработчики. В реальном приложении подключите сюда ваши протоколы.
async def _start_handler(env: CommandEnvelope) -> ExecutionResult:
    # Здесь можно вызвать, например, OPC UA метод или отправку в поле управления
    await asyncio.sleep(0.05)  # имитация I/O
    return ExecutionResult(success=True, attributes={"action": "started"})

async def _shutdown_handler(env: CommandEnvelope) -> ExecutionResult:
    await asyncio.sleep(0.05)
    return ExecutionResult(success=True, attributes={"action": "shutdown"})

async def _ota_assign_handler(env: CommandEnvelope) -> ExecutionResult:
    if not (env.params.get("image_id") or env.params.get("channel")):
        return ExecutionResult(success=False, detail="missing image_id or channel")
    await asyncio.sleep(0.05)
    return ExecutionResult(success=True, attributes={"ota": "queued"})


# ======================================================================================
# Инициализация по умолчанию (можно использовать из DI)
# ======================================================================================

import contextlib  # noqa: E402

class StdAuditLogger(AuditLogger):
    async def log(self, event: str, data: Dict[str, Any]) -> None:
        logger.info("AUDIT %s %s", event, data)

class NullMetrics(MetricsSink):
    def incr(self, name: str, tags: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        pass
    def timing(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None:
        pass


def build_default_router() -> Tuple[CommandRouter, RouterDispatcher]:
    router = CommandRouter(cfg=RouterConfig(), audit=StdAuditLogger(), metrics=NullMetrics())
    # регистрация обработчиков
    router.register("START", AsyncFuncHandler(_start_handler))
    router.register("SHUTDOWN", AsyncFuncHandler(_shutdown_handler))
    router.register("OTA_ASSIGN", AsyncFuncHandler(_ota_assign_handler))
    dispatcher = RouterDispatcher(router)
    return router, dispatcher


# ======================================================================================
# Пример запуска (опциональный, не исполняется при импорте)
# ======================================================================================

async def _example() -> None:
    router, dispatcher = build_default_router()
    await router.start()
    tenant_id = uuid.uuid4()
    device_id = uuid.uuid4()

    # Отправим несколько команд
    for cmd in ("START", "OTA_ASSIGN", "SHUTDOWN"):
        params = {"image_id": str(uuid.uuid4())} if cmd == "OTA_ASSIGN" else {}
        res = await dispatcher.dispatch(tenant_id=tenant_id, device_id=device_id, command=cmd, params=params)
        logger.info("dispatched %s -> %s at %s", cmd, res.command_id, res.scheduled_at.isoformat())

    # Дадим время на обработку
    await asyncio.sleep(1.0)
    await router.stop()


if __name__ == "__main__":
    # Для ручной проверочной прогона:
    try:
        asyncio.run(_example())
    except KeyboardInterrupt:
        pass


# ======================================================================================
# Исключения
# ======================================================================================

class Rejected(Exception):
    pass
