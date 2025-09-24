# -*- coding: utf-8 -*-
"""
Industrial Async Event Loop Supervisor (v1)

Возможности:
- Единая точка запуска/остановки фонового рантайма (supervisor)
- Регистрация задач: одноразовые, периодические, отложенные
- Политики рестартов: экспоненциальный бэкофф + джиттер, ограничение попыток
- Контроль параллелизма (Semaphore), backpressure (очереди с таймаутами)
- Корреляция через contextvars (request_id, span_id) и структурные логи
- Watchdog: мониторинг зависших задач, принудительная отмена по deadline
- Грациозное завершение по сигналам SIGINT/SIGTERM
- Хуки телеметрии (on_task_start/finish/error) — для интеграции метрик/трейсинга
- Health API: текущий статус, список задач, метрики по джобам
- Deadline/timeout для задач, автоматическая отмена
- Безопасная интеграция с внешними обработчиками (awaitable callables)

Заметки:
- Модуль не подменяет asyncio loop; он управляет Task‑ами в рамках текущего loop.
- Замените/подключите свои метрики/трейсинг в TelemetryHooks.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import logging
import math
import os
import random
import signal
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import FrameType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
)

# ------------------------------------------------------------------------------
# Логирование
# ------------------------------------------------------------------------------
logger = logging.getLogger("engine_core.event_loop")
if not logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Контекст корреляции
# ------------------------------------------------------------------------------
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
span_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def new_request_id() -> str:
    return str(uuid.uuid4())

def new_span_id() -> str:
    return uuid.uuid4().hex[:16]

# ------------------------------------------------------------------------------
# Конфигурации и политики
# ------------------------------------------------------------------------------
@dataclass
class RetryPolicy:
    max_retries: int = 5              # -1 для бесконечно
    base_delay: float = 0.2           # секунды
    max_delay: float = 30.0           # максимум бэкоффа
    jitter: float = 0.2               # [0..1] доля случайного джиттера
    multiplier: float = 2.0           # экспонента

    def next_delay(self, attempt: int) -> float:
        """attempt: 1..N"""
        delay = self.base_delay * (self.multiplier ** (attempt - 1))
        delay = min(delay, self.max_delay)
        if self.jitter > 0:
            delta = delay * self.jitter
            delay = random.uniform(max(0.0, delay - delta), delay + delta)
        return delay


@dataclass
class LoopConfig:
    shutdown_grace_s: float = 15.0
    watchdog_interval_s: float = 5.0
    default_retry: RetryPolicy = field(default_factory=RetryPolicy)
    default_task_timeout_s: Optional[float] = None   # если задан — принудительная отмена
    max_concurrency: int = 256                      # общий лимит на одновременные задачи
    queue_put_timeout_s: float = 2.0                # таймаут на backpressure при отправке в очередь

# ------------------------------------------------------------------------------
# Хуки телеметрии (заглушки для интеграции Prometheus/OpenTelemetry)
# ------------------------------------------------------------------------------
@dataclass
class TelemetryHooks:
    on_task_start: Optional[Callable[[str, str, str], None]] = None
    on_task_finish: Optional[Callable[[str, str, str, float], None]] = None
    on_task_error: Optional[Callable[[str, str, str, BaseException], None]] = None

# ------------------------------------------------------------------------------
# Сущности задач
# ------------------------------------------------------------------------------
JobCallable = Union[Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[Any]]]

@dataclass
class JobSpec:
    name: str
    fn: JobCallable
    kind: Literal["once", "periodic", "delayed"] = "once"
    interval_s: Optional[float] = None       # для periodic
    delay_s: Optional[float] = None          # для delayed
    run_immediately: bool = True             # periodic: начинать сразу или через interval
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_s: Optional[float] = None
    concurrency_key: Optional[str] = None    # общий ключ для ограничения параллельности
    max_concurrent_for_key: int = 1
    args: Tuple[Any, ...] = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaskInfo:
    name: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: Literal["pending", "running", "succeeded", "failed", "cancelled"] = "pending"
    attempts: int = 0
    last_error: Optional[str] = None
    request_id: str = field(default_factory=new_request_id)
    span_id: str = field(default_factory=new_span_id)
    timeout_s: Optional[float] = None
    task: Optional[asyncio.Task] = None
    concurrency_key: Optional[str] = None

# ------------------------------------------------------------------------------
# Супервайзер
# ------------------------------------------------------------------------------
class AsyncEventLoop:
    """
    Управляет жизненным циклом фоновых задач и джобов.
    """
    def __init__(self, cfg: Optional[LoopConfig] = None, telemetry: Optional[TelemetryHooks] = None):
        self.cfg = cfg or LoopConfig()
        self.telemetry = telemetry or TelemetryHooks()
        self._closing = asyncio.Event()
        self._global_sem = asyncio.Semaphore(self.cfg.max_concurrency)
        self._conc_sem: Dict[str, asyncio.Semaphore] = {}
        self._jobs: Dict[str, JobSpec] = {}
        self._tasks: Dict[str, TaskInfo] = {}
        self._periodic_handles: Dict[str, asyncio.Task] = {}
        self._watchdog_task: Optional[asyncio.Task] = None
        self._signal_handlers_installed = False

    # ---------------------------- Публичные API ---------------------------- #

    def register_once(self, name: str, fn: JobCallable, *, retry: Optional[RetryPolicy] = None,
                      timeout_s: Optional[float] = None, concurrency_key: Optional[str] = None,
                      max_concurrent_for_key: int = 1, *args, **kwargs) -> None:
        self._register(JobSpec(
            name=name, fn=fn, kind="once", retry=retry or self.cfg.default_retry, timeout_s=timeout_s,
            concurrency_key=concurrency_key, max_concurrent_for_key=max_concurrent_for_key,
            args=args, kwargs=kwargs
        ))

    def register_delayed(self, name: str, fn: JobCallable, *, delay_s: float,
                         retry: Optional[RetryPolicy] = None, timeout_s: Optional[float] = None,
                         concurrency_key: Optional[str] = None, max_concurrent_for_key: int = 1,
                         *args, **kwargs) -> None:
        self._register(JobSpec(
            name=name, fn=fn, kind="delayed", delay_s=delay_s,
            retry=retry or self.cfg.default_retry, timeout_s=timeout_s,
            concurrency_key=concurrency_key, max_concurrent_for_key=max_concurrent_for_key,
            args=args, kwargs=kwargs
        ))

    def register_periodic(self, name: str, fn: JobCallable, *, interval_s: float,
                          run_immediately: bool = True, retry: Optional[RetryPolicy] = None,
                          timeout_s: Optional[float] = None, concurrency_key: Optional[str] = None,
                          max_concurrent_for_key: int = 1, *args, **kwargs) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0")
        self._register(JobSpec(
            name=name, fn=fn, kind="periodic", interval_s=interval_s,
            run_immediately=run_immediately, retry=retry or self.cfg.default_retry, timeout_s=timeout_s,
            concurrency_key=concurrency_key, max_concurrent_for_key=max_concurrent_for_key,
            args=args, kwargs=kwargs
        ))

    async def start(self) -> None:
        """
        Запустить все зарегистрированные задачи и механизм наблюдения.
        """
        if not self._signal_handlers_installed:
            self._install_signal_handlers()

        # Планируем periodic/delayed и запускаем once
        for name, spec in list(self._jobs.items()):
            if spec.kind == "once":
                self._spawn_run(spec)
            elif spec.kind == "delayed":
                self._periodic_handles[name] = asyncio.create_task(self._run_delayed(spec))
            elif spec.kind == "periodic":
                self._periodic_handles[name] = asyncio.create_task(self._run_periodic(spec))

        # Watchdog
        self._watchdog_task = asyncio.create_task(self._watchdog())

        logger.info("event loop supervisor started", extra={"jobs": list(self._jobs.keys())})

    async def stop(self) -> None:
        """
        Грациозная остановка: запрет новых джобов, отмена активных, ожидание завершения.
        """
        logger.info("event loop supervisor stopping")
        self._closing.set()

        # Останавливаем периодические планировщики
        for name, h in list(self._periodic_handles.items()):
            h.cancel()
        self._periodic_handles.clear()

        # Останавливаем watchdog
        if self._watchdog_task:
            self._watchdog_task.cancel()
            with contextlib_suppress(asyncio.CancelledError):
                await self._watchdog_task

        # Отмена всех активных задач
        deadline = time.time() + self.cfg.shutdown_grace_s
        for t in list(self._tasks.values()):
            if t.task and not t.task.done():
                t.task.cancel()

        # Ждем
        pending = [t.task for t in self._tasks.values() if t.task and not t.task.done()]
        if pending:
            with contextlib_suppress(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True),
                                       timeout=max(0.0, deadline - time.time()))
        logger.info("event loop supervisor stopped")

    def health(self) -> Dict[str, Any]:
        """
        Краткий срез состояния: статусы задач, активные семафоры, время.
        """
        return {
            "time": now_utc().isoformat(),
            "closing": self._closing.is_set(),
            "tasks": [{
                "name": t.name,
                "status": t.status,
                "attempts": t.attempts,
                "timeout_s": t.timeout_s,
                "started_at": t.started_at.isoformat() if t.started_at else None,
                "created_at": t.created_at.isoformat(),
                "finished_at": t.finished_at.isoformat() if t.finished_at else None,
                "last_error": t.last_error,
            } for t in self._tasks.values()],
            "concurrency": {
                "global": self.cfg.max_concurrency,
                "keys": {k: sem._value for k, sem in self._conc_sem.items()},  # для отладки
            }
        }

    # ---------------------------- Внутренние части ---------------------------- #

    def _register(self, spec: JobSpec) -> None:
        if spec.name in self._jobs:
            raise ValueError(f"Job '{spec.name}' already registered")
        self._jobs[spec.name] = spec

    def _spawn_run(self, spec: JobSpec) -> None:
        info = TaskInfo(
            name=spec.name,
            created_at=now_utc(),
            timeout_s=spec.timeout_s if spec.timeout_s is not None else self.cfg.default_task_timeout_s,
            concurrency_key=spec.concurrency_key,
        )
        coro = self._run_job(spec, info)
        task = asyncio.create_task(coro, name=f"job:{spec.name}")
        info.task = task
        self._tasks[spec.name] = info

    async def _run_periodic(self, spec: JobSpec) -> None:
        """
        Планировщик периодической задачи.
        """
        # Первичный запуск
        if spec.run_immediately:
            self._spawn_run(spec)
        # Затем тикер
        try:
            while not self._closing.is_set():
                await asyncio.sleep(spec.interval_s or 1.0)
                if self._closing.is_set():
                    break
                self._spawn_run(spec)
        except asyncio.CancelledError:
            return

    async def _run_delayed(self, spec: JobSpec) -> None:
        try:
            await asyncio.sleep(spec.delay_s or 0.0)
            if not self._closing.is_set():
                self._spawn_run(spec)
        except asyncio.CancelledError:
            return

    def _sem_for_key(self, key: Optional[str], limit: int) -> asyncio.Semaphore:
        if not key:
            return self._global_sem
        sem = self._conc_sem.get(key)
        if not sem:
            sem = asyncio.Semaphore(limit)
            self._conc_sem[key] = sem
        return sem

    async def _run_job(self, spec: JobSpec, info: TaskInfo) -> None:
        """
        Запуск задачи с учётом ретраев, таймаутов, семафоров и контекстов.
        """
        # Контекст корреляции
        token_req = request_id_var.set(info.request_id or new_request_id())
        token_span = span_id_var.set(new_span_id())

        sem = self._sem_for_key(spec.concurrency_key, spec.max_concurrent_for_key)
        await sem.acquire()
        await self._global_sem.acquire()

        start_ts = time.time()
        info.started_at = now_utc()
        info.status = "running"
        if self.telemetry.on_task_start:
            self.telemetry.on_task_start(info.name, request_id_var.get(), span_id_var.get())

        try:
            attempt = 0
            while True:
                attempt += 1
                info.attempts = attempt
                try:
                    # Таймаут выполнения
                    if spec.timeout_s or self.cfg.default_task_timeout_s:
                        timeout = spec.timeout_s or self.cfg.default_task_timeout_s
                        await asyncio.wait_for(self._call_job(spec), timeout=timeout)
                    else:
                        await self._call_job(spec)

                    info.status = "succeeded"
                    break
                except asyncio.TimeoutError as e:
                    info.last_error = f"timeout after {spec.timeout_s or self.cfg.default_task_timeout_s}s"
                    logger.warning("job timeout", extra={"job": spec.name, "request_id": request_id_var.get(), "span": span_id_var.get()})
                    # таймаут считаем фатальной ошибкой — без ретраев (можно изменить под нужды)
                    info.status = "failed"
                    raise e
                except asyncio.CancelledError:
                    info.status = "cancelled"
                    raise
                except Exception as e:
                    info.last_error = "".join(traceback.format_exception_only(type(e), e)).strip()
                    logger.warning("job error", extra={"job": spec.name, "attempt": attempt, "request_id": request_id_var.get(), "span": span_id_var.get(), "err": info.last_error})
                    # Решение о ретрае
                    if spec.retry.max_retries == -1 or attempt < (spec.retry.max_retries + 1):
                        delay = spec.retry.next_delay(attempt)
                        await asyncio.sleep(delay)
                        continue
                    info.status = "failed"
                    raise

        finally:
            info.finished_at = now_utc()
            dur_ms = int((time.time() - start_ts) * 1000)

            # Метрики
            if info.status == "succeeded" and self.telemetry.on_task_finish:
                self.telemetry.on_task_finish(info.name, request_id_var.get(), span_id_var.get(), float(dur_ms) / 1000.0)
            if info.status == "failed" and self.telemetry.on_task_error:
                self.telemetry.on_task_error(info.name, request_id_var.get(), span_id_var.get(), Exception(info.last_error or "error"))

            # Возврат семафоров
            try:
                self._global_sem.release()
            except ValueError:
                pass
            try:
                sem.release()
            except ValueError:
                pass

            # Восстановление контекста
            request_id_var.reset(token_req)
            span_id_var.reset(token_span)

    async def _call_job(self, spec: JobSpec) -> Any:
        """
        Унификация вызова callable (без аргументов / с args/kwargs).
        """
        fn = spec.fn
        if spec.args or spec.kwargs:
            return await fn(*spec.args, **spec.kwargs)  # type: ignore[arg-type]
        return await fn()  # type: ignore[misc]

    async def _watchdog(self) -> None:
        """
        Периодический мониторинг задач и принудительная отмена зависших (если задан timeout_s).
        """
        try:
            while not self._closing.is_set():
                await asyncio.sleep(self.cfg.watchdog_interval_s)
                now = time.time()
                for ti in list(self._tasks.values()):
                    if ti.status == "running" and ti.timeout_s:
                        if ti.started_at:
                            elapsed = now - ti.started_at.timestamp()
                            if elapsed > (ti.timeout_s + 1.0):  # небольшой люфт
                                if ti.task and not ti.task.done():
                                    logger.warning("watchdog: cancelling long running task",
                                                   extra={"job": ti.name, "elapsed_s": elapsed})
                                    with contextlib_suppress(Exception):
                                        ti.task.cancel()
        except asyncio.CancelledError:
            return

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()

        def _handler(sig_name: str):
            logger.info("signal received", extra={"signal": sig_name})
            self._closing.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handler, sig.name)
            except NotImplementedError:
                # Windows
                signal.signal(sig, lambda *_: _handler(sig.name))
        self._signal_handlers_installed = True

# ------------------------------------------------------------------------------
# Вспомогательные утилиты
# ------------------------------------------------------------------------------
from contextlib import suppress as contextlib_suppress

class BoundedQueue:
    """
    Очередь с backpressure и таймаутом put.
    """
    def __init__(self, maxsize: int = 1000, put_timeout_s: float = 2.0):
        self._q: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self._put_timeout_s = put_timeout_s

    async def put(self, item: Any) -> bool:
        try:
            await asyncio.wait_for(self._q.put(item), timeout=self._put_timeout_s)
            return True
        except asyncio.TimeoutError:
            return False

    async def get(self) -> Any:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()

    def qsize(self) -> int:
        return self._q.qsize()

# ------------------------------------------------------------------------------
# Пример использования (smoke‑test). Не исполняется при импортировании.
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    async def sample_task(n: int = 1):
        rid = request_id_var.get() or new_request_id()
        span = span_id_var.get() or new_span_id()
        logger.info("run sample_task", extra={"n": n, "rid": rid, "span": span})
        await asyncio.sleep(0.25)

    async def main():
        loop = AsyncEventLoop(
            LoopConfig(
                shutdown_grace_s=10.0,
                watchdog_interval_s=2.0,
                default_task_timeout_s=5.0,
                max_concurrency=8,
            ),
            telemetry=TelemetryHooks(
                on_task_start=lambda name, rid, sid: logger.info("telemetry start", extra={"job": name, "rid": rid, "sid": sid}),
                on_task_finish=lambda name, rid, sid, dur: logger.info("telemetry finish", extra={"job": name, "dur": dur}),
                on_task_error=lambda name, rid, sid, err: logger.error("telemetry error", extra={"job": name, "err": str(err)}),
            )
        )

        # Регистрация задач
        loop.register_once("bootstrap", lambda: sample_task(1))
        loop.register_periodic("heartbeat", lambda: sample_task(2), interval_s=1.0, run_immediately=True,
                               concurrency_key="hb", max_concurrent_for_key=1)
        loop.register_delayed("delayed", lambda: sample_task(3), delay_s=3.0)

        await loop.start()
        # Работаем 5 секунд и завершаемся
        await asyncio.sleep(5.0)
        await loop.stop()

    asyncio.run(main())
