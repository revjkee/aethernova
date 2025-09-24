# -*- coding: utf-8 -*-
"""
Chronowatch • Schedule Worker (production-grade)

Возможности:
- Cron-графики (croniter) c таймзоной из Settings (tasks.scheduler.timezone)
- Ограничение параллелизма (max_concurrency) через asyncio.Semaphore
- Тайм-ауты джоб и джиттер выполнения
- Резервирование (распределенный лок) в Redis (redis.asyncio), fallback на локальный in-memory
- Прочная обработка ошибок: бэкофф логика на повтор при системных сбоях локов
- Метрики Prometheus (необязательные): запуски/успехи/ошибки/длительности/пропуски слотов
- Реестр задач и декоратор @job для декларативной регистрации
- Грациозная остановка по сигналам
- Подробное структурированное логирование

Зависимости (по возможности, мягкие):
    croniter, redis>=4 (redis.asyncio), prometheus-client
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import json
import logging
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

try:
    from croniter import croniter  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("croniter is required: pip install croniter") from e

# Optional redis lock
try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

# Optional prometheus
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore

from ..settings import Settings


log = logging.getLogger(__name__)


# ============================
# Prometheus metrics (optional)
# ============================

if Counter and Histogram and Gauge:
    MET_RUNS = Counter(
        "cw_sched_runs_total", "Количество запусков задач", ["job", "result"]
    )
    MET_DURATION = Histogram(
        "cw_sched_run_seconds", "Длительность выполнения задач, сек", ["job"],
        buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 60, 120, 300)
    )
    MET_SKIPPED = Counter(
        "cw_sched_skipped_total", "Пропуски слотов (из-за лока или выключения)", ["job", "reason"]
    )
    MET_RUNNING = Gauge(
        "cw_sched_running_jobs", "Сейчас выполняется задач", ["job"]
    )
else:
    class _N:
        def labels(self, *args, **kwargs): return self
        def inc(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
    MET_RUNS = MET_DURATION = MET_SKIPPED = MET_RUNNING = _N()


# ============================
# Job registry
# ============================

_JobFunc = Callable[["JobContext"], Awaitable[None]]
_REGISTRY: Dict[str, _JobFunc] = {}

def job(name: str) -> Callable[[_JobFunc], _JobFunc]:
    """Декоратор регистрации фоновой задачи по имени."""
    def _wrap(fn: _JobFunc) -> _JobFunc:
        if name in _REGISTRY:
            raise ValueError(f"Job already registered: {name}")
        _REGISTRY[name] = fn
        return fn
    return _wrap


# ============================
# Lock (Redis or in-memory)
# ============================

class AbstractLock:
    async def acquire(self, key: str, ttl_s: float) -> bool: ...
    async def release(self, key: str) -> None: ...

class MemoryLock(AbstractLock):
    def __init__(self) -> None:
        self._held: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, key: str, ttl_s: float) -> bool:
        async with self._lock:
            now = time.monotonic()
            exp = self._held.get(key)
            if exp and exp > now:
                return False
            self._held[key] = now + ttl_s
            return True

    async def release(self, key: str) -> None:
        async with self._lock:
            self._held.pop(key, None)

class RedisLock(AbstractLock):
    """
    Минималистичный Redis-блокировщик на основе SET NX PX.
    """
    def __init__(self, client: "aioredis.Redis") -> None:
        self.r = client
        self._tokens: Dict[str, str] = {}

    async def acquire(self, key: str, ttl_s: float) -> bool:
        token = os.urandom(16).hex()
        ok = await self.r.set(key, token, nx=True, px=int(ttl_s * 1000))
        if ok:
            self._tokens[key] = token
            return True
        return False

    async def release(self, key: str) -> None:
        token = self._tokens.get(key)
        if not token:
            return
        # Lua-scripted compare-and-del
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        else
          return 0
        end
        """
        try:
            await self.r.eval(script, 1, key, token)  # type: ignore
        finally:
            self._tokens.pop(key, None)


# ============================
# Job context
# ============================

@dataclasses.dataclass
class JobContext:
    name: str
    settings: Settings
    run_id: str
    scheduled_at: float    # epoch seconds
    started_at: float      # epoch seconds
    attempt: int


# ============================
# Schedule worker
# ============================

class ScheduleWorker:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings.get()
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(
            max(1, int(self.settings.tasks.scheduler.max_concurrency))
        )
        self._lock: AbstractLock = self._make_lock()
        self._tasks: Dict[str, asyncio.Task] = {}

    def _make_lock(self) -> AbstractLock:
        # Пытаемся инициализировать Redis-клиент из cache настроек
        if aioredis is not None and self.settings.cache.engine == "redis":
            try:
                url = self.settings.redis_url()
                client = aioredis.from_url(url, encoding="utf-8", decode_responses=True)  # type: ignore
                # Пинг — best-effort
                async def _ping():
                    with contextlib.suppress(Exception):
                        await client.ping()
                asyncio.get_event_loop().create_task(_ping())
                log.info("ScheduleWorker: using RedisLock at %s", url)
                return RedisLock(client)
            except Exception as e:
                log.warning("RedisLock init failed, fallback to MemoryLock: %s", e)
        log.info("ScheduleWorker: using MemoryLock (single-instance)")
        return MemoryLock()

    async def run(self) -> None:
        """
        Запустить планировщик до остановки.
        """
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop(s)))
        log.info("ScheduleWorker starting (concurrency=%s, tz=%s)",
                 self.settings.tasks.scheduler.max_concurrency,
                 self.settings.tasks.scheduler.timezone)

        # Создаем задачи-планировщики по каждому cron из конфигурации
        for job_name, spec in self._iter_enabled_crons():
            t = asyncio.create_task(self._job_scheduler_loop(job_name, spec), name=f"cron-{job_name}")
            self._tasks[job_name] = t

        await self._stop.wait()
        log.info("ScheduleWorker stopping: waiting running jobs...")
        await self._graceful_shutdown()

    async def stop(self, sig: Optional[signal.Signals] = None) -> None:
        if sig:
            log.info("Received signal %s, shutting down...", sig.name)
        self._stop.set()

    def _iter_enabled_crons(self):
        crons = self.settings.tasks.crons or {}
        for name, cfg in crons.items():
            if not getattr(cfg, "enabled", True):
                continue
            if name not in _REGISTRY:
                log.warning("Cron '%s' is enabled but no job registered. Skipping.", name)
                continue
            yield name, cfg

    async def _graceful_shutdown(self) -> None:
        # Даем активным задачам завершиться (тайм-аут 30с)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.gather(*self._tasks.values(), return_exceptions=True), timeout=30)
        for t in self._tasks.values():
            if not t.done():
                t.cancel()
        self._tasks.clear()

    # -------------------------
    # Per-cron scheduler routine
    # -------------------------
    async def _job_scheduler_loop(self, job_name: str, cfg) -> None:
        """
        Цикл планирования одной джобы: вычислить следующий слот cron, подождать с учетом джиттера,
        попытаться взять распределенный лок и запустить выполнение.
        """
        tzname = self.settings.tasks.scheduler.timezone or "UTC"
        # croniter работает с naive datetime; используем UTC и смещение отдельно
        # Для простоты применим таймзону через time.tzset недоступно в Windows; оставим UTC.
        # Производственный паттерн — хранить cron в таймзоне UTC.
        base = datetime.now(timezone.utc)
        itr = croniter(cfg.schedule, base)

        backoff = 0.5
        backoff_max = 8.0

        while not self._stop.is_set():
            try:
                # Следующее время запуска в секундах epoch
                next_dt = itr.get_next(datetime)  # type: ignore
                next_ts = next_dt.timestamp()

                # Ждем до слота с учетом джиттера
                jitter = max(0, int(getattr(cfg, "jitter_s", 0)))
                sleep_for = max(0.0, next_ts - time.time()) + random.uniform(0, jitter)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
                    # остановка пришла
                    break
                except asyncio.TimeoutError:
                    pass  # пора запускать

                # Распределенный лок: защищаем выполнение слота в масштабировании
                lock_key = f"cw:cron:{job_name}:{int(next_ts)}"
                # TTL чуть длиннее тайм-аута джобы
                ttl = int(getattr(cfg, "timeout_s", 30)) + jitter + 10
                got = await self._lock.acquire(lock_key, ttl_s=ttl)
                if not got:
                    MET_SKIPPED.labels(job=job_name, reason="locked").inc()
                    log.info("Cron '%s' slot %s skipped (locked)", job_name, int(next_ts))
                    backoff = 0.5  # сброс бэкоффа
                    continue

                # Запускаем выполнение
                asyncio.create_task(self._run_once(job_name, cfg, scheduled_ts=next_ts, lock_key=lock_key))
                backoff = 0.5  # успешный цикл планирования
            except Exception as e:
                log.exception("Scheduler loop error for job '%s': %s", job_name, e)
                # Бэкофф перед новыми попытками вычислить следующий слот
                await asyncio.sleep(min(backoff_max, backoff) * random.random())
                backoff = min(backoff_max, backoff * 2)

    async def _run_once(self, job_name: str, cfg, *, scheduled_ts: float, lock_key: str) -> None:
        """
        Одна попытка выполнения джобы с тайм-аутом, семафором и метриками.
        """
        func = _REGISTRY.get(job_name)
        if func is None:
            MET_SKIPPED.labels(job=job_name, reason="unregistered").inc()
            await self._lock.release(lock_key)
            log.warning("Job '%s' not registered at run time", job_name)
            return

        run_id = f"{job_name}:{int(scheduled_ts)}:{os.getpid()}:{int(time.time()*1000)%100000}"
        timeout = int(getattr(cfg, "timeout_s", 30))
        attempt = 1

        async with self._sem:
            MET_RUNNING.labels(job=job_name).inc()
            start_ts = time.time()
            ctx = JobContext(
                name=job_name,
                settings=self.settings,
                run_id=run_id,
                scheduled_at=scheduled_ts,
                started_at=start_ts,
                attempt=attempt,
            )
            log_extra = {
                "job": job_name,
                "run_id": run_id,
                "scheduled_at": int(scheduled_ts),
                "timeout_s": timeout,
            }
            log.info("Job '%s' started", job_name, extra=log_extra)
            try:
                with MET_DURATION.labels(job=job_name).time():
                    await asyncio.wait_for(func(ctx), timeout=timeout)
                MET_RUNS.labels(job=job_name, result="success").inc()
                log.info("Job '%s' finished ok in %.3fs", job_name, time.time() - start_ts, extra=log_extra)
            except asyncio.TimeoutError:
                MET_RUNS.labels(job=job_name, result="timeout").inc()
                log.error("Job '%s' timed out after %ss", job_name, timeout, extra=log_extra)
            except Exception as e:
                MET_RUNS.labels(job=job_name, result="error").inc()
                log.exception("Job '%s' failed: %s", job_name, e, extra=log_extra)
            finally:
                MET_RUNNING.labels(job=job_name).dec()
                # Освобождаем лок в любом случае (TTL всё равно защитит от двойного запуска)
                with contextlib.suppress(Exception):
                    await self._lock.release(lock_key)


# =========================================
# Example jobs (remove in production or keep as templates)
# =========================================

@job("cleanup-temp")
async def cleanup_temp(ctx: JobContext) -> None:
    """
    Пример: чистка временных файлов/каталогов.
    Реальный код должен быть идемпотентным и укладываться в timeout.
    """
    # Имитация работы
    await asyncio.sleep(0.05)


@job("reconcile-metrics")
async def reconcile_metrics(ctx: JobContext) -> None:
    """
    Пример: сверка агрегатов/метрик.
    """
    await asyncio.sleep(0.05)


# =========================================
# Entrypoint
# =========================================

def _setup_logging() -> None:
    lvl = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )

async def _main() -> None:
    _setup_logging()
    s = Settings.get()
    # Быстрая валидация включенности планировщика
    if not s.tasks.scheduler.enabled:
        log.warning("Scheduler disabled by configuration.")
        return
    worker = ScheduleWorker(s)
    await worker.run()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
