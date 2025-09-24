# -*- coding: utf-8 -*-
"""
ChronoWatch Core — Engine/Core Adapter (production-grade)

Назначение:
- Медиатор между доменной логикой планировщика (RRULE) и инфраструктурой (БД/очереди).
- Безопасная диспетчеризация due-расписаний с атомарной блокировкой, идемпотентностью и телеметрией.
- Предварительный просмотр наступлений, валидация, вычисление next_run.

Зависимости:
  - Стандартная библиотека Python 3.11+
  - Внутренний модуль: chronowatch.scheduler.rrule_engine (см. ранее)
  - Опционально OpenTelemetry (если установлен)

Совместимость:
  - Переменные окружения из .env.example и configs/security.yaml:
      TIME_DRIFT_MAX_MS
      JOB_DEFAULT_TIMEOUT_SEC
      JOB_DEFAULT_RETRIES
      JOB_RETRY_BACKOFF_BASE_MS
      JOB_RETRY_BACKOFF_MAX_MS
      IDEMPOTENCY_TTL_SEC
      GLOBAL_RPS_LIMIT / BURST (косвенно, на уровне ingress/sidecar)
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

from zoneinfo import ZoneInfo

from chronowatch.scheduler.rrule_engine import (
    RRuleEngine,
    RecurrenceConfig,
    InvalidRuleError,
    ExpansionLimitExceeded,
)

try:
    # OpenTelemetry (опционально)
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None


# =========================
# Protocols (Ports)
# =========================

class ScheduleRepository(Protocol):
    """
    Абстракция доступа к расписаниям.
    Реализация обязана обеспечивать атомарность методов с пометкой 'atomic'.
    """

    async def get_by_id(self, schedule_id: uuid.UUID) -> "ScheduleDTO | None":
        ...

    async def list_due_schedules(
        self,
        now: datetime,
        limit: int,
    ) -> List["ScheduleDTO"]:
        """
        Возвращает активные расписания, для которых next_run_at <= now, с ограничением по limit.
        """
        ...

    async def try_acquire_dispatch_lock(
        self,
        schedule_id: uuid.UUID,
        scheduled_for: datetime,
        ttl: timedelta,
    ) -> bool:
        """
        Атомарно: установить ключ (schedule_id, scheduled_for) если не существует.
        Используется для идемпотентной диспетчеризации.
        """
        ...

    async def set_next_run(
        self,
        schedule_id: uuid.UUID,
        next_run_at: Optional[datetime],
        last_run_at: Optional[datetime],
    ) -> None:
        """
        Атомарно обновляет next_run_at/last_run_at после успешной диспетчеризации.
        """
        ...

    async def record_misfire(
        self,
        schedule_id: uuid.UUID,
        scheduled_for: datetime,
        reason: str,
    ) -> None:
        """
        Логирует мисфаер (например, из-за дрейфа времени или превышения окна).
        """
        ...


class JobRepository(Protocol):
    """
    Доступ к джобам/таскам.
    """

    async def create_job(self, job: "JobDTO") -> "JobDTO":
        """
        Создает запись джобы (status=PENDING/SCHEDULED).
        Должна быть idempotent по dedup_key в границах TTL.
        """
        ...

    async def mark_enqueued(self, job_id: uuid.UUID, broker_message_id: str) -> None:
        ...


class QueuePublisher(Protocol):
    """
    Публикатор в брокер (Redis/Kafka/Rabbit/…).
    Должен поддерживать идемпотентность по dedup_key на своей стороне, если возможно.
    """

    async def publish(
        self,
        topic_or_queue: str,
        payload: Mapping[str, Any],
        *,
        dedup_key: str,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """
        Возвращает broker_message_id.
        """
        ...


class DriftGuard(Protocol):
    """
    Контроль дрейфа системного времени относительно эталона.
    """

    async def is_within_threshold(self) -> bool:
        ...

    async def current_drift_ms(self) -> int:
        ...


class TimeSource(Protocol):
    """
    Абстракция времени для тестируемости.
    """
    def now(self) -> datetime:
        ...


# =========================
# Domain DTOs
# =========================

@dataclass(frozen=True, slots=True)
class ScheduleDTO:
    id: uuid.UUID
    name: str
    tz: str  # IANA
    dtstart: Optional[datetime]
    until: Optional[datetime]
    rrules: Tuple[str, ...]
    rdates: Tuple[datetime, ...] = field(default_factory=tuple)
    exdates: Tuple[datetime, ...] = field(default_factory=tuple)
    is_active: bool = True
    grace_seconds: int = 30
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    # Дополнительные пользовательские поля для формирования payload:
    payload: Mapping[str, Any] | None = None
    priority: str = "NORMAL"               # LOW|NORMAL|HIGH|CRITICAL
    queue: str = "cron:default"
    timeout_sec: int = int(os.getenv("JOB_DEFAULT_TIMEOUT_SEC", "120"))
    max_attempts: int = int(os.getenv("JOB_DEFAULT_RETRIES", "5"))


@dataclass(frozen=True, slots=True)
class JobDTO:
    id: uuid.UUID
    schedule_id: Optional[uuid.UUID]
    queue: str
    priority: str
    payload: Mapping[str, Any] | None
    timeout_sec: int
    max_attempts: int
    dedup_key: str
    status: str = "SCHEDULED"  # PENDING|SCHEDULED|RUNNING|SUCCEEDED|FAILED|CANCELLED|DEADLETTER|RETRY
    scheduled_for: Optional[datetime] = None
    created_at: Optional[datetime] = None


# =========================
# Adapter Configuration
# =========================

@dataclass(slots=True)
class AdapterConfig:
    idempotency_ttl_sec: int = int(os.getenv("IDEMPOTENCY_TTL_SEC", "600"))
    backoff_base_ms: int = int(os.getenv("JOB_RETRY_BACKOFF_BASE_MS", "200"))
    backoff_max_ms: int = int(os.getenv("JOB_RETRY_BACKOFF_MAX_MS", "60000"))
    publish_retries: int = 5
    due_fetch_limit: int = 200
    time_drift_max_ms: int = int(os.getenv("TIME_DRIFT_MAX_MS", "200"))
    safe_preview_limit: int = 1000
    safe_preview_window_days: int = 365  # для preview


# =========================
# Engine/Core Adapter
# =========================

class EngineCoreAdapter:
    """
    Связывает:
      - RRULE-движок (повторения)
      - Schedule/Job репозитории (БД)
      - Публикатор очереди
      - DriftGuard и TimeSource
    Гарантирует:
      - Идемпотентность: dedup_key = "{schedule_uuid}:{iso_ts}"
      - Атомарную защиту от гонок диспетчеризации
      - Безопасные ретраи публикации
      - Обновление next_run_at/last_run_at только после успешной публикации
    """

    def __init__(
        self,
        schedules: ScheduleRepository,
        jobs: JobRepository,
        publisher: QueuePublisher,
        *,
        drift_guard: Optional[DriftGuard] = None,
        time_source: Optional[TimeSource] = None,
        config: Optional[AdapterConfig] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._schedules = schedules
        self._jobs = jobs
        self._publisher = publisher
        self._drift_guard = drift_guard
        self._ts = time_source or _SystemTime()
        self._cfg = config or AdapterConfig()
        self._log = logger or logging.getLogger("chronowatch.adapter.engine")

    # ---------------------------
    # Public API
    # ---------------------------

    async def plan_due(self) -> int:
        """
        Выбирает due-расписания и публикует соответствующие джобы.
        Возвращает число успешно запланированных джоб.
        """
        now = self._ts.now()
        if self._drift_guard is not None:
            within = await self._drift_guard.is_within_threshold()
            if not within:
                drift = await self._drift_guard.current_drift_ms()
                self._log.warning("time_drift_exceeds_threshold", extra={"event": "dispatch", "drift_ms": drift})
                # По политике безопасности отказываемся исполнять при превышении
                return 0

        due = await self._schedules.list_due_schedules(now, self._cfg.due_fetch_limit)
        if not due:
            return 0

        planned = 0
        for sch in due:
            try:
                planned += await self._plan_single(sch, now)
            except Exception as e:
                self._log.exception("plan_single_error", extra={"event": "dispatch", "schedule_id": str(sch.id), "error": str(e)})
                continue
        return planned

    async def compute_next_run(self, schedule: ScheduleDTO, *, from_dt: Optional[datetime] = None) -> Optional[datetime]:
        """
        Рассчитывает следующее наступление для расписания начиная с from_dt (или now()).
        """
        eng = self._engine_from_schedule(schedule)
        base = from_dt or self._ts.now().astimezone(ZoneInfo(schedule.tz))
        return eng.next_after(base, inclusive=False)

    async def preview(
        self,
        schedule: ScheduleDTO,
        window_start: datetime,
        window_end: datetime,
        *,
        limit: Optional[int] = None,
    ) -> List[datetime]:
        """
        Предварительный просмотр наступлений в окне [start, end].
        Защита по окну и количеству.
        """
        if window_end < window_start:
            raise ValueError("window_end must be >= window_start")
        # Лимит безопасности
        hard_limit = min(limit or self._cfg.safe_preview_limit, self._cfg.safe_preview_limit)
        eng = self._engine_from_schedule(schedule)
        return eng.between(window_start, window_end, limit=hard_limit, inclusive=True)

    async def validate(self, schedule: ScheduleDTO) -> None:
        """
        Проверка корректности RRULE/RDATE/EXDATE/DTSTART/UNTIL.
        """
        self._engine_from_schedule(schedule)  # построение и валидация

    # ---------------------------
    # Internal
    # ---------------------------

    async def _plan_single(self, sch: ScheduleDTO, now: datetime) -> int:
        """
        Планирует одну наступившую точку расписания (или вычисляет следующую и планирует).
        Возвращает 1 если запланировал, 0 если нечего делать.
        """
        tz = ZoneInfo(sch.tz)
        eng = self._engine_from_schedule(sch)

        # Если next_run_at отсутствует или в будущем — вычислим.
        next_run = sch.next_run_at
        if next_run is None or next_run > now:
            calc_from = (sch.last_run_at or now).astimezone(tz)
            next_run = eng.next_after(calc_from, inclusive=False)

        if next_run is None or next_run > now:
            # нечего выполнять
            return 0

        # Идемпотентный ключ
        dedup_key = self._dedup_key(sch.id, next_run)

        # Атомарная блокировка диспетчеризации для (schedule, timestamp)
        acquired = await self._schedules.try_acquire_dispatch_lock(
            sch.id,
            next_run,
            ttl=timedelta(seconds=self._cfg.idempotency_ttl_sec),
        )
        if not acquired:
            # уже обрабатывается другим воркером
            return 0

        # Собираем payload джобы
        job_payload = {
            "schedule_id": str(sch.id),
            "scheduled_for": next_run.astimezone(timezone.utc).isoformat(),
            "attempt": 1,
            "payload": sch.payload or {},
        }

        job = JobDTO(
            id=uuid.uuid4(),
            schedule_id=sch.id,
            queue=sch.queue,
            priority=sch.priority,
            payload=job_payload,
            timeout_sec=sch.timeout_sec,
            max_attempts=sch.max_attempts,
            dedup_key=dedup_key,
            status="SCHEDULED",
            scheduled_for=next_run,
        )

        # Создаем джоб в БД (идемпотентно по dedup_key)
        created = await self._jobs.create_job(job)

        # Публикуем в брокер с ретраями
        broker_message_id = await self._publish_with_retries(
            topic_or_queue=sch.queue,
            payload=self._build_broker_payload(created),
            dedup_key=dedup_key,
        )

        # Маркируем как enqueued
        await self._jobs.mark_enqueued(created.id, broker_message_id)

        # Обновляем last/next
        # Следующее наступление после этого же момента
        following = eng.next_after(next_run, inclusive=False)
        await self._schedules.set_next_run(sch.id, following, next_run)

        # Лог
        self._log.info(
            "job_enqueued",
            extra={
                "event": "dispatch",
                "schedule_id": str(sch.id),
                "job_id": str(created.id),
                "queue": sch.queue,
                "scheduled_for": next_run.isoformat(),
                "next_run_at": following.isoformat() if following else None,
            },
        )
        return 1

    async def _publish_with_retries(
        self,
        *,
        topic_or_queue: str,
        payload: Mapping[str, Any],
        dedup_key: str,
    ) -> str:
        """
        Публикация с экспоненциальным backoff и джиттером.
        """
        attempt = 0
        base = self._cfg.backoff_base_ms / 1000.0
        cap = self._cfg.backoff_max_ms / 1000.0

        while True:
            attempt += 1
            try:
                with self._span("publish", {"queue": topic_or_queue, "attempt": attempt}):
                    return await self._publisher.publish(
                        topic_or_queue,
                        payload,
                        dedup_key=dedup_key,
                        headers={"x-idempotency-key": dedup_key},
                        timeout=15.0,
                    )
            except Exception as e:
                if attempt >= self._cfg.publish_retries:
                    self._log.error("publish_failed", extra={"event": "dispatch", "attempts": attempt, "error": str(e)})
                    raise
                # backoff
                delay = min(cap, base * (2 ** (attempt - 1)))
                # простой "джиттер"
                delay = delay * (0.7 + 0.6 * (time.time() % 1.0))
                self._log.warning("publish_retry", extra={"event": "dispatch", "attempt": attempt, "sleep_sec": round(delay, 3)})
                await asyncio.sleep(delay)

    def _engine_from_schedule(self, schedule: ScheduleDTO) -> RRuleEngine:
        """
        Конструирует RRuleEngine из ScheduleDTO с безопасными лимитами.
        """
        tz = ZoneInfo(schedule.tz)
        cfg = RecurrenceConfig(
            rrules=tuple(schedule.rrules),
            rdates=tuple(d.astimezone(tz) for d in schedule.rdates),
            exdates=tuple(d.astimezone(tz) for d in schedule.exdates),
            tz=tz,
            dtstart=schedule.dtstart.astimezone(tz) if schedule.dtstart else None,
            until=schedule.until.astimezone(tz) if schedule.until else None,
            wkst=None,
            safe_max_occurrences=10_000,
            safe_max_window=timedelta(days=365 * 10),
        )
        try:
            return RRuleEngine(cfg, logger=self._log)
        except (InvalidRuleError, ExpansionLimitExceeded):
            raise
        except Exception as e:
            # Нормализуем неожиданные ошибки валидации
            raise InvalidRuleError(str(e)) from e

    def _dedup_key(self, schedule_id: uuid.UUID, ts: datetime) -> str:
        # Используем UTC-момент без миллисекунд для стабильности ключа
        iso = ts.astimezone(timezone.utc).replace(microsecond=0).isoformat()
        return f"{schedule_id}:{iso}"

    def _build_broker_payload(self, job: JobDTO) -> Mapping[str, Any]:
        return {
            "job_id": str(job.id),
            "schedule_id": str(job.schedule_id) if job.schedule_id else None,
            "queue": job.queue,
            "priority": job.priority,
            "timeout_sec": job.timeout_sec,
            "max_attempts": job.max_attempts,
            "scheduled_for": job.scheduled_for.astimezone(timezone.utc).isoformat() if job.scheduled_for else None,
            "payload": job.payload or {},
        }

    # ---------------------------
    # Telemetry helper
    # ---------------------------

    def _span(self, name: str, attributes: Optional[Mapping[str, Any]] = None):
        if _tracer is None:
            class _NullCtx:
                def __enter__(self): return self
                def __exit__(self, exc_type, exc, tb): return False
            return _NullCtx()
        span_cm = _tracer.start_as_current_span(f"adapter.{name}")
        if attributes:
            try:
                # Только примитивные типы
                span = span_cm.__enter__()
                for k, v in attributes.items():
                    if isinstance(v, (str, bool, int, float)) or v is None:
                        span.set_attribute(k, v if v is not None else "")
                return span_cm
            except Exception:
                return span_cm
        return span_cm


# =========================
# Default implementations
# =========================

class _SystemTime(TimeSource):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


# =========================
# Пример использования (справочно)
# =========================
# schedules = PostgresScheduleRepository(...)
# jobs = PostgresJobRepository(...)
# publisher = RedisQueuePublisher(...)
# drift_guard = NtpDriftGuard(max_ms=int(os.getenv("TIME_DRIFT_MAX_MS", "200")))
# adapter = EngineCoreAdapter(schedules, jobs, publisher, drift_guard=drift_guard)
# count = await adapter.plan_due()
# next_run = await adapter.compute_next_run(schedule)
# preview = await adapter.preview(schedule, start, end, limit=100)
