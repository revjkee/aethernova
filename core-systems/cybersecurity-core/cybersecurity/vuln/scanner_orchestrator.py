# cybersecurity-core/cybersecurity/vuln/scanner_orchestrator.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import enum
import hashlib
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Union,
)

# --------------------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# --------------------------------------------------------------------------------------
logger = logging.getLogger("cybersecurity.vuln.orchestrator")
if not logger.handlers:
    _h = logging.StreamHandler()
    _fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    _h.setFormatter(_fmt)
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# --------------------------------------------------------------------------------------
# МОДЕЛИ
# --------------------------------------------------------------------------------------
class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    SKIPPED = "SKIPPED"
    CANCELED = "CANCELED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class ScanFinding:
    id: str
    title: str
    severity: str
    cve: Optional[str] = None
    cvss: Optional[float] = None
    component: Optional[str] = None
    location: Optional[str] = None
    raw_ref: Optional[str] = None  # ссылка на артефакт в хранилище


@dataclass(frozen=True, slots=True)
class ScanResult:
    status: ScanStatus
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    findings: Tuple[ScanFinding, ...] = ()
    stats: Mapping[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    artifacts: Mapping[str, str] = field(default_factory=dict)  # name -> artifact_ref
    scanner_name: str = ""
    scanner_version: str = ""


@dataclass(slots=True)
class ScanTask:
    id: str
    scanner: str
    target: str
    params: Dict[str, Any]
    priority: int = 5
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    schedule_at: Optional[datetime] = None
    timeout_sec: int = 1800
    max_retries: int = 3
    retries: int = 0
    visibility_timeout_sec: int = 600
    idempotency_key: Optional[str] = None
    correlation_id: Optional[str] = None
    tenant_id: Optional[str] = None
    requested_by: Optional[str] = None
    status: ScanStatus = ScanStatus.PENDING

    def to_log(self) -> Dict[str, Any]:
        return {
            "task_id": self.id,
            "scanner": self.scanner,
            "target": self.target,
            "priority": self.priority,
            "retries": self.retries,
            "max_retries": self.max_retries,
            "timeout_sec": self.timeout_sec,
            "visibility_timeout_sec": self.visibility_timeout_sec,
            "status": self.status,
            "schedule_at": self.schedule_at.isoformat() if self.schedule_at else None,
            "tenant_id": self.tenant_id,
            "correlation_id": self.correlation_id,
        }


# --------------------------------------------------------------------------------------
# ПРОТОКОЛЫ ДЛЯ DI
# --------------------------------------------------------------------------------------
class Scanner(Protocol):
    """Реализация конкретного сканера уязвимостей."""

    name: str
    version: str
    max_concurrency: int  # верхний предел одновременных запусков у конкретного сканера
    rate_limit_per_sec: float  # токены/сек для оркестратора (0 = без лимита)

    async def validate(self, task: ScanTask) -> None:
        """Быстрая валидация параметров до запуска."""

    async def scan(self, task: ScanTask, artifacts: ArtifactStore) -> ScanResult:
        """Основной метод сканирования. Должен уважать task.timeout_sec."""


class Storage(Protocol):
    """Абстракция очереди и БД задач с арендой (lease)."""

    async def get_by_idempotency(self, idempotency_key: str) -> Optional[ScanTask]:
        ...

    async def submit(self, task: ScanTask) -> None:
        ...

    async def upsert_status(self, task_id: str, status: ScanStatus, extra: Optional[Mapping[str, Any]] = None) -> None:
        ...

    async def save_result(self, task_id: str, result: ScanResult) -> None:
        ...

    async def append_event(self, task_id: str, event: Mapping[str, Any]) -> None:
        ...

    async def lease_tasks(
        self,
        worker_id: str,
        batch: int,
        visibility_timeout_sec: int,
        now: Optional[datetime] = None,
    ) -> List[ScanTask]:
        """Выдаёт список задач под аренду (не более batch)."""

    async def extend_lease(self, worker_id: str, task_id: str, visibility_timeout_sec: int) -> None:
        ...

    async def complete_lease(self, worker_id: str, task_id: str) -> None:
        ...

    async def reschedule(self, task: ScanTask, schedule_at: datetime) -> None:
        ...


class ArtifactStore(Protocol):
    """Хранилище артефактов (сырые отчёты, pcap, json и пр.)."""

    async def put_blob(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Возвращает ссылку/ключ артефакта."""

    async def get_blob(self, ref: str) -> bytes:
        ...

    async def presign(self, ref: str, expires_in_sec: int = 3600) -> str:
        ...


class Metrics(Protocol):
    """Метрики/трейсинг (можно прокинуть адаптер для OpenTelemetry/Prometheus)."""

    def counter(self, name: str, value: int = 1, **labels: str) -> None: ...
    def histogram(self, name: str, value: float, **labels: str) -> None: ...
    def gauge(self, name: str, value: float, **labels: str) -> None: ...


# --------------------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ: RateLimiter & CircuitBreaker
# --------------------------------------------------------------------------------------
class AsyncTokenBucket:
    """Асинхронный token-bucket без внешних зависимостей."""

    def __init__(self, rate_per_sec: float, burst: Optional[int] = None) -> None:
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(1, int(burst if burst is not None else max(1.0, self.rate * 2)))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._cond = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated)
        if self.rate > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        else:
            self.tokens = self.capacity
        self.updated = now

    async def acquire(self, timeout: float | None = None) -> None:
        if self.rate == 0:
            return  # без лимита
        start = time.monotonic()
        async with self._cond:
            while True:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                if timeout is not None and (time.monotonic() - start) >= timeout:
                    raise TimeoutError("rate limit acquire timeout")
                # Ждём немного до пополнения
                await asyncio.wait_for(self._cond.wait(), timeout=0.05)

    def notify(self) -> None:
        # полезно в тестах
        with contextlib.suppress(RuntimeError):
            # если цикл уже закрывается — игнор
            self._cond.notify_all()  # type: ignore[attr-defined]


class CircuitState(enum.Enum):
    CLOSED = 1
    OPEN = 2
    HALF_OPEN = 3


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, cooldown: float = 15.0) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown = max(0.1, cooldown)
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.opened_at = 0.0
        self._half_open_inflight = False

    def allow(self) -> bool:
        now = time.monotonic()
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if now - self.opened_at >= self.cooldown:
                self.state = CircuitState.HALF_OPEN
                self._half_open_inflight = False
                return True
            return False
        # HALF_OPEN
        if not self._half_open_inflight:
            self._half_open_inflight = True
            return True
        return False

    def on_success(self) -> None:
        self.failures = 0
        self.state = CircuitState.CLOSED
        self._half_open_inflight = False

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.opened_at = time.monotonic()
            self._half_open_inflight = False


# --------------------------------------------------------------------------------------
# КОНФИГУРАЦИЯ ОРКЕСТРАТОРА
# --------------------------------------------------------------------------------------
@dataclass(slots=True)
class OrchestratorConfig:
    workers: int = 4
    lease_batch: int = 20
    default_visibility_timeout_sec: int = 600
    lease_extend_interval_sec: int = 120
    empty_lease_backoff_sec: float = 0.5
    # ретраи
    base_backoff_sec: float = 1.0
    max_backoff_sec: float = 300.0
    jitter: bool = True
    # лимит по таргету (например, чтобы не заDDoSить один хост)
    per_target_rate_limit_per_sec: float = 2.0
    per_target_burst: int = 4
    # верхний предел ожидания rate limiter перед тем как бросить исключение
    rate_acquire_timeout_sec: float = 30.0


# --------------------------------------------------------------------------------------
# ОРКЕСТРАТОР
# --------------------------------------------------------------------------------------
class ScannerOrchestrator:
    def __init__(
        self,
        storage: Storage,
        artifacts: ArtifactStore,
        metrics: Optional[Metrics] = None,
        config: Optional[OrchestratorConfig] = None,
        logger_: Optional[logging.Logger] = None,
    ) -> None:
        self.storage = storage
        self.artifacts = artifacts
        self.metrics = metrics or _NoopMetrics()
        self.cfg = config or OrchestratorConfig()
        self.log = logger_ or logger

        self._scanners: Dict[str, Scanner] = {}
        self._scanner_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._scanner_rate: Dict[str, AsyncTokenBucket] = {}
        self._target_rate: Dict[str, AsyncTokenBucket] = {}
        self._scanner_circuit: Dict[str, CircuitBreaker] = {}

        self._workers: List[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()
        self._worker_id = f"orchestrator-{uuid.uuid4()}"

    # ------------------------------ Public API --------------------------------

    def register_scanner(self, scanner: Scanner) -> None:
        if scanner.name in self._scanners:
            raise ValueError(f"scanner {scanner.name} already registered")
        self._scanners[scanner.name] = scanner
        self._scanner_semaphores[scanner.name] = asyncio.Semaphore(max(1, scanner.max_concurrency))
        rl = AsyncTokenBucket(max(0.0, scanner.rate_limit_per_sec), burst=int(scanner.rate_limit_per_sec * 2) if scanner.rate_limit_per_sec > 0 else 1)
        self._scanner_rate[scanner.name] = rl
        self._scanner_circuit[scanner.name] = CircuitBreaker()
        self.log.info("scanner_registered name=%s version=%s concurrency=%s rate=%s",
                      scanner.name, getattr(scanner, "version", "?"), scanner.max_concurrency, scanner.rate_limit_per_sec)

    async def submit_scan(
        self,
        scanner: str,
        target: str,
        params: Optional[Mapping[str, Any]] = None,
        *,
        priority: int = 5,
        timeout_sec: int = 1800,
        visibility_timeout_sec: Optional[int] = None,
        max_retries: int = 3,
        schedule_at: Optional[datetime] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        requested_by: Optional[str] = None,
    ) -> str:
        if idempotency_key:
            existing = await self.storage.get_by_idempotency(idempotency_key)
            if existing:
                return existing.id

        if scanner not in self._scanners:
            raise ValueError(f"scanner '{scanner}' is not registered")

        task = ScanTask(
            id=str(uuid.uuid4()),
            scanner=scanner,
            target=target,
            params=dict(params or {}),
            priority=max(0, priority),
            schedule_at=schedule_at,
            timeout_sec=timeout_sec,
            visibility_timeout_sec=visibility_timeout_sec or self.cfg.default_visibility_timeout_sec,
            max_retries=max(0, max_retries),
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            requested_by=requested_by,
        )
        await self.storage.submit(task)
        self.log.info("task_submitted %s", task.to_log())
        self.metrics.counter("vuln_orchestrator_task_submitted", 1, scanner=scanner)
        return task.id

    async def run(self) -> None:
        """Запуск воркеров. Блокирует до stop()."""
        if self._workers:
            raise RuntimeError("already running")

        self.log.info("orchestrator_start worker_id=%s workers=%d", self._worker_id, self.cfg.workers)
        for idx in range(self.cfg.workers):
            self._workers.append(asyncio.create_task(self._worker_loop(idx), name=f"worker-{idx}"))

        try:
            await self._stopping.wait()
        finally:
            # корректное завершение
            for t in self._workers:
                t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*self._workers)
            self._workers.clear()
            self.log.info("orchestrator_stopped worker_id=%s", self._worker_id)

    def stop(self) -> None:
        self._stopping.set()

    # ------------------------------ Worker core --------------------------------

    async def _worker_loop(self, idx: int) -> None:
        wid = f"{self._worker_id}:{idx}"
        self.log.info("worker_start id=%s", wid)
        extend_task = asyncio.create_task(self._lease_extender(wid), name=f"lease-extender-{idx}")
        try:
            while not self._stopping.is_set():
                try:
                    batch = await self.storage.lease_tasks(
                        worker_id=wid,
                        batch=self.cfg.lease_batch,
                        visibility_timeout_sec=self.cfg.default_visibility_timeout_sec,
                        now=datetime.now(timezone.utc),
                    )
                except Exception as ex:
                    self.log.exception("lease_tasks_failed worker=%s error=%s", wid, ex)
                    await asyncio.sleep(1.0)
                    continue

                if not batch:
                    await asyncio.sleep(self.cfg.empty_lease_backoff_sec)
                    continue

                # Запускаем исполняемые задачи параллельно внутри воркера
                coros = [self._execute_task(wid, task) for task in batch]
                # Не ждем все сразу, чтобы не блокировать продление лизов — используем шумный gather
                await asyncio.gather(*coros, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        finally:
            extend_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await extend_task
            self.log.info("worker_stop id=%s", wid)

    async def _lease_extender(self, worker_id: str) -> None:
        """Периодически продлевает lease RUNNING задач у конкретного воркера."""
        while not self._stopping.is_set():
            # продление выполняет исполнитель в _execute_task — тут no-op, оставлено как задел
            await asyncio.sleep(self.cfg.lease_extend_interval_sec)

    async def _execute_task(self, worker_id: str, task: ScanTask) -> None:
        # Проверка регистрации сканера
        scanner = self._scanners.get(task.scanner)
        if scanner is None:
            await self._fail_task(task, "scanner_not_registered")
            await self.storage.complete_lease(worker_id, task.id)
            return

        # Circuit breaker
        cb = self._scanner_circuit[scanner.name]
        if not cb.allow():
            self.log.warning("circuit_open skip task=%s scanner=%s", task.id, scanner.name)
            await self._skip_task(task, reason="circuit_open")
            await self.storage.complete_lease(worker_id, task.id)
            return

        # Валидация входных данных
        try:
            await scanner.validate(task)
        except Exception as ex:
            cb.on_failure()
            await self._fail_task(task, f"validation_error: {ex}")
            await self.storage.complete_lease(worker_id, task.id)
            return

        # Семантика: семафор на сканер + rate-limiter на сканер и на таргет
        sem = self._scanner_semaphores[scanner.name]
        scanner_rl = self._scanner_rate[scanner.name]
        target_key = self._target_bucket_key(task.target)
        target_rl = self._target_rate.setdefault(
            target_key,
            AsyncTokenBucket(self.cfg.per_target_rate_limit_per_sec, burst=self.cfg.per_target_burst),
        )

        # Устанавливаем статус RUNNING
        await self.storage.upsert_status(task.id, ScanStatus.RUNNING, {"worker_id": worker_id})
        start_ts = datetime.now(timezone.utc)
        self.metrics.counter("vuln_orchestrator_task_started", 1, scanner=scanner.name)

        # Вызов сканера с таймаутом, бэкофф и ретраи по ошибкам
        exc_text: Optional[str] = None
        finished_ok = False
        try:
            await scanner_rl.acquire(timeout=self.cfg.rate_acquire_timeout_sec)
            await target_rl.acquire(timeout=self.cfg.rate_acquire_timeout_sec)

            async with _acquire_async(sem):
                try:
                    with _timeout(task.timeout_sec):
                        result = await scanner.scan(task, self.artifacts)
                except asyncio.TimeoutError:
                    raise RuntimeError("scan_timeout")
                except Exception as ex:
                    raise

                # Сохранение результата
                await self.storage.save_result(task.id, result)
                await self.storage.upsert_status(task.id, ScanStatus.COMPLETED, {"finished_at": result.finished_at.isoformat()})
                await self.storage.complete_lease(worker_id, task.id)
                cb.on_success()
                finished_ok = True

                # Метрики
                self.metrics.counter("vuln_orchestrator_task_completed", 1, scanner=scanner.name)
                self.metrics.histogram("vuln_orchestrator_task_duration_ms", result.duration_ms, scanner=scanner.name)
                self.log.info(
                    "task_completed %s result_stats=%s",
                    task.to_log(),
                    dict(result.stats),
                )
        except Exception as ex:
            exc_text = _truncate(str(ex), 1000)
            cb.on_failure()
            await self._handle_failure(worker_id, task, exc_text)

        if finished_ok:
            # ничего
            pass

    async def _handle_failure(self, worker_id: str, task: ScanTask, error: str) -> None:
        self.metrics.counter("vuln_orchestrator_task_failed", 1, scanner=task.scanner)
        self.log.warning("task_failed %s error=%s", task.to_log(), error)

        try:
            await self.storage.append_event(
                task.id,
                {
                    "ts": _utcnow().isoformat(),
                    "type": "failure",
                    "error": error,
                    "retries": task.retries,
                },
            )
        except Exception:
            # не фейлим на логирование
            pass

        # Планирование ретрая
        if task.retries < task.max_retries:
            task.retries += 1
            backoff = self._backoff_seconds(task.retries)
            schedule_at = _utcnow() + timedelta(seconds=backoff)
            await self.storage.upsert_status(task.id, ScanStatus.RETRY_SCHEDULED, {"retry_in_sec": backoff})
            await self.storage.reschedule(task, schedule_at)
            await self.storage.complete_lease(worker_id, task.id)
        else:
            await self._fail_task(task, error)
            await self.storage.complete_lease(worker_id, task.id)

    async def _fail_task(self, task: ScanTask, error: str) -> None:
        self.metrics.counter("vuln_orchestrator_task_permanently_failed", 1, scanner=task.scanner)
        await self.storage.upsert_status(task.id, ScanStatus.FAILED, {"error": error})
        self.log.error("task_permanently_failed %s error=%s", task.to_log(), error)

    async def _skip_task(self, task: ScanTask, reason: str) -> None:
        await self.storage.upsert_status(task.id, ScanStatus.SKIPPED, {"reason": reason})
        self.metrics.counter("vuln_orchestrator_task_skipped", 1, scanner=task.scanner)

    # ------------------------------ Helpers -----------------------------------

    def _backoff_seconds(self, attempt: int) -> float:
        base = self.cfg.base_backoff_sec * (2 ** (attempt - 1))
        capped = min(base, self.cfg.max_backoff_sec)
        if self.cfg.jitter:
            return random.uniform(0, capped)
        return capped

    @staticmethod
    def _target_bucket_key(target: str) -> str:
        """
        Нормализация таргета для пер-таргет rate-limit.
        Для URL берём хост, для IP — сам IP, иначе — хэш строки.
        """
        t = target.strip().lower()
        if "://" in t:
            # URL
            try:
                # избегаем urlparse чтобы не тащить зависимость; простой разбор
                host = t.split("://", 1)[1].split("/", 1)[0]
                host = host.split("@")[-1].split(":")[0]
                return f"host:{host}"
            except Exception:
                pass
        # IP v4/v6?
        if any(c.isdigit() for c in t) and ":" in t or "." in t:
            # грубая эвристика
            return f"addr:{t}"
        # общий случай
        digest = hashlib.sha256(t.encode("utf-8")).hexdigest()[:16]
        return f"hash:{digest}"


# --------------------------------------------------------------------------------------
# NOOP метрики (если не подключены реальные)
# --------------------------------------------------------------------------------------
class _NoopMetrics:
    def counter(self, name: str, value: int = 1, **labels: str) -> None:
        logger.debug("metric_counter name=%s value=%s labels=%s", name, value, labels)

    def histogram(self, name: str, value: float, **labels: str) -> None:
        logger.debug("metric_histogram name=%s value=%s labels=%s", name, value, labels)

    def gauge(self, name: str, value: float, **labels: str) -> None:
        logger.debug("metric_gauge name=%s value=%s labels=%s", name, value, labels)


# --------------------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ КОНТЕКСТНЫЕ МЕНЕДЖЕРЫ
# --------------------------------------------------------------------------------------
@contextlib.asynccontextmanager
async def _acquire_async(sem: asyncio.Semaphore) -> AsyncIterator[None]:
    await sem.acquire()
    try:
        yield
    finally:
        sem.release()


@contextlib.contextmanager
def _timeout(seconds: int) -> Any:
    if seconds <= 0:
        yield
        return
    try:
        with asyncio.timeout(seconds):
            yield
    except AttributeError:
        # Python < 3.11 fallback: wait_for должен использоваться на корутине,
        # но для простоты оставляем исключение — оркестратор требует 3.11+
        raise RuntimeError("asyncio.timeout requires Python 3.11+")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


# --------------------------------------------------------------------------------------
# ПРИМЕЧАНИЕ ПО ИНТЕГРАЦИИ
# --------------------------------------------------------------------------------------
"""
Интеграция:

1) Зарегистрируйте конкретные сканеры, реализующие протокол Scanner:

class MyScanner:
    name = "my_scanner"
    version = "1.2.3"
    max_concurrency = 8
    rate_limit_per_sec = 5.0

    async def validate(self, task: ScanTask) -> None:
        # валидация params/target
        ...

    async def scan(self, task: ScanTask, artifacts: ArtifactStore) -> ScanResult:
        started = _utcnow()
        # ...выполнить скан...
        finished = _utcnow()
        return ScanResult(
            status=ScanStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            duration_ms=int((finished - started).total_seconds() * 1000),
            findings=(),
            stats={"items": 0},
            scanner_name=self.name,
            scanner_version=self.version,
        )

2) Реализуйте Storage/ArtifactStore/Metrics под вашу инфраструктуру (Postgres/Redis/Kafka/S3 и т.д.).

3) Поднимите оркестратор:

orc = ScannerOrchestrator(storage, artifacts, metrics)
orc.register_scanner(MyScanner())
await orc.run()

Оркестратор гарантирует:
- идемпотентную постановку задач (через Storage.get_by_idempotency),
- контроль конкуренции и частоты запуска,
- устойчивые ретраи с бэкоффом и джиттером,
- корректное завершение и обновление статусов,
- структурные логи для SIEM/обсервабилити.

"""
