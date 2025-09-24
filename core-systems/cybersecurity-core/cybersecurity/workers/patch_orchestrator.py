# cybersecurity-core/cybersecurity/workers/patch_orchestrator.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, time as dtime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - optional
    httpx = None  # type: ignore

from pydantic import BaseModel, Field, HttpUrl, ValidationError, ConfigDict

logger = logging.getLogger(__name__)

__all__ = [
    # Contracts
    "Severity",
    "PatchState",
    "PatchPlatform",
    "PatchTarget",
    "PatchPackage",
    "RolloutPolicy",
    "MaintenanceWindow",
    "PatchPlanItem",
    "PatchPlan",
    "PatchJobSpec",
    "PatchJob",
    "PatchResult",
    "OrchestratorConfig",
    # Providers
    "PatchProvider",
    "HttpPatchProvider",
    "InMemoryPatchProvider",
    # Orchestrator
    "PatchOrchestrator",
]

# =============================================================================
# Utilities
# =============================================================================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _uuid7() -> str:
    try:
        return str(uuid.uuid7())
    except AttributeError:
        return str(uuid.uuid4())


class _TokenBucket:
    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self.rate = max(0.001, rate)
        self.capacity = capacity if capacity and capacity > 0 else max(1.0, self.rate * 2)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                await asyncio.sleep((tokens - self.tokens) / self.rate)


class _CBState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.state = _CBState.CLOSED
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def allow(self) -> None:
        async with self._lock:
            if self.state == _CBState.OPEN:
                assert self.opened_at is not None
                if time.monotonic() - self.opened_at >= self.reset_timeout:
                    self.state = _CBState.HALF_OPEN
                else:
                    raise RuntimeError("circuit_open")

    async def success(self) -> None:
        async with self._lock:
            self.failures = 0
            self.state = _CBState.CLOSED
            self.opened_at = None

    async def failure(self) -> None:
        async with self._lock:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.state = _CBState.OPEN
                self.opened_at = time.monotonic()


async def _retry_async(
    op,
    *,
    retries: int,
    base_delay: float,
    max_delay: float,
    jitter: float = 0.2,
    retry_on: Tuple[type, ...] = (Exception,),
):
    attempt = 0
    while True:
        try:
            return await op()
        except retry_on:
            attempt += 1
            if attempt > retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = delay * (1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(0.001, delay))


# =============================================================================
# Domain contracts
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PatchState(str, Enum):
    DISCOVER = "DISCOVER"
    PLAN = "PLAN"
    DRY_RUN = "DRY_RUN"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    ROLLBACK = "ROLLBACK"
    CANCELED = "CANCELED"


class PatchPlatform(str, Enum):
    LINUX = "LINUX"
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    CONTAINER = "CONTAINER"
    KUBERNETES = "KUBERNETES"
    NETWORK = "NETWORK"
    OTHER = "OTHER"


class PatchTarget(BaseModel):
    """
    Целевой объект патча: сервер/узел/ПО.
    """
    model_config = ConfigDict(extra="allow")

    asset_id: str = Field(..., description="Уникальный идентификатор актива/хоста")
    hostname: Optional[str] = None
    platform: PatchPlatform = PatchPlatform.OTHER
    ip: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    maintenance_group: Optional[str] = Field(default=None, description="Группа обслуживания/окно")


class PatchPackage(BaseModel):
    """
    Пакет обновлений/патч: CVE/KB/версия/репо.
    """
    model_config = ConfigDict(extra="allow")

    name: str = Field(..., description="Например, 'openssl'")
    version: Optional[str] = Field(default=None, description="Целевая версия/билд")
    cves: List[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    repo: Optional[str] = None
    reboot_required: bool = False


class RolloutPolicy(BaseModel):
    """
    Правила выката: размер батча, параллелизм, паузы, авто-rollback.
    """
    batch_size: int = Field(default=10, ge=1, le=1000)
    max_parallel: int = Field(default=10, ge=1, le=1000)
    pause_between_batches_sec: float = Field(default=5.0, ge=0.0, le=3600.0)
    stop_on_first_failure: bool = False
    auto_rollback_on_failure: bool = True


class MaintenanceWindow(BaseModel):
    """
    Простые maintenance-окна по дням недели и времени (UTC).
    """
    # Список дней недели [0..6], где 0=Пн
    weekdays: List[int] = Field(default_factory=lambda: [5, 6])  # по умолчанию Sat/Sun
    start: dtime = Field(default=dtime(0, 0))
    end: dtime = Field(default=dtime(23, 59))
    tz_offset_minutes: int = Field(default=0, description="Смещение минут от UTC, если нужно локальное окно")

    def allows_now(self, group: Optional[str] = None, now: Optional[datetime] = None) -> bool:
        n = now or _now()
        # переводим now с учетом tz_offset
        n_loc = n + timedelta(minutes=self.tz_offset_minutes)
        wd = n_loc.weekday()
        if wd not in self.weekdays:
            return False
        t = n_loc.timetz()
        # нормализуем naive для сравнения
        tt = dtime(hour=t.hour, minute=t.minute, second=t.second)
        return self.start <= tt <= self.end


class PatchPlanItem(BaseModel):
    target: PatchTarget
    package: PatchPackage
    idempotency_key: str = Field(..., description="Стабильный ключ операции на target+package")
    planned: bool = True
    executed: bool = False
    verified: bool = False
    failed: bool = False
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class PatchPlan(BaseModel):
    items: List[PatchPlanItem] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)
    batches: List[List[str]] = Field(default_factory=list, description="Списки idempotency_key по батчам")


class PatchJobSpec(BaseModel):
    """
    Задание оркестрации патча.
    """
    model_config = ConfigDict(extra="allow")

    job_id: str = Field(default_factory=_uuid7)
    title: str
    description: Optional[str] = None
    targets: List[PatchTarget]
    package: PatchPackage
    rollout: RolloutPolicy = Field(default_factory=RolloutPolicy)
    maintenance: MaintenanceWindow = Field(default_factory=MaintenanceWindow)
    dry_run: bool = False
    correlation_id: Optional[str] = None
    created_at: datetime = Field(default_factory=_now)


class PatchResult(BaseModel):
    total: int
    succeeded: int
    failed: int
    verified: int
    duration_sec: float
    details: Dict[str, Any] = Field(default_factory=dict)


class PatchJob(BaseModel):
    spec: PatchJobSpec
    state: PatchState = PatchState.DISCOVER
    plan: Optional[PatchPlan] = None
    result: Optional[PatchResult] = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    canceled: bool = False
    error: Optional[str] = None


class OrchestratorConfig(BaseModel):
    rate_limit_per_sec: float = 20.0
    concurrent_jobs: int = 8
    concurrent_targets: int = 32
    retries: int = 3
    backoff_base: float = 0.2
    backoff_max: float = 2.5
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    metrics_enabled: bool = True


# =============================================================================
# Providers
# =============================================================================

class PatchProvider(abc.ABC):
    """
    Абстракция взаимодействия с реальной системой патчей.
    """

    @abc.abstractmethod
    async def prepare(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        """Пре-чек: совместимость, зависимостии, достаточность места и т.п."""
        raise NotImplementedError

    @abc.abstractmethod
    async def apply(self, target: PatchTarget, package: PatchPackage, *, idempotency_key: str) -> Dict[str, Any]:
        """Применение патча на целевом хосте (идемпотентно)."""
        raise NotImplementedError

    @abc.abstractmethod
    async def verify(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        """Проверка версии/сигнатур/агента после применения."""
        raise NotImplementedError

    @abc.abstractmethod
    async def rollback(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        """Откат патча (если поддерживается)."""
        raise NotImplementedError

    @abc.abstractmethod
    async def health(self) -> Dict[str, Any]:
        raise NotImplementedError


class HttpPatchProvider(PatchProvider):
    """
    HTTP-провайдер к внешнему сервису патч-менеджмента.
    Контракты REST (пример):
      POST /v1/patch/prepare
      POST /v1/patch/apply
      POST /v1/patch/verify
      POST /v1/patch/rollback
      GET  /v1/patch/health
    """
    def __init__(self, base_url: HttpUrl, *, token_env: Optional[str] = "PATCH_TOKEN", verify_ssl: bool = True, timeout: float = 30.0) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for HttpPatchProvider")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        tok = os.getenv(token_env) if token_env else None
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        self._client = httpx.AsyncClient(base_url=str(base_url), headers=headers, timeout=timeout, verify=verify_ssl)

    async def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        r = await self._client.post(path, json=payload)
        if r.status_code >= 400:
            raise RuntimeError(f"http_{r.status_code}:{r.text[:200]}")
        try:
            return r.json() or {}
        except Exception:
            return {}

    async def prepare(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        return await self._post("/v1/patch/prepare", {"target": target.model_dump(), "package": package.model_dump()})

    async def apply(self, target: PatchTarget, package: PatchPackage, *, idempotency_key: str) -> Dict[str, Any]:
        return await self._post("/v1/patch/apply", {"target": target.model_dump(), "package": package.model_dump(), "idempotency_key": idempotency_key})

    async def verify(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        return await self._post("/v1/patch/verify", {"target": target.model_dump(), "package": package.model_dump()})

    async def rollback(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        return await self._post("/v1/patch/rollback", {"target": target.model_dump(), "package": package.model_dump()})

    async def health(self) -> Dict[str, Any]:
        try:
            r = await self._client.get("/v1/patch/health")
            return r.json() if r.status_code == 200 else {"ok": False, "code": r.status_code}
        except Exception as e:  # pragma: no cover - network dependent
            return {"ok": False, "error": str(e)}

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._client.aclose()


class InMemoryPatchProvider(PatchProvider):
    """
    Локальный провайдер для тестов и разработки.
    """
    def __init__(self, success_rate: float = 0.9) -> None:
        self.success_rate = max(0.0, min(1.0, success_rate))

    async def prepare(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        # Эмулируем быстрый пре-чек
        await asyncio.sleep(0.005)
        return {"ok": True, "target": target.asset_id, "package": package.name}

    async def apply(self, target: PatchTarget, package: PatchPackage, *, idempotency_key: str) -> Dict[str, Any]:
        await asyncio.sleep(0.02)
        ok = random.random() <= self.success_rate
        if not ok:
            raise RuntimeError("apply_failed")
        return {"ok": True, "idempotency_key": idempotency_key}

    async def verify(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        return {"ok": True, "version": package.version or "unknown"}

    async def rollback(self, target: PatchTarget, package: PatchPackage) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        return {"ok": True, "rolled_back": True}

    async def health(self) -> Dict[str, Any]:
        return {"ok": True, "inmemory": True}


# =============================================================================
# Orchestrator
# =============================================================================

@dataclass
class _QueueItem:
    job: PatchJob
    enqueued_at: datetime


class _InMemoryQueue:
    def __init__(self) -> None:
        self._q: asyncio.Queue[_QueueItem] = asyncio.Queue()

    async def put(self, job: PatchJob) -> None:
        await self._q.put(_QueueItem(job=job, enqueued_at=_now()))

    async def get(self) -> _QueueItem:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()


class PatchOrchestrator:
    """
    Асинхронный оркестратор патчей:
      - планирование батчей
      - соблюдение maintenance-окон
      - идемпотентное применение патчей
      - verify и auto-rollback
      - отмена и остановка
      - метрики и структурированное логирование
    """

    def __init__(self, provider: PatchProvider, cfg: OrchestratorConfig = OrchestratorConfig()) -> None:
        self.cfg = cfg
        self.provider = provider
        self._queue = _InMemoryQueue()
        self._jobs: Dict[str, PatchJob] = {}
        self._stop = asyncio.Event()
        self._job_sem = asyncio.Semaphore(cfg.concurrent_jobs)
        self._target_sem = asyncio.Semaphore(cfg.concurrent_targets)
        self._rate = _TokenBucket(rate=cfg.rate_limit_per_sec)
        self._cb = CircuitBreaker()
        self._metrics: Dict[str, float] = {}

    # ---------------- Public API ----------------

    async def submit_job(self, spec: PatchJobSpec) -> PatchJob:
        spec.correlation_id = spec.correlation_id or _uuid7()
        job = PatchJob(spec=spec)
        self._jobs[spec.job_id] = job
        await self._queue.put(job)
        logger.info("patch.job_submitted", extra={"job_id": spec.job_id, "targets": len(spec.targets), "pkg": spec.package.name})
        return job

    def get_job(self, job_id: str) -> Optional[PatchJob]:
        return self._jobs.get(job_id)

    async def cancel_job(self, job_id: str) -> bool:
        j = self._jobs.get(job_id)
        if not j:
            return False
        j.canceled = True
        j.state = PatchState.CANCELED
        j.updated_at = _now()
        logger.info("patch.job_canceled", extra={"job_id": job_id})
        return True

    async def run_forever(self) -> None:
        logger.info("patch.orchestrator_start")
        while not self._stop.is_set():
            item = await self._queue.get()
            try:
                await self._job_sem.acquire()
                asyncio.create_task(self._run_job(item.job))
            finally:
                self._queue.task_done()

    async def stop(self) -> None:
        self._stop.set()

    # ---------------- Internals ----------------

    async def _run_job(self, job: PatchJob) -> None:
        t0 = time.monotonic()
        try:
            await self._rate.acquire()
            await self._cb.allow()
            await _retry_async(
                lambda: self._process_job(job),
                retries=self.cfg.retries,
                base_delay=self.cfg.backoff_base,
                max_delay=self.cfg.backoff_max,
                retry_on=(RuntimeError,),
            )
            await self._cb.success()
        except Exception as e:
            await self._cb.failure()
            job.state = PatchState.FAILED
            job.error = str(e)
            job.updated_at = _now()
            logger.exception("patch.job_failed", extra={"job_id": job.spec.job_id, "error": str(e)})
        finally:
            self._job_sem.release()
            self._metrics["last_job_duration_sec"] = time.monotonic() - t0

    async def _process_job(self, job: PatchJob) -> None:
        if job.canceled:
            job.state = PatchState.CANCELED
            job.updated_at = _now()
            return

        # DISCOVER
        job.state = PatchState.DISCOVER
        job.updated_at = _now()
        # Простейшие пре-чеки по всем таргетам
        await self._prepare_targets(job)
        if job.canceled:
            job.state = PatchState.CANCELED
            return

        # PLAN
        job.state = PatchState.PLAN
        job.plan = self._build_plan(job.spec.targets, job.spec.package, job.spec.rollout.batch_size)
        job.updated_at = _now()

        if job.spec.dry_run:
            job.state = PatchState.DRY_RUN
            await asyncio.sleep(0)  # точка планировщика
            # Ничего не выполняем — только план
            job.result = PatchResult(
                total=len(job.plan.items),
                succeeded=0,
                failed=0,
                verified=0,
                duration_sec=0.0,
                details={"dry_run": True, "batches": job.plan.batches},
            )
            job.state = PatchState.COMPLETE
            job.updated_at = _now()
            logger.info("patch.job_complete_dry_run", extra={"job_id": job.spec.job_id, "batches": len(job.plan.batches)})
            return

        # EXECUTE (respect maintenance window)
        job.state = PatchState.EXECUTE
        await self._execute_batches(job)
        if job.canceled:
            job.state = PatchState.CANCELED
            job.updated_at = _now()
            return

        # VERIFY
        job.state = PatchState.VERIFY
        succ, fail, ver = self._collect_result(job)
        job.result = PatchResult(
            total=len(job.plan.items),
            succeeded=succ,
            failed=fail,
            verified=ver,
            duration_sec=self._metrics.get("last_job_duration_sec", 0.0),
            details={"batches": job.plan.batches},
        )
        job.updated_at = _now()

        # COMPLETE / FAILED
        job.state = PatchState.COMPLETE if fail == 0 else PatchState.FAILED
        logger.info("patch.job_finished", extra={"job_id": job.spec.job_id, "state": job.state, "succ": succ, "fail": fail, "verified": ver})

    async def _prepare_targets(self, job: PatchJob) -> None:
        # Параллельные пре-чеки с ограничением по concurrency
        async def _prep(t: PatchTarget) -> None:
            if job.canceled:
                return
            async with self._target_sem:
                try:
                    await _retry_async(
                        lambda: self.provider.prepare(t, job.spec.package),
                        retries=self.cfg.retries,
                        base_delay=self.cfg.backoff_base,
                        max_delay=self.cfg.backoff_max,
                        retry_on=(Exception,),
                    )
                    logger.info("patch.prepare_ok", extra={"job_id": job.spec.job_id, "asset": t.asset_id})
                except Exception as e:
                    logger.warning("patch.prepare_failed", extra={"job_id": job.spec.job_id, "asset": t.asset_id, "error": str(e)})

        await asyncio.gather(*[_prep(t) for t in job.spec.targets])

    def _build_plan(self, targets: List[PatchTarget], pkg: PatchPackage, batch_size: int) -> PatchPlan:
        items: List[PatchPlanItem] = []
        for t in targets:
            idk = hashlib.sha256(
                json.dumps({"a": t.asset_id, "p": pkg.name, "v": pkg.version}, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            items.append(
                PatchPlanItem(
                    target=t,
                    package=pkg,
                    idempotency_key=idk,
                )
            )
        # формируем батчи
        batches: List[List[str]] = []
        cur: List[str] = []
        for it in items:
            cur.append(it.idempotency_key)
            if len(cur) >= batch_size:
                batches.append(cur)
                cur = []
        if cur:
            batches.append(cur)

        return PatchPlan(items=items, batches=batches)

    async def _execute_batches(self, job: PatchJob) -> None:
        assert job.plan is not None
        for i, batch in enumerate(job.plan.batches, start=1):
            # maintenance window
            while not job.spec.maintenance.allows_now(job.spec.targets[0].maintenance_group if job.spec.targets else None):
                logger.info("patch.wait_maintenance", extra={"job_id": job.spec.job_id, "batch": i})
                await asyncio.sleep(5.0)
                if job.canceled:
                    return

            logger.info("patch.batch_start", extra={"job_id": job.spec.job_id, "batch": i, "size": len(batch)})
            # запускаем применения в пределах max_parallel
            sem = asyncio.Semaphore(job.spec.rollout.max_parallel)

            async def _apply_item(it: PatchPlanItem) -> None:
                if job.canceled:
                    return
                async with sem:
                    it.started_at = _now()
                    try:
                        await _retry_async(
                            lambda: self.provider.apply(it.target, it.package, idempotency_key=it.idempotency_key),
                            retries=self.cfg.retries,
                            base_delay=self.cfg.backoff_base,
                            max_delay=self.cfg.backoff_max,
                            retry_on=(Exception,),
                        )
                        it.executed = True
                        # verify
                        v = await _retry_async(
                            lambda: self.provider.verify(it.target, it.package),
                            retries=self.cfg.retries,
                            base_delay=self.cfg.backoff_base,
                            max_delay=self.cfg.backoff_max,
                            retry_on=(Exception,),
                        )
                        if v.get("ok", True):
                            it.verified = True
                        it.finished_at = _now()
                        logger.info("patch.apply_ok", extra={"job_id": job.spec.job_id, "asset": it.target.asset_id})
                    except Exception as e:
                        it.failed = True
                        it.error = str(e)
                        it.finished_at = _now()
                        logger.warning("patch.apply_failed", extra={"job_id": job.spec.job_id, "asset": it.target.asset_id, "error": str(e)})
                        if job.spec.rollout.auto_rollback_on_failure:
                            with contextlib.suppress(Exception):
                                rb = await self.provider.rollback(it.target, it.package)
                                logger.info("patch.rollback", extra={"job_id": job.spec.job_id, "asset": it.target.asset_id, "ok": rb.get("ok", True)})

            # отбираем элементы текущего батча
            key_to_item = {it.idempotency_key: it for it in job.plan.items}
            tasks = [_apply_item(key_to_item[k]) for k in batch if k in key_to_item]
            await asyncio.gather(*tasks)

            # если stop_on_first_failure — прекращаем после первого неуспешного в батче
            if job.spec.rollout.stop_on_first_failure:
                if any(key_to_item[k].failed for k in batch if k in key_to_item):
                    logger.warning("patch.stop_on_failure", extra={"job_id": job.spec.job_id, "batch": i})
                    break

            # пауза между батчами
            if i < len(job.plan.batches) and job.spec.rollout.pause_between_batches_sec > 0:
                await asyncio.sleep(job.spec.rollout.pause_between_batches_sec)

    def _collect_result(self, job: PatchJob) -> Tuple[int, int, int]:
        assert job.plan is not None
        succ = sum(1 for it in job.plan.items if it.executed and not it.failed)
        fail = sum(1 for it in job.plan.items if it.failed)
        ver = sum(1 for it in job.plan.items if it.verified)
        return succ, fail, ver


# =============================================================================
# Self-test (optional)
# =============================================================================

async def _selftest() -> None:  # pragma: no cover - utility
    logging.basicConfig(level=logging.INFO)
    provider = InMemoryPatchProvider(success_rate=0.92)
    orch = PatchOrchestrator(provider)

    targets = [
        PatchTarget(asset_id=f"srv-{i:02d}", hostname=f"srv-{i:02d}.prod", platform=PatchPlatform.LINUX, maintenance_group="prod")
        for i in range(1, 25)
    ]
    pkg = PatchPackage(name="openssl", version="3.0.14-1", cves=["CVE-2024-1234"], severity=Severity.HIGH, reboot_required=False)
    spec = PatchJobSpec(
        title="Security update OpenSSL",
        description="Critical OpenSSL patch roll-out",
        targets=targets,
        package=pkg,
        rollout=RolloutPolicy(batch_size=6, max_parallel=4, pause_between_batches_sec=0.2, stop_on_first_failure=False, auto_rollback_on_failure=True),
        maintenance=MaintenanceWindow(weekdays=[_now().weekday()], start=dtime(0, 0), end=dtime(23, 59)),
        dry_run=False,
    )

    await orch.submit_job(spec)
    # Запускаем единичную обработку очереди: один job
    async def _runner():
        item = await orch._queue.get()
        try:
            await orch._run_job(item.job)
        finally:
            orch._queue.task_done()

    await _runner()
    job = orch.get_job(spec.job_id)
    if job:
        logger.info("selftest.result", extra={"job_id": job.spec.job_id, "state": job.state, "result": job.result.model_dump() if job.result else None})

if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_selftest())
