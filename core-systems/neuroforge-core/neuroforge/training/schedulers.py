# neuroforge-core/neuroforge/training/schedulers.py
from __future__ import annotations

import asyncio
import enum
import heapq
import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

log = logging.getLogger("neuroforge.training.schedulers")


# =========================
# Модель ресурсов и задач
# =========================

@dataclass(frozen=True)
class Resources:
    cpu_milli: int
    memory_mib: int
    gpu_count: int = 0
    gpu_type: Optional[str] = None

    def fits(self, other: "Resources") -> bool:
        """Проверка: self (требуемые) помещаются в other (доступные)."""
        if self.cpu_milli > other.cpu_milli:
            return False
        if self.memory_mib > other.memory_mib:
            return False
        if self.gpu_count > other.gpu_count:
            return False
        if self.gpu_count > 0 and self.gpu_type and other.gpu_type and self.gpu_type != other.gpu_type:
            return False
        return True

    def __sub__(self, other: "Resources") -> "Resources":
        return Resources(
            cpu_milli=max(0, self.cpu_milli - other.cpu_milli),
            memory_mib=max(0, self.memory_mib - other.memory_mib),
            gpu_count=max(0, self.gpu_count - other.gpu_count),
            gpu_type=self.gpu_type if self.gpu_type == other.gpu_type else self.gpu_type,
        )

    def __add__(self, other: "Resources") -> "Resources":
        # gpu_type оставляем как у self, если совместимы, иначе None
        gt = self.gpu_type if (self.gpu_type == other.gpu_type or other.gpu_type is None) else None
        return Resources(
            cpu_milli=self.cpu_milli + other.cpu_milli,
            memory_mib=self.memory_mib + other.memory_mib,
            gpu_count=self.gpu_count + other.gpu_count,
            gpu_type=gt,
        )


class Priority(enum.IntEnum):
    LOW = 10
    NORMAL = 20
    HIGH = 30
    URGENT = 40


class JobState(enum.Enum):
    QUEUED = "QUEUED"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class Job:
    job_id: str
    tenant: str
    priority: Priority
    resources: Resources
    submitted_at: float
    deadline_ts: Optional[float] = None  # epoch seconds
    preemptible: bool = True
    annotations: Dict[str, str] = field(default_factory=dict)

    # Служебные поля планировщика
    state: JobState = JobState.QUEUED
    backoff_attempts: int = 0
    backoff_until: float = 0.0   # epoch seconds
    leased_to: Optional[str] = None
    lease_id: Optional[str] = None
    lease_expires_at: float = 0.0

    def is_eligible(self, now: float) -> bool:
        if self.state != JobState.QUEUED:
            return False
        if self.backoff_until and now < self.backoff_until:
            return False
        if self.deadline_ts and now > self.deadline_ts:
            return False
        return True


# =========================
# Протоколы интеграции
# =========================

class ResourceProvider(Protocol):
    async def cluster_capacity(self) -> Resources:
        """Общая вместимость кластера (для fairness и преэмпции)."""
        ...

    async def available_capacity(self) -> Resources:
        """Текущие свободные ресурсы (для принятия решения)."""
        ...


class JobStore(Protocol):
    async def put(self, job: Job) -> None: ...
    async def get(self, job_id: str) -> Optional[Job]: ...
    async def update(self, job: Job) -> None: ...
    async def delete(self, job_id: str) -> None: ...
    async def list_queued(self) -> List[Job]: ...
    async def list_running(self) -> List[Job]: ...


class MetricsSink(Protocol):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None: ...
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None: ...


class NoopMetrics(MetricsSink):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None:
        pass
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None:
        pass


# =========================
# Исключения и утилиты
# =========================

class LeaseError(RuntimeError):
    pass


def _now() -> float:
    return time.time()


def _exp_backoff(attempts: int, base: float = 2.0, cap: float = 60.0, jitter: float = 0.8) -> float:
    exp = min(cap, base * (2 ** max(0, attempts - 1)))
    return random.uniform(exp * (1 - jitter), exp)


# =========================
# In-memory реализации
# =========================

class InMemoryResourceProvider(ResourceProvider):
    """Простая реализация трекера ресурсов, учитывающая занятость запущенных задач."""
    def __init__(self, capacity: Resources) -> None:
        self._capacity = capacity
        self._used = Resources(0, 0, 0)
        self._lock = asyncio.Lock()

    async def cluster_capacity(self) -> Resources:
        return self._capacity

    async def available_capacity(self) -> Resources:
        async with self._lock:
            return self._capacity - self._used

    async def allocate(self, r: Resources) -> bool:
        async with self._lock:
            if r.fits(self._capacity - self._used):
                self._used = self._used + r
                return True
            return False

    async def release(self, r: Resources) -> None:
        async with self._lock:
            # гарантируем невырождение ниже нуля
            self._used = Resources(
                cpu_milli=max(0, self._used.cpu_milli - r.cpu_milli),
                memory_mib=max(0, self._used.memory_mib - r.memory_mib),
                gpu_count=max(0, self._used.gpu_count - r.gpu_count),
                gpu_type=self._used.gpu_type,
            )


class InMemoryJobStore(JobStore):
    def __init__(self) -> None:
        self._data: Dict[str, Job] = {}
        self._lock = asyncio.Lock()

    async def put(self, job: Job) -> None:
        async with self._lock:
            self._data[job.job_id] = job

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._lock:
            j = self._data.get(job_id)
            return None if j is None else j

    async def update(self, job: Job) -> None:
        async with self._lock:
            if job.job_id in self._data:
                self._data[job.job_id] = job

    async def delete(self, job_id: str) -> None:
        async with self._lock:
            self._data.pop(job_id, None)

    async def list_queued(self) -> List[Job]:
        async with self._lock:
            return [j for j in self._data.values() if j.state == JobState.QUEUED]

    async def list_running(self) -> List[Job]:
        async with self._lock:
            return [j for j in self._data.values() if j.state in (JobState.LEASED, JobState.RUNNING)]


# =========================
# Базовый планировщик
# =========================

@dataclass
class Lease:
    lease_id: str
    job_id: str
    worker_id: str
    expires_at: float


class BaseScheduler(Protocol):
    async def submit(self, job: Job) -> None: ...
    async def cancel(self, job_id: str) -> None: ...
    async def dequeue_for_worker(self, worker_id: str, lease_ttl_s: int) -> Optional[Tuple[Job, Lease]]: ...
    async def renew_lease(self, lease_id: str, ttl_s: int) -> Lease: ...
    async def ack_start(self, lease_id: str) -> None: ...
    async def complete(self, lease_id: str, success: bool) -> None: ...
    async def propose_preemptions(self, urgent_job: Job) -> List[str]: ...


@dataclass
class TenantLimits:
    max_parallel: int = 100
    rate_per_sec: float = 50.0  # submit rate
    burst: int = 200


@dataclass
class _TenantState:
    inflight: int = 0
    tokens: float = 0.0
    last_ts: float = field(default_factory=_now)
    used: Resources = field(default_factory=lambda: Resources(0, 0, 0))  # для fairness


class AbstractScheduler(BaseScheduler):
    """Общий каркас: очереди, лизы, фоновые задачи, квоты."""
    def __init__(
        self,
        store: JobStore,
        resources: InMemoryResourceProvider,
        metrics: Optional[MetricsSink] = None,
        tenant_limits: Optional[Mapping[str, TenantLimits]] = None,
        lease_scan_interval_s: int = 5,
    ) -> None:
        self._store = store
        self._rp = resources
        self._metrics = metrics or NoopMetrics()
        self._lease_scan_interval_s = lease_scan_interval_s
        self._tenants: Dict[str, _TenantState] = {}
        self._tenant_limits: Dict[str, TenantLimits] = dict(tenant_limits or {})
        self._leases: Dict[str, Lease] = {}
        self._jobs_by_lease: Dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._bg_task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()

    # ---- lifecycle ----
    async def start(self) -> None:
        if self._bg_task is None:
            self._bg_task = asyncio.create_task(self._lease_reaper())

    async def stop(self) -> None:
        self._stopped.set()
        if self._bg_task:
            await self._bg_task

    # ---- tenant helpers ----
    def _tstate(self, tenant: str) -> _TenantState:
        st = self._tenants.get(tenant)
        if not st:
            st = _TenantState()
            lim = self._tenant_limits.get(tenant)
            if lim:
                st.tokens = lim.burst
            self._tenants[tenant] = st
        return st

    def _allow_submit(self, tenant: str) -> bool:
        lim = self._tenant_limits.get(tenant)
        st = self._tstate(tenant)
        if not lim:
            return True
        now = _now()
        elapsed = max(0.0, now - st.last_ts)
        st.last_ts = now
        # leaky bucket
        st.tokens = min(lim.burst, st.tokens + elapsed * lim.rate_per_sec)
        if st.tokens >= 1.0:
            st.tokens -= 1.0
            return True
        return False

    # ---- public API ----
    async def submit(self, job: Job) -> None:
        if not self._allow_submit(job.tenant):
            await self._metrics.inc("scheduler_submit_throttled_total", {"tenant": job.tenant})
            raise RuntimeError("Rate limited")
        await self._store.put(job)
        await self._metrics.inc("scheduler_submitted_total", {"tenant": job.tenant, "priority": job.priority.name})

    async def cancel(self, job_id: str) -> None:
        async with self._lock:
            job = await self._store.get(job_id)
            if not job:
                return
            if job.state in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
                return
            # Если под лизом — отзываем лиз (исполнитель увидит отмену по истечении)
            if job.lease_id and job.lease_id in self._leases:
                self._leases.pop(job.lease_id, None)
                self._jobs_by_lease.pop(job.lease_id, None)
            job.state = JobState.CANCELLED
            await self._store.update(job)
            await self._metrics.inc("scheduler_cancelled_total", {"tenant": job.tenant})

    async def dequeue_for_worker(self, worker_id: str, lease_ttl_s: int) -> Optional[Tuple[Job, Lease]]:
        now = _now()
        async with self._lock:
            avail = await self._rp.available_capacity()
            candidate = await self._select_candidate(now, avail)
            if not candidate:
                return None
            # резерв ресурсов
            if not await self._rp.allocate(candidate.resources):
                # другое расписание могло занять ресурсы; вернём None, чтобы воркер попробовал позже
                return None
            # лизуем
            lid = str(uuid.uuid4())
            lease = Lease(lease_id=lid, job_id=candidate.job_id, worker_id=worker_id, expires_at=now + lease_ttl_s)
            self._leases[lid] = lease
            self._jobs_by_lease[lid] = candidate.job_id
            candidate.state = JobState.LEASED
            candidate.leased_to = worker_id
            candidate.lease_id = lid
            candidate.lease_expires_at = lease.expires_at
            await self._store.update(candidate)
            ts = self._tstate(candidate.tenant)
            ts.inflight += 1
            ts.used = ts.used + candidate.resources
            await self._metrics.inc("scheduler_leases_total", {"tenant": candidate.tenant, "priority": candidate.priority.name})
            return candidate, lease

    async def renew_lease(self, lease_id: str, ttl_s: int) -> Lease:
        async with self._lock:
            lease = self._leases.get(lease_id)
            if not lease:
                raise LeaseError("Lease not found")
            lease.expires_at = _now() + ttl_s
            job_id = self._jobs_by_lease.get(lease_id)
            if job_id:
                job = await self._store.get(job_id)
                if job:
                    job.lease_expires_at = lease.expires_at
                    await self._store.update(job)
            return lease

    async def ack_start(self, lease_id: str) -> None:
        async with self._lock:
            job_id = self._jobs_by_lease.get(lease_id)
            if not job_id:
                raise LeaseError("Lease not found")
            job = await self._store.get(job_id)
            if not job:
                raise LeaseError("Job not found for lease")
            job.state = JobState.RUNNING
            await self._store.update(job)

    async def complete(self, lease_id: str, success: bool) -> None:
        async with self._lock:
            lease = self._leases.pop(lease_id, None)
            job_id = self._jobs_by_lease.pop(lease_id, None)
            if not lease or not job_id:
                # уже истёк и отреанимирован
                return
            job = await self._store.get(job_id)
            if not job:
                return
            # освобождаем ресурсы и обновляем счетчики
            await self._rp.release(job.resources)
            ts = self._tstate(job.tenant)
            ts.inflight = max(0, ts.inflight - 1)
            ts.used = Resources(
                cpu_milli=max(0, ts.used.cpu_milli - job.resources.cpu_milli),
                memory_mib=max(0, ts.used.memory_mib - job.resources.memory_mib),
                gpu_count=max(0, ts.used.gpu_count - job.resources.gpu_count),
                gpu_type=ts.used.gpu_type,
            )
            job.state = JobState.COMPLETED if success else JobState.FAILED
            await self._store.update(job)
            await self._metrics.inc("scheduler_completed_total", {"tenant": job.tenant, "result": "success" if success else "failed"})

            # В случае неуспеха — бэкофф и возврат в очередь (если успеваем по дедлайну)
            if not success:
                now = _now()
                job.backoff_attempts += 1
                job.backoff_until = now + _exp_backoff(job.backoff_attempts)
                if job.deadline_ts and job.backoff_until > job.deadline_ts:
                    # истечёт дедлайн — оставим как FAILED
                    return
                job.state = JobState.QUEUED
                job.leased_to = None
                job.lease_id = None
                job.lease_expires_at = 0.0
                await self._store.update(job)
                await self._metrics.inc("scheduler_requeued_total", {"tenant": job.tenant})

    async def propose_preemptions(self, urgent_job: Job) -> List[str]:
        """Предлагает список job_id к преэмпции, чтобы освободить ресурсы под urgent_job."""
        running = await self._store.list_running()
        # Находим кандидатов: наименее приоритетные и preemptible
        candidates = [j for j in running if j.preemptible and j.priority < urgent_job.priority]
        # Сортируем по (priority asc, submitted_at desc) — свежие и низкоприоритетные в первую очередь
        candidates.sort(key=lambda j: (j.priority, -j.submitted_at))
        freed = Resources(0, 0, 0)
        preempt_list: List[str] = []
        for j in candidates:
            freed = freed + j.resources
            preempt_list.append(j.job_id)
            if urgent_job.resources.fits(await self._rp.available_capacity() + freed):
                break
        return preempt_list

    # ---- внутреннее: выбор кандидата ----
    async def _select_candidate(self, now: float, available: Resources) -> Optional[Job]:
        # Реализуется в конкретном алгоритме
        raise NotImplementedError

    # ---- фон: реаниматор лизов ----
    async def _lease_reaper(self) -> None:
        while not self._stopped.is_set():
            await asyncio.sleep(self._lease_scan_interval_s)
            now = _now()
            try:
                async with self._lock:
                    expired = [lid for lid, l in self._leases.items() if l.expires_at <= now]
                    for lid in expired:
                        job_id = self._jobs_by_lease.pop(lid, None)
                        lease = self._leases.pop(lid, None)
                        if not job_id or not lease:
                            continue
                        job = await self._store.get(job_id)
                        if not job:
                            continue
                        # Возвращаем в очередь с бэкоффом (коротким), освобождаем ресурсы
                        await self._rp.release(job.resources)
                        ts = self._tstate(job.tenant)
                        ts.inflight = max(0, ts.inflight - 1)
                        ts.used = Resources(
                            cpu_milli=max(0, ts.used.cpu_milli - job.resources.cpu_milli),
                            memory_mib=max(0, ts.used.memory_mib - job.resources.memory_mib),
                            gpu_count=max(0, ts.used.gpu_count - job.resources.gpu_count),
                            gpu_type=ts.used.gpu_type,
                        )
                        job.state = JobState.QUEUED
                        job.leased_to = None
                        job.lease_id = None
                        job.lease_expires_at = 0.0
                        job.backoff_attempts = max(1, job.backoff_attempts)
                        job.backoff_until = now + _exp_backoff(job.backoff_attempts, base=1.0, cap=10.0)
                        await self._store.update(job)
                        await self._metrics.inc("scheduler_leases_expired_total", {"tenant": job.tenant})
            except Exception as e:
                log.exception("lease reaper failure: %s", e)


# =========================
# Планировщик: Priority + EDF
# =========================

class PriorityFifoScheduler(AbstractScheduler):
    """
    Выбор кандидата: по приоритету (высший), затем по дедлайну (EDF), затем FIFO по времени подачи.
    Фильтры: ресурсная влезаемость, бэкофф/дедлайн, квота тенанта.
    """
    async def _select_candidate(self, now: float, available: Resources) -> Optional[Job]:
        queued = await self._store.list_queued()
        # фильтруем по готовности и ресурсам
        eligible = [j for j in queued if j.is_eligible(now) and j.resources.fits(available)]
        if not eligible:
            return None

        # ограничение на параллелизм тенанта
        elig2: List[Job] = []
        for j in eligible:
            lim = self._tenant_limits.get(j.tenant)
            if lim and self._tstate(j.tenant).inflight >= lim.max_parallel:
                continue
            elig2.append(j)
        if not elig2:
            return None

        # сортировка: -priority, deadline(asc, None=inf), submitted_at(asc)
        def key(j: Job) -> Tuple[int, float, float]:
            ddl = j.deadline_ts if j.deadline_ts else float("inf")
            return (-int(j.priority), ddl, j.submitted_at)

        elig2.sort(key=key)
        return elig2[0]


# =========================
# Планировщик: FairShare (Dominant Share) + EDF
# =========================

class FairShareScheduler(AbstractScheduler):
    """
    Справедливое распределение по тенантам с учётом dominant share:
      share_tenant = max(cpu_used/CPU_total, mem_used/MEM_total, gpu_used/GPU_total)
    Выбор кандидата: минимальная доля -> приоритет -> EDF -> FIFO.
    """
    async def _select_candidate(self, now: float, available: Resources) -> Optional[Job]:
        queued = await self._store.list_queued()
        elig = [j for j in queued if j.is_eligible(now) and j.resources.fits(available)]
        if not elig:
            return None

        cap = await self._rp.cluster_capacity()
        def dom_share(tn: str) -> float:
            st = self._tstate(tn)
            shares: List[float] = []
            shares.append((st.used.cpu_milli or 0) / max(1, cap.cpu_milli))
            shares.append((st.used.memory_mib or 0) / max(1, cap.memory_mib))
            if cap.gpu_count > 0:
                shares.append((st.used.gpu_count or 0) / cap.gpu_count)
            return max(shares) if shares else 0.0

        # Применяем max_parallel
        elig2: List[Job] = []
        for j in elig:
            lim = self._tenant_limits.get(j.tenant)
            if lim and self._tstate(j.tenant).inflight >= lim.max_parallel:
                continue
            elig2.append(j)
        if not elig2:
            return None

        def key(j: Job) -> Tuple[float, int, float, float]:
            ddl = j.deadline_ts if j.deadline_ts else float("inf")
            return (dom_share(j.tenant), -int(j.priority), ddl, j.submitted_at)

        elig2.sort(key=key)
        return elig2[0]


# =========================
# Вспомогательные фабрики
# =========================

def make_priority_fifo_scheduler(
    capacity: Resources,
    *,
    metrics: Optional[MetricsSink] = None,
    tenant_limits: Optional[Mapping[str, TenantLimits]] = None,
) -> PriorityFifoScheduler:
    store = InMemoryJobStore()
    rp = InMemoryResourceProvider(capacity=capacity)
    sched = PriorityFifoScheduler(store=store, resources=rp, metrics=metrics, tenant_limits=tenant_limits)
    return sched


def make_fair_share_scheduler(
    capacity: Resources,
    *,
    metrics: Optional[MetricsSink] = None,
    tenant_limits: Optional[Mapping[str, TenantLimits]] = None,
) -> FairShareScheduler:
    store = InMemoryJobStore()
    rp = InMemoryResourceProvider(capacity=capacity)
    sched = FairShareScheduler(store=store, resources=rp, metrics=metrics, tenant_limits=tenant_limits)
    return sched


# =========================
# Пример использования (док-комментарий)
# =========================
"""
async def main():
    sched = make_fair_share_scheduler(
        capacity=Resources(cpu_milli=16000, memory_mib=65536, gpu_count=4, gpu_type="a100"),
        tenant_limits={"tenantA": TenantLimits(max_parallel=10, rate_per_sec=20.0, burst=50)}
    )
    await sched.start()

    # submit jobs
    await sched.submit(Job(
        job_id=str(uuid.uuid4()),
        tenant="tenantA",
        priority=Priority.HIGH,
        resources=Resources(4000, 8192, 1, "a100"),
        submitted_at=time.time(),
        deadline_ts=time.time() + 3600,
        preemptible=True,
    ))

    # worker pulls
    pair = await sched.dequeue_for_worker(worker_id="worker-1", lease_ttl_s=60)
    if pair:
        job, lease = pair
        await sched.ack_start(lease.lease_id)
        # run training...
        await asyncio.sleep(5)
        await sched.complete(lease.lease_id, success=True)

    await sched.stop()
"""
