# physical_integration/twin/synchronizer.py
# Python 3.10+
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from pydantic import BaseModel, Field, ConfigDict
    PydanticV2 = True
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field  # type: ignore
    PydanticV2 = False  # type: ignore

try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry  # optional
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

# =============================================================================
# Config & models
# =============================================================================

@dataclass(frozen=True)
class SynchronizerConfig:
    tenant_id: str
    synchronizer_id: str = "twin-sync-1"
    # параллелизм и окна
    concurrency: int = 8
    batch_size: int = 200
    full_resync_interval: timedelta = timedelta(minutes=15)
    lease_ttl: timedelta = timedelta(minutes=5)
    # ретраи/тайминги
    max_retries: int = 5
    base_backoff: float = 0.3
    backoff_factor: float = 2.0
    max_backoff: float = 15.0
    idle_sleep: float = 0.5
    # поведение патчей
    patch_section: str = "reported"  # reported|desired
    apply_desired_policy: bool = False
    # лимиты
    patch_max_ops: int = 500
    # observability
    enable_metrics: bool = True

class TwinSnapshot(BaseModel):
    if PydanticV2:
        model_config = ConfigDict(extra="allow")
    entity_id: str
    etag: Optional[str] = None
    desired: Dict[str, Any] = Field(default_factory=dict)
    reported: Dict[str, Any] = Field(default_factory=dict)
    updated_at: Optional[str] = None

class ObservedState(BaseModel):
    if PydanticV2:
        model_config = ConfigDict(extra="allow")
    entity_id: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    collected_at: Optional[str] = None

class PatchOp(BaseModel):
    op: str  # add|remove|replace
    path: str
    value: Optional[Any] = None

class SyncResult(BaseModel):
    entity_id: str
    patched: bool
    patch_hash: Optional[str] = None
    applied_ops: int = 0
    attempts: int = 0
    etag_new: Optional[str] = None
    status: str = "ok"  # ok|noop|conflict|error
    error: Optional[str] = None
    duration_ms: int = 0

# =============================================================================
# Interfaces (adapters & store)
# =============================================================================

class TwinPlatformAdapter:
    """
    Интерфейс внешней платформы Digital Twin (Azure DT, AWS TwinMaker, кастом и т.п.).
    """

    async def fetch_twin(self, tenant_id: str, entity_id: str) -> TwinSnapshot:
        raise NotImplementedError

    async def apply_patch(
        self,
        tenant_id: str,
        entity_id: str,
        patch: Sequence[PatchOp],
        *,
        if_match: Optional[str],
        idempotency_key: Optional[str],
    ) -> str:
        """
        Применяет JSON-Patch к twin и возвращает новый ETag/версию.
        Должна бросать Conflict/Precondition Failed при рассинхронизации.
        """
        raise NotImplementedError

class PhysicalStateAdapter:
    """
    Источник наблюдаемого состояния (ваш Registry/Telemetry/внешние API).
    """

    async def get_observed(self, tenant_id: str, entity_id: str) -> ObservedState:
        raise NotImplementedError

class EntitySource:
    """
    Источник идентификаторов для полной инвентаризации.
    """

    async def iter_entities(self, tenant_id: str, *, batch_size: int) -> AsyncIterator[List[str]]:
        raise NotImplementedError

class TwinStore:
    """
    Локальное хранилище метаданных синхронизации (lease, чекпоинты, кэш ETag/patch hash).
    """

    async def acquire_lease(self, key: str, holder: str, ttl: timedelta) -> bool:
        raise NotImplementedError

    async def renew_lease(self, key: str, holder: str, ttl: timedelta) -> bool:
        raise NotImplementedError

    async def release_lease(self, key: str, holder: str) -> None:
        raise NotImplementedError

    async def get_last_patch_hash(self, tenant_id: str, entity_id: str) -> Optional[str]:
        raise NotImplementedError

    async def set_last_patch_hash(self, tenant_id: str, entity_id: str, patch_hash: str) -> None:
        raise NotImplementedError

    async def record_result(self, tenant_id: str, result: SyncResult) -> None:
        raise NotImplementedError

# =============================================================================
# Metrics
# =============================================================================

class _Metrics:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and _PROM_AVAILABLE
        if not self.enabled:
            # no-op stubs
            self.started = self.ok = self.noop = self.conflict = self.err = self.ops = self.duration = self.inflight = None  # type: ignore
            return
        self.started = Counter("twin_sync_started_total", "Sync attempts", ["tenant"])
        self.ok = Counter("twin_sync_ok_total", "Successful patches", ["tenant"])
        self.noop = Counter("twin_sync_noop_total", "No-change results", ["tenant"])
        self.conflict = Counter("twin_sync_conflict_total", "Conflicts", ["tenant"])
        self.err = Counter("twin_sync_error_total", "Errors", ["tenant"])
        self.ops = Histogram("twin_sync_ops", "Number of ops per patch", ["tenant"], buckets=(0, 1, 2, 5, 10, 50, 200, 500))
        self.duration = Histogram("twin_sync_duration_seconds", "Sync duration", ["tenant"], buckets=(0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5))
        self.inflight = Gauge("twin_sync_inflight", "In-flight entity reconciliations", ["tenant"])

    def inc(self, metric: Optional[Any], tenant: str, v: float = 1.0) -> None:
        if self.enabled and metric is not None:
            metric.labels(tenant).inc(v)

    def obs(self, metric: Optional[Any], tenant: str, v: float) -> None:
        if self.enabled and metric is not None:
            metric.labels(tenant).observe(v)

    def add(self, metric: Optional[Any], tenant: str, v: float) -> None:
        # alias for Gauge inc/dec if needed
        pass

# =============================================================================
# Diff & patch generation (RFC 6902)
# =============================================================================

def _json_pointer(path: List[str]) -> str:
    # RFC6901 escaping
    esc = [p.replace("~", "~0").replace("/", "~1") for p in path]
    return "/" + "/".join(esc)

def _diff(from_obj: Any, to_obj: Any, base: Optional[List[str]] = None, out: Optional[List[PatchOp]] = None, *, max_ops: int = 10_000) -> List[PatchOp]:
    """
    Генератор JSON-Patch (replace/add/remove) для преобразования from_obj -> to_obj.
    Простая рекурсивная стратегия для dict/list/scalar.
    """
    if out is None:
        out = []
    if base is None:
        base = []

    if len(out) >= max_ops:
        # защита от раздувания
        return out

    if type(from_obj) != type(to_obj):
        out.append(PatchOp(op="replace", path=_json_pointer(base), value=to_obj))
        return out

    if isinstance(from_obj, dict):
        # removed
        for k in from_obj.keys() - to_obj.keys():
            out.append(PatchOp(op="remove", path=_json_pointer(base + [k])))
            if len(out) >= max_ops:  # pragma: no cover
                return out
        # added
        for k in to_obj.keys() - from_obj.keys():
            out.append(PatchOp(op="add", path=_json_pointer(base + [k]), value=to_obj[k]))
            if len(out) >= max_ops:
                return out
        # modified
        for k in from_obj.keys() & to_obj.keys():
            _diff(from_obj[k], to_obj[k], base + [k], out, max_ops=max_ops)
        return out

    if isinstance(from_obj, list):
        # простая стратегия: если списки отличаются по длине/элементам — replace целиком
        if len(from_obj) != len(to_obj) or any(a != b for a, b in zip(from_obj, to_obj)):
            out.append(PatchOp(op="replace", path=_json_pointer(base), value=to_obj))
        return out

    # scalar
    if from_obj != to_obj:
        out.append(PatchOp(op="replace", path=_json_pointer(base), value=to_obj))
    return out

def build_reported_patch(twin: TwinSnapshot, observed: ObservedState, *, patch_max_ops: int) -> List[PatchOp]:
    """
    Строит JSON-Patch, чтобы секция reported в twin соответствовала observed.payload.
    """
    from_obj = twin.reported or {}
    to_obj = observed.payload or {}
    ops = _diff(from_obj, to_obj, base=["reported"], max_ops=patch_max_ops)
    return ops

# =============================================================================
# Policy for desired (optional)
# =============================================================================

DesiredPolicy = Callable[[TwinSnapshot, ObservedState], Dict[str, Any]]

def default_desired_policy(twin: TwinSnapshot, observed: ObservedState) -> Dict[str, Any]:
    """
    Пример: если в observed пришло новое поле firmware.available, пробрасываем desired.update_fw=true.
    Настройте под свой домен.
    """
    desired = dict(twin.desired or {})
    fw_av = observed.payload.get("firmware", {}).get("available") if isinstance(observed.payload.get("firmware"), dict) else None
    if fw_av and not desired.get("update_fw"):
        desired["update_fw"] = True
    return desired

def build_desired_patch(twin: TwinSnapshot, desired_new: Dict[str, Any], *, patch_max_ops: int) -> List[PatchOp]:
    return _diff(twin.desired or {}, desired_new or {}, base=["desired"], max_ops=patch_max_ops)

# =============================================================================
# Utility: retries & backoff
# =============================================================================

async def _retry(
    func: Callable[[], Awaitable[Any]],
    *,
    retries: int,
    base: float,
    factor: float,
    max_sleep: float,
    on_error: Optional[Callable[[int, BaseException], None]] = None,
) -> Any:
    attempt = 0
    while True:
        try:
            return await func()
        except Exception as e:
            attempt += 1
            if attempt > retries:
                raise
            sleep = min(max_sleep, base * (factor ** (attempt - 1)))
            # джиттер для шатдаунов «стада»
            sleep = sleep * (0.8 + 0.4 * random.random())
            if on_error:
                on_error(attempt, e)
            await asyncio.sleep(sleep)

def _hash_patch(ops: Sequence[PatchOp]) -> str:
    m = hashlib.sha256()
    for op in ops:
        m.update(op.op.encode("utf-8"))
        m.update(op.path.encode("utf-8"))
        if op.value is not None:
            m.update(json.dumps(op.value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return m.hexdigest()

# =============================================================================
# Synchronizer core
# =============================================================================

class TwinSynchronizer:
    """
    Высокоуровневый оркестратор синхронизации Twin ↔ Observed.
    """

    def __init__(
        self,
        cfg: SynchronizerConfig,
        twin_store: TwinStore,
        twin_adapter: TwinPlatformAdapter,
        physical_adapter: PhysicalStateAdapter,
        entity_source: EntitySource,
        *,
        desired_policy: DesiredPolicy = default_desired_policy,
    ) -> None:
        self.cfg = cfg
        self.twin_store = twin_store
        self.twin_adapter = twin_adapter
        self.physical_adapter = physical_adapter
        self.entity_source = entity_source
        self.desired_policy = desired_policy

        self._metrics = _Metrics(cfg.enable_metrics)
        self._stop = asyncio.Event()
        self._sema = asyncio.Semaphore(cfg.concurrency)
        self._last_full_resync = datetime.min.replace(tzinfo=timezone.utc)

    async def stop(self) -> None:
        self._stop.set()

    # -------- public API --------

    async def run(self) -> None:
        """
        Основной цикл: удерживаем lease и выполняем смешанный синк (события + периодический полный обход).
        """
        lease_key = f"twin-sync:{self.cfg.tenant_id}"
        holder = self.cfg.synchronizer_id
        ttl = self.cfg.lease_ttl

        while not self._stop.is_set():
            try:
                if await self.twin_store.acquire_lease(lease_key, holder, ttl):
                    await self._run_with_lease(lease_key, holder, ttl)
                else:
                    # ожидание возможности получить lease
                    await asyncio.sleep(min(2.0, self.cfg.idle_sleep * 2))
            except Exception as e:  # жесткая защита цикла
                log.exception("synchronizer fatal loop error: %s", e)
                await asyncio.sleep(1.0)

    async def _run_with_lease(self, lease_key: str, holder: str, ttl: timedelta) -> None:
        renew_task = asyncio.create_task(self._lease_renewer(lease_key, holder, ttl))
        try:
            while not self._stop.is_set():
                # полный обход по расписанию
                now = datetime.now(timezone.utc)
                if now - self._last_full_resync >= self.cfg.full_resync_interval:
                    await self._full_resync_pass()
                    self._last_full_resync = now
                # «пустой» сон, можно заменить на ожидание событийной очереди
                await asyncio.sleep(self.cfg.idle_sleep)
        finally:
            renew_task.cancel()
            with contextlib.suppress(Exception):  # type: ignore
                await self.twin_store.release_lease(lease_key, holder)

    async def _lease_renewer(self, lease_key: str, holder: str, ttl: timedelta) -> None:
        try:
            while not self._stop.is_set():
                await asyncio.sleep(ttl.total_seconds() * 0.5)
                ok = await self.twin_store.renew_lease(lease_key, holder, ttl)
                if not ok:
                    log.warning("lost lease for %s", lease_key)
                    return
        except asyncio.CancelledError:  # pragma: no cover
            return
        except Exception as e:  # pragma: no cover
            log.error("lease renew error: %s", e)

    async def _full_resync_pass(self) -> None:
        """
        Последовательно обрабатывает сущности батчами, ограничивая параллелизм.
        """
        tenant = self.cfg.tenant_id
        log.info("full resync pass started tenant=%s", tenant)
        async for batch in self.entity_source.iter_entities(tenant, batch_size=self.cfg.batch_size):
            tasks = [asyncio.create_task(self._reconcile_entity(eid)) for eid in batch]
            # ограничить одновременную работу семафором
            for t in tasks:
                await self._sema.acquire()
                t.add_done_callback(lambda _t: self._sema.release())  # noqa: E731
            # дождаться завершения всей пачки
            await asyncio.gather(*tasks, return_exceptions=True)
        log.info("full resync pass finished tenant=%s", tenant)

    # -------- reconciliation --------

    async def _reconcile_entity(self, entity_id: str) -> SyncResult:
        tenant = self.cfg.tenant_id
        self._metrics.inc(self._metrics.started, tenant)
        start = time.perf_counter()
        try:
            twin = await self.twin_adapter.fetch_twin(tenant, entity_id)
            observed = await self.physical_adapter.get_observed(tenant, entity_id)

            # формируем патч на секцию reported
            ops_reported = build_reported_patch(twin, observed, patch_max_ops=self.cfg.patch_max_ops)

            # опционально desired
            ops_desired: List[PatchOp] = []
            if self.cfg.apply_desired_policy:
                desired_new = self.desired_policy(twin, observed)
                ops_desired = build_desired_patch(twin, desired_new, patch_max_ops=self.cfg.patch_max_ops)

            ops = ops_reported + ops_desired
            if not ops:
                dur = int(1000 * (time.perf_counter() - start))
                res = SyncResult(entity_id=entity_id, patched=False, applied_ops=0, attempts=1, duration_ms=dur, status="noop")
                await self.twin_store.record_result(tenant, res)
                self._metrics.inc(self._metrics.noop, tenant)
                return res

            patch_hash = _hash_patch(ops)

            # идемпотентность: если такой патч уже применяли — пропускаем
            last_hash = await self.twin_store.get_last_patch_hash(tenant, entity_id)
            if last_hash == patch_hash:
                dur = int(1000 * (time.perf_counter() - start))
                res = SyncResult(entity_id=entity_id, patched=False, patch_hash=patch_hash, applied_ops=0, attempts=1, duration_ms=dur, status="noop")
                await self.twin_store.record_result(tenant, res)
                self._metrics.inc(self._metrics.noop, tenant)
                return res

            async def _apply() -> str:
                return await self.twin_adapter.apply_patch(
                    tenant, entity_id, ops, if_match=twin.etag, idempotency_key=patch_hash
                )

            def _on_err(attempt: int, err: BaseException) -> None:
                log.warning("patch attempt %d failed for entity=%s: %s", attempt, entity_id, err)

            new_etag = await _retry(
                _apply,
                retries=self.cfg.max_retries,
                base=self.cfg.base_backoff,
                factor=self.cfg.backoff_factor,
                max_sleep=self.cfg.max_backoff,
                on_error=_on_err,
            )

            await self.twin_store.set_last_patch_hash(tenant, entity_id, patch_hash)
            dur = int(1000 * (time.perf_counter() - start))
            res = SyncResult(
                entity_id=entity_id,
                patched=True,
                patch_hash=patch_hash,
                applied_ops=len(ops),
                attempts=1,  # attempts не считает внутренние ретраи, при необходимости расширьте
                etag_new=new_etag,
                duration_ms=dur,
                status="ok",
            )
            await self.twin_store.record_result(tenant, res)
            self._metrics.inc(self._metrics.ok, tenant)
            self._metrics.obs(self._metrics.ops, tenant, float(len(ops)))
            self._metrics.obs(self._metrics.duration, tenant, dur / 1000.0)
            return res

        except Exception as e:
            dur = int(1000 * (time.perf_counter() - start))
            log.error("reconcile failed entity=%s: %s", entity_id, e, exc_info=True)
            res = SyncResult(entity_id=entity_id, patched=False, applied_ops=0, attempts=1, duration_ms=dur, status="error", error=str(e))
            try:
                await self.twin_store.record_result(self.cfg.tenant_id, res)
            finally:
                self._metrics.inc(self._metrics.err, tenant)
            return res

# =============================================================================
# Context helpers
# =============================================================================

import contextlib  # placed here to avoid circular hints

@contextlib.asynccontextmanager
async def run_synchronizer(sync: TwinSynchronizer):
    """
    Контекстный менеджер для запуска синхронизатора в задаче и корректной остановки.
    """
    task = asyncio.create_task(sync.run())
    try:
        yield
    finally:
        await sync.stop()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=5.0)

# =============================================================================
# Example skeleton adapters (to implement in your codebase)
# =============================================================================

class InMemoryTwinStore(TwinStore):
    """
    Простейшая in-memory реализация для отладки. В проде замените на PostgreSQL/Redis.
    """
    def __init__(self) -> None:
        self._lease: Dict[str, Tuple[str, float]] = {}
        self._hash: Dict[Tuple[str, str], str] = {}

    async def acquire_lease(self, key: str, holder: str, ttl: timedelta) -> bool:
        now = time.monotonic()
        h, exp = self._lease.get(key, (None, 0.0))  # type: ignore
        if not h or exp < now:
            self._lease[key] = (holder, now + ttl.total_seconds())
            return True
        return h == holder

    async def renew_lease(self, key: str, holder: str, ttl: timedelta) -> bool:
        now = time.monotonic()
        h, exp = self._lease.get(key, (None, 0.0))  # type: ignore
        if h == holder and exp >= now:
            self._lease[key] = (holder, now + ttl.total_seconds())
            return True
        return False

    async def release_lease(self, key: str, holder: str) -> None:
        h, _ = self._lease.get(key, (None, 0.0))  # type: ignore
        if h == holder:
            self._lease.pop(key, None)

    async def get_last_patch_hash(self, tenant_id: str, entity_id: str) -> Optional[str]:
        return self._hash.get((tenant_id, entity_id))

    async def set_last_patch_hash(self, tenant_id: str, entity_id: str, patch_hash: str) -> None:
        self._hash[(tenant_id, entity_id)] = patch_hash

    async def record_result(self, tenant_id: str, result: SyncResult) -> None:
        log.debug("RESULT %s %s", tenant_id, result.model_dump() if PydanticV2 else result.dict())  # type: ignore

# =============================================================================
# Notes:
#  - Рекомендовано хранить last_patch_hash/ETag/lease в транзакционной БД или Redis с TTL.
#  - Если внешняя платформа возвращает 412 Precondition Failed, перезагрузите Twin и пересоберите патч.
#  - Для событийного режима прокиньте очередь изменений и вызывайте _reconcile_entity(eid) по событию.
#  - Для больших массивов используйте keyset-пагинацию в EntitySource.iter_entities.
# =============================================================================
