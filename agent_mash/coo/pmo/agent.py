# agent_mash/pmo/agent.py
from __future__ import annotations

import asyncio
import dataclasses
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from agent_mash.core.routing import (
    DispatchResult,
    DispatchStatus,
    RouteDecision,
    RouteTarget,
    RouteTargetType,
    WorkId,
    WorkItem,
    WorkMeta,
    WorkforceRouter,
)

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PMOError(RuntimeError):
    pass


class InvalidBacklog(PMOError):
    pass


class PlanningRejected(PMOError):
    pass


class ExecutionError(PMOError):
    pass


class WorkClass(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"


@dataclass(frozen=True, slots=True)
class BacklogItem:
    """
    Единица backlog на уровне PMO. PMO не привязан к конкретным агентам.
    Он формирует work items и отдаёт в routing.WorkforceRouter.

    Поля intentionally минимальны: PMO должен уметь работать с любым доменом.
    """

    kind: str
    payload: dict[str, Any]
    work_class: WorkClass = WorkClass.NORMAL
    priority_hint: Optional[int] = None
    deadline_seconds: Optional[int] = None

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None

    correlation_id: Optional[str] = None
    tags: dict[str, str] = dataclasses.field(default_factory=dict)

    # Идемпотентность: если задан, PMO обязан дать одинаковый dedupe_key на уровне WorkItem.
    dedupe_parts: Optional[Mapping[str, Any]] = None

    # Мягкие ограничения PMO: не ломают routing, а ограничивают планирование.
    max_parallelism_key: Optional[str] = None


@dataclass(frozen=True, slots=True)
class PMOConfig:
    source: str = "pmo.agent"
    default_deadline_seconds: Optional[int] = 900

    # Глобальная параллельность PMO-исполнения (не путать с router max_concurrency).
    max_inflight: int = 200

    # Soft quota: сколько задач одного tenant держим в одном батче в приоритете.
    per_tenant_soft_quota: int = 2000

    # Если backlog огромный, PMO может резать на чанки.
    max_batch_size: int = 5000

    # Простейшая fairness-политика: лимит подряд идущих задач одного tenant в порядке исполнения.
    fairness_run_limit: int = 200

    # Приоритеты: меньше число = выше приоритет в routing.py, но здесь мы формируем числовую шкалу.
    # Эти значения используются как базовые, затем корректируются hint-ами и классом.
    base_priority_critical: int = 10
    base_priority_high: int = 30
    base_priority_normal: int = 100
    base_priority_low: int = 200
    base_priority_background: int = 500


@dataclass(frozen=True, slots=True)
class PlanStats:
    total: int
    per_tenant: dict[str, int]
    per_kind: dict[str, int]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DispatchEntry:
    backlog: BacklogItem
    work: WorkItem


@dataclass(frozen=True, slots=True)
class DispatchPlan:
    id: str
    created_at: datetime
    entries: list[DispatchEntry]
    stats: PlanStats


@dataclass(frozen=True, slots=True)
class ExecutionStats:
    accepted: int
    succeeded: int
    failed: int
    rejected: int
    deadletter: int
    duration_ms: int


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    plan_id: str
    started_at: datetime
    finished_at: datetime
    stats: ExecutionStats
    results: list[DispatchResult]


class PMOPolicy:
    """
    Политики планирования и нормализации, не завязанные на конкретный домен.
    """

    def normalize_priority(self, item: BacklogItem, cfg: PMOConfig) -> int:
        base = {
            WorkClass.CRITICAL: cfg.base_priority_critical,
            WorkClass.HIGH: cfg.base_priority_high,
            WorkClass.NORMAL: cfg.base_priority_normal,
            WorkClass.LOW: cfg.base_priority_low,
            WorkClass.BACKGROUND: cfg.base_priority_background,
        }[item.work_class]

        if item.priority_hint is None:
            return int(base)

        # Hint корректирует базу, но не даёт уйти в экстремумы.
        # Чем меньше число, тем выше приоритет.
        hinted = int(item.priority_hint)
        return max(1, min(10_000, hinted))

    def normalize_deadline(self, item: BacklogItem, cfg: PMOConfig) -> Optional[datetime]:
        if item.deadline_seconds is not None:
            if item.deadline_seconds <= 0:
                return utc_now()
            return utc_now() + timedelta(seconds=int(item.deadline_seconds))
        if cfg.default_deadline_seconds is None:
            return None
        return utc_now() + timedelta(seconds=int(cfg.default_deadline_seconds))

    def validate_item(self, item: BacklogItem) -> None:
        if not item.kind or not isinstance(item.kind, str):
            raise InvalidBacklog("BacklogItem.kind must be a non-empty string")
        if not isinstance(item.payload, dict):
            raise InvalidBacklog("BacklogItem.payload must be a dict")


class PMOAgent:
    """
    PMO-агент: принимает backlog, строит план и исполняет его через WorkforceRouter.

    Инварианты:
    - Не делает предположений о конкретных agent-типах, только о WorkItem.kind.
    - Детерминированно формирует dedupe_key при наличии dedupe_parts.
    - Применяет fairness по tenant и ограничивает batch-size.
    """

    def __init__(
        self,
        *,
        router: WorkforceRouter,
        config: Optional[PMOConfig] = None,
        policy: Optional[PMOPolicy] = None,
    ) -> None:
        self._router = router
        self._cfg = config or PMOConfig()
        self._policy = policy or PMOPolicy()
        self._sem = asyncio.Semaphore(max(1, int(self._cfg.max_inflight)))

    def plan(self, backlog: Iterable[BacklogItem]) -> DispatchPlan:
        items = list(backlog)
        if not items:
            raise InvalidBacklog("Backlog is empty")

        cfg = self._cfg

        per_tenant: dict[str, int] = {}
        per_kind: dict[str, int] = {}

        entries: list[DispatchEntry] = []
        created_at = utc_now()

        for item in items:
            self._policy.validate_item(item)

            tenant_key = item.tenant_id or "public"
            per_tenant[tenant_key] = per_tenant.get(tenant_key, 0) + 1
            per_kind[item.kind] = per_kind.get(item.kind, 0) + 1

        # Ограничение батча: планируем только max_batch_size наиболее важных.
        # Важно: мы не можем честно доказать "самые важные" без доменных сигналов,
        # поэтому используем нормализованный приоритет как единственный сигнал.
        normalized = []
        for item in items:
            pri = self._policy.normalize_priority(item, cfg)
            normalized.append((pri, item))

        normalized.sort(key=lambda x: x[0])  # меньше = важнее
        if len(normalized) > cfg.max_batch_size:
            normalized = normalized[: cfg.max_batch_size]

        # Fairness: сглаживаем длинные серии tenant-ов
        ordered_items = self._apply_fairness([it for _, it in normalized])

        for item in ordered_items:
            deadline = self._policy.normalize_deadline(item, cfg)
            priority = self._policy.normalize_priority(item, cfg)

            meta = WorkMeta.default(source=cfg.source)
            if item.correlation_id:
                meta = dataclasses.replace(meta, correlation_id=item.correlation_id)
            if item.tags:
                meta = dataclasses.replace(meta, tags=dict(item.tags))

            # WorkId: если есть dedupe_parts, используем детерминированный id через WorkId.from_deterministic
            # иначе - random uuid.
            wid = WorkId.from_deterministic(item.dedupe_parts) if item.dedupe_parts is not None else WorkId.new()

            work = WorkItem(
                id=wid,
                kind=item.kind,
                payload=self._coerce_payload(item.payload),
                meta=meta,
                priority=int(priority),
                deadline=deadline,
                tenant_id=item.tenant_id,
                user_id=item.user_id,
                dedupe_key=self._dedupe_key_from_parts(item.dedupe_parts),
            )
            entries.append(DispatchEntry(backlog=item, work=work))

        stats = PlanStats(
            total=len(entries),
            per_tenant=dict(per_tenant),
            per_kind=dict(per_kind),
            created_at=created_at,
        )

        plan_id = f"pmo-{created_at.strftime('%Y%m%dT%H%M%S')}-{len(entries)}"
        return DispatchPlan(id=plan_id, created_at=created_at, entries=entries, stats=stats)

    async def execute(self, plan: DispatchPlan) -> ExecutionReport:
        started_at = utc_now()
        t0 = asyncio.get_running_loop().time()

        results: list[DispatchResult] = []
        accepted = succeeded = failed = rejected = deadletter = 0

        async def _run_one(entry: DispatchEntry) -> DispatchResult:
            async with self._sem:
                return await self._router.handle(entry.work)

        tasks = [asyncio.create_task(_run_one(e)) for e in plan.entries]

        # Сбор результатов с сохранением порядка по plan.entries
        for t in tasks:
            res = await t
            results.append(res)

            if res.status == DispatchStatus.ACCEPTED:
                accepted += 1
            elif res.status == DispatchStatus.SUCCEEDED:
                succeeded += 1
            elif res.status == DispatchStatus.REJECTED:
                rejected += 1
            elif res.status == DispatchStatus.DEADLETTER:
                deadletter += 1
            elif res.status == DispatchStatus.FAILED:
                failed += 1
            else:
                # RETRYING обычно не должен быть финальным статусом из router.handle
                # но учитываем для полноты.
                failed += 1

        t1 = asyncio.get_running_loop().time()
        duration_ms = int((t1 - t0) * 1000)
        finished_at = utc_now()

        stats = ExecutionStats(
            accepted=accepted,
            succeeded=succeeded,
            failed=failed,
            rejected=rejected,
            deadletter=deadletter,
            duration_ms=duration_ms,
        )

        logger.info(
            "pmo_execute plan_id=%s total=%d accepted=%d succeeded=%d failed=%d rejected=%d deadletter=%d dur_ms=%d",
            plan.id,
            len(plan.entries),
            accepted,
            succeeded,
            failed,
            rejected,
            deadletter,
            duration_ms,
        )

        return ExecutionReport(
            plan_id=plan.id,
            started_at=started_at,
            finished_at=finished_at,
            stats=stats,
            results=results,
        )

    def plan_and_execute_sync(self, backlog: Iterable[BacklogItem]) -> ExecutionReport:
        """
        Sync entrypoint для окружений без явного event loop.
        Использовать только там, где это уместно.
        """
        plan = self.plan(backlog)
        return asyncio.run(self.execute(plan))

    def explain_dispatch(self, work: WorkItem) -> RouteDecision:
        """
        Детерминированно показывает решение роутинга без исполнения.
        Это полезно для PMO-диагностики.
        """
        return self._router._engine.decide(work)  # type: ignore[attr-defined]

    def _apply_fairness(self, items: list[BacklogItem]) -> list[BacklogItem]:
        """
        Простая fairness-перемежающая политика.
        Цель: не допускать слишком длинных серий одного tenant.
        """
        if not items:
            return items

        run_limit = max(1, int(self._cfg.fairness_run_limit))

        # Группируем по tenant
        buckets: dict[str, list[BacklogItem]] = {}
        for it in items:
            k = it.tenant_id or "public"
            buckets.setdefault(k, []).append(it)

        # Сортируем tenants по размеру, чтобы крупные не задавили мелких
        tenants = sorted(buckets.keys(), key=lambda k: len(buckets[k]), reverse=True)

        out: list[BacklogItem] = []
        while True:
            progressed = False
            for tenant in tenants:
                b = buckets.get(tenant)
                if not b:
                    continue
                take = min(run_limit, len(b))
                out.extend(b[:take])
                del b[:take]
                progressed = True
            if not progressed:
                break

        return out

    def _coerce_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Приведение payload к JSON-совместимому виду не гарантируется без доменных правил,
        поэтому здесь только безопасная нормализация:
        - запрещаем вложенные объекты, которые нельзя сериализовать predictably, не падая.
        """
        out: dict[str, Any] = {}
        for k, v in payload.items():
            if not isinstance(k, str):
                out[str(k)] = self._safe_value(v)
            else:
                out[k] = self._safe_value(v)
        return out

    def _safe_value(self, v: Any) -> Any:
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        if isinstance(v, (list, tuple)):
            return [self._safe_value(x) for x in v]
        if isinstance(v, dict):
            return {str(kk): self._safe_value(vv) for kk, vv in v.items()}
        # Фоллбек: строковое представление, чтобы не ломать пайплайн
        return str(v)

    def _dedupe_key_from_parts(self, parts: Optional[Mapping[str, Any]]) -> Optional[str]:
        """
        dedupe_key формируется внутри routing.default_work_item, но здесь мы создаём WorkItem вручную.
        Делаем то же самое: стабильный ключ от stable-json представления.
        """
        if parts is None:
            return None
        try:
            import json

            stable = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
            import hashlib

            return hashlib.sha256(stable.encode("utf-8")).hexdigest()
        except Exception:
            # Если не удалось стабильно сериализовать, отключаем dedupe, чтобы не получить ложные дедупы.
            return None
