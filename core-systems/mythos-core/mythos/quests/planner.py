# mythos-core/mythos/quests/planner.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import functools
import hashlib
import json
import math
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator

# =============================================================================
# Идентификаторы и утилиты
# =============================================================================

def new_id() -> str:
    """Лексикографически-распределенный ID (в духе ULID, без внешних зависимостей)."""
    ts_ms = int(time.time() * 1000)
    rnd = base64.urlsafe_b64encode(os.urandom(10)).decode().rstrip("=")
    return f"{ts_ms:013d}-{rnd}"

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

# =============================================================================
# Модели домена
# =============================================================================

class TimeWindow(BaseModel):
    """Временное окно, когда задачу можно начать."""
    start: Optional[datetime] = None
    end: Optional[datetime] = None

    @model_validator(mode="after")
    def _check(self) -> "TimeWindow":
        if self.start and self.end and self.end <= self.start:
            raise ValueError("time window end must be greater than start")
        return self

class ResourceDemand(BaseModel):
    """Требования/выделение ресурса на время выполнения задачи."""
    name: str
    amount: float = Field(1.0, ge=0.0)

class SkillRequirement(BaseModel):
    name: str
    min_level: int = Field(1, ge=0)

class QuestTask(BaseModel):
    """Описатель одной задачи в каталоге."""
    id: str
    name: str
    tags: List[str] = Field(default_factory=list)
    duration: timedelta = Field(default=timedelta(minutes=5))
    reward: float = Field(0.0, description="Полезность/очки за выполнение")
    risk: float = Field(0.0, description="Риск/штраф 0..1")
    prerequisites_expr: Optional[str] = Field(
        default=None,
        description="Безопасная DSL: completed('task_x') and skill('lockpicking')>=2 and cooldown_passed('task_y', 3600)",
    )
    depends_on: List[str] = Field(default_factory=list, description="Прямые зависимости в DAG (id задач)")
    requires: List[ResourceDemand] = Field(default_factory=list)
    provides: List[ResourceDemand] = Field(default_factory=list)
    skills: List[SkillRequirement] = Field(default_factory=list)
    time_window: Optional[TimeWindow] = None
    soft_deadline: Optional[datetime] = None
    mandatory: bool = False
    cooldown_seconds: int = 0
    location: Optional[str] = None

    @field_validator("risk")
    @classmethod
    def _risk_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("risk must be in [0,1]")
        return v

class PlayerProfile(BaseModel):
    actor_id: str
    skills: Dict[str, int] = Field(default_factory=dict)
    inventory: Dict[str, float] = Field(default_factory=dict)
    flags: Dict[str, bool] = Field(default_factory=dict)
    completed_tasks: List[str] = Field(default_factory=list)
    cooldowns: Dict[str, datetime] = Field(default_factory=dict)  # task_id -> last_finish_at (UTC)
    location: Optional[str] = None

class WorldLimits(BaseModel):
    resource_caps: Dict[str, float] = Field(default_factory=dict)  # upper capacity per resource
    time_budget: Optional[timedelta] = None

class PlanGoal(BaseModel):
    """Высокоуровневые цели (по тегам/конкретным задачам)."""
    include_tags: List[str] = Field(default_factory=list)
    exclude_tags: List[str] = Field(default_factory=list)
    include_tasks: List[str] = Field(default_factory=list)
    exclude_tasks: List[str] = Field(default_factory=list)

class PlanRequest(BaseModel):
    tenant_id: str
    profile: PlayerProfile
    now: datetime = Field(default_factory=utc_now)
    goals: PlanGoal = Field(default_factory=PlanGoal)
    world: WorldLimits = Field(default_factory=WorldLimits)
    idempotency_key: Optional[str] = None

class ScheduledStep(BaseModel):
    task_id: str
    name: str
    start_at: datetime
    end_at: datetime
    expected_utility: float
    reasons: List[str] = Field(default_factory=list)
    resources_used: Dict[str, float] = Field(default_factory=dict)
    location: Optional[str] = None

class QuestPlan(BaseModel):
    plan_id: str
    tenant_id: str
    actor_id: str
    created_at: datetime = Field(default_factory=utc_now)
    steps: List[ScheduledStep] = Field(default_factory=list)
    total_utility: float = 0.0
    makespan: timedelta = Field(default=timedelta())
    reasons: List[str] = Field(default_factory=list)
    etag: str = ""

    def compute_etag(self) -> str:
        payload = self.model_dump(mode="json")
        j = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(j).hexdigest()

# =============================================================================
# Интерфейсы интеграции
# =============================================================================

class QuestCatalog(Protocol):
    """Каталог задач: поставляет возможные задачи для планирования."""
    async def list_tasks(self, tenant_id: str, profile: PlayerProfile) -> List[QuestTask]: ...

class WorldAdapter(Protocol):
    """Адаптер мира: факты, расстояния, стоимость путешествий."""
    async def travel_cost(self, from_loc: Optional[str], to_loc: Optional[str]) -> float: ...
    async def is_flag(self, key: str) -> bool: ...

class TimelineLogger(Protocol):
    """Опционально: логирование событий планирования в таймлайн."""
    async def log(self, tenant_id: str, actor_id: str, title: str, message: str, labels: Dict[str, str]) -> None: ...

# Базовые безопасные стабы

class InMemoryCatalog:
    def __init__(self, tasks: List[QuestTask]) -> None:
        self._tasks = {t.id: t for t in tasks}

    async def list_tasks(self, tenant_id: str, profile: PlayerProfile) -> List[QuestTask]:
        return list(self._tasks.values())

class NullWorld:
    async def travel_cost(self, from_loc: Optional[str], to_loc: Optional[str]) -> float:
        if not from_loc or not to_loc or from_loc == to_loc:
            return 0.0
        return 1.0

    async def is_flag(self, key: str) -> bool:
        return False

class NullTimeline:
    async def log(self, tenant_id: str, actor_id: str, title: str, message: str, labels: Dict[str, str]) -> None:
        return None

# =============================================================================
# Безопасная мини-DSL для предусловий
# =============================================================================

import ast

_ALLOWED_NODES = (
    ast.Module, ast.Expr, ast.BoolOp, ast.BinOp, ast.UnaryOp,
    ast.Name, ast.Load, ast.Call, ast.keyword, ast.Compare,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE,
    ast.Constant, ast.Subscript, ast.Index
)

class PredicateContext:
    """Контекст проверки предусловий."""
    def __init__(self, req: PlanRequest, completed: set[str]) -> None:
        self.req = req
        self.completed = completed

    def completed(self, task_id: str) -> bool:
        return task_id in self.completed or task_id in set(self.req.profile.completed_tasks)

    def skill(self, name: str) -> int:
        return int(self.req.profile.skills.get(name, 0))

    def has(self, item: str, amount: float = 1.0) -> bool:
        return float(self.req.profile.inventory.get(item, 0.0)) >= amount

    def flag(self, key: str) -> bool:
        return bool(self.req.profile.flags.get(key, False))

    def cooldown_passed(self, task_id: str, seconds: int) -> bool:
        last = self.req.profile.cooldowns.get(task_id)
        if not last:
            return True
        return (self.req.now - last).total_seconds() >= seconds

def _safe_eval_predicate(expr: str, ctx: PredicateContext) -> bool:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ValueError(f"invalid predicate syntax: {e}")

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"disallowed expression node: {type(node).__name__}")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id not in {"completed", "skill", "has", "flag", "cooldown_passed"}:
                raise ValueError(f"disallowed function: {node.func.id}")

    env = {
        "completed": ctx.completed,
        "skill": ctx.skill,
        "has": ctx.has,
        "flag": ctx.flag,
        "cooldown_passed": ctx.cooldown_passed,
    }
    code = compile(tree, filename="<predicate>", mode="eval")
    return bool(eval(code, {"__builtins__": {}}, env))

# =============================================================================
# Ресурсная модель
# =============================================================================

@dataclass
class ResourceState:
    caps: Dict[str, float]
    used: Dict[str, float]

    def can_allocate(self, demands: Sequence[ResourceDemand]) -> tuple[bool, Optional[str]]:
        for d in demands:
            cap = self.caps.get(d.name, math.inf)
            if self.used.get(d.name, 0.0) + d.amount > cap + 1e-9:
                return (False, d.name)
        return (True, None)

    def allocate(self, demands: Sequence[ResourceDemand]) -> None:
        for d in demands:
            self.used[d.name] = self.used.get(d.name, 0.0) + d.amount

    def release(self, provides: Sequence[ResourceDemand]) -> None:
        for p in provides:
            self.used[p.name] = max(0.0, self.used.get(p.name, 0.0) - p.amount)

# =============================================================================
# Планировщик
# =============================================================================

class PlannerConfig(BaseModel):
    """Тонкая настройка поведения планировщика."""
    max_steps: int = 50
    prefer_mandatory: bool = True
    risk_aversion: float = 0.5     # 0..1 (1 — максимально избегать риска)
    travel_penalty: float = 0.2    # вес штрафа за перемещение
    deadline_penalty: float = 0.5  # штраф за нарушение мягкого дедлайна
    goal_bonus: float = 0.3        # бонус за соответствие целевым тегам
    min_utility_threshold: float = 0.01

class PlannerError(Exception):
    pass

class QuestPlanner:
    """Промышленный планировщик квестов."""

    def __init__(
        self,
        catalog: QuestCatalog,
        world: Optional[WorldAdapter] = None,
        timeline: Optional[TimelineLogger] = None,
        config: Optional[PlannerConfig] = None,
    ) -> None:
        self.catalog = catalog
        self.world = world or NullWorld()
        self.timeline = timeline or NullTimeline()
        self.config = config or PlannerConfig()
        self._lock = asyncio.Lock()
        self._idem_cache: Dict[str, QuestPlan] = {}

    # ----------------------------
    # Публичное API
    # ----------------------------

    async def plan(self, req: PlanRequest) -> QuestPlan:
        """Построить план. Идемпотентно при заданном idempotency_key."""
        cache_key = self._cache_key(req)
        async with self._lock:
            if cache_key and cache_key in self._idem_cache:
                return self._idem_cache[cache_key]

        tasks = await self.catalog.list_tasks(req.tenant_id, req.profile)
        validated = self._filter_and_validate(tasks, req)
        plan = await self._build_plan(req, validated)

        plan.etag = plan.compute_etag()
        await self._log(req, "plan.created", f"steps={len(plan.steps)} utility={plan.total_utility:.3f}", {
            "actor_id": req.profile.actor_id,
            "plan_id": plan.plan_id,
        })

        async with self._lock:
            if cache_key:
                self._idem_cache[cache_key] = plan

        return plan

    async def replan(self, req: PlanRequest, previous: QuestPlan) -> QuestPlan:
        """Перестроить план с учетом новых фактов, сохраняя уже выполненные шаги."""
        done = {s.task_id for s in previous.steps if s.end_at <= req.now}
        req2 = req.model_copy(deep=True)
        req2.profile.completed_tasks = list(set(req2.profile.completed_tasks) | done)
        return await self.plan(req2)

    # ----------------------------
    # Внутреннее
    # ----------------------------

    def _cache_key(self, req: PlanRequest) -> Optional[str]:
        if not req.idempotency_key:
            return None
        payload = {
            "tenant_id": req.tenant_id,
            "actor_id": req.profile.actor_id,
            "key": req.idempotency_key,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def _filter_and_validate(self, tasks: List[QuestTask], req: PlanRequest) -> Dict[str, QuestTask]:
        """Проверка корректности DAG и фильтрация по целям (жесткая фильтрация исключений)."""
        catalog: Dict[str, QuestTask] = {}
        for t in tasks:
            catalog[t.id] = t

        # Проверка зависимостей
        for t in catalog.values():
            for d in t.depends_on:
                if d not in catalog:
                    raise PlannerError(f"task '{t.id}' depends on unknown '{d}'")
            if t.id in t.depends_on:
                raise PlannerError(f"task '{t.id}' depends on itself")

        # Жестко исключаем по целям
        excl = set(req.goals.exclude_tasks)
        excl_tags = set(req.goals.exclude_tags)
        filtered: Dict[str, QuestTask] = {}
        for t in catalog.values():
            if t.id in excl:
                continue
            if excl_tags and set(t.tags) & excl_tags:
                continue
            filtered[t.id] = t
        return filtered

    async def _build_plan(self, req: PlanRequest, catalog: Dict[str, QuestTask]) -> QuestPlan:
        cfg = self.config
        res_state = ResourceState(caps=req.world.resource_caps, used={})
        completed = set(req.profile.completed_tasks)
        now = req.now
        deadline_hard = now + (req.world.time_budget or timedelta.max)

        # Топологическая сортировка по depends_on (чтобы знать порядок допуска)
        topo = self._topo_order(catalog)
        available: set[str] = set()  # кандидаты без неудовлетворенных зависимостей
        unmet_deps: Dict[str, set[str]] = {tid: set(catalog[tid].depends_on) for tid in catalog}
        for tid in topo:
            if not unmet_deps[tid]:
                available.add(tid)

        steps: List[ScheduledStep] = []
        cur_time = now
        cur_loc = req.profile.location
        reasons_global: List[str] = []

        # Жадный отбор
        for _ in range(cfg.max_steps):
            candidates = []
            for tid in list(available):
                task = catalog[tid]
                if tid in completed:
                    available.remove(tid)
                    continue
                ok, why_not = await self._admissible(task, req, res_state, cur_time, completed)
                if not ok:
                    continue
                score, expl = await self._score(task, req, cur_loc, cur_time, deadline_hard)
                if cfg.prefer_mandatory and task.mandatory:
                    score += 1.0  # жесткий приоритет
                    expl.append("bonus:mandatory")
                candidates.append((score, expl, task))

            if not candidates:
                break

            candidates.sort(key=lambda x: x[0], reverse=True)
            best_score, best_expl, task = candidates[0]
            if best_score < cfg.min_utility_threshold:
                reasons_global.append("stop:min_utility_threshold")
                break

            # Расписание: последовательное исполнение, учитывая time_window
            start_at, end_at = await self._schedule(cur_time, task)
            # Ресурсы
            res_state.allocate(task.requires)

            step = ScheduledStep(
                task_id=task.id,
                name=task.name,
                start_at=start_at,
                end_at=end_at,
                expected_utility=best_score,
                reasons=best_expl,
                resources_used={d.name: d.amount for d in task.requires},
                location=task.location,
            )
            steps.append(step)
            cur_time = end_at
            cur_loc = task.location or cur_loc
            completed.add(task.id)

            # Обновить зависящие
            for tid, deps in unmet_deps.items():
                deps.discard(task.id)
                if not deps:
                    available.add(tid)

            # Освобождение/предоставление ресурсов
            res_state.release(task.provides)

            # Прекращение по бюджету времени
            if cur_time > deadline_hard:
                reasons_global.append("stop:time_budget_exceeded")
                break

        total_utility = sum(s.expected_utility for s in steps)
        makespan = (steps[-1].end_at - steps[0].start_at) if steps else timedelta()
        plan = QuestPlan(
            plan_id=new_id(),
            tenant_id=req.tenant_id,
            actor_id=req.profile.actor_id,
            steps=steps,
            total_utility=total_utility,
            makespan=makespan,
            reasons=reasons_global,
        )
        return plan

    def _topo_order(self, catalog: Dict[str, QuestTask]) -> List[str]:
        indeg: Dict[str, int] = {tid: 0 for tid in catalog}
        graph: Dict[str, List[str]] = {tid: [] for tid in catalog}
        for t in catalog.values():
            for dep in t.depends_on:
                graph[dep].append(t.id)
                indeg[t.id] += 1
        # Kahn
        q = [tid for tid, d in indeg.items() if d == 0]
        out: List[str] = []
        while q:
            v = q.pop(0)
            out.append(v)
            for w in graph[v]:
                indeg[w] -= 1
                if indeg[w] == 0:
                    q.append(w)
        if len(out) != len(catalog):
            raise PlannerError("dependency cycle detected in quest catalog")
        return out

    async def _admissible(
        self,
        task: QuestTask,
        req: PlanRequest,
        res_state: ResourceState,
        cur_time: datetime,
        completed: set[str],
    ) -> tuple[bool, Optional[str]]:
        # Навыки
        for sk in task.skills:
            if req.profile.skills.get(sk.name, 0) < sk.min_level:
                return (False, f"skill:{sk.name}")

        # Кулдаун
        if task.cooldown_seconds > 0:
            last = req.profile.cooldowns.get(task.id)
            if last and (req.now - last).total_seconds() < task.cooldown_seconds:
                return (False, "cooldown")

        # Временное окно
        if task.time_window:
            if task.time_window.start and cur_time < task.time_window.start:
                return (False, "too_early")
            if task.time_window.end and cur_time > task.time_window.end:
                return (False, "too_late")

        # Ресурсы
        ok, blocker = res_state.can_allocate(task.requires)
        if not ok:
            return (False, f"resource:{blocker}")

        # Предикаты DSL
        if task.prerequisites_expr:
            ctx = PredicateContext(req, completed)
            try:
                ok = _safe_eval_predicate(task.prerequisites_expr, ctx)
            except ValueError as e:
                raise PlannerError(f"predicate error in task '{task.id}': {e}")
            if not ok:
                return (False, "predicate")

        return (True, None)

    async def _score(
        self,
        task: QuestTask,
        req: PlanRequest,
        cur_loc: Optional[str],
        cur_time: datetime,
        deadline_hard: datetime,
    ) -> tuple[float, List[str]]:
        cfg = self.config
        reasons: List[str] = []
        # Базовая полезность
        utility = float(task.reward)
        reasons.append(f"reward:{utility:.2f}")

        # Риск
        if task.risk > 0:
            penalty = cfg.risk_aversion * task.risk * utility
            utility -= penalty
            reasons.append(f"risk_penalty:{penalty:.2f}")

        # Стоимость путешествия
        travel = await self.world.travel_cost(cur_loc, task.location)
        if travel > 0:
            penalty = cfg.travel_penalty * travel
            utility -= penalty
            reasons.append(f"travel_penalty:{penalty:.2f}")

        # Дедлайн
        if task.soft_deadline and (cur_time + task.duration) > task.soft_deadline:
            overdue = (cur_time + task.duration - task.soft_deadline).total_seconds()
            penalty = cfg.deadline_penalty * (overdue / max(1.0, task.duration.total_seconds()))
            utility -= penalty
            reasons.append(f"deadline_penalty:{penalty:.2f}")

        # Соответствие целям
        goal_bonus = 0.0
        if req.goals.include_tasks and task.id in set(req.goals.include_tasks):
            goal_bonus += cfg.goal_bonus
        if req.goals.include_tags and (set(task.tags) & set(req.goals.include_tags)):
            goal_bonus += cfg.goal_bonus * 0.5
        if goal_bonus > 0:
            utility += goal_bonus
            reasons.append(f"goal_bonus:{goal_bonus:.2f}")

        return (utility, reasons)

    async def _schedule(self, cur_time: datetime, task: QuestTask) -> tuple[datetime, datetime]:
        start = cur_time
        tw = task.time_window
        if tw and tw.start and start < tw.start:
            start = tw.start
        end = start + task.duration
        return (start, end)

    async def _log(self, req: PlanRequest, title: str, message: str, labels: Dict[str, str]) -> None:
        try:
            await self.timeline.log(req.tenant_id, req.profile.actor_id, title, message, labels)
        except Exception:
            # Логирование не должно ломать планирование
            pass

# =============================================================================
# Пример простого использования (для документации; не исполняется автоматически)
# =============================================================================
"""
from mythos.quests.planner import (
    QuestPlanner, InMemoryCatalog, NullWorld, NullTimeline,
    QuestTask, ResourceDemand, SkillRequirement, TimeWindow,
    PlanRequest, PlayerProfile, WorldLimits, PlanGoal
)
from datetime import timedelta, datetime, timezone

tasks = [
    QuestTask(
        id="gather_berries",
        name="Собрать ягоды",
        tags=["gather", "food"],
        duration=timedelta(minutes=10),
        reward=3.0,
        risk=0.05,
        requires=[ResourceDemand(name="stamina", amount=1.0)],
        cooldown_seconds=600,
        location="forest",
    ),
    QuestTask(
        id="cook_jam",
        name="Сварить варенье",
        tags=["craft", "food"],
        duration=timedelta(minutes=15),
        reward=4.0,
        depends_on=["gather_berries"],
        prerequisites_expr="has('berries', 10) and skill('cooking')>=1",
        requires=[ResourceDemand(name='fuel', amount=1.0)],
        location="camp"
    ),
]

catalog = InMemoryCatalog(tasks)
planner = QuestPlanner(catalog, NullWorld(), NullTimeline())

req = PlanRequest(
    tenant_id="t1",
    profile=PlayerProfile(actor_id="u1", skills={"cooking": 1}, inventory={"berries": 12}),
    goals=PlanGoal(include_tags=["food"]),
    world=WorldLimits(resource_caps={"stamina": 2.0, "fuel": 1.0}, time_budget=timedelta(hours=1))
)

plan = await planner.plan(req)
print(plan.model_dump_json(indent=2, ensure_ascii=False))
"""
