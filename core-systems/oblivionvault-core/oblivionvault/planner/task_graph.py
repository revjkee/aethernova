# -*- coding: utf-8 -*-
"""
OblivionVault Core — Task Graph / Planner (industrial-grade)

Особенности:
- Типобезопасные Task/Dependency/Resources, состояния задач и ошибки планировщика
- Валидация DAG: отсутствие циклов, висячих зависимостей, дубликатов; подсказки по устранению
- Топологическая сортировка (Kahn), вычисление критического пути (longest path по оценкам длительности)
- Построение батчей исполнения с учетом:
  * глобального max_concurrency
  * лимитов ресурсов (cpu/mem/io/gpu и произвольные ключи)
  * per-key concurrency (concurrency_key -> max_parallel)
  * anti-affinity (запрет одновременного запуска задач с одинаковым ключом)
  * барьеров (этапы/стадии; задачи следующих стадий не стартуют, пока не завершены все предыдущие)
  * предикатов/условий выполнения (безопасная оценка)
- Инкрементальный пересчет: dirty-пропагация от изменившихся задач/артефактов
- Сериализация в детерминированный JSON + стабильный SHA256 хэш для кэширования/идемпотентности
- События переходов состояний (hook-и) и базовый runtime-интерфейс (без привязки к конкретному исполнителю)

Зависимости: только стандартная библиотека.
Совместимость: Python 3.10+
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple


# =========================
# Ошибки планировщика
# =========================

class PlannerError(Exception):
    """Базовая ошибка планировщика."""


class ValidationError(PlannerError):
    """Ошибка валидации графа задач."""


class SchedulingError(PlannerError):
    """Ошибка построения расписания/батчей."""


# =========================
# Модель ресурсов и задач
# =========================

@dataclass(frozen=True)
class Resources:
    """Абстрактные ресурсы. Значения — неотрицательные числа."""
    cpu: float = 0.0
    mem: float = 0.0     # в МБ или ГБ — единицы задаёт вызывающий код
    io: float = 0.0
    gpu: float = 0.0
    extra: Mapping[str, float] = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        for k, v in [("cpu", self.cpu), ("mem", self.mem), ("io", self.io), ("gpu", self.gpu)]:
            if v < 0:
                raise ValidationError(f"Resource {k} must be >= 0")
        for k, v in self.extra.items():
            if v < 0:
                raise ValidationError(f"Resource '{k}' must be >= 0")

    def plus(self, other: "Resources") -> "Resources":
        ex = defaultdict(float, {**self.extra})
        for k, v in other.extra.items():
            ex[k] += v
        return Resources(
            cpu=self.cpu + other.cpu,
            mem=self.mem + other.mem,
            io=self.io + other.io,
            gpu=self.gpu + other.gpu,
            extra=dict(ex),
        )

    def leq(self, cap: "Resources") -> bool:
        """Сравнение с лимитами (<= для всех ключей)."""
        if self.cpu > cap.cpu or self.mem > cap.mem or self.io > cap.io or self.gpu > cap.gpu:
            return False
        for k, v in self.extra.items():
            if v > cap.extra.get(k, 0.0):
                return False
        # любая доп. квота в cap.extra не препятствие
        return True


class EdgeKind(str, Enum):
    HARD = "hard"   # строгая зависимость: A завершился -> можно B
    SOFT = "soft"   # мягкая (предпочтительная), не участвует в топологии


@dataclass(frozen=True)
class Dependency:
    """Зависимость A -> B."""
    upstream: str
    downstream: str
    kind: EdgeKind = EdgeKind.HARD
    note: Optional[str] = None


class TaskState(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    CANCELED = "CANCELED"


ConditionFunc = Callable[[Mapping[str, Any]], bool]


def _compile_condition(expr: Optional[str]) -> Optional[ConditionFunc]:
    """
    Компилирует безопасное булево выражение (подмножество Python) в функцию.
    Доступны только литералы, сравнения, логика, обращения к переменным из контекста.
    """
    if not expr:
        return None

    tree = ast.parse(expr, mode="eval")

    allowed_nodes = (
        ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare,
        ast.Name, ast.Load, ast.Constant, ast.And, ast.Or, ast.Not,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
        ast.Is, ast.IsNot
    )

    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            raise ValidationError(f"Unsupported expression node: {type(node).__name__}")

    code = compile(tree, "<cond>", "eval")

    def _fn(ctx: Mapping[str, Any]) -> bool:
        return bool(eval(code, {"__builtins__": {}}, dict(ctx)))

    return _fn


@dataclass
class Task:
    """Описатель задачи в графе."""
    id: str
    name: Optional[str] = None
    estimate_ms: int = 0                      # оценка длительности, для critical path
    resources: Resources = field(default_factory=Resources)
    labels: Dict[str, str] = field(default_factory=dict)

    # Условия и барьеры
    condition: Optional[str] = None           # безопасное выражение (ctx -> bool)
    barrier_stage: int = 0                    # номер стадии/барьера (0..N)

    # Ограничители параллелизма
    concurrency_key: Optional[str] = None     # ключ (например, "tenant:prod")
    concurrency_limit: int = 1                # макс. задач с этим ключом одновременно
    anti_affinity_key: Optional[str] = None   # запрет одновременного запуска с тем же ключом

    # Ретраи и таймауты (для рантайма)
    retries: int = 0
    backoff_sec: float = 0.0
    timeout_sec: Optional[float] = None

    # Артефакты/инпуты — для dirty-пропагации (произвольные идентификаторы)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)

    def compiled_condition(self) -> Optional[ConditionFunc]:
        return _compile_condition(self.condition)


# =========================
# Граф задач
# =========================

class TaskGraph:
    """DAG задач с жесткими и мягкими зависимостями."""

    def __init__(self) -> None:
        self.tasks: Dict[str, Task] = {}
        self.edges: List[Dependency] = []
        self._in: Dict[str, Set[str]] = defaultdict(set)   # входящие (hard)
        self._out: Dict[str, Set[str]] = defaultdict(set)  # исходящие (hard)
        self._soft_in: Dict[str, Set[str]] = defaultdict(set)
        self._soft_out: Dict[str, Set[str]] = defaultdict(set)

    # ---- построение ----
    def add_task(self, task: Task) -> "TaskGraph":
        if task.id in self.tasks:
            raise ValidationError(f"Duplicate task id: {task.id}")
        self.tasks[task.id] = task
        return self

    def add_dependency(self, dep: Dependency) -> "TaskGraph":
        if dep.upstream == dep.downstream:
            raise ValidationError("Self-dependency is not allowed")
        if dep.kind == EdgeKind.HARD:
            self._out[dep.upstream].add(dep.downstream)
            self._in[dep.downstream].add(dep.upstream)
        else:
            self._soft_out[dep.upstream].add(dep.downstream)
            self._soft_in[dep.downstream].add(dep.upstream)
        self.edges.append(dep)
        return self

    # ---- валидация ----
    def validate(self) -> None:
        # существование узлов
        missing: Set[str] = set()
        for e in self.edges:
            if e.upstream not in self.tasks:
                missing.add(e.upstream)
            if e.downstream not in self.tasks:
                missing.add(e.downstream)
        if missing:
            raise ValidationError(f"Dependencies reference unknown tasks: {sorted(missing)}")

        # нет висячих задач без исходных ребер? (разрешено, но предупреждение можно оставить вызывающему коду)

        # циклы
        cycles = self._find_cycles()
        if cycles:
            raise ValidationError(f"Cycle(s) detected: {cycles}")

        # барьерные стадии должны возрастать вдоль hard-ребер
        for u, vs in self._out.items():
            su = self.tasks[u].barrier_stage
            for v in vs:
                sv = self.tasks[v].barrier_stage
                if sv < su:
                    raise ValidationError(
                        f"Barrier stage of '{v}' ({sv}) < '{u}' ({su}). Stages must be non-decreasing along HARD edges."
                    )

        # concurrency_limit корректен
        for t in self.tasks.values():
            if t.concurrency_limit < 1:
                raise ValidationError(f"Task {t.id}: concurrency_limit must be >=1")

    def _find_cycles(self) -> List[List[str]]:
        indeg = {k: len(self._in.get(k, set())) for k in self.tasks.keys()}
        q = deque([n for n, d in indeg.items() if d == 0])
        visited = 0
        while q:
            n = q.popleft()
            visited += 1
            for m in self._out.get(n, set()):
                indeg[m] -= 1
                if indeg[m] == 0:
                    q.append(m)
        if visited == len(self.tasks):
            return []
        # Восстановление хотя бы одного цикла (приблизительно)
        return [["<cycle>"]]

    # ---- топология/критический путь ----
    def topo_order(self) -> List[str]:
        self.validate()
        indeg = {k: len(self._in.get(k, set())) for k in self.tasks.keys()}
        q = deque(sorted([n for n, d in indeg.items() if d == 0]))
        order: List[str] = []
        while q:
            n = q.popleft()
            order.append(n)
            for m in self._out.get(n, set()):
                indeg[m] -= 1
                if indeg[m] == 0:
                    q.append(m)
        if len(order) != len(self.tasks):
            raise ValidationError("Graph has cycles (topo_order)")
        return order

    def critical_path(self) -> Tuple[int, List[str]]:
        """
        Возвращает (total_estimate_ms, path_ids). Если оценки нулевые, путь определяется количеством узлов.
        """
        order = self.topo_order()
        dist: Dict[str, int] = {t: -10**18 for t in self.tasks}
        prev: Dict[str, Optional[str]] = {t: None for t in self.tasks}
        for t in order:
            if len(self._in.get(t, set())) == 0:
                dist[t] = max(dist[t], self.tasks[t].estimate_ms)

            for u in self._in.get(t, set()):
                cand = dist[u] + max(1, self.tasks[t].estimate_ms)
                if cand > dist[t]:
                    dist[t] = cand
                    prev[t] = u

        # конец пути — узел с max dist
        end = max(dist, key=lambda k: dist[k])
        total = max(0, dist[end])
        path = []
        cur: Optional[str] = end
        while cur:
            path.append(cur)
            cur = prev[cur]
        path.reverse()
        return total, path

    # ---- сериализация/хэш ----
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tasks": [self._task_to_json(t) for t in self.tasks.values()],
            "edges": [dataclasses.asdict(e) for e in self.edges],
        }

    @staticmethod
    def _task_to_json(t: Task) -> Dict[str, Any]:
        d = asdict(t)
        # resources.extra — обычный dict
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskGraph":
        g = cls()
        for td in data.get("tasks", []):
            # аккуратно собираем dataclass обратно
            res = td.get("resources", {}) or {}
            r = Resources(
                cpu=float(res.get("cpu", 0.0)),
                mem=float(res.get("mem", 0.0)),
                io=float(res.get("io", 0.0)),
                gpu=float(res.get("gpu", 0.0)),
                extra=dict(res.get("extra", {}) or {}),
            )
            t = Task(
                id=td["id"],
                name=td.get("name"),
                estimate_ms=int(td.get("estimate_ms", 0)),
                resources=r,
                labels=dict(td.get("labels", {}) or {}),
                condition=td.get("condition"),
                barrier_stage=int(td.get("barrier_stage", 0)),
                concurrency_key=td.get("concurrency_key"),
                concurrency_limit=int(td.get("concurrency_limit", 1)),
                anti_affinity_key=td.get("anti_affinity_key"),
                retries=int(td.get("retries", 0)),
                backoff_sec=float(td.get("backoff_sec", 0.0)),
                timeout_sec=td.get("timeout_sec"),
                inputs=list(td.get("inputs", []) or []),
                outputs=list(td.get("outputs", []) or []),
            )
            g.add_task(t)
        for ed in data.get("edges", []):
            g.add_dependency(Dependency(
                upstream=ed["upstream"],
                downstream=ed["downstream"],
                kind=EdgeKind(ed.get("kind", "hard")),
                note=ed.get("note"),
            ))
        return g

    def stable_hash(self) -> str:
        """Детерминированный SHA256 контента графа."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    # ---- dirty-пропагация ----
    def affected_subgraph(self, changed: Iterable[str]) -> Set[str]:
        """
        Возвращает множество task.id, зависящих от заданных артефактов/задач.
        Вход: список либо task.id, либо output-артефакты (совпадают с Task.outputs).
        """
        changed_set = set(changed)
        # начальные задачи по совпадению либо id, либо outputs
        start: Set[str] = set()
        for tid, t in self.tasks.items():
            if tid in changed_set or (set(t.outputs) & changed_set):
                start.add(tid)

        # обход вниз по hard-ребрам
        q = deque(start)
        seen = set(start)
        while q:
            u = q.popleft()
            for v in self._out.get(u, set()):
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        return seen


# =========================
# Планировщик батчей
# =========================

@dataclass
class ScheduleConfig:
    max_concurrency: int = 16
    capacity: Resources = field(default_factory=lambda: Resources(cpu=math.inf, mem=math.inf, io=math.inf, gpu=math.inf))
    # per-key лимиты: concurrency_key -> max_parallel
    per_key_limits: Mapping[str, int] = field(default_factory=dict)


@dataclass
class Batch:
    """Набор задач, которые можно выполнить параллельно при соблюдении ограничений."""
    index: int
    tasks: List[str]
    resources_sum: Resources
    stage: int


class Scheduler:
    """Строит батчи исполнения, учитывая ресурсы, барьеры, аффинность и условия."""

    def __init__(self, graph: TaskGraph) -> None:
        self.g = graph
        self.g.validate()

    def build_batches(
        self,
        cfg: ScheduleConfig,
        *,
        context: Optional[Mapping[str, Any]] = None,
        only_tasks: Optional[Iterable[str]] = None,
        fail_on_unplaceable: bool = True,
    ) -> List[Batch]:
        """
        Возвращает список параллельных батчей (в волнах), где каждая волна удовлетворяет:
        - топологическим ограничениям (HARD deps)
        - барьерным стадиям
        - лимитам ресурсов и параллелизма
        - условиям задач (condition == True)
        """
        if context is None:
            context = {}

        # Подмножество задач
        allowed: Optional[Set[str]] = set(only_tasks) if only_tasks else None

        # indegree по HARD
        indeg: Dict[str, int] = {tid: len(self.g._in.get(tid, set())) for tid in self.g.tasks}
        done: Set[str] = set()
        scheduled: Set[str] = set()
        ready: Set[str] = set()

        # вычисляем стартовый ready
        for tid, deg in indeg.items():
            if deg == 0:
                ready.add(tid)

        # отфильтруем по условиям
        def cond_ok(t: Task) -> bool:
            fn = t.compiled_condition()
            return True if fn is None else fn(context)

        batches: List[Batch] = []
        stage = 0

        # Помощники для per-key ограничений и anti-affinity
        def can_place(current: List[str], add: str, res_sum: Resources, limits: Mapping[str, int]) -> bool:
            t = self.g.tasks[add]
            # ресурсы
            new_sum = res_sum.plus(t.resources)
            if not new_sum.leq(cfg.capacity):
                return False
            if len(current) + 1 > cfg.max_concurrency:
                return False
            # per-key limit
            if t.concurrency_key:
                maxp = limits.get(t.concurrency_key, t.concurrency_limit)
                if sum(1 for x in current if self.g.tasks[x].concurrency_key == t.concurrency_key) + 1 > maxp:
                    return False
            # anti-affinity
            if t.anti_affinity_key and any(self.g.tasks[x].anti_affinity_key == t.anti_affinity_key for x in current):
                return False
            return True

        # Основной цикл стадий (barrier_stage)
        max_stage = max((t.barrier_stage for t in self.g.tasks.values()), default=0)
        while stage <= max_stage:
            # в рамках текущей стадии отбираем задачи с barrier_stage == stage
            stage_ready: Set[str] = {tid for tid in ready
                                     if self.g.tasks[tid].barrier_stage == stage
                                     and tid not in scheduled
                                     and (allowed is None or tid in allowed)
                                     and cond_ok(self.g.tasks[tid])}

            # пока добавляются батчи в этой стадии
            while stage_ready:
                batch_tasks: List[str] = []
                res_sum = Resources()

                # жадно набираем задачи
                # сортировка: по убыванию estimate_ms, затем по id для детерминизма
                candidates = sorted(stage_ready, key=lambda x: (-self.g.tasks[x].estimate_ms, x))
                for tid in candidates:
                    if tid in batch_tasks:
                        continue
                    if can_place(batch_tasks, tid, res_sum, cfg.per_key_limits):
                        batch_tasks.append(tid)
                        res_sum = res_sum.plus(self.g.tasks[tid].resources)

                if not batch_tasks:
                    # ни одна задача не помещается — dead-end
                    if fail_on_unplaceable:
                        raise SchedulingError(
                            f"Cannot place any task at stage {stage} with current capacity/limits. "
                            f"Consider raising capacity or splitting stage."
                        )
                    # иначе выходим из стадии
                    break

                # фиксируем батч
                b = Batch(index=len(batches), tasks=batch_tasks, resources_sum=res_sum, stage=stage)
                batches.append(b)

                # помечаем задачи как завершенные для разблокировки зависимостей
                for tid in batch_tasks:
                    scheduled.add(tid)
                    done.add(tid)
                    for v in self.g._out.get(tid, set()):
                        indeg[v] -= 1
                        if indeg[v] == 0:
                            ready.add(v)

                # обновляем stage_ready (могли разблокироваться новые задачи той же стадии)
                stage_ready = {tid for tid in ready
                               if self.g.tasks[tid].barrier_stage == stage
                               and tid not in scheduled
                               and (allowed is None or tid in allowed)
                               and cond_ok(self.g.tasks[tid])}

            # переход к следующей стадии
            stage += 1

        # проверим, всё ли запланировано (включая задачи следующих стадий, появившиеся из-за условий)
        remaining = [tid for tid in self.g.tasks if tid not in scheduled and (allowed is None or tid in allowed)]
        if remaining:
            # некоторые могли быть неразблокированы из-за условий false — это допустимо
            unresolved = [tid for tid in remaining if indeg.get(tid, 0) == 0 and cond_ok(self.g.tasks[tid])]
            if unresolved:
                raise SchedulingError(f"Unscheduled ready tasks remain: {unresolved}")

        return batches


# =========================
# FSM состояний (минимальный рантайм-интерфейс)
# =========================

TransitionHook = Callable[[str, TaskState, TaskState, Mapping[str, Any]], None]


class StateMachine:
    """
    Простейшая машина состояний задач с хуками переходов и зависимостью от графа.
    Не исполняет задачи, а только управляет готовностью/блокировкой.
    """

    def __init__(self, graph: TaskGraph) -> None:
        self.g = graph
        self.state: Dict[str, TaskState] = {tid: TaskState.PENDING for tid in self.g.tasks}
        self.hooks: List[TransitionHook] = []
        self._indeg: Dict[str, int] = {tid: len(self.g._in.get(tid, set())) for tid in self.g.tasks}

    def add_hook(self, fn: TransitionHook) -> None:
        self.hooks.append(fn)

    def _emit(self, tid: str, old: TaskState, new: TaskState, ctx: Mapping[str, Any]) -> None:
        for h in self.hooks:
            try:
                h(tid, old, new, ctx)
            except Exception:
                # хук не должен валить планировщик
                pass

    def ready_set(self) -> List[str]:
        """Возвращает список задач, готовых к запуску (topo-ready и не запущенных)."""
        out = []
        for tid, st in self.state.items():
            if st == TaskState.PENDING and self._indeg.get(tid, 0) == 0:
                out.append(tid)
        return sorted(out)

    def set_state(self, tid: str, new_state: TaskState, *, ctx: Optional[Mapping[str, Any]] = None) -> None:
        if tid not in self.state:
            raise PlannerError(f"Unknown task '{tid}'")
        old = self.state[tid]
        self.state[tid] = new_state
        self._emit(tid, old, new_state, ctx or {})

        # разблокировка downstream по SUCCESS
        if new_state == TaskState.SUCCESS:
            for v in self.g._out.get(tid, set()):
                self._indeg[v] -= 1

        # блокировка downstream по FAILED (fail-fast)
        if new_state == TaskState.FAILED:
            for v in self.g._out.get(tid, set()):
                if self.state[v] == TaskState.PENDING:
                    self.state[v] = TaskState.BLOCKED
                    self._emit(v, TaskState.PENDING, TaskState.BLOCKED, ctx or {})


# =========================
# Пример самопроверки
# =========================

if __name__ == "__main__":  # pragma: no cover
    # Небольшой smoke-test
    g = TaskGraph()
    g.add_task(Task(id="A", estimate_ms=100, resources=Resources(cpu=1)))
    g.add_task(Task(id="B", estimate_ms=200, resources=Resources(cpu=1), barrier_stage=0))
    g.add_task(Task(id="C", estimate_ms=300, resources=Resources(cpu=2), barrier_stage=1, concurrency_key="tenant:1"))
    g.add_task(Task(id="D", estimate_ms=50,  resources=Resources(cpu=1), barrier_stage=1, concurrency_key="tenant:1"))
    g.add_dependency(Dependency(upstream="A", downstream="C"))
    g.add_dependency(Dependency(upstream="B", downstream="C"))
    g.add_dependency(Dependency(upstream="C", downstream="D"))

    g.validate()
    total, path = g.critical_path()
    print("critical_path:", total, path)
    cfg = ScheduleConfig(max_concurrency=2, capacity=Resources(cpu=3))
    batches = Scheduler(g).build_batches(cfg)
    for b in batches:
        print(f"batch[{b.index}] stage={b.stage} -> {b.tasks}, cpu={b.resources_sum.cpu}")
    print("hash:", g.stable_hash())
