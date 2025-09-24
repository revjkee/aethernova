# omnimind-core/ops/omnimind/planner/graph_planner.py
from __future__ import annotations

import heapq
import json
import logging
import math
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

# --------------------------------------------------------------------------------------
# Логирование
# --------------------------------------------------------------------------------------
LOG = logging.getLogger("omnimind.planner")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# --------------------------------------------------------------------------------------
# Исключения
# --------------------------------------------------------------------------------------
class PlannerError(Exception):
    pass


class ValidationError(PlannerError):
    pass


class CycleError(ValidationError):
    pass


# --------------------------------------------------------------------------------------
# Доменные сущности
# --------------------------------------------------------------------------------------
@dataclass(slots=True)
class RetryPolicy:
    max_retries: int = 0
    backoff_initial_s: float = 1.0
    backoff_multiplier: float = 2.0
    backoff_max_s: float = 60.0


ConditionFn = Callable[[Dict[str, Any]], bool]


@dataclass(slots=True)
class Task:
    """
    Базовая задача DAG.

    id: уникальный идентификатор.
    name: произвольное имя.
    duration_s: продолжительность в секундах (детерминированная оценка для планирования).
    deps: зависимости (id задач, которые должны завершиться раньше).
    priority: больший приоритет — раньше в очереди.
    resources: требования по ресурсам {имя: количество}; сравниваются с общим capacity.
    earliest_start_s: не начинать раньше этого времени (относительно t0 расписания).
    deadline_s: должен завершиться не позже (относительно t0 расписания).
    condition: если задана и возвращает False — задача пропускается.
    retry: метаданные, не влияют на планирование времени, но доступны потребителям результата.
    meta: произвольные дополнительные атрибуты.
    """
    id: str
    name: str
    duration_s: float
    deps: Set[str] = field(default_factory=set)
    priority: int = 0
    resources: Dict[str, float] = field(default_factory=dict)
    earliest_start_s: Optional[float] = None
    deadline_s: Optional[float] = None
    condition: Optional[ConditionFn] = None
    retry: Optional[RetryPolicy] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.duration_s < 0:
            raise ValidationError(f"Task {self.id}: negative duration")
        for k, v in self.resources.items():
            if v < 0:
                raise ValidationError(f"Task {self.id}: negative resource '{k}' = {v}")


@dataclass(slots=True)
class ScheduleEntry:
    task_id: str
    start_s: Optional[float]  # None, если пропущена
    end_s: Optional[float]    # None, если пропущена
    skipped: bool = False
    reason: Optional[str] = None  # причина пропуска/нарушения дедлайна и т. п.


@dataclass(slots=True)
class PlanResult:
    """
    Результат планирования.
    """
    schedule: Dict[str, ScheduleEntry]            # task_id -> entry
    ordered: List[str]                            # топологический порядок
    stages: List[List[str]]                       # уровни конвейера (по топо-уровню)
    critical_path: List[str]                      # список id на критическом пути
    makespan_s: float                             # длительность всего плана
    capacity: Dict[str, float]                    # использованная конфигурация ресурсов
    violations: List[str]                         # текстовые описания нарушений


# --------------------------------------------------------------------------------------
# Планировщик
# --------------------------------------------------------------------------------------
class GraphPlanner:
    def __init__(self, tasks: Optional[Iterable[Task]] = None, *, treat_skipped_as_satisfied: bool = True) -> None:
        self._tasks: Dict[str, Task] = {}
        self.treat_skipped_as_satisfied = treat_skipped_as_satisfied
        if tasks:
            for t in tasks:
                self.add_task(t)

    # --------------- CRUD ---------------
    def add_task(self, task: Task) -> None:
        if task.id in self._tasks:
            raise ValidationError(f"Task id not unique: {task.id}")
        self._tasks[task.id] = task

    def remove_task(self, task_id: str) -> None:
        if task_id in self._tasks:
            del self._tasks[task_id]
            for t in self._tasks.values():
                t.deps.discard(task_id)

    def get_task(self, task_id: str) -> Task:
        return self._tasks[task_id]

    def tasks(self) -> List[Task]:
        return list(self._tasks.values())

    # --------------- Валидация и топология ---------------
    def validate(self) -> None:
        if not self._tasks:
            raise ValidationError("No tasks to plan")
        # неизвестные зависимости
        for t in self._tasks.values():
            for d in t.deps:
                if d not in self._tasks:
                    raise ValidationError(f"Task {t.id}: unknown dependency '{d}'")
            if t.deadline_s is not None and t.earliest_start_s is not None:
                if t.deadline_s < t.earliest_start_s:
                    raise ValidationError(f"Task {t.id}: deadline before earliest_start")
        # циклы
        self._assert_acyclic()

    def _assert_acyclic(self) -> None:
        indeg = {tid: 0 for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                indeg[t.id] += 1
        q = [tid for tid, deg in indeg.items() if deg == 0]
        seen = 0
        adj = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                adj[d].add(t.id)
        while q:
            u = q.pop()
            seen += 1
            for v in adj[u]:
                indeg[v] -= 1
                if indeg[v] == 0:
                    q.append(v)
        if seen != len(self._tasks):
            raise CycleError("Dependency graph contains a cycle")

    def toposort(self) -> List[str]:
        indeg = {tid: 0 for tid in self._tasks}
        adj: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                adj[d].add(t.id)
                indeg[t.id] += 1
        # стабильная сортировка: по приоритету, затем по id (детерминированность)
        heap: List[Tuple[int, str]] = []
        for tid, deg in indeg.items():
            if deg == 0:
                # мин-куча: используем отрицание приоритета, чтобы больший приоритет выходил раньше
                heapq.heappush(heap, (-self._tasks[tid].priority, tid))
        out: List[str] = []
        while heap:
            _, u = heapq.heappop(heap)
            out.append(u)
            for v in sorted(adj[u]):  # стабильность
                indeg[v] -= 1
                if indeg[v] == 0:
                    heapq.heappush(heap, (-self._tasks[v].priority, v))
        if len(out) != len(self._tasks):
            raise CycleError("Dependency graph contains a cycle")
        return out

    def stages(self) -> List[List[str]]:
        """
        Уровни DAG (длина наибольшего пути от истока), полезно для конвейерных стадий.
        """
        order = self.toposort()
        level: Dict[str, int] = {tid: 0 for tid in self._tasks}
        for u in order:
            lu = level[u]
            for v in (x.id for x in self._tasks.values() if u in x.deps):
                level[v] = max(level[v], lu + 1)
        maxlvl = max(level.values(), default=0)
        buckets: List[List[str]] = [[] for _ in range(maxlvl + 1)]
        for tid, lv in level.items():
            buckets[lv].append(tid)
        for b in buckets:
            b.sort()
        return buckets

    def critical_path(self) -> Tuple[float, List[str]]:
        """
        Наибольшая суммарная длительность (makespan нижней границы) и список задач на критическом пути.
        """
        order = self.toposort()
        # граф смежности по deps (u -> v)
        succ: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        pred: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                succ[d].add(t.id)
                pred[t.id].add(d)
        dist: Dict[str, float] = {tid: 0.0 for tid in self._tasks}
        # классический DP по ациклическому графу
        for u in order:
            du = self._tasks[u].duration_s
            for v in succ[u]:
                dist[v] = max(dist[v], dist[u] + du)
        # завершаем на вершинах-стоках
        makespan = 0.0
        sink = None
        for tid in self._tasks:
            if not succ[tid]:
                val = dist[tid] + self._tasks[tid].duration_s
                if val > makespan:
                    makespan = val
                    sink = tid
        # восстановление пути
        path: List[str] = []
        if sink is not None:
            cur = sink
            while True:
                path.append(cur)
                # ищем предшественника, давшего максимум
                if not pred[cur]:
                    break
                best = None
                best_val = -math.inf
                for p in pred[cur]:
                    val = dist[p] + self._tasks[p].duration_s
                    if math.isclose(val, dist[cur], rel_tol=1e-9) or val == dist[cur]:
                        if val > best_val:
                            best_val = val
                            best = p
                if best is None:
                    break
                cur = best
            path.reverse()
        return makespan, path

    # --------------- Расписание с ограничениями ресурсов ---------------
    def schedule(
        self,
        capacity: Dict[str, float],
        *,
        t0_s: float = 0.0,
        context: Optional[Dict[str, Any]] = None,
    ) -> PlanResult:
        """
        Простое событийное расписание с ограничениями ресурсов.
        Алгоритм:
          - поддерживает пропуски (condition=False);
          - задачи готовы, когда все зависимости уже завершены или пропущены;
          - выбор задач: приоритет (desc), потом критичность (длина до стока), потом id;
          - ресурсы: требования не должны превышать свободную емкость;
          - если ничего не стартует — перемещаем «время» к ближайшему завершению или к минимальному earliest_start.
        """
        self.validate()

        context = context or {}
        # оценка критичности: расстояние до стока (по длительности)
        # для эвристики сортировки (чем больше — тем критичнее)
        crit_score = self._criticality_scores()

        # предвычисления
        order = self.toposort()
        deps_of: Dict[str, Set[str]] = {t.id: set(t.deps) for t in self._tasks.values()}
        children: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                children[d].add(t.id)

        # пропуски по условию
        skipped: Set[str] = set()
        for tid in order:
            t = self._tasks[tid]
            if t.condition is not None:
                try:
                    ok = bool(t.condition(context))
                except Exception as e:
                    LOG.warning("condition error for %s: %s", tid, e)
                    ok = False
                if not ok:
                    skipped.add(tid)

        # готовность зависимостей (учитываем политику treat_skipped_as_satisfied)
        pending: Set[str] = set(self._tasks.keys()) - skipped
        scheduled: Dict[str, ScheduleEntry] = {}
        for tid in skipped:
            scheduled[tid] = ScheduleEntry(task_id=tid, start_s=None, end_s=None, skipped=True, reason="condition=false")

        # ресурсы (текущее использование)
        used: Dict[str, float] = {k: 0.0 for k in capacity}
        # события завершения: (end_time, task_id)
        running: List[Tuple[float, str]] = []
        heapq.heapify(running)

        now = float(t0_s)
        violations: List[str] = []

        def deps_satisfied(tid: str) -> bool:
            ds = deps_of[tid]
            if not ds:
                return True
            for d in ds:
                e = scheduled.get(d)
                if not e:
                    return False
                if e.skipped and not self.treat_skipped_as_satisfied:
                    return False
                if (not e.skipped) and (e.end_s is None):
                    return False
            return True

        def earliest_allowed(tid: str) -> float:
            t = self._tasks[tid]
            return t.earliest_start_s if t.earliest_start_s is not None else t0_s

        def can_start(tid: str) -> bool:
            t = self._tasks[tid]
            # ресурсная проверка
            for r, need in t.resources.items():
                cap = capacity.get(r, 0.0)
                if need > (cap - used.get(r, 0.0) + 1e-9):
                    return False
            return True

        def allocate(tid: str) -> None:
            for r, need in self._tasks[tid].resources.items():
                used[r] = used.get(r, 0.0) + need

        def release(tid: str) -> None:
            for r, need in self._tasks[tid].resources.items():
                used[r] = used.get(r, 0.0) - need
                if used[r] < 0:
                    used[r] = 0.0

        # основной цикл
        while pending or running:
            # 1) перевести время к ближайшему событию, если нечего запускать сейчас
            ready_now = [
                tid for tid in list(pending)
                if deps_satisfied(tid) and earliest_allowed(tid) <= now
            ]

            # сортировка ready: приоритет desc, критичность desc, id asc
            ready_now.sort(
                key=lambda tid: (
                    -self._tasks[tid].priority,
                    -crit_score.get(tid, 0.0),
                    tid,
                )
            )

            started_any = False
            for tid in ready_now:
                if not can_start(tid):
                    continue
                # стартуем
                t = self._tasks[tid]
                allocate(tid)
                start = now
                end = start + t.duration_s
                scheduled[tid] = ScheduleEntry(task_id=tid, start_s=start, end_s=end, skipped=False)
                heapq.heappush(running, (end, tid))
                pending.discard(tid)
                started_any = True

            if started_any:
                # попробуем запустить ещё на этой же отметке времени — цикл повторится
                continue

            # 2) Нечего стартовать прямо сейчас. Сдвигаем время.
            if running:
                end_time, tid = heapq.heappop(running)
                # если между now и end_time были ready, они не могли стартовать по ресурсам/окнам
                now = max(now, end_time)
                release(tid)
                # дедлайн
                t = self._tasks[tid]
                if t.deadline_s is not None and scheduled[tid].end_s and scheduled[tid].end_s > t.deadline_s + t0_s:
                    violations.append(f"deadline missed: {tid} ends at {scheduled[tid].end_s}, deadline={t.deadline_s + t0_s}")
                continue

            # 3) Нет running. Значит ограничения по earliest_start.
            if pending:
                next_time = min(earliest_allowed(tid) for tid in pending if deps_satisfied(tid))
                if math.isfinite(next_time):
                    now = max(now, next_time)
                    continue

            # 4) Ничего не можем сделать — тупик (должно быть невозможно при корректном DAG)
            if pending:
                raise PlannerError(f"Stuck with pending tasks: {sorted(pending)}")

        makespan = 0.0
        for e in scheduled.values():
            if not e.skipped and e.end_s is not None:
                makespan = max(makespan, e.end_s - t0_s)

        # уровни и критический путь
        stages = self.stages()
        cp_len, cp_path = self.critical_path()
        return PlanResult(
            schedule=scheduled,
            ordered=self.toposort(),
            stages=stages,
            critical_path=cp_path,
            makespan_s=makespan,
            capacity=dict(capacity),
            violations=violations,
        )

    # --------------- Помощники / экспорты ---------------
    def _criticality_scores(self) -> Dict[str, float]:
        """
        Оценка «критичности» узла как длина (по времени) до стока.
        """
        order = list(reversed(self.toposort()))
        pred: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        succ: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                pred[t.id].add(d)
                succ[d].add(t.id)
        score = {tid: self._tasks[tid].duration_s for tid in self._tasks}
        for u in order:
            for p in pred[u]:
                score[p] = max(score[p], self._tasks[p].duration_s + score[u])
        return score

    def to_json(self) -> str:
        data = {
            "tasks": [self._task_to_dict(t) for t in self._tasks.values()],
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _task_to_dict(self, t: Task) -> Dict[str, Any]:
        d = asdict(t)
        # condition/retry сериализуем аккуратно
        d["deps"] = sorted(list(t.deps))
        if t.condition is not None:
            d["condition"] = getattr(t.condition, "__name__", "callable")
        if t.retry is not None:
            d["retry"] = asdict(t.retry)
        return d

    @staticmethod
    def plan_to_json(plan: PlanResult) -> str:
        out = {
            "ordered": plan.ordered,
            "stages": plan.stages,
            "critical_path": plan.critical_path,
            "makespan_s": plan.makespan_s,
            "capacity": plan.capacity,
            "violations": plan.violations,
            "schedule": {
                tid: {
                    "start_s": e.start_s,
                    "end_s": e.end_s,
                    "skipped": e.skipped,
                    "reason": e.reason,
                }
                for tid, e in plan.schedule.items()
            },
        }
        return json.dumps(out, ensure_ascii=False, indent=2)

    def to_mermaid(self) -> str:
        """
        Экспорт в Mermaid Flowchart для визуализации DAG.
        """
        lines = ["flowchart TD"]
        for t in self._tasks.values():
            label = f"{t.id}[\"{t.name}\\n{t.duration_s}s\"]"
            lines.append(label)
        for t in self._tasks.values():
            for d in t.deps:
                lines.append(f"{d} --> {t.id}")
        return "\n".join(lines)

    # --------------- Ре-планирование при сбое ---------------
    def replan_on_failure(
        self,
        last_plan: PlanResult,
        failed_task_id: str,
        *,
        drop_dependents: bool = False,
    ) -> PlanResult:
        """
        Перепланирование при падении задачи.
        Если drop_dependents=True — все потомки удаляются из будущего плана.
        Иначе — потомки останутся, если больше не зависят от fail (например, soft-deps).
        """
        if failed_task_id not in self._tasks:
            raise ValidationError(f"Unknown task: {failed_task_id}")

        if drop_dependents:
            # удаляем всех достижимых по ребрам из failed
            to_drop = self._descendants(failed_task_id)
            to_drop.add(failed_task_id)
            for tid in to_drop:
                self.remove_task(tid)
        else:
            # помечаем зависимость как пропущенную (если политика допускает)
            if not self.treat_skipped_as_satisfied:
                raise PlannerError("Cannot replan without dropping dependents when skipped≠satisfied")
            # превращаем fail в «пропуск» через condition
            t = self._tasks[failed_task_id]
            nt = Task(
                id=t.id,
                name=t.name,
                duration_s=t.duration_s,
                deps=set(t.deps),
                priority=t.priority,
                resources=dict(t.resources),
                earliest_start_s=t.earliest_start_s,
                deadline_s=t.deadline_s,
                condition=lambda ctx: False,  # сделаем всегда False
                retry=t.retry,
                meta=dict(t.meta),
            )
            self._tasks[failed_task_id] = nt

        # запускаем новое планирование (с прежними ресурсами и t0=0)
        return self.schedule(capacity={"cpu": math.inf})

    def _descendants(self, root: str) -> Set[str]:
        adj: Dict[str, Set[str]] = {tid: set() for tid in self._tasks}
        for t in self._tasks.values():
            for d in t.deps:
                adj[d].add(t.id)
        out: Set[str] = set()
        stack = [root]
        while stack:
            u = stack.pop()
            for v in adj[u]:
                if v not in out:
                    out.add(v)
                    stack.append(v)
        return out


# --------------------------------------------------------------------------------------
# Пример использования (локальный тест)
# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    # Пример DAG:
    #   A(3s)  B(2s)
    #      \   /
    #        C(4s) -- D(1s)
    #                /
    #            E(2s)
    A = Task(id="A", name="Fetch data", duration_s=3, resources={"cpu": 1}, priority=5)
    B = Task(id="B", name="Validate schema", duration_s=2, resources={"cpu": 1}, priority=4)
    C = Task(id="C", name="Transform", duration_s=4, deps={"A", "B"}, resources={"cpu": 2}, priority=3)
    D = Task(id="D", name="Index", duration_s=1, deps={"C"}, resources={"cpu": 1}, earliest_start_s=2.0)
    E = Task(id="E", name="Write report", duration_s=2, deps={"C"}, resources={"cpu": 1}, deadline_s=12.0)

    planner = GraphPlanner([A, B, C, D, E], treat_skipped_as_satisfied=True)
    LOG.info("Topological order: %s", planner.toposort())
    LOG.info("Stages: %s", planner.stages())
    cp_len, cp_path = planner.critical_path()
    LOG.info("Critical path: %s (%.2fs)", cp_path, cp_len)

    plan = planner.schedule(capacity={"cpu": 2}, t0_s=0.0)
    print(GraphPlanner.plan_to_json(plan))
    # Визуализация DAG:
    # print(planner.to_mermaid())
