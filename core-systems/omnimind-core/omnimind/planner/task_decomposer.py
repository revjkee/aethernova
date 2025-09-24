# SPDX-License-Identifier: Apache-2.0
"""
Omnimind Task Decomposer: из бизнес-цели строит промышленный план (DAG) с оценками,
критическим путём и экспортом.

Особенности:
- Без внешних зависимостей (только стандартная библиотека).
- Детерминированные ID задач (BLAKE2b от цели и имени).
- Рецепты (templates) для типовых сценариев: k8s, ansible, terraform, release, incident.
- PERT-оценки (optimistic, most_likely, pessimistic), критический путь (CPM), slack.
- Проверка DAG: отсутствие циклов, топологическая сортировка.
- Экспорт: JSON и Markdown, сериализация и стабильный порядок.
- Расширяемость: подключаемые рецепты и кастомные шаблоны через API.

Назначение:
- Планирование в CI/CD, генерация чек-листов, автоматизация бэклогов.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import itertools
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


# ============================== Модели данных =============================== #

class TaskType(str, enum.Enum):
    ANALYSIS = "analysis"
    DESIGN = "design"
    IMPLEMENT = "implement"
    TEST = "test"
    SECURITY = "security"
    REVIEW = "review"
    RELEASE = "release"
    RUNBOOK = "runbook"
    MIGRATION = "migration"
    DEPLOY = "deploy"
    OBSERVABILITY = "observability"
    INCIDENT = "incident"
    DOCS = "docs"
    VERIFY = "verify"

class Priority(str, enum.Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"

class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass(frozen=True)
class Estimate:
    """PERT-оценка в днях; допускаются дробные значения."""
    optimistic: float
    most_likely: float
    pessimistic: float

    def expected(self) -> float:
        return (self.optimistic + 4 * self.most_likely + self.pessimistic) / 6.0

    def variance(self) -> float:
        return ((self.pessimistic - self.optimistic) / 6.0) ** 2

    @staticmethod
    def from_simple(days: float) -> "Estimate":
        d = float(days)
        return Estimate(optimistic=max(0.25, 0.5 * d), most_likely=d, pessimistic=1.5 * d)

@dataclass
class Task:
    id: str
    name: str
    type: TaskType
    description: str
    deps: List[str] = field(default_factory=list)
    estimate: Estimate = field(default_factory=lambda: Estimate.from_simple(1.0))
    priority: Priority = Priority.P2
    owner_role: str = "engineer"
    artifacts: List[str] = field(default_factory=list)
    acceptance: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_notes: str = ""
    tags: List[str] = field(default_factory=list)

@dataclass
class Plan:
    objective: str
    context: Dict[str, Any]
    tasks: Dict[str, Task]  # по id
    created_at: datetime

@dataclass
class ScheduleItem:
    task_id: str
    es: float  # earliest start (days since start)
    ef: float  # earliest finish
    ls: float  # latest start
    lf: float  # latest finish
    slack: float

@dataclass
class Schedule:
    start_at: datetime
    items: Dict[str, ScheduleItem]
    critical_path: List[str]
    duration_days: float


# ============================== Вспомогательные ============================= #

def _blake_id(*parts: str, length: int = 12) -> str:
    h = hashlib.blake2b(digest_size=16)
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()[:length]

def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())

def _unique(seq: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

def _toposort(tasks: Mapping[str, Task]) -> List[str]:
    """Kahn's algorithm."""
    incoming: Dict[str, int] = {tid: 0 for tid in tasks}
    graph: Dict[str, List[str]] = {tid: [] for tid in tasks}
    for t in tasks.values():
        for d in t.deps:
            if d not in tasks:
                raise ValueError(f"dependency '{d}' of '{t.id}' does not exist")
            incoming[t.id] += 1
            graph[d].append(t.id)
    Q: List[str] = [tid for tid, deg in incoming.items() if deg == 0]
    order: List[str] = []
    while Q:
        n = Q.pop()
        order.append(n)
        for m in graph[n]:
            incoming[m] -= 1
            if incoming[m] == 0:
                Q.append(m)
    if len(order) != len(tasks):
        # Найдём цикл для диагностики
        cyclic = [tid for tid, deg in incoming.items() if deg > 0]
        raise ValueError(f"DAG has cycles, unresolved: {cyclic}")
    return order

def _pert_schedule(tasks: Mapping[str, Task], start_at: Optional[datetime] = None) -> Schedule:
    """Расчёт ES/EF/LS/LF и критического пути (по ожидаемым значениям)."""
    start_at = start_at or datetime.now(timezone.utc)
    order = _toposort(tasks)
    es: Dict[str, float] = {tid: 0.0 for tid in tasks}
    ef: Dict[str, float] = {tid: 0.0 for tid in tasks}
    for tid in order:
        t = tasks[tid]
        es[tid] = 0.0 if not t.deps else max(ef[d] for d in t.deps)
        ef[tid] = es[tid] + max(0.0, t.estimate.expected())

    # Обратный проход
    duration = max(ef.values()) if ef else 0.0
    lf: Dict[str, float] = {tid: duration for tid in tasks}
    ls: Dict[str, float] = {tid: 0.0 for tid in tasks}
    for tid in reversed(order):
        t = tasks[tid]
        if not any(tid in tasks[down].deps for down in tasks):  # если нет потомков
            lf[tid] = duration
        else:
            children = [down for down in tasks if tid in tasks[down].deps]
            lf[tid] = min(ls[ch] for ch in children)
        ls[tid] = lf[tid] - t.estimate.expected()

    slack: Dict[str, float] = {tid: max(0.0, ls[tid] - es[tid]) for tid in tasks}
    critical = [tid for tid in order if math.isclose(slack[tid], 0.0, abs_tol=1e-9)]
    items = {
        tid: ScheduleItem(task_id=tid, es=es[tid], ef=ef[tid], ls=ls[tid], lf=lf[tid], slack=slack[tid])
        for tid in tasks
    }
    return Schedule(start_at=start_at, items=items, critical_path=critical, duration_days=duration)

def _fmt_days(x: float) -> str:
    return f"{x:.2f}d"

def _safe_format(template: str, context: Mapping[str, Any]) -> str:
    """Безопасная подстановка {var} -> str(context[var]) без KeyError."""
    def repl(m: re.Match[str]) -> str:
        k = m.group(1)
        return str(context.get(k, f"{{{k}}}"))
    return re.sub(r"\{([\w\.]+)\}", repl, template)

# ============================== Рецепты (templates) ========================= #

@dataclass(frozen=True)
class TaskTemplate:
    name: str
    type: TaskType
    description: str
    est_days: float
    deps: List[str] = field(default_factory=list)
    priority: Priority = Priority.P2
    owner_role: str = "engineer"
    artifacts: List[str] = field(default_factory=list)
    acceptance: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_notes: str = ""
    tags: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class Recipe:
    name: str
    when_any_keywords: List[str]
    templates: List[TaskTemplate]

# Встроенная библиотека рецептов
DEFAULT_RECIPES: List[Recipe] = [
    Recipe(
        name="k8s_deployment",
        when_any_keywords=["k8s", "kubernetes", "helm", "deployment", "hpa", "ingress"],
        templates=[
            TaskTemplate(
                name="Анализ требования и рисков",
                type=TaskType.ANALYSIS,
                description="Собрать нефункциональные требования, RTO/RPO, оценить лимиты HPA и трафик.",
                est_days=0.5,
                acceptance=[
                    "Требования зафиксированы в ADR",
                    "Риски классифицированы и согласованы"
                ],
                tags=["k8s", "adr"]
            ),
            TaskTemplate(
                name="Подготовить Helm-шаблоны",
                type=TaskType.DESIGN,
                description="Разработать/адаптировать Helm-чарт {service}.",
                est_days=1.0,
                deps=["Анализ требования и рисков"],
                artifacts=["charts/{service}"],
                acceptance=["helm template проходит без ошибок", "чек-лист безопасности helm-lint"],
                tags=["helm", "templates"]
            ),
            TaskTemplate(
                name="Добавить наблюдаемость",
                type=TaskType.OBSERVABILITY,
                description="ServiceMonitor, Grafana dashboard для {service}, алерты SLIs.",
                est_days=0.8,
                deps=["Подготовить Helm-шаблоны"],
                acceptance=["SLIs/SLOs определены", "Алёрты созданы"],
                tags=["observability"]
            ),
            TaskTemplate(
                name="Деплой в staging",
                type=TaskType.DEPLOY,
                description="Деплой {service} в namespace {namespace} (staging).",
                est_days=0.5,
                deps=["Добавить наблюдаемость"],
                acceptance=["Pod Ready", "Health 200", "Ошибки в логах отсутствуют"],
                tags=["staging"]
            ),
            TaskTemplate(
                name="Нагрузочное тестирование",
                type=TaskType.TEST,
                description="Профиль нагрузки {load_profile}; собрать метрики, убедиться в отсутствии троттлинга.",
                est_days=1.0,
                deps=["Деплой в staging"],
                acceptance=["Ошибки < 0.1%", "p95 латентность < целевое значение"],
                tags=["loadtest"]
            ),
            TaskTemplate(
                name="Деплой в production",
                type=TaskType.RELEASE,
                description="Пошаговый релиз {service} с откатом при сбое.",
                est_days=0.5,
                deps=["Нагрузочное тестирование"],
                acceptance=["Чек-лист релиза выполнен", "Мониторинг зелёный 24ч"],
                priority=Priority.P1,
                tags=["prod"]
            ),
            TaskTemplate(
                name="Документация и ранбук",
                type=TaskType.DOCS,
                description="README/Runbook/алерты для {service}.",
                est_days=0.5,
                deps=["Деплой в production"],
                acceptance=["Ранбук оформлен", "Ссылки добавлены в каталог"],
                tags=["docs", "runbook"]
            ),
        ],
    ),
    Recipe(
        name="ansible_role",
        when_any_keywords=["ansible", "role", "playbook"],
        templates=[
            TaskTemplate("Анализ и требования", TaskType.ANALYSIS, "Определить цели роли {role}.", 0.3),
            TaskTemplate("Реализация роли", TaskType.IMPLEMENT, "Создать/обновить роль {role}.", 1.0, deps=["Анализ и требования"]),
            TaskTemplate("Molecule тесты", TaskType.TEST, "Добавить/обновить Molecule сценарии.", 0.7, deps=["Реализация роли"]),
            TaskTemplate("Документация", TaskType.DOCS, "Опубликовать README и примеры.", 0.3, deps=["Molecule тесты"]),
        ],
    ),
    Recipe(
        name="terraform_module",
        when_any_keywords=["terraform", "tf", "iac"],
        templates=[
            TaskTemplate("Дизайн модуля", TaskType.DESIGN, "Спецификация входов/выходов модуля {module}.", 0.5),
            TaskTemplate("Реализация модуля", TaskType.IMPLEMENT, "Реализовать {module}.", 1.2, deps=["Дизайн модуля"]),
            TaskTemplate("Проверка безопасности", TaskType.SECURITY, "tflint/conftest/policies.", 0.5, deps=["Реализация модуля"]),
            TaskTemplate("Публикация", TaskType.RELEASE, "Версионирование и релиз.", 0.2, deps=["Проверка безопасности"]),
        ],
    ),
    Recipe(
        name="service_release",
        when_any_keywords=["release", "tag", "package"],
        templates=[
            TaskTemplate("Сборка артефактов", TaskType.IMPLEMENT, "Собрать артефакты {service}.", 0.5),
            TaskTemplate("Тестирование", TaskType.TEST, "Запустить тесты и линтеры.", 0.5, deps=["Сборка артефактов"]),
            TaskTemplate("Подпись и публикация", TaskType.RELEASE, "Подписать/опубликовать релиз.", 0.3, deps=["Тестирование"]),
        ],
    ),
    Recipe(
        name="incident_response",
        when_any_keywords=["incident", "outage", "p1", "sev"],
        templates=[
            TaskTemplate("Стабилизация", TaskType.INCIDENT, "Стабилизировать сервис {service}.", 0.2, priority=Priority.P0, risk_level=RiskLevel.HIGH),
            TaskTemplate("Root cause", TaskType.ANALYSIS, "Найти корневую причину.", 0.5, deps=["Стабилизация"], priority=Priority.P0),
            TaskTemplate("Фикс", TaskType.IMPLEMENT, "Реализовать исправление.", 0.5, deps=["Root cause"], priority=Priority.P0),
            TaskTemplate("Постмортем", TaskType.DOCS, "Оформить постмортем.", 0.3, deps=["Фикс"]),
        ],
    ),
]


# ============================== Декомпозер ================================= #

class TaskDecomposer:
    """
    Основной класс: анализирует цель и контекст, выбирает рецепты, строит DAG,
    рассчитывает расписание и даёт экспорт.
    """

    def __init__(self, recipes: Optional[Sequence[Recipe]] = None) -> None:
        self.recipes: List[Recipe] = list(recipes or DEFAULT_RECIPES)

    # ---------- Публичное API ---------- #

    def decompose(
        self,
        objective: str,
        context: Optional[Mapping[str, Any]] = None,
        *,
        start_at: Optional[datetime] = None,
        max_parallel: int = 0,
    ) -> Tuple[Plan, Schedule]:
        """
        Построить план и расписание из цели и контекста.
        :param objective: бизнес-цель (строка)
        :param context: переопределимые переменные для шаблонов
        :param start_at: момент старта (UTC). Если None — сейчас.
        :param max_parallel: ограничение параллельности в аналитике (0 = без ограничений)
        """
        ctx = dict(context or {})
        ctx.setdefault("service", "omnimind-core")
        ctx.setdefault("namespace", "default")
        ctx.setdefault("role", "omnimind-core")
        ctx.setdefault("module", "omnimind-module")
        ctx.setdefault("load_profile", "baseline")

        templates = self._select_templates(objective)
        tasks = self._instantiate_templates(objective, templates, ctx)
        self._validate(tasks)
        plan = Plan(objective=_norm(objective), context=ctx, tasks=tasks, created_at=datetime.now(timezone.utc))
        schedule = _pert_schedule(plan.tasks, start_at=start_at)
        if max_parallel and max_parallel > 0:
            # только анализируем перегрузку; сам граф не меняем
            self._suggest_parallelization(schedule, max_parallel=max_parallel)
        return plan, schedule

    def export_json(self, plan: Plan, schedule: Schedule) -> str:
        """Стабильный JSON с сортировкой по топологии."""
        order = _toposort(plan.tasks)
        out: Dict[str, Any] = {
            "objective": plan.objective,
            "created_at": plan.created_at.isoformat(),
            "context": plan.context,
            "tasks": [],
            "schedule": {
                "start_at": schedule.start_at.isoformat(),
                "duration_days": schedule.duration_days,
                "critical_path": schedule.critical_path,
                "items": {},
            },
        }
        for tid in order:
            t = plan.tasks[tid]
            out["tasks"].append(
                {
                    "id": t.id,
                    "name": t.name,
                    "type": t.type.value,
                    "description": t.description,
                    "deps": t.deps,
                    "estimate": dataclasses.asdict(t.estimate),
                    "priority": t.priority.value,
                    "owner_role": t.owner_role,
                    "artifacts": t.artifacts,
                    "acceptance": t.acceptance,
                    "risk_level": t.risk_level.value,
                    "risk_notes": t.risk_notes,
                    "tags": t.tags,
                }
            )
        for tid, item in schedule.items.items():
            out["schedule"]["items"][tid] = dataclasses.asdict(item)
        return json.dumps(out, ensure_ascii=False, indent=2, sort_keys=False)

    def export_markdown(self, plan: Plan, schedule: Schedule) -> str:
        order = _toposort(plan.tasks)
        lines: List[str] = []
        lines.append(f"# План: {plan.objective}")
        lines.append("")
        lines.append(f"- Создано: {plan.created_at.isoformat()}")
        lines.append(f"- Длительность (PERT): {_fmt_days(schedule.duration_days)}")
        lines.append(f"- Критический путь: {' ➜ '.join(plan.tasks[t].name for t in schedule.critical_path)}")
        lines.append("")
        lines.append("## Задачи")
        lines.append("")
        for i, tid in enumerate(order, 1):
            t = plan.tasks[tid]
            s = schedule.items[tid]
            lines.append(f"### {i}. {t.name} [{t.type.value}] `{t.id}`")
            lines.append(f"- Приоритет: {t.priority.value}")
            lines.append(f"- Оценка (PERT): {_fmt_days(t.estimate.expected())} (σ={math.sqrt(t.estimate.variance()):.2f})")
            lines.append(f"- Зависимости: {', '.join(plan.tasks[d].name for d in t.deps) if t.deps else 'нет'}")
            lines.append(f"- Владелец (роль): {t.owner_role}")
            if t.artifacts:
                lines.append(f"- Артефакты: {', '.join(t.artifacts)}")
            if t.acceptance:
                lines.append(f"- Критерии приёмки: " + "; ".join(t.acceptance))
            lines.append(f"- График: ES={_fmt_days(s.es)}, EF={_fmt_days(s.ef)}, LS={_fmt_days(s.ls)}, LF={_fmt_days(s.lf)}, slack={_fmt_days(s.slack)}")
            if t.tags:
                lines.append(f"- Теги: {', '.join(t.tags)}")
            if t.risk_notes:
                lines.append(f"- Риск: {t.risk_level.value} — {t.risk_notes}")
            lines.append("")
        return "\n".join(lines)

    # ---------- Внутреннее ---------- #

    def _select_templates(self, objective: str) -> List[TaskTemplate]:
        obj = objective.lower()
        hits: List[TaskTemplate] = []
        for r in self.recipes:
            if any(k in obj for k in r.when_any_keywords):
                hits.extend(r.templates)
        # Всегда добавим финальную верификацию
        if not any(t.type == TaskType.VERIFY for t in hits):
            hits.append(
                TaskTemplate(
                    name="Финальная верификация результата",
                    type=TaskType.VERIFY,
                    description="Сверка требований, smoke-тест, согласование заинтересованных сторон.",
                    est_days=0.2,
                    deps=[hits[-1].name] if hits else [],
                    acceptance=["Список требований закрыт", "Smoke-тест зелёный", "Ок от владельца"],
                    priority=Priority.P1,
                )
            )
        if not hits:
            # Generic каркас
            hits = [
                TaskTemplate("Уточнение требований", TaskType.ANALYSIS, "Согласовать критерии успеха.", 0.5),
                TaskTemplate("Реализация", TaskType.IMPLEMENT, "Выполнить работу.", 1.0, deps=["Уточнение требований"]),
                TaskTemplate("Тестирование", TaskType.TEST, "Проверка результата.", 0.5, deps=["Реализация"]),
                TaskTemplate("Документация", TaskType.DOCS, "Описать изменения.", 0.3, deps=["Тестирование"]),
                TaskTemplate("Финальная верификация результата", TaskType.VERIFY, "Сверка требований и релиз.", 0.2, deps=["Документация"]),
            ]
        return hits

    def _instantiate_templates(
        self, objective: str, templates: Sequence[TaskTemplate], ctx: Mapping[str, Any]
    ) -> Dict[str, Task]:
        # Сначала формируем карты имён -> id, затем подставляем deps
        name_to_id: Dict[str, str] = {}
        for t in templates:
            name = _safe_format(t.name, ctx)
            name_to_id[name] = _blake_id(objective, name)

        tasks: Dict[str, Task] = {}
        for tmpl in templates:
            name = _safe_format(tmpl.name, ctx)
            desc = _safe_format(tmpl.description, ctx)
            deps = [_safe_format(d, ctx) for d in tmpl.deps]
            dep_ids = [name_to_id[d] for d in deps if d in name_to_id]
            tid = name_to_id[name]
            tasks[tid] = Task(
                id=tid,
                name=name,
                type=tmpl.type,
                description=desc,
                deps=_unique(dep_ids),
                estimate=Estimate.from_simple(tmpl.est_days),
                priority=tmpl.priority,
                owner_role=tmpl.owner_role,
                artifacts=[_safe_format(a, ctx) for a in tmpl.artifacts],
                acceptance=[_safe_format(a, ctx) for a in tmpl.acceptance],
                risk_level=tmpl.risk_level,
                risk_notes=_safe_format(tmpl.risk_notes, ctx) if tmpl.risk_notes else "",
                tags=list(dict.fromkeys([_safe_format(tag, ctx) for tag in tmpl.tags])),
            )
        return tasks

    def _validate(self, tasks: Mapping[str, Task]) -> None:
        if not tasks:
            raise ValueError("no tasks generated")
        # self-deps и несуществующие deps уже проверяются в _toposort; запускаем его здесь
        _toposort(tasks)
        # базовые инварианты
        for tid, t in tasks.items():
            if not t.name or not t.name.strip():
                raise ValueError(f"task {tid} has empty name")
            if t.estimate.optimistic <= 0 or t.estimate.pessimistic <= 0:
                raise ValueError(f"task {t.name} has non-positive estimate")
            if any(d == tid for d in t.deps):
                raise ValueError(f"task {t.name} depends on itself")

    def _suggest_parallelization(self, schedule: Schedule, max_parallel: int) -> None:
        """
        Аналитика: сколько конкурирующих задач может стартовать в каждый момент времени.
        Не модифицирует план; служит для диагностики перегрузки ресурсов.
        """
        # Собираем интервалы [es, ef)
        intervals = sorted(
            ((it.es, it.ef, tid) for tid, it in schedule.items.items()),
            key=lambda x: (x[0], x[1]),
        )
        # Линейный подсчёт пересечений
        points: List[Tuple[float, int]] = []
        for es, ef, _ in intervals:
            points.append((es, +1))
            points.append((ef, -1))
        points.sort()
        concurrent = 0
        peak = 0
        for _, delta in points:
            concurrent += delta
            peak = max(peak, concurrent)
        schedule.items["_analytics"] = ScheduleItem(
            task_id="_analytics", es=0.0, ef=0.0, ls=0.0, lf=0.0, slack=max(0.0, float(peak - max_parallel))
        )


# ============================== Утилиты импорта/экспорта ==================== #

def save_json(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")

def save_markdown(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


# ============================== Пример использования ======================== #
if __name__ == "__main__":
    # Демонстрационный сценарий: декомпозиция деплоя k8s сервиса
    objective = "Внедрить HPA и релиз helm-чарта для k8s сервиса omnimind-core в namespace production"
    ctx = {
        "service": "omnimind-core",
        "namespace": "production",
        "load_profile": "peak-traffic-2x",
        "module": "observability",
        "role": "omnimind-core",
    }

    decomposer = TaskDecomposer()
    plan, schedule = decomposer.decompose(objective, ctx, max_parallel=3)

    out_dir = Path("./_out")
    save_json(out_dir / "plan.json", decomposer.export_json(plan, schedule))
    save_markdown(out_dir / "plan.md", decomposer.export_markdown(plan, schedule))
