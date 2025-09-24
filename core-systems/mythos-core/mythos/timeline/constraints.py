# mythos-core/mythos/timeline/constraints.py
# -*- coding: utf-8 -*-
"""
Модуль временных ограничений Mythos Core: проверка и планирование.

Особенности:
- Базовые типы и контракты (StateProvider/Constraint/Composite).
- Готовые ограничения: рабочие окна (по дням/интервалам), дата-диапазон,
  блэкауты, зависимости, cooldown, rate-limit, конкуренция, бюджет.
- Диагностика: коды нарушений, структурированные сообщения, explain().
- Планировщик: schedule_earliest() — поиск ближайшего слота с учётом TZ,
  длительности и всех ограничений; защита по горизонту/итерациям.
- Без внешних зависимостей. Опционально использует dateutil.rrule, если доступен.

Совместимость: Python 3.11+, tz через zoneinfo.
Лицензия: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, time, UTC
from enum import Enum
from typing import (
    Protocol, Iterable, Sequence, Optional, Mapping, Any, List, Tuple, Dict, runtime_checkable,
)
from zoneinfo import ZoneInfo

# Опционально rrule (если установлен, пригодится для сложных календарей)
try:  # pragma: no cover
    from dateutil.rrule import rrulestr  # noqa: F401
    _HAS_DATEUTIL = True
except Exception:  # pragma: no cover
    _HAS_DATEUTIL = False


# ==========================
# Базовые структуры
# ==========================

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class Violation:
    code: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Evaluation:
    decision: Decision
    violations: List[Violation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.decision == Decision.ALLOW

    @staticmethod
    def allow() -> "Evaluation":
        return Evaluation(Decision.ALLOW, [])

    @staticmethod
    def deny(code: str, message: str, **data: Any) -> "Evaluation":
        return Evaluation(Decision.DENY, [Violation(code, message, data)])

    def merge(self, other: "Evaluation") -> "Evaluation":
        if self.decision == Decision.DENY or other.decision == Decision.DENY:
            return Evaluation(Decision.DENY, self.violations + other.violations)
        if self.decision == Decision.UNKNOWN and other.decision == Decision.UNKNOWN:
            return Evaluation(Decision.UNKNOWN, self.violations + other.violations)
        if self.decision == Decision.UNKNOWN and other.decision == Decision.ALLOW:
            return Evaluation(Decision.UNKNOWN, self.violations)
        if self.decision == Decision.ALLOW and other.decision == Decision.UNKNOWN:
            return Evaluation(Decision.UNKNOWN, other.violations)
        return Evaluation(Decision.ALLOW, self.violations + other.violations)


@dataclass(slots=True, frozen=True)
class TimeInterval:
    start: datetime  # включительно
    end: datetime    # исключительно

    def duration(self) -> timedelta:
        return self.end - self.start

    def contains(self, t: datetime) -> bool:
        return self.start <= t < self.end

    def overlaps(self, other: "TimeInterval") -> bool:
        return self.start < other.end and other.start < self.end

    def intersection(self, other: "TimeInterval") -> Optional["TimeInterval"]:
        if not self.overlaps(other):
            return None
        s = max(self.start, other.start)
        e = min(self.end, other.end)
        if s >= e:
            return None
        return TimeInterval(s, e)


@dataclass(slots=True, frozen=True)
class Candidate:
    """
    Запланируемое действие/событие.
    """
    id: str
    key: str
    duration: timedelta
    tz: str = "UTC"
    resources: Dict[str, float] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)


# ==========================
# Контекст/Состояние (контракты)
# ==========================

@runtime_checkable
class StateProvider(Protocol):
    """
    Абстракция поверх вашей БД/кэша/шины событий.
    Реализации обязаны быть потокобезопасными для чтения.
    """

    def now(self, tz: Optional[str] = None) -> datetime:
        """Текущее время в заданной TZ (или UTC по умолчанию)."""

    def is_completed(self, dependency_id: str) -> bool:
        """Завершена ли зависимость (квест/задача/событие)."""

    def last_occurrence(self, key: str) -> Optional[datetime]:
        """Время последнего завершения события с данным ключом."""

    def history(self, key: str, window: TimeInterval) -> Sequence[datetime]:
        """Возвращает отметки времени завершения событий key внутри окна."""

    def concurrent_count(self, resource: str, moment: TimeInterval) -> int:
        """
        Сколько событий потребляют данный ресурс внутри интервала moment.
        Для грубой оценки конкуренции допустимо считать пересечение с их интервалами.
        """

    def budget_remaining(self, resource: str, period_start: datetime, period: timedelta) -> float:
        """
        Сколько бюджетных единиц ресурса доступно на период [period_start, period_start+period).
        """

# Референсная in-memory имплементация (для тестов/юнитов)
class InMemoryState(StateProvider):
    def __init__(self, now_dt: Optional[datetime] = None):
        self._now = now_dt or datetime.now(UTC)
        self._completed: set[str] = set()
        self._occ: Dict[str, List[datetime]] = {}
        self._concurrency: List[Tuple[str, TimeInterval]] = []
        self._budgets: Dict[Tuple[str, datetime, timedelta], float] = {}

    def now(self, tz: Optional[str] = None) -> datetime:
        if tz:
            return self._now.astimezone(ZoneInfo(tz))
        return self._now

    def is_completed(self, dependency_id: str) -> bool:
        return dependency_id in self._completed

    def mark_completed(self, dep_id: str) -> None:
        self._completed.add(dep_id)

    def add_occurrence(self, key: str, when: datetime) -> None:
        self._occ.setdefault(key, []).append(when)

    def history(self, key: str, window: TimeInterval) -> Sequence[datetime]:
        items = self._occ.get(key, [])
        return [t for t in items if window.contains(t)]

    def last_occurrence(self, key: str) -> Optional[datetime]:
        items = self._occ.get(key, [])
        return max(items) if items else None

    def add_concurrency(self, resource: str, interval: TimeInterval) -> None:
        self._concurrency.append((resource, interval))

    def concurrent_count(self, resource: str, moment: TimeInterval) -> int:
        n = 0
        for r, iv in self._concurrency:
            if r == resource and iv.overlaps(moment):
                n += 1
        return n

    def set_budget(self, resource: str, period_start: datetime, period: timedelta, value: float) -> None:
        self._budgets[(resource, period_start, period)] = value

    def budget_remaining(self, resource: str, period_start: datetime, period: timedelta) -> float:
        return self._budgets.get((resource, period_start, period), 0.0)


# ==========================
# Базовый контракт ограничения
# ==========================

class Constraint(Protocol):
    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        """Проверить размещение кандидата в `start` (TZ кандидата)."""

    def explain(self) -> str:
        """Короткое человекочитаемое описание ограничения."""


# ==========================
# Утилиты по времени/окнам
# ==========================

def _coerce_tz(dt: datetime, tz: str) -> datetime:
    z = ZoneInfo(tz)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=z)
    return dt.astimezone(z)

def _mk_interval(start: datetime, duration: timedelta, tz: str) -> TimeInterval:
    s = _coerce_tz(start, tz)
    return TimeInterval(s, s + duration)

def _weekday_name(i: int) -> str:
    return ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i % 7]


# ==========================
# Конкретные ограничения
# ==========================

@dataclass(slots=True)
class DateRangeConstraint(Constraint):
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    tz: str = "UTC"

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        s = _coerce_tz(start, self.tz)
        iv = _mk_interval(s, candidate.duration, self.tz)
        if self.start and iv.start < _coerce_tz(self.start, self.tz):
            return Evaluation.deny("DATE_RANGE_BEFORE", "start is before allowed window",
                                   allowed_from=_coerce_tz(self.start, self.tz).isoformat())
        if self.end and iv.end > _coerce_tz(self.end, self.tz):
            return Evaluation.deny("DATE_RANGE_AFTER", "end is after allowed window",
                                   allowed_until=_coerce_tz(self.end, self.tz).isoformat())
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Allowed between {self.start} and {self.end} in {self.tz}"


@dataclass(slots=True)
class WorkingHoursConstraint(Constraint):
    """
    Рабочие окна по дням недели.
    hours: mapping weekday(int 0=Mon..6=Sun) -> list[(start_time, end_time)]
    Пример: {0: [(09:00, 18:00)], 1: [(09:00, 18:00)], ..., 5:[(10:00,14:00)]}
    """
    hours: Dict[int, List[Tuple[time, time]]]
    tz: str = "UTC"

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        s = _coerce_tz(start, self.tz)
        iv = _mk_interval(s, candidate.duration, self.tz)
        # Разбиваем интервал по дням; каждый день должен попадать в соответствующие окна
        cur = iv.start
        while cur < iv.end:
            wd = cur.weekday()
            segments = self.hours.get(wd, [])
            # Определяем дневной кусок
            day_end = cur.replace(hour=23, minute=59, second=59, microsecond=999999)
            chunk_end = min(iv.end, day_end)
            # Проверяем, что [cur, chunk_end] попадает хотя бы в одно окно
            ok = False
            for st, en in segments:
                seg = TimeInterval(cur.replace(hour=st.hour, minute=st.minute, second=st.second, microsecond=0),
                                   cur.replace(hour=en.hour, minute=en.minute, second=en.second, microsecond=0))
                if seg.contains(cur) and chunk_end <= seg.end:
                    ok = True
                    break
            if not ok:
                return Evaluation.deny(
                    "OUTSIDE_WORKING_HOURS",
                    f"time chunk not allowed on {_weekday_name(wd)}",
                    day=_weekday_name(wd),
                    required_windows=[(a.strftime("%H:%M"), b.strftime("%H:%M")) for a, b in segments],
                )
            cur = chunk_end
        return Evaluation.allow()

    def explain(self) -> str:
        desc = { _weekday_name(k): [(a.strftime("%H:%M"), b.strftime("%H:%M"))] for k, (a,b) in
                 {k:v[0] for k, v in self.hours.items() if v}.items() }
        return f"Working windows in {self.tz}: {desc}"


@dataclass(slots=True)
class BlackoutConstraint(Constraint):
    """
    Набор запрещённых интервалов (блэкауты).
    """
    blackouts: List[TimeInterval]
    tz: str = "UTC"

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        iv = _mk_interval(start, candidate.duration, self.tz)
        for b in self.blackouts:
            # приводим в TZ ограничения
            bt = TimeInterval(_coerce_tz(b.start, self.tz), _coerce_tz(b.end, self.tz))
            if iv.overlaps(bt):
                return Evaluation.deny("BLACKOUT_OVERLAP", "candidate overlaps blackout window",
                                       blackout_start=bt.start.isoformat(), blackout_end=bt.end.isoformat())
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Disallow overlaps with {len(self.blackouts)} blackout windows"


@dataclass(slots=True)
class DependencyConstraint(Constraint):
    """
    Требует завершённых зависимостей по идентификаторам.
    """
    dependencies: List[str]

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        missing = [d for d in self.dependencies if not state.is_completed(d)]
        if missing:
            return Evaluation.deny("DEPENDENCY_UNMET", "dependencies are not completed", missing=missing)
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Requires completed dependencies: {self.dependencies}"


@dataclass(slots=True)
class CooldownConstraint(Constraint):
    """
    Запрещает запуск, если после последнего выполнения прошло меньше cooldown.
    """
    cooldown: timedelta

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        last = state.last_occurrence(candidate.key)
        if last is None:
            return Evaluation.allow()
        if start < last + self.cooldown:
            return Evaluation.deny("COOLDOWN_ACTIVE", "cooldown not elapsed",
                                   last=last.isoformat(), allowed_from=(last + self.cooldown).isoformat())
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Cooldown {self.cooldown}"


@dataclass(slots=True)
class RateLimitConstraint(Constraint):
    """
    Не более `limit` выполнений ключа в скользящем окне `window`.
    """
    limit: int
    window: timedelta

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        w = TimeInterval(start - self.window, start)
        count = len(state.history(candidate.key, w))
        if count >= self.limit:
            return Evaluation.deny("RATE_LIMIT_EXCEEDED", "rate limit reached",
                                   limit=self.limit, window_seconds=int(self.window.total_seconds()))
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Rate ≤ {self.limit}/{self.window}"


@dataclass(slots=True)
class ConcurrencyConstraint(Constraint):
    """
    Не более `max_concurrent` одновременных задач для ресурса (ключ ресурса).
    Проверяет пересечение интервалов.
    """
    resource: str
    max_concurrent: int

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        iv = TimeInterval(start, start + candidate.duration)
        c = state.concurrent_count(self.resource, iv)
        if c >= self.max_concurrent:
            return Evaluation.deny("CONCURRENCY_LIMIT", "too many concurrent tasks",
                                   resource=self.resource, in_use=c, limit=self.max_concurrent)
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Concurrency {self.resource} <= {self.max_concurrent}"


@dataclass(slots=True)
class BudgetConstraint(Constraint):
    """
    Требует доступного бюджета (например, токенов API, слотов GPU и т.д.)
    на период, к которому принадлежит запуск (округление к началу периода).
    """
    resource: str
    period: timedelta
    required_units: float

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        # Нормализуем старт к началу периода по TZ кандидата
        tz = candidate.tz or "UTC"
        s = _coerce_tz(start, tz)
        epoch = datetime(1970, 1, 1, tzinfo=s.tzinfo)
        elapsed = (s - epoch)
        periods = int(elapsed.total_seconds() // self.period.total_seconds())
        period_start = epoch + timedelta(seconds=periods * self.period.total_seconds())
        remaining = state.budget_remaining(self.resource, period_start, self.period)
        if remaining < self.required_units:
            return Evaluation.deny("BUDGET_EXCEEDED", "insufficient budget",
                                   resource=self.resource, required=self.required_units, remaining=remaining)
        return Evaluation.allow()

    def explain(self) -> str:
        return f"Requires {self.required_units} units of {self.resource} per {self.period}"


# ==========================
# Композиторы ограничений
# ==========================

@dataclass(slots=True)
class AllOf(Constraint):
    constraints: List[Constraint]

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        result = Evaluation.allow()
        for c in self.constraints:
            ev = c.evaluate(state, candidate, start)
            result = result.merge(ev)
            if result.decision == Decision.DENY:
                # короткий путь — уже отказ
                break
        return result

    def explain(self) -> str:
        return "ALL OF: " + " & ".join([c.explain() for c in self.constraints])


@dataclass(slots=True)
class AnyOf(Constraint):
    constraints: List[Constraint]

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        violations: List[Violation] = []
        for c in self.constraints:
            ev = c.evaluate(state, candidate, start)
            if ev.decision == Decision.ALLOW:
                return Evaluation.allow()
            violations.extend(ev.violations)
        return Evaluation(Decision.DENY, violations or [Violation("ANY_FAILED", "no alternatives matched", {})])

    def explain(self) -> str:
        return "ANY OF: " + " | ".join([c.explain() for c in self.constraints])


@dataclass(slots=True)
class Not(Constraint):
    constraint: Constraint

    def evaluate(self, state: StateProvider, candidate: Candidate, start: datetime) -> Evaluation:
        ev = self.constraint.evaluate(state, candidate, start)
        if ev.decision == Decision.ALLOW:
            return Evaluation.deny("NEGATION", "negated constraint matched")
        return Evaluation.allow()

    def explain(self) -> str:
        return "NOT: " + self.constraint.explain()


# ==========================
# Планировщик (поиск ближайшего слота)
# ==========================

@dataclass(slots=True)
class ScheduleResult:
    ok: bool
    start: Optional[datetime]
    end: Optional[datetime]
    violations: List[Violation] = field(default_factory=list)


def schedule_earliest(
    state: StateProvider,
    candidate: Candidate,
    constraint: Constraint,
    *,
    after: Optional[datetime] = None,
    horizon: timedelta = timedelta(days=14),
    step: timedelta = timedelta(minutes=15),
    hard_windows: Optional[List[TimeInterval]] = None,
) -> ScheduleResult:
    """
    Поиск ближайшего допустимого старта для кандидата.

    Алгоритм:
      1) Начинаем с `after` (или сейчас из state.now()).
      2) Идём шагами `step`, не выходя за `horizon`.
      3) Если заданы жесткие окна (`hard_windows`), тестируем только внутри их пересечений.
      4) На первой ALLOW возвращаем слот. Иначе — собираем последние нарушения.

    Ограничения:
      - step должен быть <= duration (обычно 5-15 мин).
      - horizon ограничивает время выполнения (защита от бесконечного поиска).
    """
    tz = candidate.tz or "UTC"
    start_at = _coerce_tz(after or state.now(tz), tz)
    deadline = start_at + horizon
    last_violations: List[Violation] = []

    def _within_hard_windows(ts: datetime) -> bool:
        if not hard_windows:
            return True
        for w in hard_windows:
            wtz = TimeInterval(_coerce_tz(w.start, tz), _coerce_tz(w.end, tz))
            if wtz.contains(ts) and ts + candidate.duration <= wtz.end:
                return True
        return False

    cur = start_at
    while cur + candidate.duration <= deadline:
        if _within_hard_windows(cur):
            ev = constraint.evaluate(state, candidate, cur)
            if ev.ok:
                return ScheduleResult(True, cur, cur + candidate.duration, [])
            last_violations = ev.violations  # сохраняем последнюю причину отказа
        # Оптимизация: если попали в блэкаут с известным окончанием — можно прыгнуть дальше.
        cur += step

    return ScheduleResult(False, None, None, last_violations)


# ==========================
# Пример простого профиля ограничений (конструктор)
# ==========================

def make_default_slo_profile(tz: str = "UTC") -> Constraint:
    """
    Пример композиции ограничений для прод-окружения:
      - Рабочие часы Пн-Пт 09:00-18:00
      - Без запусков в выходные
      - Rate ≤ 10/час
      - Cooldown 5 минут
    """
    wh = WorkingHoursConstraint(
        hours={d: [(time(9, 0), time(18, 0))] for d in range(0, 5)},  # Mon..Fri
        tz=tz,
    )
    return AllOf([
        wh,
        RateLimitConstraint(limit=10, window=timedelta(hours=1)),
        CooldownConstraint(cooldown=timedelta(minutes=5)),
    ])


# ==========================
# Пример использования (докстринг)
# ==========================
"""
Пример:

from datetime import timedelta, datetime
from zoneinfo import ZoneInfo

state = InMemoryState()
cand = Candidate(id="evt-1", key="email.dispatch", duration=timedelta(minutes=10), tz="Europe/Stockholm")

constraint = AllOf([
    DateRangeConstraint(start=datetime(2025, 8, 1, tzinfo=ZoneInfo("Europe/Stockholm")),
                        end=datetime(2025, 9, 1, tzinfo=ZoneInfo("Europe/Stockholm")),
                        tz="Europe/Stockholm"),
    WorkingHoursConstraint(hours={d:[(time(9), time(18))] for d in range(0,5)}, tz="Europe/Stockholm"),
    BlackoutConstraint(blackouts=[], tz="Europe/Stockholm"),
    DependencyConstraint(dependencies=["etl.snapshot.2025-08-26"]),
    CooldownConstraint(cooldown=timedelta(minutes=15)),
    RateLimitConstraint(limit=100, window=timedelta(hours=1)),
    ConcurrencyConstraint(resource="email.sender", max_concurrent=5),
    BudgetConstraint(resource="tokens.email", period=timedelta(days=1), required_units=1.0),
])

# Настраиваем состояние
state.mark_completed("etl.snapshot.2025-08-26")
state.set_budget("tokens.email",
                 datetime(2025,8,27,tzinfo=ZoneInfo("Europe/Stockholm")).replace(hour=0, minute=0, second=0, microsecond=0),
                 timedelta(days=1),
                 value=100.0)

res = schedule_earliest(state, cand, constraint,
                        after=datetime(2025,8,27,8,0,tzinfo=ZoneInfo("Europe/Stockholm")),
                        horizon=timedelta(days=2),
                        step=timedelta(minutes=15))
if res.ok:
    print("Scheduled at", res.start, "→", res.end)
else:
    for v in res.violations:
        print(v.code, v.message, v.data)
"""
