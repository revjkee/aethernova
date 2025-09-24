# chronowatch-core/chronowatch/sla/budget.py
from __future__ import annotations

import dataclasses
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "WindowSpec",
    "SLOSpec",
    "BurnAlertSpec",
    "BudgetSnapshot",
    "BurnAlertEvent",
    "RollingBuckets",
    "SLOBudgetTracker",
]

# ---------------------------
# Спецификации
# ---------------------------

@dataclass(slots=True)
class WindowSpec:
    """Скользящее окно SLO."""
    duration_seconds: int            # длина окна, например 28 дней = 2419200
    bucket_seconds: int = 60         # ширина бакета, например 60

    def __post_init__(self) -> None:
        if self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if self.bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        if self.bucket_seconds > self.duration_seconds:
            raise ValueError("bucket_seconds must be <= duration_seconds")


@dataclass(slots=True)
class SLOSpec:
    """Целевое значение SLO."""
    name: str
    objective: float                 # доля хороших событий, например 0.999
    window: WindowSpec
    description: str = ""

    def __post_init__(self) -> None:
        if not (0.0 < self.objective <= 1.0):
            raise ValueError("objective must be in (0, 1]")


@dataclass(slots=True)
class BurnAlertSpec:
    """Настройка мультиоконного burn-rate алерта."""
    name: str
    short_window_seconds: int        # напр. 5 минут
    long_window_seconds: int         # напр. 1 час
    short_burn_rate_threshold: float # напр. 14.4
    long_burn_rate_threshold: float  # напр. 6.0
    min_duration_seconds: int = 0    # гистерезис удержания в активном состоянии
    cool_down_seconds: int = 0       # пауза после снятия алерта


# ---------------------------
# Снимки и события
# ---------------------------

@dataclass(slots=True)
class BudgetSnapshot:
    ts: float
    slo_name: str
    objective: float
    window_seconds: int

    total: int
    good: int
    bad: int

    compliance: float                 # good / total, если total > 0, иначе 1.0
    error_rate: float                 # bad / total, если total > 0, иначе 0.0

    budget_allowed: float             # допустимая доля ошибок = 1 - objective
    budget_total_events: float        # допустимая ошибка в событиях = budget_allowed * total
    budget_consumed_events: float     # bad
    budget_remaining_events: float    # max(0, budget_total_events - bad)
    budget_remaining_ratio: float     # доля оставшегося бюджета к допустимому, [0, 1], если total > 0

    burn_rates: Dict[int, float] = field(default_factory=dict)  # окно секунд -> burn rate
    diagnostics: Dict[str, float] = field(default_factory=dict) # p50_latency и т. п. если надо


@dataclass(slots=True)
class BurnAlertEvent:
    ts: float
    name: str
    active: bool
    short_burn_rate: float
    long_burn_rate: float
    reason: str
    meta: Dict[str, float] = field(default_factory=dict)


# ---------------------------
# Вспомогательные структуры
# ---------------------------

class RollingBuckets:
    """
    Кольцевой агрегатор по бакетам фиксированной ширины.
    Потокобезопасно при использовании внешней блокировки.
    """
    __slots__ = ("bucket_seconds", "duration_seconds", "buckets", "total", "good")

    def __init__(self, duration_seconds: int, bucket_seconds: int) -> None:
        self.bucket_seconds = bucket_seconds
        self.duration_seconds = duration_seconds
        # buckets: deque[(bucket_start_ts: int, good: int, total: int)]
        self.buckets: Deque[Tuple[int, int, int]] = deque()
        self.total = 0
        self.good = 0

    @staticmethod
    def _align(ts: float, bucket_seconds: int) -> int:
        return int(ts // bucket_seconds) * bucket_seconds

    def _evict_old(self, now: float) -> None:
        horizon = int(now) - self.duration_seconds
        while self.buckets and self.buckets[0][0] < horizon:
            _, g, t = self.buckets.popleft()
            self.good -= g
            self.total -= t

    def add(self, good: int, total: int, ts: Optional[float] = None) -> None:
        if good < 0 or total < 0 or good > total:
            raise ValueError("invalid counters: 0 <= good <= total")
        now = time.time() if ts is None else ts
        bstart = self._align(now, self.bucket_seconds)
        self._evict_old(now)

        if self.buckets and self.buckets[-1][0] == bstart:
            last_start, g, t = self.buckets.pop()
            g += good
            t += total
            self.buckets.append((last_start, g, t))
        else:
            self.buckets.append((bstart, good, total))
        self.good += good
        self.total += total

    def sum_window(self, window_seconds: int, now: Optional[float] = None) -> Tuple[int, int]:
        now = time.time() if now is None else now
        self._evict_old(now)
        if window_seconds >= self.duration_seconds:
            return self.good, self.total
        horizon = int(now) - window_seconds
        g = t = 0
        for start, bg, bt in reversed(self.buckets):
            if start < horizon:
                break
            g += bg
            t += bt
        return g, t

    def snapshot_all(self, now: Optional[float] = None) -> Tuple[int, int]:
        now = time.time() if now is None else now
        self._evict_old(now)
        return self.good, self.total


# ---------------------------
# Основной трекер бюджета
# ---------------------------

class SLOBudgetTracker:
    """
    Промышленный трекер SLO и Error Budget.
    - RollingBuckets по окну
    - Потокобезопасные обновления
    - Исключения по событию через predicate
    - Мультиоконные burn-rate алерты
    """

    def __init__(
        self,
        slo: SLOSpec,
        *,
        burn_alerts: Iterable[BurnAlertSpec] = (),
        exclusion_predicate: Optional[Callable[[float, Dict[str, str]], bool]] = None,
        on_alert: Optional[Callable[[BurnAlertEvent], None]] = None,
        on_snapshot: Optional[Callable[[BudgetSnapshot], None]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.slo = slo
        self.buckets = RollingBuckets(slo.window.duration_seconds, slo.window.bucket_seconds)
        self._lock = threading.RLock()
        self._clock = clock

        self._exclusion = exclusion_predicate  # если вернет True, событие исключаем из SLO
        self._on_alert = on_alert
        self._on_snapshot = on_snapshot

        # Состояние алертов: name -> dict
        self._alert_state: Dict[str, Dict[str, float]] = {}
        self._burn_specs: List[BurnAlertSpec] = list(burn_alerts)

    # ---------- обновление ----------

    def update(self, good: int, total: int, *, labels: Optional[Dict[str, str]] = None, ts: Optional[float] = None) -> None:
        """Добавить наблюдение. Если exclusion_predicate вернул True, запись игнорируется."""
        labels = labels or {}
        t = self._clock() if ts is None else ts
        if self._exclusion and self._exclusion(t, labels):
            return
        with self._lock:
            self.buckets.add(good, total, ts=t)

    # ---------- расчеты ----------

    def _calc_snapshot(self, now: Optional[float] = None, extra_windows: Iterable[int] = ()) -> BudgetSnapshot:
        now = self._clock() if now is None else now
        with self._lock:
            g, t = self.buckets.snapshot_all(now)
            bad = max(0, t - g)
            objective = self.slo.objective
            allowed = max(0.0, 1.0 - objective)

            compliance = 1.0 if t == 0 else g / t
            error_rate = 0.0 if t == 0 else bad / t
            budget_total_events = allowed * t
            budget_consumed_events = float(bad)
            budget_remaining_events = max(0.0, budget_total_events - budget_consumed_events)
            budget_remaining_ratio = 1.0 if budget_total_events == 0 else max(0.0, budget_remaining_events / budget_total_events)

            burn_rates: Dict[int, float] = {}
            for w in set(extra_windows):
                gg, tt = self.buckets.sum_window(w, now)
                bb = max(0, tt - gg)
                er = 0.0 if tt == 0 else bb / tt
                burn_rates[w] = 0.0 if allowed == 0.0 else er / allowed

            snap = BudgetSnapshot(
                ts=now,
                slo_name=self.slo.name,
                objective=objective,
                window_seconds=self.slo.window.duration_seconds,
                total=t,
                good=g,
                bad=bad,
                compliance=compliance,
                error_rate=error_rate,
                budget_allowed=allowed,
                budget_total_events=budget_total_events,
                budget_consumed_events=budget_consumed_events,
                budget_remaining_events=budget_remaining_events,
                budget_remaining_ratio=budget_remaining_ratio,
                burn_rates=burn_rates,
            )

        if self._on_snapshot:
            try:
                self._on_snapshot(snap)
            except Exception:
                # Сторонние ошибки не должны ломать расчеты
                pass
        return snap

    def snapshot(self, now: Optional[float] = None) -> BudgetSnapshot:
        windows = []
        for spec in self._burn_specs:
            windows.append(spec.short_window_seconds)
            windows.append(spec.long_window_seconds)
        return self._calc_snapshot(now=now, extra_windows=windows)

    # ---------- алерты ----------

    def _emit_alert(self, e: BurnAlertEvent) -> None:
        if self._on_alert:
            try:
                self._on_alert(e)
            except Exception:
                pass

    def check_alerts(self, now: Optional[float] = None) -> List[BurnAlertEvent]:
        now = self._clock() if now is None else now
        snap = self._calc_snapshot(now=now, extra_windows=[w for s in self._burn_specs for w in (s.short_window_seconds, s.long_window_seconds)])
        events: List[BurnAlertEvent] = []

        for spec in self._burn_specs:
            sname = spec.name
            state = self._alert_state.setdefault(sname, {
                "active": 0.0,
                "last_change": 0.0,
                "cooldown_until": 0.0,
            })

            br_short = snap.burn_rates.get(spec.short_window_seconds, 0.0)
            br_long = snap.burn_rates.get(spec.long_window_seconds, 0.0)

            over = (br_short >= spec.short_burn_rate_threshold) and (br_long >= spec.long_burn_rate_threshold)
            active = bool(state["active"])
            changed = False

            if over and not active and now >= state["cooldown_until"]:
                # Вход в активное состояние
                state["active"] = 1.0
                state["last_change"] = now
                changed = True
            elif active and not over:
                # Проверяем удержание в активном состоянии
                if spec.min_duration_seconds > 0 and now - state["last_change"] < spec.min_duration_seconds:
                    pass  # удерживаем
                else:
                    # Выходим из активного состояния
                    state["active"] = 0.0
                    state["last_change"] = now
                    if spec.cool_down_seconds > 0:
                        state["cooldown_until"] = now + spec.cool_down_seconds
                    changed = True

            if changed:
                evt = BurnAlertEvent(
                    ts=now,
                    name=spec.name,
                    active=bool(state["active"]),
                    short_burn_rate=br_short,
                    long_burn_rate=br_long,
                    reason="activated" if state["active"] else "cleared",
                    meta={
                        "short_window_s": float(spec.short_window_seconds),
                        "long_window_s": float(spec.long_window_seconds),
                        "short_threshold": float(spec.short_burn_rate_threshold),
                        "long_threshold": float(spec.long_burn_rate_threshold),
                        "cooldown_until": state["cooldown_until"],
                    },
                )
                self._emit_alert(evt)
                events.append(evt)

        return events


# ---------------------------
# Утилиты построения
# ---------------------------

def default_burn_alerts_for_objective(objective: float) -> List[BurnAlertSpec]:
    """
    Возвращает разумные параметры мультиоконных алертов для заданного SLO.
    Значения можно скорректировать под вашу нагрузку.
    """
    # Допустимая доля ошибок
    err = max(1e-9, 1.0 - objective)

    # Примеры окон и порогов
    # Короткое окно более агрессивное, длинное — стабилизирующее
    # Пропорционально допустимой ошибке выставляем burn-rate thresholds.
    if objective >= 0.999:  # 99.9
        short = BurnAlertSpec(
            name="high-burn-5m-1h",
            short_window_seconds=5 * 60,
            long_window_seconds=60 * 60,
            short_burn_rate_threshold=14.4,  # пример
            long_burn_rate_threshold=6.0,
            min_duration_seconds=0,
            cool_down_seconds=60,
        )
    elif objective >= 0.99:  # 99
        short = BurnAlertSpec(
            name="high-burn-30m-6h",
            short_window_seconds=30 * 60,
            long_window_seconds=6 * 60 * 60,
            short_burn_rate_threshold=6.0,
            long_burn_rate_threshold=2.0,
            min_duration_seconds=0,
            cool_down_seconds=60,
        )
    else:
        short = BurnAlertSpec(
            name="high-burn-1h-24h",
            short_window_seconds=60 * 60,
            long_window_seconds=24 * 60 * 60,
            short_burn_rate_threshold=4.0,
            long_burn_rate_threshold=1.5,
            min_duration_seconds=0,
            cool_down_seconds=60,
        )
    return [short]


def build_tracker(
    name: str,
    objective: float,
    window_seconds: int,
    bucket_seconds: int = 60,
    *,
    burn_alerts: Optional[List[BurnAlertSpec]] = None,
    exclusion_predicate: Optional[Callable[[float, Dict[str, str]], bool]] = None,
    on_alert: Optional[Callable[[BurnAlertEvent], None]] = None,
    on_snapshot: Optional[Callable[[BudgetSnapshot], None]] = None,
) -> SLOBudgetTracker:
    slo = SLOSpec(
        name=name,
        objective=objective,
        window=WindowSpec(duration_seconds=window_seconds, bucket_seconds=bucket_seconds),
        description=f"SLO {objective:.5f} over {window_seconds}s",
    )
    alerts = burn_alerts if burn_alerts is not None else default_burn_alerts_for_objective(objective)
    return SLOBudgetTracker(
        slo,
        burn_alerts=alerts,
        exclusion_predicate=exclusion_predicate,
        on_alert=on_alert,
        on_snapshot=on_snapshot,
    )


# ---------------------------
# Пример локального запуска
# ---------------------------

if __name__ == "__main__":  # pragma: no cover
    # Демонстрация. Не используется в проде.
    def print_alert(evt: BurnAlertEvent) -> None:
        print(
            f"[ALERT] ts={evt.ts:.0f} name={evt.name} active={evt.active} "
            f"br_short={evt.short_burn_rate:.2f} br_long={evt.long_burn_rate:.2f} reason={evt.reason}"
        )

    def print_snap(s: BudgetSnapshot) -> None:
        print(
            f"[SNAP] ts={s.ts:.0f} total={s.total} good={s.good} bad={s.bad} "
            f"comp={s.compliance:.6f} err={s.error_rate:.6f} rem={s.budget_remaining_ratio:.3f} "
            f"burns={{{', '.join(f'{k}:{v:.2f}' for k, v in s.burn_rates.items())}}}"
        )

    # 99.9 за 28 дней
    tracker = build_tracker(
        name="frontend-availability",
        objective=0.999,
        window_seconds=28 * 24 * 60 * 60,
        bucket_seconds=60,
        on_alert=print_alert,
        on_snapshot=print_snap,
    )

    # Синтетический поток: 100 успешных и иногда 10 неудач
    now = time.time()
    for i in range(300):
        ok = 100
        fail = 0 if i % 30 else 10
        tracker.update(good=ok, total=ok + fail, ts=now + i * 10)
        if i % 12 == 0:
            tracker.check_alerts(now=now + i * 10)
