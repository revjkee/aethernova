"""
chronowatch.timebase.monotonic

Промышленная монотоничная таймбаза для ChronoWatch:
- Высокоточное монотоничное время (ns) на базе time.monotonic_ns().
- Калибровка в UNIX-время (ns) через якорь (anchor) mono↔unix.
- Потокобезопасные обновления калибровки, контроль дрейфа и "откатов".
- EWMA-оценка джиттера сна для адаптивной точности sleep_until().
- Дедлайны, периодический тикер с компенсацией дрейфа.
- Асинхронные sleep_утилиты без активного busy-spin.

Зависимости: только стандартная библиотека Python 3.11+.
"""

from __future__ import annotations

import asyncio
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional, Tuple

__all__ = [
    "MonotonicClock",
    "Deadline",
    "Ticker",
    "sleep_until",
    "sleep_for",
]

log = logging.getLogger("chronowatch.timebase.monotonic")


def _monotonic_ns() -> int:
    """
    Возвращает монотоничное время в наносекундах.
    На большинстве платформ гарантированно не убывает.
    """
    try:
        return time.monotonic_ns()
    except AttributeError:  # крайне устаревшие среды
        return int(time.monotonic() * 1e9)


def _unix_time_ns() -> int:
    """Текущее UNIX-время в наносекундах по системным стеночным часам."""
    try:
        return time.time_ns()
    except AttributeError:
        return int(time.time() * 1e9)


@dataclass(slots=True)
class _EWMA:
    """
    Экспоненциальное скользящее среднее (EWMA) для оценки джиттера/ошибки сна.
    alpha в [0,1]: чем больше alpha, тем быстрее адаптация и больше вес недавних измерений.
    """
    alpha: float = 0.2
    value_ns: float = 0.0
    initialized: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, sample_ns: int) -> None:
        with self._lock:
            if not self.initialized:
                self.value_ns = float(sample_ns)
                self.initialized = True
            else:
                self.value_ns = self.alpha * float(sample_ns) + (1.0 - self.alpha) * self.value_ns

    def get(self) -> int:
        with self._lock:
            return int(self.value_ns if self.initialized else 0)


@dataclass(slots=True)
class _Anchor:
    """
    Якорь калибровки mono↔unix:
    unix_ns = unix_anchor_ns + (mono_now - mono_anchor_ns).
    """
    mono_anchor_ns: int
    unix_anchor_ns: int
    version: int = 1


class MonotonicClock:
    """
    Центральная монотоничная таймбаза.

    Свойства:
      - now_ns(): монотоничное текущее время.
      - unix_from_mono_ns(mono_ns): проекция в UNIX-время по текущей калибровке.
      - unix_now_ns(): оценка UNIX сейчас через монотоничный ход (избегает скачков стеночных часов).
      - calibrate_to_wall(): переякорение по системным часам (атомарно).
      - apply_ntp_telemetry(ntp_unix_ns): плавная калибровка по эталонному времени.
      - drift(): оценка дрейфа unix_now_ns() против текущей стенки.

    Все операции потокобезопасны.
    """

    # Порог предупреждения о дрейфе (наносекунды)
    DEFAULT_MAX_DRIFT_NS = 20_000_000  # 20 ms

    def __init__(self, *, max_drift_ns: int | None = None, ewma_alpha: float = 0.2) -> None:
        self._lock = threading.RLock()
        mono = _monotonic_ns()
        unix = _unix_time_ns()
        self._anchor: _Anchor = _Anchor(mono_anchor_ns=mono, unix_anchor_ns=unix, version=1)
        self._max_drift_ns = int(max_drift_ns if max_drift_ns is not None else self.DEFAULT_MAX_DRIFT_NS)
        self._sleep_error_ewma = _EWMA(alpha=ewma_alpha)
        self._last_mono_ns = mono  # защита от гипотетического "отката"
        log.debug("MonotonicClock initialized: mono=%d unix=%d", mono, unix)

    # ---------------- Base time getters ----------------

    def now_ns(self) -> int:
        """Монотоничное время сейчас (ns), защищено от редкого гипотетического убывания."""
        m = _monotonic_ns()
        with self._lock:
            if m < self._last_mono_ns:
                # Не должно происходить, но если ОС вернула меньше — пиннимся к последнему значению.
                log.warning("monotonic_ns decreased: last=%d current=%d", self._last_mono_ns, m)
                m = self._last_mono_ns
            else:
                self._last_mono_ns = m
        return m

    def unix_from_mono_ns(self, mono_ns: int) -> int:
        """Проекция монотоничного момента в UNIX-время по текущей калибровке."""
        with self._lock:
            delta = mono_ns - self._anchor.mono_anchor_ns
            return self._anchor.unix_anchor_ns + delta

    def unix_now_ns(self) -> int:
        """Оценка текущего UNIX-времени, стабильная к скачкам стеночных часов."""
        m = self.now_ns()
        return self.unix_from_mono_ns(m)

    # ---------------- Calibration ----------------

    def calibrate_to_wall(self) -> _Anchor:
        """
        Жестко привязывает текущий якорь к системным стеночным часам.
        Использовать при старте сервиса или после существенной коррекции.
        """
        m = self.now_ns()
        u = _unix_time_ns()
        with self._lock:
            self._anchor = _Anchor(mono_anchor_ns=m, unix_anchor_ns=u, version=self._anchor.version + 1)
            log.info("Re-anchored monotonic->unix: mono=%d unix=%d version=%d", m, u, self._anchor.version)
            return self._anchor

    def apply_ntp_telemetry(self, ntp_unix_ns: int, *, soft: bool = True, gain: float = 0.1) -> Tuple[int, int]:
        """
        Плавно подстраивает якорь к эталонному времени (например, NTP).
        soft=True: линейная подстройка якоря с коэффициентом gain.
        soft=False: мгновенное переякорение на ntp_unix_ns.

        Возвращает (drift_ns, new_version).
        """
        m = self.now_ns()
        with self._lock:
            # Текущее предсказанное UNIX и наблюдение NTP
            predicted = self._anchor.unix_anchor_ns + (m - self._anchor.mono_anchor_ns)
            drift = ntp_unix_ns - predicted  # положительный => отстаем
            if abs(drift) > self._max_drift_ns:
                log.warning("Clock drift exceeds threshold: drift=%dns threshold=%dns", drift, self._max_drift_ns)

            if soft:
                # Сдвигаем только якорь unix_anchor_ns, чтобы монотоничный ход сохранился
                adj = int(drift * max(0.0, min(1.0, gain)))
                new_unix_anchor = self._anchor.unix_anchor_ns + adj
                self._anchor = _Anchor(
                    mono_anchor_ns=self._anchor.mono_anchor_ns,
                    unix_anchor_ns=new_unix_anchor,
                    version=self._anchor.version + 1,
                )
                log.debug("Soft NTPlike adjust: drift=%d adj=%d version=%d", drift, adj, self._anchor.version)
            else:
                # Жесткая коррекция: unix_anchor_ns := ntp - (m - mono_anchor_ns)
                base_delta = m - self._anchor.mono_anchor_ns
                new_unix_anchor = ntp_unix_ns - base_delta
                self._anchor = _Anchor(
                    mono_anchor_ns=self._anchor.mono_anchor_ns,
                    unix_anchor_ns=new_unix_anchor,
                    version=self._anchor.version + 1,
                )
                log.info("Hard NTPlike reanchor: drift=%d version=%d", drift, self._anchor.version)
            return drift, self._anchor.version

    def drift(self) -> int:
        """
        Возвращает текущий дрейф (ns) между unix_now_ns() и системной стенкой time.time_ns().
        Положительное значение означает отставание проекции от стенки.
        """
        predicted = self.unix_now_ns()
        wall = _unix_time_ns()
        return wall - predicted

    # ---------------- EWMA jitter stats (sleep error) ----------------

    def record_sleep_error(self, planned_ns: int, woke_at_ns: int) -> None:
        """
        Сохранить ошибку пробуждения (насколько позже или раньше проснулись относительно планового момента).
        Используется для адаптивной точности sleep_until.
        """
        err = max(0, woke_at_ns - planned_ns)  # интересует опоздание; "раньше" практически не бывает
        self._sleep_error_ewma.add(err)

    def get_sleep_error_ewma_ns(self) -> int:
        """Текущая EWMA-оценка ошибки сна в наносекундах."""
        return self._sleep_error_ewma.get()

    # ---------------- Convenience ----------------

    def deadline_ns(self, timeout_ns: int) -> int:
        """Вернуть дедлайн (монотоничный) через timeout_ns от теперь."""
        return self.now_ns() + max(0, int(timeout_ns))

    def non_decreasing_unix_now_ns(self, *, prev_unix_ns: int) -> int:
        """
        Возвращает неубывающее UNIX-время: гарантирует, что новое значение >= prev_unix_ns.
        """
        u = self.unix_now_ns()
        return u if u >= prev_unix_ns else prev_unix_ns


# ---------- Deadlines ----------

@dataclass(slots=True)
class Deadline:
    """
    Удобный контейнер для дедлайнов на монотоничной шкале.

    Пример:
        clock = MonotonicClock()
        dl = Deadline.start(clock, timeout_ns=500_000_000)  # 500ms
        remaining = dl.remaining_ns(clock)
    """
    due_ns: int

    @classmethod
    def start(cls, clock: MonotonicClock, timeout_ns: int) -> "Deadline":
        return cls(due_ns=clock.deadline_ns(timeout_ns))

    def expired(self, clock: MonotonicClock) -> bool:
        return clock.now_ns() >= self.due_ns

    def remaining_ns(self, clock: MonotonicClock) -> int:
        now = clock.now_ns()
        return 0 if now >= self.due_ns else self.due_ns - now


# ---------- Ticker with drift compensation ----------

class Ticker:
    """
    Периодический тикер с компенсацией дрейфа: планирует тики как anchor + k*period,
    невзирая на реальную длительность сна, что устраняет накопление ошибки.

    Использование:
        async for t in ticker.iter_ticks():
            ...
    """

    def __init__(self, clock: MonotonicClock, period_ns: int, *, start_immediately: bool = True) -> None:
        if period_ns <= 0:
            raise ValueError("period_ns must be positive")
        self._clock = clock
        self._period_ns = int(period_ns)
        self._k = 0
        self._anchor_ns = clock.now_ns()
        if not start_immediately:
            self._anchor_ns = self._anchor_ns + self._period_ns
        self._closed = False

    def next_deadline_ns(self) -> int:
        return self._anchor_ns + self._k * self._period_ns

    def close(self) -> None:
        self._closed = True

    async def iter_ticks(self) -> AsyncIterator[int]:
        """
        Асинхронный генератор, возвращает момент тика (монотоничный ns).
        Останавливается при close().
        """
        while not self._closed:
            due = self.next_deadline_ns()
            await sleep_until(due, clock=self._clock)
            self._k += 1
            yield due


# ---------- Async sleeps ----------

# Пороги для многослойного ожидания:
# - если осталось > COARSE_SLEEP_THRESHOLD_NS: один крупный asyncio.sleep
# - затем серия коротких снов вплоть до FINE_GUARD_NS
# - остаток, как правило, "съедает" планировщик, без активного busy-spin
COARSE_SLEEP_THRESHOLD_NS = 50_000_000     # 50 ms
FINE_GUARD_NS = 2_000_000                  # 2 ms
MIN_SLEEP_SLICE_NS = 1_000_000             # 1 ms
MAX_SHORT_SLEEPS = 20                      # защита от зацикливания


async def sleep_until(deadline_ns: int, *, clock: Optional[MonotonicClock] = None) -> None:
    """
    Асинхронно спит до дедлайна в монотоничных наносекундах.
    Не использует активное вращение; комбинирует крупный и мелкие сны.
    Адаптивно учитывает EWMA-ошибку сна из clock.record_sleep_error().

    Если clock не передан, используется локальный MonotonicClock без глобальной калибровки.
    """
    clk = clock or MonotonicClock()
    now = clk.now_ns()
    remaining = deadline_ns - now
    if remaining <= 0:
        return

    # Крупная фаза
    if remaining > COARSE_SLEEP_THRESHOLD_NS:
        # Оставим запас под джиттер и мелкую фазу
        overshoot_ns = max(FINE_GUARD_NS, clk.get_sleep_error_ewma_ns())
        coarse = max(0, remaining - overshoot_ns)
        await asyncio.sleep(coarse / 1e9)

    # Мелкая фаза короткими срезами
    short_sleeps = 0
    while True:
        now = clk.now_ns()
        remaining = deadline_ns - now
        if remaining <= 0:
            clk.record_sleep_error(deadline_ns, now)
            return
        if short_sleeps >= MAX_SHORT_SLEEPS:
            # Не зацикливаемся: одно финальное ожидание
            await asyncio.sleep(remaining / 1e9)
            now = clk.now_ns()
            clk.record_sleep_error(deadline_ns, now)
            return
        slice_ns = max(MIN_SLEEP_SLICE_NS, min(FINE_GUARD_NS, remaining))
        await asyncio.sleep(slice_ns / 1e9)
        short_sleeps += 1


async def sleep_for(delta_ns: int, *, clock: Optional[MonotonicClock] = None) -> None:
    """
    Спать delta_ns от текущего монотоничного времени.
    """
    clk = clock or MonotonicClock()
    await sleep_until(clk.deadline_ns(delta_ns), clock=clk)


# ---------- Простейшие самопроверки (опционально) ----------

if __name__ == "__main__":
    # Неблокирующие проверки промера работоспособности при локальном запуске.
    logging.basicConfig(level=logging.INFO)

    clk = MonotonicClock()
    start_mono = clk.now_ns()
    start_unix = clk.unix_now_ns()

    async def demo() -> None:
        tkr = Ticker(clk, period_ns=50_000_000)  # 50 ms
        hits = 5
        async for due in tkr.iter_ticks():
            now = clk.now_ns()
            log.info("tick: due=%d now=%d late_ns=%d ewma=%d",
                     due, now, max(0, now - due), clk.get_sleep_error_ewma_ns())
            hits -= 1
            if hits == 0:
                tkr.close()

    log.info("Start unix=%d mono=%d drift=%dns", start_unix, start_mono, clk.drift())

    asyncio.run(demo())

    end_unix = clk.unix_now_ns()
    log.info("Elapsed (mono) ~ %0.3f ms, unix advanced ~ %0.3f ms",
             (clk.now_ns() - start_mono) / 1e6,
             (end_unix - start_unix) / 1e6)
