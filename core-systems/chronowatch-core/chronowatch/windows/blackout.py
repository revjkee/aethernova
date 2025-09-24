"""
Chronowatch Core — Blackout windows engine.

Назначение:
  - Определять, попадает ли момент времени или интервал изменений в blackout-окна
    (freeze/запрет релизов), заданные в календарях Chronowatch.
  - Поддержка абсолютных периодов и RRULE-повторов с длительностью.
  - Корректная работа с таймзонами (IANA), DST и наивными датами.

Ключевые определения:
  - Интервалы считаются полуоткрытыми: [start, end)
    Это гарантирует отсутствие двойного учета крайних точек.
  - Все вычисления ведутся в таймзоне календаря; во внешнем API допускаются
    наивные datetime — они будут интерпретированы в TZ календаря.

Совместимость конфигурации (пример выдержки):
  calendars:
    business_se_default:
      timezone: "Europe/Stockholm"
      blackout_periods:
        - name: "Black Friday Campaign"
          period: { start: "2025-11-28", end: "2025-12-01" }  # даты (end — исключающее)
        - name: "Release Freeze"
          rrule:  "FREQ=DAILY;BYHOUR=19;BYMINUTE=0;BYSECOND=0"
          duration: "02:00:00"  # HH:MM:SS

Bindings (для сервиса):
  bindings:
    services:
      - name: "chronowatch-core-api"
        calendar: "business_se_default"
        rollout_policy:
          change_freeze_respect: true

Публичный API:
  - BlackoutEngine.from_config_dict(cfg) -> engine
  - engine.is_blackout(dt, service_name) -> (bool, reason | None)
  - engine.intersect_windows(start, end, service_name) -> list[WindowHit]
  - engine.next_allowed_time(start_dt, service_name, min_duration=None) -> datetime

Зависимости:
  - Стандартная библиотека Python 3.10+
  - dateutil (опционально) для RRULE; без нее RRULE-записи не поддерживаются.

Автор: Chronowatch Platform Ops
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, time as dtime
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Tuple

import json
import re
import threading

try:
    # Python 3.9+: IANA TZ
    from zoneinfo import ZoneInfo
except Exception as _e:  # pragma: no cover
    ZoneInfo = None  # type: ignore

try:
    from dateutil import rrule as du_rrule
    from dateutil import tz as du_tz
except Exception:
    du_rrule = None  # type: ignore
    du_tz = None  # type: ignore


# =========================
# Вспомогательные сущности
# =========================

@dataclass(frozen=True)
class TimeWindow:
    """Полуоткрытый интервал [start, end) в tz календаря."""
    start: datetime
    end: datetime
    name: str = ""
    source: str = ""  # например: calendars.<name>.blackout_periods[i]

    def contains(self, dt: datetime) -> bool:
        return self.start <= dt < self.end

    def intersects(self, other_start: datetime, other_end: datetime) -> bool:
        return self.start < other_end and other_start < self.end

    def intersection(self, other_start: datetime, other_end: datetime) -> Optional["TimeWindow"]:
        if not self.intersects(other_start, other_end):
            return None
        s = max(self.start, other_start)
        e = min(self.end, other_end)
        return TimeWindow(s, e, name=self.name, source=self.source)


@dataclass(frozen=True)
class WindowHit:
    """Результат пересечения blackout-окна с запросом."""
    window: TimeWindow
    overlap_start: datetime
    overlap_end: datetime

    @property
    def duration(self) -> timedelta:
        return self.overlap_end - self.overlap_start

    @property
    def reason(self) -> str:
        base = self.window.name or "blackout"
        if self.window.source:
            return f"{base} ({self.window.source})"
        return base


# =========================
# Исключения
# =========================

class BlackoutError(Exception):
    pass


class UnsupportedRuleError(BlackoutError):
    pass


# =========================
# Парсинг конфигурации
# =========================

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parse_iso_date_or_datetime(s: str, tz: ZoneInfo) -> datetime:
    """
    Принимает 'YYYY-MM-DD' либо полную ISO datetime.
    Даты без времени интерпретируются как 00:00:00 локального TZ.
    """
    if _ISO_DATE.match(s):
        dt = datetime.fromisoformat(s).replace(tzinfo=tz)
        return dt
    # fromisoformat с tz или без
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    else:
        dt = dt.astimezone(tz)
    return dt


def _parse_duration(s: str) -> timedelta:
    """
    Формат HH:MM[:SS]; допускается ISO 8601 PTnHnMnS (ограниченно).
    """
    if s.upper().startswith("PT"):
        # Простейший парсер PTnHnMnS
        hours = minutes = seconds = 0
        m = re.findall(r"(\d+)([HMS])", s.upper())
        for val, unit in m:
            v = int(val)
            if unit == "H":
                hours = v
            elif unit == "M":
                minutes = v
            elif unit == "S":
                seconds = v
        return timedelta(hours=hours, minutes=minutes, seconds=seconds)
    parts = s.split(":")
    if len(parts) not in (2, 3):
        raise ValueError(f"Invalid duration: {s}")
    hh = int(parts[0]); mm = int(parts[1]); ss = int(parts[2]) if len(parts) == 3 else 0
    return timedelta(hours=hh, minutes=mm, seconds=ss)


def _tz(info: Dict[str, Any], default_tz: str) -> ZoneInfo:
    tz_name = info.get("timezone") or default_tz
    if ZoneInfo is None:
        raise BlackoutError("zoneinfo not available in runtime")
    try:
        return ZoneInfo(tz_name)
    except Exception as e:
        raise BlackoutError(f"Invalid timezone: {tz_name}") from e


# =========================
# Компилятор правил blackout
# =========================

@dataclass
class _CompiledCalendar:
    name: str
    tz: ZoneInfo
    # Статические абсолютные интервалы (например, period start/end)
    static_windows: List[TimeWindow]
    # RRULE-окна: хранится исходник и длительность; разворачиваются по запросу
    rrules: List[Tuple[str, timedelta, str]]  # (rrule, duration, source)


class BlackoutEngine:
    """
    Движок blackout-окон для календарей Chronowatch.

    Конструктор:
      engine = BlackoutEngine(calendars_map, service_to_calendar, default_calendar=None)

    Простая инициализация из словаря календарей:
      engine = BlackoutEngine.from_config_dict(cfg_dict)
    """

    def __init__(
        self,
        calendars: Dict[str, _CompiledCalendar],
        service_bindings: Dict[str, str],
        default_calendar: Optional[str] = None,
        fail_open: bool = False,
    ) -> None:
        self._cal = calendars
        self._svc = service_bindings
        self._default_cal = default_calendar
        self._fail_open = fail_open
        self._lock = threading.RLock()

    # --------- Публичные фабрики ---------

    @classmethod
    def from_config_dict(cls, cfg: Dict[str, Any]) -> "BlackoutEngine":
        """
        Ожидается структура как в business_calendar.example.yaml:
          - calendars: { <name>: { timezone, blackout_periods: [...], ... } }
          - bindings.services: [{ name, calendar, rollout_policy.change_freeze_respect }]
        """
        calendars_blk = (cfg.get("calendars") or {})
        calendars: Dict[str, _CompiledCalendar] = {}

        for cal_name, cal in calendars_blk.items():
            tz = _tz(cal, cal.get("timezone") or (cfg.get("defaults") or {}).get("timezone") or "UTC")
            static_windows: List[TimeWindow] = []
            rrules: List[Tuple[str, timedelta, str]] = []

            # 1) blackout_periods: абсолютные периоды или RRULE c duration
            for idx, blk in enumerate(cal.get("blackout_periods") or []):
                source = f"calendars.{cal_name}.blackout_periods[{idx}]"
                nm = blk.get("name") or "blackout"
                if "period" in blk:
                    p = blk["period"] or {}
                    start_raw = p.get("start")
                    end_raw = p.get("end")
                    if not start_raw or not end_raw:
                        raise BlackoutError(f"Invalid period in {source}: start/end required")
                    start = _parse_iso_date_or_datetime(str(start_raw), tz)
                    end   = _parse_iso_date_or_datetime(str(end_raw), tz)
                    # Дата без времени 'YYYY-MM-DD' для end трактуется как 00:00 этого дня => [start, end)
                    # если нужно включить целый день, укажите end следующий день.
                    if end <= start:
                        raise BlackoutError(f"Invalid period in {source}: end <= start")
                    static_windows.append(TimeWindow(start, end, name=nm, source=source))
                elif "rrule" in blk:
                    if du_rrule is None:
                        raise UnsupportedRuleError("RRULE is not supported, dateutil is not installed")
                    rule = str(blk["rrule"])
                    duration = _parse_duration(str(blk.get("duration") or "01:00:00"))
                    rrules.append((rule, duration, source))
                else:
                    raise BlackoutError(f"Unknown blackout block type in {source}")

            calendars[cal_name] = _CompiledCalendar(
                name=cal_name,
                tz=tz,
                static_windows=sorted(static_windows, key=lambda w: (w.start, w.end)),
                rrules=rrules,
            )

        # 2) Привязка сервисов к календарям
        service_bindings: Dict[str, str] = {}
        default_calendar: Optional[str] = None

        for svc in (cfg.get("bindings") or {}).get("services") or []:
            name = svc.get("name")
            cal  = svc.get("calendar")
            if not name or not cal:
                continue
            rp = (svc.get("rollout_policy") or {})
            respect = bool(rp.get("change_freeze_respect", True))
            if respect:
                service_bindings[name] = cal

        # Если в defaults указан timezone, но default calendar нет — это нормально
        # default_calendar можно указать явно (не обязательно)
        return cls(
            calendars=calendars,
            service_bindings=service_bindings,
            default_calendar=default_calendar,
            fail_open=False,
        )

    # --------- Вспомогательные методы ---------

    def _calendar_for_service(self, service: Optional[str]) -> Optional[_CompiledCalendar]:
        if service and service in self._svc:
            cal_name = self._svc[service]
            return self._cal.get(cal_name)
        if self._default_cal:
            return self._cal.get(self._default_cal)
        return None

    @staticmethod
    def _normalize_dt(dt: datetime, tz: ZoneInfo) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=tz)
        return dt.astimezone(tz)

    # RRULE разворачивание с кешем (на сутки вперед/назад)
    @staticmethod
    @lru_cache(maxsize=512)
    def _expand_rrule_cached(
        rrule_str: str, duration_seconds: int, tz_name: str, pivot_iso: str
    ) -> Tuple[Tuple[str, ...], int]:
        """
        Возвращает кортеж ISO-строк стартов событий вокруг pivot (±36ч) и длительность в секундах.
        Кеш-ключ учитывает rrule, tz и округленный pivot.
        """
        if du_rrule is None:
            return tuple(), duration_seconds
        tz = ZoneInfo(tz_name)
        pivot = datetime.fromisoformat(pivot_iso).replace(tzinfo=tz)
        start = pivot - timedelta(hours=36)
        end   = pivot + timedelta(hours=36)

        # Библиотека dateutil.rrule не принимает таймзону отдельно; используем локальные naive times
        # Построим rrule с базовым dtstart = start (в локальной TZ)
        # Если BYHOUR/BYMINUTE/BYSECOND заданы, rrule применит время.
        rule = du_rrule.rrulestr(rrule_str, dtstart=start.replace(tzinfo=None))
        occ = list(rule.between(start.replace(tzinfo=None), end.replace(tzinfo=None), inc=True))
        # Преобразуем в TZ-aware
        occ_tz = [o.replace(tzinfo=tz) for o in occ]
        iso = tuple(x.isoformat() for x in occ_tz)
        return iso, duration_seconds

    def _expand_rrules_near(self, cal: _CompiledCalendar, pivot: datetime) -> Iterable[TimeWindow]:
        for rule, dur, source in cal.rrules:
            iso_list, dur_sec = self._expand_rrule_cached(rule, int(dur.total_seconds()), cal.tz.key, pivot.isoformat())
            for iso in iso_list:
                start = datetime.fromisoformat(iso)
                end = start + timedelta(seconds=dur_sec)
                yield TimeWindow(start, end, name="blackout", source=source)

    # Слияние перечня окон (опционально — если потребуется оптимизация)
    @staticmethod
    def _merge_sorted_windows(windows: List[TimeWindow]) -> List[TimeWindow]:
        if not windows:
            return windows
        windows.sort(key=lambda w: w.start)
        merged: List[TimeWindow] = []
        cur = windows[0]
        for w in windows[1:]:
            if w.start <= cur.end:
                # Объединяем; для метаданных сохраняем имя/источник текущего
                cur = TimeWindow(cur.start, max(cur.end, w.end), name=cur.name or w.name, source=cur.source or w.source)
            else:
                merged.append(cur)
                cur = w
        merged.append(cur)
        return merged

    # --------- Публичные операции ---------

    def is_blackout(self, when: datetime, service: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        True/False и текст причины для точки времени.
        """
        cal = self._calendar_for_service(service)
        if cal is None:
            return ((False, None) if self._fail_open else (False, None))
        t = self._normalize_dt(when, cal.tz)

        # Статические окна
        for w in cal.static_windows:
            if w.contains(t):
                return True, (w.name or "blackout")

        # Динамические окна (RRULE)
        for w in self._expand_rrules_near(cal, t):
            if w.contains(t):
                return True, (w.name or "blackout")

        return False, None

    def intersect_windows(
        self,
        start: datetime,
        end: datetime,
        service: Optional[str] = None,
    ) -> List[WindowHit]:
        """
        Возвращает список пересечений blackout-окон с указанным интервалом [start, end).
        """
        if end <= start:
            raise BlackoutError("end must be greater than start")

        cal = self._calendar_for_service(service)
        if cal is None:
            return []

        s = self._normalize_dt(start, cal.tz)
        e = self._normalize_dt(end, cal.tz)

        hits: List[WindowHit] = []

        # Статические
        for w in cal.static_windows:
            if w.intersects(s, e):
                inter = w.intersection(s, e)
                if inter:
                    hits.append(WindowHit(window=w, overlap_start=inter.start, overlap_end=inter.end))

        # RRULE около интересующего диапазона
        pivot = s + (e - s) / 2
        for w in self._expand_rrules_near(cal, pivot):
            if w.intersects(s, e):
                inter = w.intersection(s, e)
                if inter:
                    hits.append(WindowHit(window=w, overlap_start=inter.start, overlap_end=inter.end))

        # Можно объединить и нормализовать (не обязательно)
        return hits

    def next_allowed_time(
        self,
        start: datetime,
        service: Optional[str] = None,
        min_duration: Optional[timedelta] = None,
        search_horizon: timedelta = timedelta(days=30),
    ) -> datetime:
        """
        Ищет ближайшее время не в blackout, начиная с 'start'.
        Если задано min_duration, вернет момент, с которого как минимум min_duration не
        пересекается с blackout-окнами. Поиск ограничен search_horizon.

        Возвращает datetime в TZ календаря.
        """
        cal = self._calendar_for_service(service)
        if cal is None:
            # Нет календаря — по умолчанию разрешено
            return start

        cur = self._normalize_dt(start, cal.tz)
        deadline = cur + search_horizon

        # Итеративно перескакиваем через окна blackout
        while cur < deadline:
            blocked, _ = self.is_blackout(cur, service=service)
            if not blocked:
                if not min_duration:
                    return cur
                # Проверим, что следующий blackout не начнется раньше чем через min_duration
                end_check = cur + min_duration
                hits = self.intersect_windows(cur, end_check, service=service)
                if not hits:
                    return cur
                # есть пересечение — сдвигаем cur на конец ближайшего пересечения
                nearest_end = min(h.overlap_end for h in hits if h.overlap_start <= cur + min_duration)
                cur = max(nearest_end, cur + timedelta(minutes=1))
                continue
            # Найдем ближайшее пересечение в [cur, cur+1d) и перепрыгнем через его конец
            hits = self.intersect_windows(cur, cur + timedelta(days=1), service=service)
            if hits:
                cur = max(h.overlap_end for h in hits)
            else:
                # на всякий случай защищаемся от зацикливания
                cur = cur + timedelta(minutes=5)

        raise BlackoutError("next_allowed_time search exceeded horizon")


# =========================
# Утилиты интеграции
# =========================

def engine_from_raw_config(raw: Dict[str, Any]) -> BlackoutEngine:
    """
    Враппер, допускающий передачу конфига как dict или JSON-строки.
    """
    if isinstance(raw, str):
        cfg = json.loads(raw)
    else:
        cfg = raw
    return BlackoutEngine.from_config_dict(cfg)


# =========================
# Примитивные self-tests (doctest стиль)
# Запускаются при необходимости: python -m chronowatch.windows.blackout
# =========================

if __name__ == "__main__":  # pragma: no cover
    cfg = {
        "defaults": {"timezone": "Europe/Stockholm"},
        "calendars": {
            "se": {
                "timezone": "Europe/Stockholm",
                "blackout_periods": [
                    {
                        "name": "campaign",
                        "period": {"start": "2025-11-28", "end": "2025-12-01"},
                    },
                    {
                        "name": "daily-freeze",
                        "rrule": "FREQ=DAILY;BYHOUR=19;BYMINUTE=0;BYSECOND=0",
                        "duration": "02:00:00",
                    },
                ],
            }
        },
        "bindings": {
            "services": [
                {"name": "chronowatch-core-api", "calendar": "se", "rollout_policy": {"change_freeze_respect": True}}
            ]
        },
    }

    eng = BlackoutEngine.from_config_dict(cfg)

    tz = ZoneInfo("Europe/Stockholm")
    t1 = datetime(2025, 11, 28, 12, 0, tzinfo=tz)
    print("is_blackout 2025-11-28 12:00:", eng.is_blackout(t1, "chronowatch-core-api"))

    t2 = datetime(2025, 11, 27, 19, 30, tzinfo=tz)
    print("is_blackout daily 19:30:", eng.is_blackout(t2, "chronowatch-core-api"))

    start = datetime(2025, 11, 27, 18, 0, tzinfo=tz)
    end = datetime(2025, 11, 27, 21, 0, tzinfo=tz)
    hits = eng.intersect_windows(start, end, "chronowatch-core-api")
    for h in hits:
        print("hit:", h.reason, h.overlap_start, "->", h.overlap_end)

    na = eng.next_allowed_time(datetime(2025, 11, 28, 10, 0, tzinfo=tz), "chronowatch-core-api", timedelta(hours=1))
    print("next allowed:", na.isoformat())
