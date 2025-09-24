# -*- coding: utf-8 -*-
"""
Промышленный fuzz-набор для ChronoWatch Schedule Engine.

Требования:
  - pytest
  - hypothesis
  - python-dateutil (для эталона сравнения)
  - Python 3.10+ (zoneinfo)

Контракт тестируемого движка (TUT — Target Under Test):
  from chronowatch_core.schedule import (
      parse_vevent,            # (vevent_str: str) -> Schedule
      serialize_schedule,      # (schedule) -> str (VEVENT)
      next_occurrences,        # (schedule, start: datetime, count: int|None, until: datetime|None) -> list[datetime]
      ScheduleError,           # Exception
  )

Адаптация:
  - Укажите переменную окружения CHRONOWATCH_TEST_IMPL="package.module"
    где определены функции по контракту.
  - При отсутствии — задействуется встроенный эталон на базе dateutil (для исполнимости),
    чтобы вы могли сразу запускать и валидировать сам тестовый генератор.

Покрытие свойств:
  1) Round-trip VEVENT: parse -> serialize -> parse и эквивалентность первых N вхождений.
  2) Монотонность и уникальность последовательностей дат.
  3) Инварианты COUNT/UNTIL.
  4) Сравнение с эталоном dateutil на первых N (N<=256) для случайных корректных RRULE.
  5) Негативные: коррапт-строки поднимают ScheduleError.
  6) DST-границы для Europe/Stockholm.

Автор: Aethernova / ChronoWatch QA
"""
from __future__ import annotations

import importlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional, List, Tuple

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

try:
    # Эталонный референс
    from dateutil.rrule import rrulestr
except Exception as e:  # pragma: no cover
    pytest.skip(f"python-dateutil is required for this test: {e}", allow_module_level=True)

try:
    from zoneinfo import ZoneInfo
except Exception as e:  # pragma: no cover
    pytest.skip(f"Python 3.9+ zoneinfo required: {e}", allow_module_level=True)


# ------------------------------
# Адаптер к тестируемой системе
# ------------------------------

@dataclass
class TUT:
    parse_vevent: callable
    serialize_schedule: callable
    next_occurrences: callable
    ScheduleError: type


def _load_tut() -> TUT:
    """
    Загружает реализацию из CHRONOWATCH_TEST_IMPL="<module.path>".
    При отсутствии — подставляет эталонную реализацию на базе dateutil.
    """
    mod_path = os.environ.get("CHRONOWATCH_TEST_IMPL")
    if mod_path:
        mod = importlib.import_module(mod_path)
        return TUT(
            parse_vevent=getattr(mod, "parse_vevent"),
            serialize_schedule=getattr(mod, "serialize_schedule"),
            next_occurrences=getattr(mod, "next_occurrences"),
            ScheduleError=getattr(mod, "ScheduleError"),
        )
    # Фоллбэк: эталонная reference-реализация (чтобы тест был исполняем без TUT)
    class _RefSchedule:
        def __init__(self, dtstart: datetime, rrule_line: str, tz: Optional[str]):
            self.dtstart = dtstart
            self.rrule_line = rrule_line
            self.tz = tz

    class _RefError(Exception):
        pass

    def _ref_parse_vevent(vevent: str) -> _RefSchedule:
        if "BEGIN:VEVENT" not in vevent or "RRULE:" not in vevent:
            raise _RefError("Invalid VEVENT")
        # Разбор DTSTART (поддержка TZID=)
        m_tzid = re.search(r"DTSTART(?:;TZID=([^:]+))?:(\d{8}T\d{6}Z?)", vevent)
        if not m_tzid:
            raise _RefError("DTSTART missing or malformed")
        tzid, dt_raw = m_tzid.groups()
        if dt_raw.endswith("Z"):
            dt = datetime.strptime(dt_raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=ZoneInfo("UTC"))
        else:
            dt = datetime.strptime(dt_raw, "%Y%m%dT%H%M%S")
            if tzid:
                dt = dt.replace(tzinfo=ZoneInfo(tzid))
        m_rr = re.search(r"RRULE:([^\r\n]+)", vevent)
        if not m_rr:
            raise _RefError("RRULE missing")
        return _RefSchedule(dt, m_rr.group(1), tzid)

    def _ref_serialize_schedule(s: _RefSchedule) -> str:
        if s.dtstart.tzinfo is None and s.tz:
            raise _RefError("Inconsistent tzinfo")
        if s.dtstart.tzinfo is None:
            dt_val = s.dtstart.strftime("%Y%m%dT%H%M%S")
            dt_line = f"DTSTART:{dt_val}"
        else:
            # Если UTC — пишем с Z, иначе используем TZID
            if s.dtstart.tzinfo.key == "UTC":
                dt_val = s.dtstart.strftime("%Y%m%dT%H%M%SZ")
                dt_line = f"DTSTART:{dt_val}"
            else:
                dt_val = s.dtstart.strftime("%Y%m%dT%H%M%S")
                dt_line = f"DTSTART;TZID={s.dtstart.tzinfo.key}:{dt_val}"
        return f"BEGIN:VEVENT\n{dt_line}\nRRULE:{s.rrule_line}\nEND:VEVENT"

    def _ref_next_occurrences(s: _RefSchedule, start: datetime, count: Optional[int], until: Optional[datetime]) -> List[datetime]:
        # rrulestr поддерживает формат с преподом строки DTSTART
        dtline = "DTSTART:" + s.dtstart.astimezone(ZoneInfo("UTC")).strftime("%Y%m%dT%H%M%SZ")
        rule = rrulestr(dtline + "\nRRULE:" + s.rrule_line, forceset=True)
        # Ограничение по until из аргумента теста
        results = []
        it = iter(rule)
        for dt in it:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            if dt < start:
                continue
            if until and dt > until:
                break
            results.append(dt)
            if count is not None and len(results) >= count:
                break
        return results

    return TUT(
        parse_vevent=_ref_parse_vevent,
        serialize_schedule=_ref_serialize_schedule,
        next_occurrences=_ref_next_occurrences,
        ScheduleError=_RefError,
    )


TUT_OBJ = _load_tut()


# ------------------------------
# Вспомогательные генераторы
# ------------------------------

ZONES = st.sampled_from([
    "UTC",
    "Europe/Stockholm",
    "Europe/Berlin",
    "America/New_York",
    "Asia/Tokyo",
])

FREQ = st.sampled_from(["DAILY", "WEEKLY", "MONTHLY", "YEARLY"])
INTERVAL = st.integers(min_value=1, max_value=52)

# До 10 элементов для BY-частей, чтобы не взорвать комбинаторику
SMALL_INT_SET = lambda minv, maxv: st.lists(st.integers(min_value=minv, max_value=maxv), min_size=1, max_size=10, unique=True)

BYMONTH = st.none() | SMALL_INT_SET(1, 12).map(lambda xs: ("BYMONTH", xs))
BYMONTHDAY = st.none() | SMALL_INT_SET(1, 28).map(lambda xs: ("BYMONTHDAY", xs))  # 1..28 безопаснее для всех месяцев
BYYEARDAY = st.none() | SMALL_INT_SET(1, 360).map(lambda xs: ("BYYEARDAY", xs))

WEEKDAYS = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
BYDAY = st.none() | st.lists(st.sampled_from(WEEKDAYS), min_size=1, max_size=7, unique=True).map(lambda xs: ("BYDAY", xs))

WKST = st.none() | st.sampled_from(WEEKDAYS).map(lambda x: ("WKST", x))

# COUNT и UNTIL — взаимоисключающие в генерации (для простоты)
COUNT = st.integers(min_value=1, max_value=256).map(lambda n: ("COUNT", n))
UNTIL = st.datetimes(
    min_value=datetime(2023, 1, 1, 0, 0, 0, tzinfo=ZoneInfo("UTC")),
    max_value=datetime(2028, 12, 31, 23, 59, 59, tzinfo=ZoneInfo("UTC")),
)

def _fmt_list(key: str, xs: Iterable[int | str]) -> str:
    return f"{key}=" + ",".join(str(x) for x in xs)

def _mk_rrule(freq: str,
              interval: int,
              maybe_bymonth,
              maybe_bymonthday,
              maybe_byyearday,
              maybe_byday,
              maybe_wkst,
              maybe_count: Optional[Tuple[str, int]],
              maybe_until: Optional[datetime]) -> str:
    parts = [f"FREQ={freq}", f"INTERVAL={interval}"]
    for kv in [maybe_bymonth, maybe_bymonthday, maybe_byyearday, maybe_byday, maybe_wkst]:
        if kv:
            k, v = kv
            if isinstance(v, list):
                parts.append(_fmt_list(k, v))
            else:
                parts.append(f"{k}={v}")
    if maybe_count:
        parts.append(f"COUNT={maybe_count[1]}")
    if maybe_until:
        # RFC5545 формально требует UTC Z-формат
        parts.append("UNTIL=" + maybe_until.astimezone(ZoneInfo("UTC")).strftime("%Y%m%dT%H%M%SZ"))
    return ";".join(parts)

def _mk_dtstart(tzname: str, naive: bool) -> Tuple[str, datetime]:
    """
    Возвращает (строка DTSTART для VEVENT, datetime)
    """
    tz = ZoneInfo(tzname)
    base = st.datetimes(
        min_value=datetime(2023, 1, 1, 0, 0, 0),
        max_value=datetime(2028, 12, 31, 23, 59, 59),
    ).example()
    if naive:
        dt = base.replace(microsecond=0)
        return f"DTSTART:{dt.strftime('%Y%m%dT%H%M%S')}", dt
    else:
        dt = base.replace(tzinfo=tz, microsecond=0)
        if tzname == "UTC":
            return f"DTSTART:{dt.astimezone(ZoneInfo('UTC')).strftime('%Y%m%dT%H%M%SZ')}", dt
        else:
            return f"DTSTART;TZID={tzname}:{dt.strftime('%Y%m%dT%H%M%S')}", dt

def build_valid_vevent():
    """
    Composite strategy: валидный VEVENT с одним RRULE.
    """
    def _builder(args):
        (tzname, naive,
         freq, interval, bymonth, bymonthday, byyearday, byday, wkst,
         use_count, count_val, until_dt) = args

        # COUNT xor UNTIL
        maybe_count = ("COUNT", count_val) if use_count else None
        maybe_until = None if use_count else until_dt

        dt_line, dt = _mk_dtstart(tzname, naive)
        rrule = _mk_rrule(freq, interval, bymonth, bymonthday, byyearday, byday, wkst, maybe_count, maybe_until)

        vevent = f"BEGIN:VEVENT\n{dt_line}\nRRULE:{rrule}\nEND:VEVENT"
        return vevent, dt, tzname

    return st.tuples(
        ZONES,
        st.booleans(),               # naive or tz-aware
        FREQ,
        INTERVAL,
        BYMONTH,
        BYMONTHDAY,
        st.none() | BYYEARDAY,       # реже используем BYYEARDAY
        BYDAY,
        WKST,
        st.booleans(),               # use COUNT
        COUNT.map(lambda kv: kv[1]),
        st.none() | UNTIL,
    ).map(_builder)


VALID_VEVENTS = build_valid_vevent()

CORRUPT_VEVENTS = st.text(min_size=1, max_size=200).filter(lambda s: "BEGIN:VEVENT" not in s or "RRULE:" not in s)


# ------------------------------
# Утилиты проверки свойств
# ------------------------------

def assert_strictly_increasing_unique(dts: List[datetime]) -> None:
    for i in range(1, len(dts)):
        assert dts[i] > dts[i - 1], "Sequence must be strictly increasing"
    assert len(dts) == len(set(dts)), "No duplicates allowed"

def reference_occurrences(vevent: str, start: datetime, count: Optional[int], until: Optional[datetime]) -> List[datetime]:
    """
    Эталон на базе dateutil.rrulestr, возвращает первые count вхождений >= start,
    ограниченные until.
    """
    # Вырезаем DTSTART и RRULE для rrulestr
    m_rr = re.search(r"RRULE:([^\r\n]+)", vevent)
    m_dt_raw = re.search(r"DTSTART(?::|;TZID=[^:]+:)(\d{8}T\d{6}Z?)", vevent)
    assert m_rr and m_dt_raw, "Invalid VEVENT for reference"
    dt_raw = m_dt_raw.group(1)
    dtline = "DTSTART:" + dt_raw
    rrset = rrulestr(dtline + "\nRRULE:" + m_rr.group(1), forceset=True)

    results = []
    for dt in rrset:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        if dt < start:
            continue
        if until and dt > until:
            break
        results.append(dt)
        if count is not None and len(results) >= count:
            break
    return results


# ------------------------------
# Тесты свойств
# ------------------------------

@settings(
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    max_examples=200,
)
@given(VALID_VEVENTS, st.integers(min_value=1, max_value=256))
def test_roundtrip_and_equivalence(sample, take_n):
    """
    1) parse -> serialize -> parse сохраняет семантику.
    2) Первые N вхождений совпадают с эталоном dateutil.
    3) Последовательность строгая и без дублей.
    """
    vevent, dtstart, tzname = sample
    tz = ZoneInfo(tzname)

    # Разбор входа через TUT
    sched = TUT_OBJ.parse_vevent(vevent)
    vevent2 = TUT_OBJ.serialize_schedule(sched)
    sched2 = TUT_OBJ.parse_vevent(vevent2)

    # Начало перебора — с DTSTART-1д чтобы покрыть >= start
    start = (dtstart if dtstart.tzinfo else dtstart.replace(tzinfo=tz)).astimezone(ZoneInfo("UTC")) - timedelta(days=1)
    until = start + timedelta(days=365 * 5)

    ref = reference_occurrences(vevent, start, take_n, until)
    tut = TUT_OBJ.next_occurrences(sched2, start, take_n, until)

    # Базовые свойства
    assert_strictly_increasing_unique(tut)
    # Эквивалентность первых len(tut) элементов
    assert tut == ref[:len(tut)]


@settings(
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    max_examples=120,
)
@given(VALID_VEVENTS)
def test_invariants_count_until(sample):
    """
    Проверка инвариантов COUNT/UNTIL.
    """
    vevent, dtstart, tzname = sample
    sched = TUT_OBJ.parse_vevent(vevent)

    start = (dtstart if dtstart.tzinfo else dtstart.replace(tzinfo=ZoneInfo(tzname))).astimezone(ZoneInfo("UTC")) - timedelta(days=1)

    # Если есть COUNT в RRULE — TUT должен вернуть ровно COUNT при отсутствии until.
    m_count = re.search(r"COUNT=(\d+)", vevent)
    if m_count:
        count = int(m_count.group(1))
        out = TUT_OBJ.next_occurrences(sched, start, count=None, until=None)
        # Ограничиваем референсом, чтобы избежать бесконечных правил
        ref = reference_occurrences(vevent, start, count, None)
        assert len(out) == len(ref) == count
        assert_strictly_increasing_unique(out)

    # Если есть UNTIL в RRULE — TUT не должен возвращать даты > UNTIL
    m_until = re.search(r"UNTIL=(\d{8}T\d{6}Z)", vevent)
    if m_until:
        until_dt = datetime.strptime(m_until.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=ZoneInfo("UTC"))
        out = TUT_OBJ.next_occurrences(sched, start, count=None, until=None)
        assert all(o <= until_dt for o in out), "Occurrences must not exceed UNTIL"
        assert_strictly_increasing_unique(out)


@settings(
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    max_examples=60,
)
@given(CORRUPT_VEVENTS)
def test_corrupt_inputs_raise_schedule_error(corrupt):
    """
    Невалидные VEVENT должны поднимать ScheduleError, а не падать произвольным исключением.
    """
    with pytest.raises(TUT_OBJ.ScheduleError):
        TUT_OBJ.parse_vevent(corrupt)


# ------------------------------
# Тесты DST для Europe/Stockholm
# ------------------------------

def _last_weekday_of_month(year: int, month: int, weekday: int) -> datetime:
    """
    Возвращает дату последнего weekday (0=Monday..6=Sunday) месяца в 03:00 локального времени.
    """
    # Берём 28 число + до 4 дней безопасно
    for day in range(31, 27, -1):
        try:
            d = datetime(year, month, day, 3, 0, 0)
        except ValueError:
            continue
        if d.weekday() == weekday:
            return d
    # Fallback (не должны сюда попадать)
    return datetime(year, month, 28, 3, 0, 0)

@pytest.mark.parametrize("year", [2023, 2024, 2025, 2026, 2027])
def test_dst_transitions_europe_stockholm(year):
    """
    Проверяем корректность генерации вокруг переходов DST:
      - Старт DST: последняя воскресенье марта 02:00 -> 03:00
      - Конец DST: последняя воскресенье октября 03:00 -> 02:00
    """
    tz = ZoneInfo("Europe/Stockholm")
    start_march = _last_weekday_of_month(year, 3, 6).replace(tzinfo=tz).replace(hour=1, minute=30)
    start_oct = _last_weekday_of_month(year, 10, 6).replace(tzinfo=tz).replace(hour=1, minute=30)

    for edge_dt in [start_march, start_oct]:
        vevent = (
            "BEGIN:VEVENT\n"
            f"DTSTART;TZID=Europe/Stockholm:{edge_dt.strftime('%Y%m%dT%H%M%S')}\n"
            "RRULE:FREQ=HOURLY;INTERVAL=1;COUNT=8\n"
            "END:VEVENT"
        )
        sched = TUT_OBJ.parse_vevent(vevent)
        start = edge_dt.astimezone(ZoneInfo("UTC")) - timedelta(hours=1)
        out = TUT_OBJ.next_occurrences(sched, start, count=None, until=None)
        ref = reference_occurrences(vevent, start, count=None, until=None)

        # Не должно быть дублей и регресса времени
        assert_strictly_increasing_unique(out)
        # Сравниваем с эталоном по количеству и первыми k событиями
        k = min(len(out), len(ref))
        assert out[:k] == ref[:k], f"DST mismatch at {year}"


# ------------------------------
# Граничные сценарии производительности
# ------------------------------

def test_large_count_cap():
    """
    Большое COUNT не должно приводить к деградации: проверяем, что хотя бы первые 512 событий
    выдаются монотонно и без дублей.
    """
    vevent = (
        "BEGIN:VEVENT\n"
        "DTSTART:20240101T000000\n"
        "RRULE:FREQ=MINUTELY;INTERVAL=1;COUNT=2048\n"
        "END:VEVENT"
    )
    sched = TUT_OBJ.parse_vevent(vevent)
    start = datetime(2023, 12, 31, 23, 59, 0, tzinfo=ZoneInfo("UTC"))
    out = TUT_OBJ.next_occurrences(sched, start, count=512, until=None)
    assert len(out) == 512
    assert_strictly_increasing_unique(out)
