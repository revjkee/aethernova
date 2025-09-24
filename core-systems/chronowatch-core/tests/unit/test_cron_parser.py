# -*- coding: utf-8 -*-
"""
Промышленный набор тестов для cron-парсера chronowatch-core.

Дизайн:
- Не делает предположений о конкретном пути модуля: пытается несколько импортов.
- Автоматически детектирует возможности (CAPABILITIES), если они объявлены
  в модуле/классе, и условно включает/пропускает соответствующие тесты.
- Совместим с минимальными реализациями (POSIX 5 полей) и расширенными (секунды,
  макросы, имена дней/месяцев и т.п.).
"""

from __future__ import annotations

import datetime as _dt
import importlib
import typing as _t
import os

import pytest

# ------------------------- Импорт парсера/интерфейса -------------------------

def _import_cron_impl():
    """
    Пытаемся найти реальную реализацию в проекте. Если не нашли — skip всего файла.
    Возвращаем кортеж (module, CronExpression, api), где api — словарь с функциями.
    """
    candidates = [
        # Предпочтительный вариант пакета
        ("chronowatch_core.cron.parser", "CronExpression", {"parse": "parse_cron", "next_run": "next_run", "iter_runs": "iter_runs"}),
        ("chronowatch_core.cron.cron_parser", "CronExpression", {"parse": "parse", "next_run": "next_run", "iter_runs": "iter_runs"}),
        ("chronowatch_core.cron_parser", "CronExpression", {"parse": "parse", "next_run": "next_run", "iter_runs": "iter_runs"}),
        ("chronowatch_core.scheduling.cron", "CronExpression", {"parse": "parse", "next_run": "next_run", "iter_runs": "iter_runs"}),
    ]
    first_error = None
    for mod_name, class_name, api_map in candidates:
        try:
            mod = importlib.import_module(mod_name)
            CronExpression = getattr(mod, class_name, None)
            # Функции могут быть как в модуле, так и статическими методами класса
            def _get_callable(key):
                target = api_map[key]
                if hasattr(mod, target):
                    return getattr(mod, target)
                if CronExpression and hasattr(CronExpression, target):
                    return getattr(CronExpression, target)
                return None
            api = {
                "parse": _get_callable("parse"),
                "next_run": _get_callable("next_run"),
                "iter_runs": _get_callable("iter_runs"),
            }
            if CronExpression is None or api["parse"] is None:
                raise AttributeError("Not enough API")
            # Опциональный тип ошибки
            CronError = getattr(mod, "CronError", ValueError)
            # Возможности
            capabilities = set()
            for holder in (mod, CronExpression):
                caps = getattr(holder, "CAPABILITIES", None)
                if isinstance(caps, (set, list, tuple)):
                    capabilities |= set(caps)
            return mod, CronExpression, CronError, api, capabilities
        except Exception as e:
            first_error = first_error or e
            continue
    pytest.skip(f"Не найден cron-парсер в проекте ({first_error})", allow_module_level=True)

MOD, CronExpression, CronError, API, CAPS = _import_cron_impl()

# Удобные шорткаты
parse = API["parse"]
next_run = API.get("next_run", None)
iter_runs = API.get("iter_runs", None)

# Метки возможностей. Реализация может объявить ровно такие строки в CAPABILITIES.
HAS_SECONDS   = "seconds-field" in CAPS
HAS_MACROS    = "macros" in CAPS                  # @hourly/@daily/.../@reboot
HAS_NAMES     = "month-dow-names" in CAPS         # JAN..DEC, MON..SUN
HAS_RANGES    = True                               # ожидается для всех
HAS_STEPS     = True
HAS_LISTS     = True
HAS_NTH_DOW   = "nth-dow" in CAPS                  # Quartz: MON#2
HAS_LAST      = "last-day" in CAPS                 # L
HAS_NEAREST_W = "nearest-weekday" in CAPS          # W


# ------------------------- Вспомогательные утилиты --------------------------

UTC = _dt.timezone.utc
try:
    from zoneinfo import ZoneInfo
    STO = ZoneInfo("Europe/Stockholm")
except Exception:
    STO = UTC  # на всякий случай

def dt(y, M, d, h=0, m=0, s=0, tz=UTC):
    return _dt.datetime(y, M, d, h, m, s, tzinfo=tz)

def assume_next_run(expr: str, start: _dt.datetime, expect: _dt.datetime):
    """
    Помощник: вызывает реализацию next_run из API или через объект CronExpression.
    """
    if next_run is not None:
        got = next_run(expr, start)
    else:
        ce = parse(expr)
        assert hasattr(ce, "next_after"), "CronExpression должен иметь next_after()"
        got = ce.next_after(start)
    assert got == expect, f"next_run({expr!r}, {start}) => {got}, ожидалось {expect}"


# ------------------------- БАЗОВЫЙ ПАРСИНГ ----------------------------------

@pytest.mark.parametrize("expr", [
    "*/5 * * * *",
    "0 0 * * *",
    "15 10 * * 1-5",
    "0 0 1 * *",
    "30 23 28-31 * *",
])
def test_parse_valid_minimal(expr):
    ce = parse(expr)
    assert isinstance(ce, CronExpression)
    # Должны быть как минимум 5 нормализованных полей
    fields = getattr(ce, "fields", None)
    if fields is not None:
        assert len(fields) in (5, 6)
    # Проверим repr/str не падают
    assert repr(ce)
    assert str(ce)


@pytest.mark.parametrize("expr", [
    "", " ", "*", "* * *", "* * * * * * *",
    "60 * * * *",           # минута вне домена
    "* 24 * * *",           # час вне домена
    "* * 0 * *",            # день месяца вне домена
    "* * * 13 *",           # месяц вне домена
    "* * * * 8",            # день недели вне домена
    "*/0 * * * *",          # шаг 0
    "1--3 * * * *",         # битый диапазон
    "1,,3 * * * *",         # пустой элемент списка
])
def test_parse_invalid_raises(expr):
    with pytest.raises(CronError):
        parse(expr)


# ------------------------- СЕКУНДНОЕ ПОЛЕ (опционально) ---------------------

@pytest.mark.skipif(not HAS_SECONDS, reason="Реализация не поддерживает 6-е поле секунд")
def test_parse_with_seconds_and_next_run():
    ce = parse("5 */10 * * * *")  # sec=5, min=*/10
    start = dt(2025, 1, 1, 0, 0, 0, UTC)
    # ожидаем 00:00:05, затем 00:10:05
    assume_next_run("5 */10 * * * *", start, dt(2025, 1, 1, 0, 0, 5, UTC))
    assume_next_run("5 */10 * * * *", dt(2025, 1, 1, 0, 0, 5, UTC), dt(2025, 1, 1, 0, 10, 5, UTC))


# ------------------------- ШАГИ/ДИАПАЗОНЫ/СПИСКИ ----------------------------

@pytest.mark.parametrize("expr,start,expect", [
    ("*/15 * * * *", dt(2025, 1, 1, 0, 0, tz=UTC), dt(2025, 1, 1, 0, 15, tz=UTC)),
    ("*/15 * * * *", dt(2025, 1, 1, 0, 14, tz=UTC), dt(2025, 1, 1, 0, 15, tz=UTC)),
    ("0 0-6/2 * * *", dt(2025, 1, 1, 0, 0, tz=UTC), dt(2025, 1, 1, 2, 0, tz=UTC)),
    ("0 8,12,16 * * *", dt(2025, 1, 1, 11, 30, tz=UTC), dt(2025, 1, 1, 12, 0, tz=UTC)),
])
def test_steps_ranges_lists(expr, start, expect):
    ce = parse(expr)
    assert isinstance(ce, CronExpression)
    assume_next_run(expr, start, expect)


# ------------------------- МАКРОСЫ (опционально) ----------------------------

@pytest.mark.skipif(not HAS_MACROS, reason="Реализация не поддерживает @macros")
@pytest.mark.parametrize("macro,expected", [
    ("@hourly", "0 * * * *"),
    ("@daily",  "0 0 * * *"),
    ("@weekly", "0 0 * * 0"),
    ("@monthly","0 0 1 * *"),
    ("@yearly", "0 0 1 1 *"),
    ("@annually","0 0 1 1 *"),
])
def test_macros_expand(macro, expected):
    ce_macro = parse(macro)
    ce_expected = parse(expected)
    # Считаем эквивалентными по next_run для одинаковой точки
    base = dt(2025, 1, 2, 3, 4, tz=UTC)
    if next_run is not None:
        n1 = next_run(macro, base)
        n2 = next_run(expected, base)
    else:
        n1 = ce_macro.next_after(base)
        n2 = ce_expected.next_after(base)
    assert n1 == n2


@pytest.mark.skipif(not HAS_MACROS, reason="Реализация не поддерживает @macros")
def test_reboot_macro_semantics():
    # @reboot часто не имеет смысла в next_run; допускаем NotImplemented или None
    base = dt(2025, 1, 1, 0, 0, tz=UTC)
    try:
        if next_run is not None:
            n = next_run("@reboot", base)
        else:
            n = parse("@reboot").next_after(base)
    except NotImplementedError:
        pytest.xfail("Реализация не планирует @reboot через next_run()")
    else:
        assert n is None or isinstance(n, _dt.datetime)


# ------------------------- ЗОНЫ ВРЕМЕНИ И DST --------------------------------

@pytest.mark.parametrize("tz", [UTC, STO])
def test_timezone_basic_next_run(tz):
    # Ежедневно в 01:30 локального TZ
    expr = "30 1 * * *"
    start = dt(2025, 1, 1, 1, 29, tz=tz)
    expect = dt(2025, 1, 1, 1, 30, tz=tz)
    assume_next_run(expr, start, expect)


def test_timezone_change_monotonicity_stockholm():
    # Проверяем, что next_run не "отматывается назад" через DST.
    # Весенний переход в Europe/Stockholm в 2025 году: 2025-03-30 02:00->03:00.
    expr = "0 3 * * *"  # 03:00 существует и после перехода
    start = dt(2025, 3, 29, 4, 0, tz=STO)
    n1 = (next_run(expr, start) if next_run else parse(expr).next_after(start))
    n2 = (next_run(expr, n1) if next_run else parse(expr).next_after(n1))
    assert n2 > n1 >= start


# ------------------------- ГРАНИЦЫ МЕСЯЦА/ДНИ НЕДЕЛИ ------------------------

def test_dom_31_skips_short_months():
    # 31-е число должно перескочить апрель и найти 2025-05-31.
    expr = "0 0 31 * *"
    start = dt(2025, 4, 1, 0, 0, tz=UTC)
    expect = dt(2025, 5, 31, 0, 0, tz=UTC)
    assume_next_run(expr, start, expect)


@pytest.mark.skipif(not HAS_NAMES, reason="Нет поддержки имен месяцев/дней")
def test_month_and_dow_names():
    expr = "0 9 * JAN MON"
    ce = parse(expr)
    assert isinstance(ce, CronExpression)
    start = dt(2025, 1, 1, 8, 0, tz=UTC)  # Jan, Wed
    # Ближайший понедельник января 2025 — 2025-01-06 09:00
    expect = dt(2025, 1, 6, 9, 0, tz=UTC)
    assume_next_run(expr, start, expect)


# ------------------------- ИТЕРАЦИИ И ПРОИЗВОДИТЕЛЬНОСТЬ ---------------------

@pytest.mark.parametrize("expr,start,count", [
    ("*/5 * * * *", dt(2025, 1, 1, 0, 0, tz=UTC), 12),   # за час: 12 точек
    ("0 * * * *",   dt(2025, 1, 1, 0, 0, tz=UTC), 24),   # за сутки: 24 точки
])
def test_iter_runs_count(expr, start, count):
    # Проверим, что iter_runs дает ожидаемое кол-во событий на ограниченном окне.
    end = start + _dt.timedelta(hours=1 if "*/5" in expr else 24)
    if iter_runs is not None:
        items = list(iter_runs(expr, start, end))
    else:
        ce = parse(expr)
        assert hasattr(ce, "iter_between")
        items = list(ce.iter_between(start, end))
    assert len(items) == count
    # Монотонность
    assert all(items[i] < items[i+1] for i in range(len(items)-1))


# ------------------------- ОШИБКИ И СООБЩЕНИЯ -------------------------------

@pytest.mark.parametrize("expr,fragment", [
    ("60 * * * *", "minute"),
    ("* 24 * * *", "hour"),
    ("* * 0 * *", "day-of-month"),
    ("* * * 13 *", "month"),
    ("* * * * 8", "day-of-week"),
])
def test_errors_have_human_messages(expr, fragment):
    with pytest.raises(CronError) as ei:
        parse(expr)
    msg = str(ei.value).lower()
    # Сообщение об ошибке должно содержать понятную подсказку по домену
    assert fragment in msg


# ------------------------- НЕОБЯЗАТЕЛЬНЫЕ РАСШИРЕНИЯ -------------------------

@pytest.mark.skipif(not HAS_NTH_DOW, reason="Нет поддержки nth-dow (#)")
def test_quartz_nth_dow():
    # Второй понедельник месяца в 10:00
    expr = "0 10 ? * MON#2" if HAS_SECONDS else "0 10 * * MON#2"
    ce = parse(expr)
    # Фиксируем февраль 2025 (второй понедельник = 10-е)
    base = dt(2025, 2, 1, 0, 0, tz=UTC)
    expect = dt(2025, 2, 10, 10, 0, tz=UTC)
    assume_next_run(expr, base, expect)

@pytest.mark.skipif(not HAS_LAST, reason="Нет поддержки 'L' (последний день)")
def test_last_day_of_month():
    expr = "0 8 L * *"
    base = dt(2025, 2, 1, 0, 0, tz=UTC)
    expect = dt(2025, 2, 28, 8, 0, tz=UTC)  # 2025 невисокосный
    assume_next_run(expr, base, expect)

@pytest.mark.skipif(not HAS_NEAREST_W, reason="Нет поддержки 'W' (ближайший будний)")
def test_nearest_weekday():
    # Если 1-е сентября выпало на выходной, перенос на ближайший будний.
    expr = "0 9 1W 9 *"
    # В 2024-09-01 было воскресенье -> перенос на 2024-09-02 09:00
    base = dt(2024, 8, 31, 0, 0, tz=UTC)
    expect = dt(2024, 9, 2, 9, 0, tz=UTC)
    assume_next_run(expr, base, expect)


# ------------------------- КРАЕВЫЕ ИНВАРИАНТЫ --------------------------------

def test_next_run_strictly_greater_than_start():
    expr = "*/10 * * * *"
    base = dt(2025, 1, 1, 0, 0, tz=UTC)
    n1 = (next_run(expr, base) if next_run else parse(expr).next_after(base))
    assert n1 > base
    n2 = (next_run(expr, n1) if next_run else parse(expr).next_after(n1))
    assert n2 > n1

@pytest.mark.parametrize("expr", [
    "0 0 * * *",
    "15 10 * * 1-5",
    "*/7 * * * *",
])
def test_string_roundtrip(expr):
    ce = parse(expr)
    s = str(ce)
    # Пытаемся распарсить обратно строковое представление
    ce2 = parse(s)
    assert str(ce2) == s
