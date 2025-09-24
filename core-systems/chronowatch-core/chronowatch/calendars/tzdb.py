"""
chronowatch.calendars.tzdb
Промышленный слой работы с таймзонами и локальным временем.

Возможности:
- Парсинг TZ: IANA (Europe/Stockholm), UTC-синонимы (UTC, Z), фиксированные смещения (+03:00, -0700).
- Кэширование ZoneInfo/offset-таймзон.
- Безопасное локализование на границах DST:
  * ambiguous (двойное локальное время осенью) — выбор earlier|later|strict (PEP495 fold).
  * nonexistent (пропущенное локальное время весной) — policy: strict|shift_forward.
- Конвертации: now_in(tz), to_utc, from_utc, convert.
- Еженедельные окна: weekday mon..sun и минуты от полуночи локально; проверка попадания в окно.
- Список доступных TZ и версия базы.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache
from typing import Iterable, Optional, Sequence

import re
import os

try:
    from zoneinfo import ZoneInfo, available_timezones
except Exception as e:  # pragma: no cover
    raise RuntimeError("Python >= 3.9 with zoneinfo stdlib is required") from e


# =========================
# Исключения
# =========================

class TimeZoneError(Exception):
    """Базовая ошибка работы с таймзонами."""


class UnknownTimeZoneError(TimeZoneError):
    """Запрошенная таймзона не найдена."""


class AmbiguousTimeError(TimeZoneError):
    """Локальное время неоднозначно (двойное), требуется disambiguation."""


class NonExistentTimeError(TimeZoneError):
    """Локальное время не существует (весенний провал DST)."""


# =========================
# Константы и утилиты
# =========================

_UTC = timezone.utc
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_TZ_OFFSET_RE = re.compile(r"^(?P<sign>[+-])(?P<h>\d{2})(?::?(?P<m>\d{2}))?$")
_UTC_ALIASES = {"UTC", "Etc/UTC", "Z", "UCT", "Universal", "GMT"}  # GMT трактуем как UTC


@dataclass(frozen=True)
class LocalizePolicy:
    """
    Политика локализации неоднозначных/несуществующих времен.

    ambiguous: 'earlier'|'later'|'strict'
    nonexistent: 'strict'|'shift_forward'
    shift_limit: ограничение поиска следующего валидного времени (минуты)
    """
    ambiguous: str = "earlier"
    nonexistent: str = "strict"
    shift_limit: int = 180

    def validate(self) -> None:
        if self.ambiguous not in ("earlier", "later", "strict"):
            raise ValueError("ambiguous must be earlier|later|strict")
        if self.nonexistent not in ("strict", "shift_forward"):
            raise ValueError("nonexistent must be strict|shift_forward")
        if self.shift_limit < 1 or self.shift_limit > 1440:
            raise ValueError("shift_limit must be within [1..1440]")


# =========================
# Парсинг и кэширование TZ
# =========================

@lru_cache(maxsize=4096)
def _parse_fixed_offset(spec: str) -> tzinfo:
    """
    Парсит фиксированное смещение вида +HH:MM, -HHMM, +HH.
    Возвращает datetime.timezone.
    """
    m = _TZ_OFFSET_RE.match(spec)
    if not m:
        raise UnknownTimeZoneError(f"Invalid fixed offset: {spec}")
    sign = 1 if m.group("sign") == "+" else -1
    hours = int(m.group("h"))
    minutes = int(m.group("m") or "0")
    if hours > 23 or minutes > 59:
        raise UnknownTimeZoneError(f"Invalid fixed offset range: {spec}")
    delta = timedelta(hours=hours, minutes=minutes) * sign
    return timezone(delta)


@lru_cache(maxsize=4096)
def get_tz(tz_name: str | tzinfo | None) -> tzinfo:
    """
    Унифицированный доступ к tzinfo по имени/объекту/None.
    - IANA: 'Europe/Stockholm' и пр.
    - UTC-алиасы: 'UTC', 'Z', ...
    - Фиксированные смещения: '+03:00', '-0700'.
    - tzinfo -> возвращается как есть.
    - None -> берется DEFAULT_TZ из окружения или 'UTC'.
    """
    if isinstance(tz_name, tzinfo):
        return tz_name

    if tz_name is None:
        tz_env = os.environ.get("DEFAULT_TZ", "UTC")
        return get_tz(tz_env)

    tz_norm = tz_name.strip()

    if tz_norm in _UTC_ALIASES:
        return _UTC

    # фиксированные смещения
    if _TZ_OFFSET_RE.match(tz_norm):
        return _parse_fixed_offset(tz_norm)

    # попытка IANA
    try:
        return ZoneInfo(tz_norm)
    except Exception as e:
        raise UnknownTimeZoneError(f"Unknown timezone: {tz_name}") from e


def tzdb_version() -> str:
    """
    Возвращает версию базы tzdata, если доступна (через пакет tzdata),
    иначе 'system'.
    """
    try:
        import tzdata  # type: ignore
        return getattr(tzdata, "__version__", "tzdata-unknown")
    except Exception:
        return "system"


def list_timezones(substr: str | None = None) -> Sequence[str]:
    """
    Возвращает список доступных IANA-таймзон. При переданном substr фильтрует по подстроке (case-insensitive).
    """
    try:
        tzs = sorted(available_timezones())
    except Exception:
        tzs = []
    if substr:
        s = substr.lower()
        return [t for t in tzs if s in t.lower()]
    return tzs


# =========================
# Базовые операции времени
# =========================

def ensure_aware(dt: datetime, default_tz: tzinfo = _UTC) -> datetime:
    """
    Делает datetime aware: если naive — привязывает default_tz.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=default_tz)
    return dt


def now_utc() -> datetime:
    return datetime.now(tz=_UTC)


def now_in(tz_name: str | tzinfo | None) -> datetime:
    """
    Текущее время в указанной таймзоне.
    """
    tz = get_tz(tz_name)
    return now_utc().astimezone(tz)


def to_utc(dt: datetime, assume_tz: str | tzinfo | None = _UTC) -> datetime:
    """
    Преобразует datetime в UTC. Если dt naive — считается в assume_tz.
    """
    dt_aw = ensure_aware(dt, default_tz=get_tz(assume_tz))
    return dt_aw.astimezone(_UTC)


def from_utc(utc_dt: datetime, to_tz: str | tzinfo | None) -> datetime:
    """
    Переводит время из UTC в целевую таймзону.
    """
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=_UTC)
    return utc_dt.astimezone(get_tz(to_tz))


def convert(dt: datetime, to_tz: str | tzinfo | None, assume_tz: str | tzinfo | None = _UTC) -> datetime:
    """
    Универсальная конвертация: naive трактуется в assume_tz, далее перевод в to_tz.
    """
    return from_utc(to_utc(dt, assume_tz=assume_tz), to_tz=to_tz)


# =========================
# Локализация на границах DST
# =========================

def _is_ambiguous(naive_dt: datetime, tz: tzinfo) -> bool:
    """
    Проверка неоднозначности: сравниваем оффсеты при fold=0 и fold=1.
    """
    if naive_dt.tzinfo is not None:
        raise ValueError("naive_dt must be naive")
    dt0 = naive_dt.replace(tzinfo=tz, fold=0)
    dt1 = naive_dt.replace(tzinfo=tz, fold=1)
    return dt0.utcoffset() != dt1.utcoffset()


def _localize_ambiguous(naive_dt: datetime, tz: tzinfo, pick: str) -> datetime:
    if pick == "earlier":
        return naive_dt.replace(tzinfo=tz, fold=0)
    elif pick == "later":
        return naive_dt.replace(tzinfo=tz, fold=1)
    raise AmbiguousTimeError("Ambiguous local time; set policy ambiguous=earlier|later|strict")


def _is_nonexistent(naive_dt: datetime, tz: tzinfo) -> bool:
    """
    Эвристика: если обратное преобразование в локаль не сохраняет стеночное время — момент не существует.
    """
    candidate = naive_dt.replace(tzinfo=tz)
    back = candidate.astimezone(tz)
    return back.replace(tzinfo=None) != naive_dt


def _shift_forward_to_valid(naive_dt: datetime, tz: tzinfo, limit_min: int) -> datetime:
    """
    Сдвигает несуществующее локальное время вперед до первого валидного,
    ограничение поиска — limit_min (минуты).
    """
    for i in range(limit_min + 1):
        probe = naive_dt + timedelta(minutes=i)
        if not _is_nonexistent(probe, tz):
            # Если момент все еще ambiguous, применим earlier (детерминированность)
            if _is_ambiguous(probe, tz):
                return probe.replace(tzinfo=tz, fold=0)
            return probe.replace(tzinfo=tz)
    raise NonExistentTimeError("Cannot find valid local time within shift_limit minutes")


def localize(
    naive_dt: datetime,
    tz_name: str | tzinfo | None,
    policy: LocalizePolicy | None = None,
) -> datetime:
    """
    Превращает NAIVE локальное время в aware с учетом DST-переходов.

    policy.ambiguous: 'earlier'|'later'|'strict' (по умолчанию earlier)
    policy.nonexistent: 'strict'|'shift_forward' (по умолчанию strict)
    """
    if naive_dt.tzinfo is not None:
        raise ValueError("localize() expects naive datetime")

    pol = policy or LocalizePolicy()
    pol.validate()

    tz = get_tz(tz_name)

    # Сначала проверяем nonexistent (весенний провал)
    if _is_nonexistent(naive_dt, tz):
        if pol.nonexistent == "shift_forward":
            return _shift_forward_to_valid(naive_dt, tz, pol.shift_limit)
        raise NonExistentTimeError("Nonexistent local time; set policy nonexistent=shift_forward")

    # Затем ambiguous (осенний дубль)
    if _is_ambiguous(naive_dt, tz):
        if pol.ambiguous == "strict":
            raise AmbiguousTimeError("Ambiguous local time; set policy ambiguous=earlier|later")
        return _localize_ambiguous(naive_dt, tz, pol.ambiguous)

    # Обычный случай
    return naive_dt.replace(tzinfo=tz)


# =========================
# Weekly окна и базовые вычисления
# =========================

def weekday_str(dt: datetime, tz_name: str | tzinfo | None) -> str:
    """
    Возвращает 'mon'..'sun' для указанного времени.
    """
    tz = get_tz(tz_name)
    loc = ensure_aware(dt, _UTC).astimezone(tz)
    return _WEEKDAYS[loc.weekday()]


def minutes_from_midnight(dt: datetime, tz_name: str | tzinfo | None) -> int:
    """
    Возвращает минуты от локальной полуночи для dt в таймзоне.
    """
    tz = get_tz(tz_name)
    loc = ensure_aware(dt, _UTC).astimezone(tz)
    return loc.hour * 60 + loc.minute


def in_weekly_window(
    utc_dt: datetime,
    tz_name: str | tzinfo | None,
    days: Iterable[str],
    start_min: int,
    end_min: int,
) -> bool:
    """
    Проверка попадания UTC-времени в weekly-окно локального времени.

    Условия (соответствуют JSON Schema v1 и OPA-политике):
    - days: набор 'mon'..'sun' (регистронезависимо).
    - 0 <= start_min < end_min <= 1440 (пересечение полуночи НЕ допускается по контракту).
    """
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=_UTC)
    if not (0 <= start_min < end_min <= 1440):
        raise ValueError("start_min/end_min must satisfy 0 <= start < end <= 1440")

    dayset = {d.lower() for d in days}
    if not dayset.issubset(set(_WEEKDAYS)):
        raise ValueError("days must be subset of {'mon','tue','wed','thu','fri','sat','sun'}")

    tz = get_tz(tz_name)
    loc = utc_dt.astimezone(tz)
    d = _WEEKDAYS[loc.weekday()]
    mins = loc.hour * 60 + loc.minute
    return (d in dayset) and (start_min <= mins < end_min)


# =========================
# Разное
# =========================

def parse_iso8601(s: str, assume_tz: str | tzinfo | None = _UTC) -> datetime:
    """
    Парсинг ISO-8601: поддержка 'Z'. Если таймзона не указана — трактуется в assume_tz.
    """
    ss = s.strip()
    if ss.endswith("Z"):
        # fromisoformat не принимает 'Z', заменим на +00:00
        ss = ss[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ss)
    except ValueError as e:
        raise ValueError(f"Invalid ISO8601 datetime: {s}") from e
    if dt.tzinfo is None:
        return dt.replace(tzinfo=get_tz(assume_tz))
    return dt


def is_valid_timezone(name: str) -> bool:
    try:
        get_tz(name)
        return True
    except UnknownTimeZoneError:
        return False


# =========================
# Примеры безопасных пресетов политик
# =========================

SAFE_EARLIER_STRICT = LocalizePolicy(ambiguous="earlier", nonexistent="strict")
SAFE_LATER_SHIFT = LocalizePolicy(ambiguous="later", nonexistent="shift_forward", shift_limit=180)
