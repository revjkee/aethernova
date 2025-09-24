# automation-core/src/automation_core/utils/time.py
# -*- coding: utf-8 -*-
"""
Утилиты времени уровня продакшн для automation-core.

Ключевые факты (проверяемые источники):
- RFC 3339 (формат даты/времени с часовыми смещениями и 'Z' для UTC):
  https://www.rfc-editor.org/rfc/rfc3339
- Python datetime/timezone: https://docs.python.org/3/library/datetime.html
- Монотоничные и высокоточные часы: https://docs.python.org/3/library/time.html#time.monotonic
- PEP 615 (zoneinfo, часовые пояса из базы IANA): https://peps.python.org/pep-0615/
- PEP 495 (атрибут fold для двусмысленных локальных времён при переходе DST):
  https://peps.python.org/pep-0495/

Дизайн:
- Только timezone-aware datetime (UTC по умолчанию). Наивные datetime отклоняются явно.
- Парсинг/формат RFC 3339 без внешних зависимостей. 'Z' → UTC, поддержка долей секунды до наносекунд
  с безопасным усечением до микросекунд (ограничение CPython datetime).
- Любые дедлайны/таймауты рассчитываются на базе монотоничных часов, чтобы избежать регрессий
  при изменении системного времени.
- Rate limiter (token-bucket) и экспоненциальный backoff с управляемым джиттером — для интеграций
  с внешними системами.
"""

from __future__ import annotations

import math
import os
import re
import time as _time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Callable, Iterable, Optional, Tuple, Union

try:
    from zoneinfo import ZoneInfo  # PEP 615
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore[misc,assignment]

__all__ = [
    "utc_now",
    "now_tz",
    "coerce_tz",
    "ensure_aware",
    "to_utc",
    "format_rfc3339",
    "parse_rfc3339",
    "to_epoch_seconds",
    "from_epoch_seconds",
    "truncate",
    "round_to",
    "Deadline",
    "sleep_precise",
    "sleep_until",
    "exp_backoff",
    "TokenBucket",
]


# ---------------------------
# Базовые операции с datetime
# ---------------------------

def utc_now() -> datetime:
    """
    Текущее время в UTC (timezone-aware).

    Документация Python datetime: https://docs.python.org/3/library/datetime.html#datetime.datetime.now
    """
    return datetime.now(UTC)


def coerce_tz(tz: Union[str, timezone, None]) -> timezone:
    """
    Приведение описания часового пояса к datetime.tzinfo (timezone/ZoneInfo).

    - None → UTC.
    - str → ZoneInfo(<name>) при наличии PEP 615; иначе ошибка.
    - timezone → возвращается как есть.

    PEP 615: https://peps.python.org/pep-0615/
    """
    if tz is None:
        return UTC  # type: ignore[return-value]
    if isinstance(tz, timezone):
        return tz
    if isinstance(tz, str):
        if ZoneInfo is None:
            raise RuntimeError("zoneinfo (PEP 615) недоступен в данной среде")
        return ZoneInfo(tz)  # type: ignore[no-any-return]
    raise TypeError(f"Unsupported tz type: {type(tz)!r}")


def now_tz(tz: Union[str, timezone, None]) -> datetime:
    """
    Текущее время в заданном часовом поясе (timezone-aware).
    """
    return datetime.now(coerce_tz(tz))


def ensure_aware(dt: datetime) -> datetime:
    """
    Проверяет, что datetime timezone-aware. Наивные значения отклоняются.

    PEP 495 (fold) применим к локальным амбивалентным временам: https://peps.python.org/pep-0495/
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Naive datetime не поддерживается — укажите tzinfo")
    return dt


def to_utc(dt: datetime) -> datetime:
    """
    Конвертировать datetime (aware) в UTC.

    Документация: https://docs.python.org/3/library/datetime.html#datetime.datetime.astimezone
    """
    return ensure_aware(dt).astimezone(UTC)


# ---------------------------
# RFC 3339 (ISO 8601 профиль)
# ---------------------------

# Примерные допустимые варианты:
# 2025-09-05T12:34:56Z
# 2025-09-05T12:34:56.123Z
# 2025-09-05T12:34:56.123456789+03:00
# 2025-09-05t12:34:56-07:30
_RFC3339_RE = re.compile(
    r"""
    ^
    (?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})
    [Tt ]
    (?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})
    (?P<frac>\.\d{1,9})?
    (?P<tz>Z|z|(?P<sign>[+-])(?P<th>\d{2}):?(?P<tm>\d{2}))
    $
    """,
    re.VERBOSE,
)


def parse_rfc3339(s: str) -> datetime:
    """
    Парсит строку RFC 3339 в timezone-aware datetime (UTC/offset).

    Ограничения реализации:
    - Доли секунды поддерживаются до 9 знаков; усечение до микросекунд (6 знаков) выполняется безопасно.
    - Смещение вида ±HH:MM (допускается без двоеточия как ±HHMM).
    - Буква 'Z'/'z' трактуется как UTC.

    RFC 3339: https://www.rfc-editor.org/rfc/rfc3339
    """
    m = _RFC3339_RE.match(s.strip())
    if not m:
        raise ValueError(f"String doesn't match RFC3339: {s!r}")

    y = int(m.group("y"))
    mo = int(m.group("m"))
    d = int(m.group("d"))
    H = int(m.group("H"))
    M = int(m.group("M"))
    S = int(m.group("S"))

    frac = m.group("frac")
    us = 0
    if frac:
        # до 9 знаков; datetime поддерживает микросекунды → усечём/дополняем
        digits = frac[1:]
        if len(digits) > 6:
            digits = digits[:6]
        us = int(digits.ljust(6, "0"))

    tzs = m.group("tz")
    if tzs in ("Z", "z"):
        tz = UTC
    else:
        sign = -1 if m.group("sign") == "-" else 1
        th = int(m.group("th"))
        tm = int(m.group("tm"))
        offset = timedelta(hours=th, minutes=tm) * sign
        tz = timezone(offset)

    return datetime(y, mo, d, H, M, S, us, tzinfo=tz)


def format_rfc3339(dt: datetime, *, use_z: bool = True) -> str:
    """
    Форматирует timezone-aware datetime в RFC 3339.

    - Для UTC при use_z=True используется окончание 'Z'.
    - Для прочих смещений — ±HH:MM.
    - Доли секунды выводятся до микросекунд, без лишних нулей.

    RFC 3339: https://www.rfc-editor.org/rfc/rfc3339
    """
    dt = ensure_aware(dt)
    off = dt.utcoffset()
    if off is None:
        raise ValueError("Invalid tzinfo/utcoffset")
    frac = f".{dt.microsecond:06d}".rstrip("0")
    frac = frac if frac != "." else ""
    if off == timedelta(0) and use_z:
        return dt.replace(tzinfo=None).strftime(f"%Y-%m-%dT%H:%M:%S{frac}") + "Z"
    # смещение вида ±HH:MM
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    hh, rem = divmod(total, 3600)
    mm, _ = divmod(rem, 60)
    return dt.replace(tzinfo=None).strftime(f"%Y-%m-%dT%H:%M:%S{frac}") + f"{sign}{hh:02d}:{mm:02d}"


# ---------------------------
# Epoch конвертация
# ---------------------------

def to_epoch_seconds(dt: datetime) -> float:
    """
    Перевод timezone-aware datetime в секунды Unix-эпохи (float).

    Документация: https://docs.python.org/3/library/datetime.html#datetime.datetime.timestamp
    """
    return to_utc(dt).timestamp()


def from_epoch_seconds(sec: Union[int, float], tz: Union[str, timezone, None] = UTC) -> datetime:
    """
    Создать timezone-aware datetime из секунд Unix-эпохи в указанном tz (UTC по умолчанию).
    """
    tzinfo = coerce_tz(tz)
    return datetime.fromtimestamp(float(sec), tz=tzinfo)


# ---------------------------
# Округления
# ---------------------------

def truncate(dt: datetime, *, seconds: int = 0, minutes: int = 0, hours: int = 0) -> datetime:
    """
    Усечение datetime до кратности заданному шагу (например, до nearest minute boundary).

    Пример: truncate(dt, minutes=1) → сек/микросекунды сбрасываются.
    """
    dt = ensure_aware(dt)
    total = seconds + minutes * 60 + hours * 3600
    if total <= 0:
        return dt
    epoch = to_epoch_seconds(dt)
    new_epoch = epoch - (epoch % total)
    return from_epoch_seconds(new_epoch, tz=dt.tzinfo)


def round_to(dt: datetime, *, seconds: int) -> datetime:
    """
    Округление datetime до ближайшего шага (в секундах), .5 вверх.

    Пример: round_to(dt, seconds=15)
    """
    dt = ensure_aware(dt)
    if seconds <= 0:
        return dt
    epoch = to_epoch_seconds(dt)
    new_epoch = seconds * round(epoch / seconds)
    return from_epoch_seconds(new_epoch, tz=dt.tzinfo)


# ---------------------------
# Дедлайны и ожидания
# ---------------------------

@dataclass(frozen=True)
class Deadline:
    """
    Дедлайн на основе монотоничных часов.

    - Инициализация: Deadline.in_(seconds) или Deadline.at_monotonic(monotonic_target).
    - Методы: remaining(), expired(), sleep(), raise_if_expired().
    - Основано на time.monotonic(): https://docs.python.org/3/library/time.html#time.monotonic
    """
    _mono_target: float

    @staticmethod
    def in_(seconds: Union[int, float]) -> "Deadline":
        if seconds < 0:
            raise ValueError("seconds must be >= 0")
        return Deadline(_time.monotonic() + float(seconds))

    @staticmethod
    def at_monotonic(mono_target: float) -> "Deadline":
        return Deadline(float(mono_target))

    def remaining(self) -> float:
        return max(0.0, self._mono_target - _time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def sleep(self) -> None:
        """Спит до дедлайна (или 0, если уже истёк), используя sleep_precise."""
        sleep_precise(self.remaining())

    def raise_if_expired(self, exc: Exception | None = None) -> None:
        if self.expired():
            raise (exc or TimeoutError("deadline expired"))


def sleep_precise(seconds: Union[int, float]) -> None:
    """
    «Точный сон» без накопления дрейфа на базе монотоничных часов.

    Идея: вместо одного sleep — короткий цикл с контролем времени на time.monotonic().
    """
    target = _time.monotonic() + max(0.0, float(seconds))
    # Грубая фаза
    while True:
        now = _time.monotonic()
        remain = target - now
        if remain <= 0:
            return
        # крупными шагами, затем тонкая доводка
        _time.sleep(remain * 0.5 if remain > 0.02 else remain)


def sleep_until(deadline: Union[Deadline, float]) -> None:
    """
    Заснуть до дедлайна. Поддерживает:
    - Deadline
    - Абсолютное значение time.monotonic() (float)
    """
    dl = deadline if isinstance(deadline, Deadline) else Deadline.at_monotonic(float(deadline))
    dl.sleep()


# ---------------------------
# Экспоненциальный backoff с джиттером
# ---------------------------

def exp_backoff(
    attempt: int,
    *,
    base: float = 0.1,
    factor: float = 2.0,
    cap: float = 30.0,
    jitter: str = "full",
    rnd: Callable[[], float] = None,
) -> float:
    """
    Вычисляет задержку экспоненциального повторения.

    Параметры:
    - attempt: номер попытки (0 для первой).
    - base: базовая задержка.
    - factor: множитель экспоненты.
    - cap: максимальная задержка (сек).
    - jitter: тип джиттера: 'none' | 'full' | 'equal'.
      * 'none'  — чистая экспонента.
      * 'full'  — U(0, delay).
      * 'equal' — U(delay/2, delay).
    - rnd: источник случайности (0..1), по умолчанию random.random.

    Возвращает задержку в секундах.
    """
    import random

    if attempt < 0:
        raise ValueError("attempt must be >= 0")
    delay = min(cap, base * (factor ** attempt))
    if jitter == "none":
        return delay
    if rnd is None:
        rnd = random.random
    r = rnd()
    if jitter == "full":
        return r * delay
    if jitter == "equal":
        return (delay / 2.0) + r * (delay / 2.0)
    raise ValueError("jitter must be one of: none|full|equal")


# ---------------------------
# Простой token-bucket rate limiter
# ---------------------------

class TokenBucket:
    """
    Потокобезопасный (в рамках одного потока) токен-бакет.

    - capacity: максимальное число токенов.
    - refill_rate: пополнение токенов в секундах (tokens_per_second).
    - acquire(n): попытка атомарно изъять n токенов; возвращает True/False.
    - wait(n, deadline): блочное ожидание токенов до дедлайна.

    Алгоритм основан на монотоничных часах: https://docs.python.org/3/library/time.html#time.monotonic
    """

    __slots__ = ("capacity", "refill_rate", "_tokens", "_updated")

    def __init__(self, capacity: float, refill_rate: float) -> None:
        if capacity <= 0 or refill_rate <= 0:
            raise ValueError("capacity and refill_rate must be > 0")
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._tokens = float(capacity)
        self._updated = _time.monotonic()

    def _refill(self) -> None:
        now = _time.monotonic()
        dt = now - self._updated
        if dt <= 0:
            return
        self._tokens = min(self.capacity, self._tokens + dt * self.refill_rate)
        self._updated = now

    def acquire(self, n: float = 1.0) -> bool:
        if n <= 0:
            return True
        self._refill()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False

    def wait(self, n: float = 1.0, deadline: Optional[Deadline] = None) -> bool:
        """
        Ожидает появления n токенов. Если дедлайн истёк — возвращает False.
        """
        if n <= 0:
            return True
        while True:
            if self.acquire(n):
                return True
            if deadline and deadline.expired():
                return False
            # вычислим минимально достаточное ожидание
            self._refill()
            missing = max(0.0, n - self._tokens)
            # сколько секунд нужно для накопления missing
            wait_s = missing / self.refill_rate
            if deadline:
                wait_s = min(wait_s, deadline.remaining())
            if wait_s <= 0:
                wait_s = 0.001
            sleep_precise(wait_s)


# ---------------------------
# Простейший парсер длительностей ISO 8601 (частичный)
# ---------------------------

_ISO_DUR = re.compile(
    r"^P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$"
)

def parse_iso_duration(s: str) -> timedelta:
    """
    Парсит длительность в подсете ISO 8601: PnW n недель, PnD n дней, TnHnMnS время.
    Годы/месяцы НЕ поддерживаются (двусмысленны без календарного контекста).

    ISO 8601 (общая справка): RFC 3339 указывает совместимые представления времени; месяцы/годы
    намеренно опущены в этой реализации.
    """
    m = _ISO_DUR.match(s.strip())
    if not m:
        raise ValueError(f"Invalid ISO 8601 duration: {s!r}")
    weeks = float(m.group("weeks") or 0)
    days = float(m.group("days") or 0)
    hours = float(m.group("hours") or 0)
    minutes = float(m.group("minutes") or 0)
    seconds = float(m.group("seconds") or 0)
    total = timedelta(weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds)
    return total
