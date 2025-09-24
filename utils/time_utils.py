# utils/time_utils.py

from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
from typing import Union, Optional


def utcnow() -> datetime:
    """Возвращает текущее время в UTC с tzinfo"""
    return datetime.now(timezone.utc)


def to_utc(dt: Union[datetime, str]) -> datetime:
    """
    Преобразует строку или datetime в UTC datetime

    Args:
        dt (datetime | str): входные данные

    Returns:
        datetime: нормализованное UTC время
    """
    if isinstance(dt, str):
        dt = date_parser.parse(dt)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    return dt


def time_diff_seconds(dt1: Union[datetime, str], dt2: Union[datetime, str]) -> float:
    """Разница во времени (в секундах) между двумя моментами"""
    t1 = to_utc(dt1)
    t2 = to_utc(dt2)
    return (t1 - t2).total_seconds()


def add_minutes(dt: Union[datetime, str], minutes: int) -> datetime:
    """Добавляет указанное количество минут к datetime"""
    dt = to_utc(dt)
    return dt + timedelta(minutes=minutes)


def add_hours(dt: Union[datetime, str], hours: int) -> datetime:
    """Добавляет часы"""
    dt = to_utc(dt)
    return dt + timedelta(hours=hours)


def add_days(dt: Union[datetime, str], days: int) -> datetime:
    """Добавляет дни"""
    dt = to_utc(dt)
    return dt + timedelta(days=days)


def isoformat(dt: Union[datetime, str], with_ms: bool = False) -> str:
    """Возвращает ISO8601-строку с или без миллисекунд"""
    dt = to_utc(dt)
    if with_ms:
        return dt.isoformat(timespec="milliseconds")
    return dt.isoformat()


def humanize_delta(delta_seconds: float) -> str:
    """Превращает секунды в человеко-читаемый формат"""
    if delta_seconds < 60:
        return f"{int(delta_seconds)} seconds"
    elif delta_seconds < 3600:
        return f"{int(delta_seconds // 60)} minutes"
    elif delta_seconds < 86400:
        return f"{int(delta_seconds // 3600)} hours"
    else:
        return f"{int(delta_seconds // 86400)} days"
