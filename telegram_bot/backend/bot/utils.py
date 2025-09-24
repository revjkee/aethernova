from typing import Any
import orjson
from datetime import datetime


def json_dumps(obj: Any) -> str:
    """
    Быстрая и эффективная сериализация объекта в JSON строку с помощью orjson.
    Возвращает строку в utf-8.
    """
    return orjson.dumps(obj).decode('utf-8')


def json_loads(data: bytes | str) -> Any:
    """
    Десериализация JSON из bytes или строки в Python объект.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return orjson.loads(data)


def format_timeslot(time_str: str) -> str:
    """
    Приводит строку времени ISO 8601 к читаемому формату 'HH:MM'.
    Пример: '2025-08-01T08:00:00' -> '08:00'
    """
    dt = datetime.fromisoformat(time_str)
    return dt.strftime('%H:%M')


def format_datetime_readable(dt: datetime) -> str:
    """
    Форматирует datetime в строку вида '01 Авг 2025 08:00'
    """
    months = ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн', 'Июл', 'Авг', 'Сен', 'Окт', 'Ноя', 'Дек']
    day = dt.day
    month = months[dt.month - 1]
    year = dt.year
    time = dt.strftime('%H:%M')
    return f"{day:02d} {month} {year} {time}"


def safe_get(d: dict, key: str, default=None):
    """
    Безопасное извлечение значения из словаря, чтобы избежать KeyError.
    """
    return d.get(key, default)
