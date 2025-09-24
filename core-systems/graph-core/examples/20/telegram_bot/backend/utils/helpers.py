from datetime import datetime, time, timedelta
from typing import Optional


def parse_time_str(time_str: str) -> time:
    """
    Преобразует строку 'HH:MM' в объект datetime.time.
    """
    return datetime.strptime(time_str, "%H:%M").time()


def format_time_slot(start: time, end: time) -> str:
    """
    Форматирует временной слот в читаемый вид, например "08:00 - 10:00".
    """
    return f"{start.strftime('%H:%M')} - {end.strftime('%H:%M')}"


def is_time_in_range(check_time: time, start: time, end: time) -> bool:
    """
    Проверяет, находится ли check_time в диапазоне [start, end).
    """
    return start <= check_time < end


def datetime_to_str(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Преобразует datetime в строку по заданному формату.
    """
    return dt.strftime(fmt)


def str_to_datetime(date_str: str, fmt: str = "%Y-%m-%d") -> datetime:
    """
    Преобразует строку с датой в datetime.
    """
    return datetime.strptime(date_str, fmt)


def next_day(date: datetime) -> datetime:
    """
    Возвращает datetime следующего дня с тем же временем.
    """
    return date + timedelta(days=1)


def clamp_time_to_slots(check_time: time, slots: list[tuple[time, time]]) -> Optional[tuple[time, time]]:
    """
    Проверяет, в какой слот попадает check_time, возвращает этот слот или None.
    """
    for start, end in slots:
        if start <= check_time < end:
            return start, end
    return None
