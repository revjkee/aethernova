import re
from datetime import datetime
from typing import Optional


class ValidationError(ValueError):
    pass


def validate_phone(phone: str) -> bool:
    """
    Проверяет корректность номера телефона.
    Формат: +7XXXXXXXXXX или 10 цифр без кода страны.
    """
    pattern = re.compile(r"^\+7\d{10}$|^\d{10}$")
    if not pattern.match(phone):
        raise ValidationError("Неверный формат телефона. Ожидается +7XXXXXXXXXX или 10 цифр.")
    return True


def validate_email(email: str) -> bool:
    """
    Проверяет корректность email.
    Простая проверка формата.
    """
    pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
    if not pattern.match(email):
        raise ValidationError("Неверный формат email.")
    return True


def validate_time_slot(time_str: str) -> bool:
    """
    Проверяет корректность времени слота в формате HH:MM.
    """
    try:
        datetime.strptime(time_str, "%H:%M")
        return True
    except ValueError:
        raise ValidationError("Время слота должно быть в формате HH:MM.")


def validate_date(date_str: str, date_format: str = "%Y-%m-%d") -> bool:
    """
    Проверяет корректность даты по формату, по умолчанию ISO YYYY-MM-DD.
    """
    try:
        datetime.strptime(date_str, date_format)
        return True
    except ValueError:
        raise ValidationError(f"Дата должна быть в формате {date_format}.")


def validate_name(name: str, min_len: int = 2, max_len: int = 50) -> bool:
    """
    Проверяет корректность имени (длина и допустимые символы).
    """
    if not (min_len <= len(name.strip()) <= max_len):
        raise ValidationError(f"Имя должно содержать от {min_len} до {max_len} символов.")
    if not re.match(r"^[A-Za-zА-Яа-яЁё\s\-]+$", name):
        raise ValidationError("Имя содержит недопустимые символы.")
    return True
