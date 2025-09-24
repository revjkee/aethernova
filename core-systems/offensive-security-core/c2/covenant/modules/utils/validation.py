# Валидация входных контрактов и ролей
# validation.py
# Модуль валидации входных контрактов и ролей
# Ключевая задача — строгая проверка корректности данных и прав доступа для безопасности системы

from typing import Any, Dict, List, Union
from enum import Enum


class ValidationError(Exception):
    """Исключение при ошибках валидации."""
    pass


class Role(Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"
    # Добавить по необходимости новые роли


def validate_contract_fields(data: Dict[str, Any], required_fields: List[str]) -> None:
    """
    Проверяет наличие всех обязательных полей в контракте.
    Выбрасывает ValidationError при отсутствии или пустом поле.
    """
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    if missing_fields:
        raise ValidationError(f"Отсутствуют обязательные поля: {', '.join(missing_fields)}")

    for field in required_fields:
        value = data.get(field)
        if isinstance(value, str) and not value.strip():
            raise ValidationError(f"Поле '{field}' не может быть пустым или содержать только пробелы")


def validate_field_type(data: Dict[str, Any], field: str, expected_type: Union[type, tuple]) -> None:
    """
    Проверяет тип поля, выбрасывает ValidationError, если тип не соответствует.
    """
    if field not in data:
        raise ValidationError(f"Поле '{field}' отсутствует в данных")

    if not isinstance(data[field], expected_type):
        expected_names = (
            expected_type.__name__
            if isinstance(expected_type, type)
            else ", ".join(t.__name__ for t in expected_type)
        )
        actual_name = type(data[field]).__name__
        raise ValidationError(f"Поле '{field}' должно быть типа {expected_names}, получено {actual_name}")


def validate_role(role: str) -> None:
    """
    Проверяет, что роль корректна и разрешена в системе.
    """
    if role not in Role._value2member_map_:
        raise ValidationError(f"Роль '{role}' не распознана или запрещена")


def validate_contract(data: Dict[str, Any], required_fields: List[str], field_types: Dict[str, Union[type, tuple]]) -> None:
    """
    Комплексная валидация контракта:
    - Проверка наличия обязательных полей
    - Проверка типов полей
    """
    validate_contract_fields(data, required_fields)

    for field, expected_type in field_types.items():
        if field in data:
            validate_field_type(data, field, expected_type)


def validate_user_access(user_role: str, required_role: str) -> None:
    """
    Проверяет, что роль пользователя соответствует или превышает требуемую роль.
    Пример простой иерархии: admin > user > guest.
    """
    hierarchy = {
        Role.GUEST.value: 0,
        Role.USER.value: 1,
        Role.ADMIN.value: 2,
    }

    if user_role not in hierarchy:
        raise ValidationError(f"Неизвестная роль пользователя: {user_role}")

    if required_role not in hierarchy:
        raise ValidationError(f"Неизвестная требуемая роль: {required_role}")

    if hierarchy[user_role] < hierarchy[required_role]:
        raise ValidationError(f"Недостаточно прав: требуется роль '{required_role}', у пользователя '{user_role}'")


# Универсальная функция для проверки валидности email
def validate_email(email: str) -> None:
    import re
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not re.match(pattern, email):
        raise ValidationError(f"Неверный формат email: {email}")

# Можно расширять функциями для проверки числовых диапазонов, длины строк, специальных форматов и т.п.
