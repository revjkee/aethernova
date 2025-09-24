# utils/validator.py

from typing import Any, Type, Optional, Dict, Union
from pydantic import BaseModel, ValidationError
from utils.logger import logger


class ValidationFailure(Exception):
    """Ошибка при валидации данных через Pydantic"""
    def __init__(self, message: str, errors: Optional[list] = None):
        super().__init__(message)
        self.errors = errors or []


def validate_input(
    data: Union[Dict, Any],
    schema: Type[BaseModel],
    strict: bool = False,
    raise_on_error: bool = True
) -> Optional[BaseModel]:
    """
    Валидация данных через pydantic-схему.

    Args:
        data (dict or object): входные данные
        schema (BaseModel): класс-схема pydantic
        strict (bool): отклонять неизвестные поля, если True
        raise_on_error (bool): выбрасывать ли исключение

    Returns:
        schema instance or None

    Raises:
        ValidationFailure: если данные невалидны и raise_on_error=True
    """
    try:
        model_instance = schema(**data)
        logger.debug(f"[Validator] Validated against {schema.__name__}")
        return model_instance
    except ValidationError as ve:
        msg = f"[Validator] Validation failed for {schema.__name__}: {ve.errors()}"
        logger.warning(msg)
        if raise_on_error:
            raise ValidationFailure(msg, ve.errors())
        return None
