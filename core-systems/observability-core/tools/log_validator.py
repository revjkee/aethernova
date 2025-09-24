# observability/dashboards/tools/log_validator.py

from typing import Dict, Any, List, Optional, Callable
import re


class ValidationError(Exception):
    """Ошибка валидации лог-сообщения."""


class LogValidator:
    """
    Валидирует логи на соответствие обязательным полям,
    типам данных и пользовательским правилам.
    """

    def __init__(
        self,
        required_fields: Optional[List[str]] = None,
        field_types: Optional[Dict[str, type]] = None,
        custom_rules: Optional[List[Callable[[Dict[str, Any]], None]]] = None,
        pattern_fields: Optional[Dict[str, str]] = None
    ):
        self.required_fields = required_fields or []
        self.field_types = field_types or {}
        self.custom_rules = custom_rules or []
        self.pattern_fields = {
            field: re.compile(pattern) for field, pattern in (pattern_fields or {}).items()
        }

    def validate(self, log: Dict[str, Any]) -> bool:
        self._check_required_fields(log)
        self._check_field_types(log)
        self._check_field_patterns(log)
        self._apply_custom_rules(log)
        return True

    def _check_required_fields(self, log: Dict[str, Any]):
        for field in self.required_fields:
            if field not in log:
                raise ValidationError(f"Missing required field: {field}")

    def _check_field_types(self, log: Dict[str, Any]):
        for field, expected_type in self.field_types.items():
            if field in log and not isinstance(log[field], expected_type):
                raise ValidationError(f"Field '{field}' has invalid type: {type(log[field])}, expected: {expected_type}")

    def _check_field_patterns(self, log: Dict[str, Any]):
        for field, pattern in self.pattern_fields.items():
            if field in log and isinstance(log[field], str):
                if not pattern.match(log[field]):
                    raise ValidationError(f"Field '{field}' does not match pattern: {pattern.pattern}")

    def _apply_custom_rules(self, log: Dict[str, Any]):
        for rule in self.custom_rules:
            rule(log)
