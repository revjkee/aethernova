import logging
from typing import Any, Dict, Tuple, Optional, List, Union, Callable

logger = logging.getLogger("calibration.validator")


class ValidationError(Exception):
    """Ошибка валидации параметра."""


class ParameterSpec:
    """
    Спецификация параметра: допустимые значения, тип, ограничения.
    Используется для валидации входных данных в калибровке.
    """

    def __init__(
        self,
        name: str,
        param_type: type,
        *,
        required: bool = True,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        choices: Optional[List[Any]] = None,
        custom_validator: Optional[Callable[[Any], bool]] = None
    ):
        self.name = name
        self.param_type = param_type
        self.required = required
        self.min_value = min_value
        self.max_value = max_value
        self.choices = choices
        self.custom_validator = custom_validator

    def validate(self, value: Any) -> None:
        if value is None:
            if self.required:
                raise ValidationError(f"Параметр '{self.name}' обязателен")
            return

        if not isinstance(value, self.param_type):
            raise ValidationError(
                f"Параметр '{self.name}' должен быть типа {self.param_type.__name__}, но получен {type(value).__name__}"
            )

        if self.param_type in [int, float]:
            if self.min_value is not None and value < self.min_value:
                raise ValidationError(
                    f"Значение параметра '{self.name}' меньше минимального ({self.min_value})"
                )
            if self.max_value is not None and value > self.max_value:
                raise ValidationError(
                    f"Значение параметра '{self.name}' превышает максимум ({self.max_value})"
                )

        if self.choices is not None and value not in self.choices:
            raise ValidationError(
                f"Значение параметра '{self.name}' должно быть одним из: {self.choices}"
            )

        if self.custom_validator and not self.custom_validator(value):
            raise ValidationError(
                f"Кастомная валидация не пройдена для параметра '{self.name}'"
            )


class ParameterValidator:
    """
    Главный валидатор параметров конфигурации.
    Поддерживает множество параметров и их проверку по спецификациям.
    """

    def __init__(self):
        self._specs: Dict[str, ParameterSpec] = {}

    def add_spec(self, spec: ParameterSpec) -> None:
        self._specs[spec.name] = spec
        logger.debug(f"Добавлена спецификация параметра: {spec.name}")

    def validate_config(self, config: Dict[str, Any]) -> None:
        """
        Валидирует словарь конфигурации по заранее добавленным спецификациям.
        """
        for name, spec in self._specs.items():
            value = config.get(name)
            try:
                spec.validate(value)
            except ValidationError as e:
                logger.error(f"Ошибка валидации: {e}")
                raise

        # Проверка на неизвестные параметры
        for key in config:
            if key not in self._specs:
                logger.warning(f"Нераспознанный параметр: {key}")

    def reset(self) -> None:
        self._specs.clear()
        logger.info("Сброшены все спецификации параметров.")


def validate_dynamic_constraints(dependency_graph, config: Dict[str, Any]) -> None:
    """
    Дополнительная валидация зависимых параметров на уровне связей.
    """
    affected = dependency_graph.affected_nodes(changed="*")
    for node in affected:
        if node not in config:
            logger.warning(f"Отсутствует зависимый параметр: {node}")
