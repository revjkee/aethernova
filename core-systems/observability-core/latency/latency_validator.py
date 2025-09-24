import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("latency")

# Конфигурация допустимых диапазонов значений (в секундах)
DEFAULT_LATENCY_LIMITS = {
    "min": 0.000001,
    "max": 300.0,  # 5 минут
}

# Обязательные поля latency-события
REQUIRED_FIELDS = {
    "event_id": str,
    "trace_id": str,
    "span_id": str,
    "timestamp": float,
    "duration": float,
    "stage": str,
    "source": str,
}


class LatencyValidationError(Exception):
    """Исключение при нарушении структуры или логики latency-события."""
    pass


def validate_latency_event(
    event: Dict[str, Any],
    limits: Optional[Dict[str, float]] = None
) -> None:
    """
    Проверка валидности latency-события.
    Выбрасывает LatencyValidationError при нарушениях.
    """
    limits = limits or DEFAULT_LATENCY_LIMITS

    # Проверка обязательных полей
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in event:
            raise LatencyValidationError(f"Missing required field: {field}")
        if not isinstance(event[field], expected_type):
            raise LatencyValidationError(f"Invalid type for field '{field}': expected {expected_type.__name__}, got {type(event[field]).__name__}")

    # Проверка допустимого диапазона времени
    duration = event["duration"]
    if not (limits["min"] <= duration <= limits["max"]):
        raise LatencyValidationError(
            f"Duration {duration:.6f} out of allowed range [{limits['min']}, {limits['max']}]"
        )

    # Проверка целостности идентификаторов
    if len(event["trace_id"]) != 32:
        raise LatencyValidationError("Invalid trace_id length")
    if len(event["span_id"]) != 16:
        raise LatencyValidationError("Invalid span_id length")
    if len(event["event_id"]) < 8:
        raise LatencyValidationError("Invalid event_id length")


def is_valid_latency_event(
    event: Dict[str, Any],
    limits: Optional[Dict[str, float]] = None
) -> bool:
    """
    Безопасная проверка latency-события.
    Возвращает True при успехе, иначе False с логом.
    """
    try:
        validate_latency_event(event, limits)
        return True
    except LatencyValidationError as e:
        logger.warning(f"[LATENCY VALIDATOR] Invalid event: {e}")
        return False
