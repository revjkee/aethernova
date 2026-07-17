import logging
from typing import Any

logger = logging.getLogger("latency")

# Allowed duration range in milliseconds.
DEFAULT_LATENCY_LIMITS = {
    "min": 0.0,
    "max": 300_000.0,
}

REQUIRED_FIELDS = {
    "event_id": str,
    "name": str,
    "start_time": float,
    "end_time": float,
    "duration_ms": float,
    "metadata": dict,
}


class LatencyValidationError(Exception):
    """Исключение при нарушении структуры или логики latency-события."""

    pass


def validate_latency_event(event: dict[str, Any], limits: dict[str, float] | None = None) -> None:
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
            actual_type = type(event[field]).__name__
            raise LatencyValidationError(
                f"Invalid type for field '{field}': "
                f"expected {expected_type.__name__}, got {actual_type}"
            )

    # Проверка допустимого диапазона времени
    duration = event["duration_ms"]
    if not (limits["min"] <= duration <= limits["max"]):
        raise LatencyValidationError(
            f"Duration {duration:.3f} out of allowed range [{limits['min']}, {limits['max']}]"
        )

    if len(event["event_id"]) < 8:
        raise LatencyValidationError("Invalid event_id length")


def is_valid_latency_event(event: dict[str, Any], limits: dict[str, float] | None = None) -> bool:
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
