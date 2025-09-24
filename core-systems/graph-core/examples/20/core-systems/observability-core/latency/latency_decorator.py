import functools
import inspect
import time
import asyncio
from typing import Callable, Optional
from .latency_tracker import get_latency_tracker
from .latency_event import LatencyEvent


def track_latency(
    stage_name: str,
    category: str = "function",
    context_getter: Optional[Callable] = None,
):
    """
    Универсальный декоратор для измерения времени выполнения функций.
    Автоматически регистрирует событие в latency-трекере.

    :param stage_name: Название этапа
    :param category: Категория (по умолчанию "function")
    :param context_getter: Опционально: функция, возвращающая dict с context_id, request_id и др.
    """

    def decorator(func: Callable):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                try:
                    return await func(*args, **kwargs)
                finally:
                    _finalize_latency(stage_name, category, start_time, context_getter, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    _finalize_latency(stage_name, category, start_time, context_getter, *args, **kwargs)
            return sync_wrapper

    return decorator


def _finalize_latency(
    stage_name: str,
    category: str,
    start_time: float,
    context_getter: Optional[Callable],
    *args,
    **kwargs,
):
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000.0

    # Получение контекста (если задан)
    context: dict = context_getter(*args, **kwargs) if context_getter else {}
    request_id = context.get("request_id", "unknown")
    context_id = context.get("context_id", None)

    # Формирование события
    event = LatencyEvent(
        request_id=request_id,
        context_id=context_id,
        category=category,
        stages=[{
            "name": stage_name,
            "duration_ms": duration_ms,
            "start_time": start_time,
            "end_time": end_time,
        }]
    )

    tracker = get_latency_tracker()
    tracker.track_event(event)
