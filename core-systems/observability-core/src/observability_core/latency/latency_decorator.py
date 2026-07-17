"""Latency decorator for synchronous and asynchronous callables."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from .latency_tracker import get_tracker


def track_latency(
    stage_name: str,
    category: str = "function",
    context_getter: Callable[..., dict[str, Any]] | None = None,
):
    """Measure a function and append an event to the current tracker."""

    def decorator(func: Callable[..., Any]):
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                tracker = get_tracker()
                event = tracker.start(
                    stage_name,
                    _metadata(category, context_getter, args, kwargs),
                )
                try:
                    return await func(*args, **kwargs)
                finally:
                    event.stop()

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            tracker = get_tracker()
            event = tracker.start(
                stage_name,
                _metadata(category, context_getter, args, kwargs),
            )
            try:
                return func(*args, **kwargs)
            finally:
                event.stop()

        return sync_wrapper

    return decorator


def _metadata(
    category: str,
    context_getter: Callable[..., dict[str, Any]] | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    context = context_getter(*args, **kwargs) if context_getter else {}
    return {"category": category, **context}
