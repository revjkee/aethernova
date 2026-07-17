"""Per-context collection of latency events."""

from __future__ import annotations

import contextvars
import logging
import uuid
from threading import RLock

from .latency_event import LatencyEvent

_logger = logging.getLogger("latency_tracker")
_tracker_context: contextvars.ContextVar[LatencyTracker | None] = contextvars.ContextVar(
    "latency_tracker_context",
    default=None,
)


class LatencyTracker:
    def __init__(self, request_id: str | None = None) -> None:
        self.request_id = request_id or str(uuid.uuid4())
        self.events: list[LatencyEvent] = []
        self.lock = RLock()

    def start(
        self,
        name: str,
        metadata: dict[str, object] | None = None,
    ) -> LatencyEvent:
        with self.lock:
            event = LatencyEvent(name=name, metadata=dict(metadata or {}))
            self.events.append(event)
            _logger.debug("[%s] started event %s", self.request_id, name)
            return event

    def stop(self, name: str) -> LatencyEvent | None:
        with self.lock:
            event = next(
                (
                    candidate
                    for candidate in reversed(self.events)
                    if candidate.name == name and candidate.end_time is None
                ),
                None,
            )
            if event is None:
                _logger.warning("unfinished event %s not found", name)
                return None
            event.stop()
            _logger.debug(
                "[%s] stopped event %s in %.3f ms",
                self.request_id,
                name,
                event.duration_ms or 0.0,
            )
            return event

    def track_event(self, event: LatencyEvent) -> None:
        with self.lock:
            event.stop()
            self.events.append(event)

    def summary(self) -> dict[str, object]:
        with self.lock:
            return {
                "request_id": self.request_id,
                "events": [event.to_dict() for event in self.events],
            }

    def stop_all(self) -> None:
        with self.lock:
            for event in self.events:
                if event.end_time is None:
                    event.stop()


def get_tracker() -> LatencyTracker:
    tracker = _tracker_context.get()
    if tracker is None:
        tracker = LatencyTracker()
        _tracker_context.set(tracker)
    return tracker


get_latency_tracker = get_tracker


def reset_tracker() -> None:
    _tracker_context.set(None)
