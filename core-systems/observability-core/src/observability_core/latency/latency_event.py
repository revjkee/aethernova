"""Canonical latency event model."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

__all__ = ["LatencyEvent", "LatencyEventSchema"]


@dataclass
class LatencyEvent:
    name: str
    start_time: float = field(default_factory=time.perf_counter)
    end_time: float | None = None
    duration: float | None = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float | None:
        return round(self.duration * 1000, 3) if self.duration is not None else None

    def stop(self) -> LatencyEvent:
        if self.end_time is not None:
            return self
        self.end_time = time.perf_counter()
        self.duration = self.end_time - self.start_time
        return self

    def to_dict(self, normalize: bool = True) -> dict[str, Any]:
        self.stop()
        base = {
            "event_id": self.event_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
        }
        if normalize:
            base["metadata"] = self._normalize_metadata()
        else:
            base["metadata"] = self.metadata
        return base

    def _normalize_metadata(self) -> dict[str, Any]:
        def _convert(value: Any) -> Any:
            if isinstance(value, (str, int, float, bool, type(None))):
                return value
            try:
                return json.dumps(value)
            except Exception:
                return str(value)

        return {key: _convert(value) for key, value in self.metadata.items()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class LatencyEventSchema:
    """Serialization and aggregation helpers for latency events."""

    @staticmethod
    def serialize(event: LatencyEvent) -> dict[str, Any]:
        return event.to_dict()

    @staticmethod
    def to_json(event: LatencyEvent) -> str:
        return event.to_json()

    @staticmethod
    def normalize(events: list[LatencyEvent]) -> list[dict[str, Any]]:
        return [event.to_dict() for event in events]

    @staticmethod
    def filter_by_duration(events: list[LatencyEvent], min_ms: float) -> list[LatencyEvent]:
        for event in events:
            event.stop()
        return [event for event in events if (event.duration_ms or 0) >= min_ms]

    @staticmethod
    def aggregate_durations(events: list[LatencyEvent]) -> dict[str, float]:
        aggregate: dict[str, float] = {}
        for event in events:
            event.stop()
            aggregate[event.name] = aggregate.get(event.name, 0.0) + (event.duration_ms or 0.0)
        return {name: round(duration, 3) for name, duration in aggregate.items()}
