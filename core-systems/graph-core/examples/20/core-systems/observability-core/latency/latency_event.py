import time
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import uuid

__all__ = ["LatencyEvent", "LatencyEventSchema"]

@dataclass
class LatencyEvent:
    name: str
    start_time: float = field(default_factory=time.perf_counter)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def stop(self):
        if self.end_time is not None:
            return
        self.end_time = time.perf_counter()
        self.duration = self.end_time - self.start_time

    def to_dict(self, normalize: bool = True) -> Dict[str, Any]:
        self.stop()
        base = {
            "event_id": self.event_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration * 1000, 3) if self.duration else None,
        }
        if normalize:
            base["metadata"] = self._normalize_metadata()
        else:
            base["metadata"] = self.metadata
        return base

    def _normalize_metadata(self) -> Dict[str, Any]:
        def _convert(val):
            if isinstance(val, (str, int, float, bool, type(None))):
                return val
            try:
                return json.dumps(val)
            except Exception:
                return str(val)
        return {k: _convert(v) for k, v in self.metadata.items()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

class LatencyEventSchema:
    """Схема для сериализации и нормализации latency-метрик"""

    @staticmethod
    def serialize(event: LatencyEvent) -> Dict[str, Any]:
        return event.to_dict()

    @staticmethod
    def to_json(event: LatencyEvent) -> str:
        return event.to_json()

    @staticmethod
    def normalize(events: list[LatencyEvent]) -> list[Dict[str, Any]]:
        return [event.to_dict() for event in events]

    @staticmethod
    def filter_by_duration(events: list[LatencyEvent], min_ms: float) -> list[LatencyEvent]:
        return [e for e in events if (e.duration or 0) * 1000 >= min_ms]

    @staticmethod
    def aggregate_durations(events: list[LatencyEvent]) -> Dict[str, float]:
        agg = {}
        for e in events:
            if e.name not in agg:
                agg[e.name] = 0
            if e.duration:
                agg[e.name] += e.duration
        return {k: round(v * 1000, 3) for k, v in agg.items()}  # ms
