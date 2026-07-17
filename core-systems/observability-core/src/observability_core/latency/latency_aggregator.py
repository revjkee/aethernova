"""Thread-safe latency aggregation."""

from __future__ import annotations

import threading
from collections import defaultdict
from statistics import mean, stdev

from .latency_event import LatencyEvent


class LatencyAggregator:
    """
    Агрегатор latency-событий. Поддерживает поточную агрегацию по:
    - имени события
    - trace_id
    - стадиям (metadata["stage"])
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.events_by_name: dict[str, list[LatencyEvent]] = defaultdict(list)
        self.events_by_trace: dict[str, list[LatencyEvent]] = defaultdict(list)
        self.stage_metrics: dict[str, list[float]] = defaultdict(list)

    def record(self, event: LatencyEvent) -> None:
        """Регистрирует событие в агрегаторе."""
        event.stop()
        with self.lock:
            self.events_by_name[event.name].append(event)
            if event.metadata.get("trace_id"):
                self.events_by_trace[event.metadata["trace_id"]].append(event)
            if stage := event.metadata.get("stage"):
                self.stage_metrics[str(stage)].append(event.duration_ms or 0.0)

    def get_summary(self) -> dict[str, dict[str, float]]:
        """Возвращает агрегированную сводку по событиям."""
        summary = {}
        with self.lock:
            for name, events in self.events_by_name.items():
                durations = [
                    duration for event in events if (duration := event.duration_ms) is not None
                ]
                if durations:
                    summary[name] = {
                        "count": len(durations),
                        "avg_ms": round(mean(durations), 2),
                        "min_ms": round(min(durations), 2),
                        "max_ms": round(max(durations), 2),
                        "stdev_ms": round(stdev(durations), 2) if len(durations) > 1 else 0.0,
                    }
        return summary

    def get_trace_events(self, trace_id: str) -> list[LatencyEvent]:
        """Возвращает все события по trace_id."""
        with self.lock:
            return self.events_by_trace.get(trace_id, [])

    def get_stage_breakdown(self) -> dict[str, dict[str, float]]:
        """Сводка по стадиям обработки."""
        with self.lock:
            breakdown = {}
            for stage, durations in self.stage_metrics.items():
                if durations:
                    breakdown[stage] = {
                        "count": len(durations),
                        "avg_ms": round(mean(durations), 2),
                        "max_ms": round(max(durations), 2),
                        "min_ms": round(min(durations), 2),
                    }
            return breakdown

    def reset(self) -> None:
        """Очистка всех агрегированных данных (например, между batch-интервалами)."""
        with self.lock:
            self.events_by_name.clear()
            self.events_by_trace.clear()
            self.stage_metrics.clear()
