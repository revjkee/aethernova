import threading
from collections import defaultdict
from statistics import mean, stdev
from typing import Dict, List, Optional
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
        self.events_by_name: Dict[str, List[LatencyEvent]] = defaultdict(list)
        self.events_by_trace: Dict[str, List[LatencyEvent]] = defaultdict(list)
        self.stage_metrics: Dict[str, List[float]] = defaultdict(list)

    def record(self, event: LatencyEvent):
        """Регистрирует событие в агрегаторе."""
        with self.lock:
            self.events_by_name[event.name].append(event)
            if event.metadata.get("trace_id"):
                self.events_by_trace[event.metadata["trace_id"]].append(event)
            if stage := event.metadata.get("stage"):
                self.stage_metrics[stage].append(event.duration_ms)

    def get_summary(self) -> Dict[str, Dict[str, float]]:
        """Возвращает агрегированную сводку по событиям."""
        summary = {}
        with self.lock:
            for name, events in self.events_by_name.items():
                durations = [e.duration_ms for e in events]
                if durations:
                    summary[name] = {
                        "count": len(durations),
                        "avg_ms": round(mean(durations), 2),
                        "min_ms": round(min(durations), 2),
                        "max_ms": round(max(durations), 2),
                        "stdev_ms": round(stdev(durations), 2) if len(durations) > 1 else 0.0
                    }
        return summary

    def get_trace_events(self, trace_id: str) -> Optional[List[LatencyEvent]]:
        """Возвращает все события по trace_id."""
        with self.lock:
            return self.events_by_trace.get(trace_id, [])

    def get_stage_breakdown(self) -> Dict[str, Dict[str, float]]:
        """Сводка по стадиям обработки."""
        with self.lock:
            breakdown = {}
            for stage, durations in self.stage_metrics.items():
                if durations:
                    breakdown[stage] = {
                        "count": len(durations),
                        "avg_ms": round(mean(durations), 2),
                        "max_ms": round(max(durations), 2),
                        "min_ms": round(min(durations), 2)
                    }
            return breakdown

    def reset(self):
        """Очистка всех агрегированных данных (например, между batch-интервалами)."""
        with self.lock:
            self.events_by_name.clear()
            self.events_by_trace.clear()
            self.stage_metrics.clear()
