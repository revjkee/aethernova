from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple


class MetricError(ValueError):
    pass


class MetricType(str, Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MetricError(f"{name} must be a non-empty string")
    return value.strip()


def _require_mapping(value: Any, name: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise MetricError(f"{name} must be a mapping")
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise MetricError(f"{name} keys and values must be strings")
    return value


def _now_epoch_seconds() -> int:
    return int(time.time())


@dataclass(frozen=True, slots=True)
class MetricSnapshot:
    name: str
    type: MetricType
    value: Any
    labels: Mapping[str, str]
    timestamp: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "value": self.value,
            "labels": dict(self.labels),
            "timestamp": self.timestamp,
        }


class _BaseMetric:
    def __init__(self, name: str, mtype: MetricType, labels: Optional[Mapping[str, str]] = None) -> None:
        self._name = _require_str(name, "metric name")
        self._type = MetricType(mtype)
        self._labels = dict(_require_mapping(labels or {}, "labels"))
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return self._name

    @property
    def type(self) -> MetricType:
        return self._type

    @property
    def labels(self) -> Mapping[str, str]:
        return dict(self._labels)

    def snapshot(self) -> MetricSnapshot:
        raise NotImplementedError


class Counter(_BaseMetric):
    """
    Monotonic increasing counter.
    """

    def __init__(self, name: str, labels: Optional[Mapping[str, str]] = None) -> None:
        super().__init__(name, MetricType.COUNTER, labels)
        self._value: int = 0

    def inc(self, amount: int = 1) -> None:
        if not isinstance(amount, int) or amount < 0:
            raise MetricError("counter increment must be non-negative integer")
        with self._lock:
            self._value += amount

    def snapshot(self) -> MetricSnapshot:
        with self._lock:
            value = self._value
        return MetricSnapshot(
            name=self._name,
            type=self._type,
            value=value,
            labels=self._labels,
            timestamp=_now_epoch_seconds(),
        )


class Gauge(_BaseMetric):
    """
    Gauge metric that can go up or down.
    """

    def __init__(self, name: str, labels: Optional[Mapping[str, str]] = None) -> None:
        super().__init__(name, MetricType.GAUGE, labels)
        self._value: float = 0.0

    def set(self, value: float) -> None:
        if not isinstance(value, (int, float)):
            raise MetricError("gauge value must be numeric")
        with self._lock:
            self._value = float(value)

    def inc(self, amount: float = 1.0) -> None:
        if not isinstance(amount, (int, float)):
            raise MetricError("gauge increment must be numeric")
        with self._lock:
            self._value += float(amount)

    def dec(self, amount: float = 1.0) -> None:
        if not isinstance(amount, (int, float)):
            raise MetricError("gauge decrement must be numeric")
        with self._lock:
            self._value -= float(amount)

    def snapshot(self) -> MetricSnapshot:
        with self._lock:
            value = self._value
        return MetricSnapshot(
            name=self._name,
            type=self._type,
            value=value,
            labels=self._labels,
            timestamp=_now_epoch_seconds(),
        )


class Histogram(_BaseMetric):
    """
    Histogram with fixed buckets.
    """

    def __init__(
        self,
        name: str,
        buckets: Iterable[float],
        labels: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__(name, MetricType.HISTOGRAM, labels)

        b = sorted(float(x) for x in buckets)
        if not b or any(x <= 0 for x in b):
            raise MetricError("histogram buckets must be positive numbers")

        self._buckets = tuple(b)
        self._counts: Dict[float, int] = {k: 0 for k in self._buckets}
        self._sum: float = 0.0
        self._count: int = 0

    def observe(self, value: float) -> None:
        if not isinstance(value, (int, float)):
            raise MetricError("histogram observation must be numeric")

        v = float(value)
        with self._lock:
            self._sum += v
            self._count += 1
            for b in self._buckets:
                if v <= b:
                    self._counts[b] += 1

    def snapshot(self) -> MetricSnapshot:
        with self._lock:
            value = {
                "buckets": dict(self._counts),
                "count": self._count,
                "sum": self._sum,
            }
        return MetricSnapshot(
            name=self._name,
            type=self._type,
            value=value,
            labels=self._labels,
            timestamp=_now_epoch_seconds(),
        )


class MetricRegistry:
    """
    Central registry for all metrics.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: Dict[str, _BaseMetric] = {}

    def register(self, metric: _BaseMetric) -> None:
        if not isinstance(metric, _BaseMetric):
            raise MetricError("metric must be a metric instance")
        with self._lock:
            if metric.name in self._metrics:
                raise MetricError(f"metric already registered: {metric.name}")
            self._metrics[metric.name] = metric

    def get(self, name: str) -> _BaseMetric:
        n = _require_str(name, "metric name")
        with self._lock:
            try:
                return self._metrics[n]
            except KeyError as exc:
                raise MetricError(f"unknown metric: {n}") from exc

    def snapshot_all(self) -> Tuple[MetricSnapshot, ...]:
        with self._lock:
            metrics = list(self._metrics.values())
        return tuple(m.snapshot() for m in metrics)
