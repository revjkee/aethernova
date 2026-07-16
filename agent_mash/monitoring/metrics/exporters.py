# agent_mash/monitoring/metrics/exporters.py
from __future__ import annotations

import dataclasses
import enum
import threading
import time
import typing as t
import re
import json
import math

__all__ = [
    "MetricError",
    "MetricValidationError",
    "MetricType",
    "Metric",
    "MetricSample",
    "MetricSnapshot",
    "MetricRegistry",
    "MetricsExporter",
    "PrometheusTextExporter",
    "JsonExporter",
]


# =========================
# Errors
# =========================

class MetricError(RuntimeError):
    """Base monitoring metrics error."""


class MetricValidationError(MetricError):
    """Raised when metric validation fails."""


# =========================
# Metric types
# =========================

class MetricType(str, enum.Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


# =========================
# Helpers
# =========================

_METRIC_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_metric_name(name: str) -> None:
    if not isinstance(name, str) or not _METRIC_NAME_RE.match(name):
        raise MetricValidationError(f"invalid metric name: {name}")


def _validate_labels(labels: dict[str, str]) -> None:
    for k, v in labels.items():
        if not isinstance(k, str) or not _LABEL_NAME_RE.match(k):
            raise MetricValidationError(f"invalid label name: {k}")
        if not isinstance(v, str):
            raise MetricValidationError(f"label value must be string: {k}")


def _now() -> float:
    return time.time()


# =========================
# Metric model
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class Metric:
    name: str
    type: MetricType
    description: str = ""

    def validate(self) -> None:
        _validate_metric_name(self.name)
        if not isinstance(self.type, MetricType):
            raise MetricValidationError("invalid metric type")
        if not isinstance(self.description, str):
            raise MetricValidationError("description must be string")


@dataclasses.dataclass(frozen=True, slots=True)
class MetricSample:
    metric: Metric
    value: float
    labels: dict[str, str]
    timestamp: float

    def validate(self) -> None:
        self.metric.validate()

        if not isinstance(self.value, (int, float)) or math.isnan(self.value):
            raise MetricValidationError("metric value must be numeric and not NaN")

        if not isinstance(self.timestamp, (int, float)) or self.timestamp <= 0:
            raise MetricValidationError("timestamp must be positive number")

        if not isinstance(self.labels, dict):
            raise MetricValidationError("labels must be dict[str,str]")
        _validate_labels(self.labels)


# =========================
# Snapshot
# =========================

@dataclasses.dataclass(frozen=True, slots=True)
class MetricSnapshot:
    """
    Immutable snapshot of all collected metrics at a moment in time.
    """
    collected_at: float
    samples: tuple[MetricSample, ...]

    def validate(self) -> None:
        if not isinstance(self.collected_at, (int, float)):
            raise MetricValidationError("collected_at must be numeric timestamp")
        for s in self.samples:
            s.validate()


# =========================
# Registry
# =========================

class MetricRegistry:
    """
    Thread-safe registry for metrics.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._samples: list[MetricSample] = []

    def record(
        self,
        *,
        metric: Metric,
        value: float,
        labels: dict[str, str] | None = None,
        timestamp: float | None = None,
    ) -> None:
        if labels is None:
            labels = {}
        if timestamp is None:
            timestamp = _now()

        sample = MetricSample(
            metric=metric,
            value=float(value),
            labels=dict(labels),
            timestamp=float(timestamp),
        )
        sample.validate()

        with self._lock:
            self._samples.append(sample)

    def snapshot(self) -> MetricSnapshot:
        with self._lock:
            snap = MetricSnapshot(
                collected_at=_now(),
                samples=tuple(self._samples),
            )
            self._samples.clear()

        snap.validate()
        return snap


# =========================
# Exporters
# =========================

class MetricsExporter(t.Protocol):
    """
    Exporter contract.
    """

    def export(self, snapshot: MetricSnapshot) -> t.Any: ...


# -------------------------
# Prometheus text exporter
# -------------------------

class PrometheusTextExporter:
    """
    Exports metrics in Prometheus text exposition format.

    Reference:
    Prometheus exposition format specification.
    https://prometheus.io/docs/instrumenting/exposition_formats/
    """

    def export(self, snapshot: MetricSnapshot) -> str:
        snapshot.validate()

        lines: list[str] = []
        seen: set[str] = set()

        for sample in snapshot.samples:
            m = sample.metric
            if m.name not in seen:
                seen.add(m.name)
                lines.append(f"# HELP {m.name} {m.description}")
                lines.append(f"# TYPE {m.name} {m.type.value}")

            label_str = ""
            if sample.labels:
                parts = [f'{k}="{v}"' for k, v in sorted(sample.labels.items())]
                label_str = "{" + ",".join(parts) + "}"

            lines.append(
                f"{m.name}{label_str} {sample.value} {int(sample.timestamp * 1000)}"
            )

        return "\n".join(lines) + "\n"


# -------------------------
# JSON exporter
# -------------------------

class JsonExporter:
    """
    Exports metrics snapshot as structured JSON.
    Useful for push-based pipelines or logging.
    """

    def export(self, snapshot: MetricSnapshot) -> str:
        snapshot.validate()

        payload = {
            "collected_at": snapshot.collected_at,
            "samples": [
                {
                    "name": s.metric.name,
                    "type": s.metric.type.value,
                    "description": s.metric.description,
                    "value": s.value,
                    "labels": dict(s.labels),
                    "timestamp": s.timestamp,
                }
                for s in snapshot.samples
            ],
        }

        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
