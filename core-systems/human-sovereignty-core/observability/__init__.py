"""
Human Sovereignty Core – Observability module.

This package provides a backend-agnostic metrics foundation
for counters, gauges, and histograms.

No side effects on import.
"""

from .metrics import (
    MetricError,
    MetricType,
    MetricSnapshot,
    MetricRegistry,
    Counter,
    Gauge,
    Histogram,
)

__all__ = [
    "MetricError",
    "MetricType",
    "MetricSnapshot",
    "MetricRegistry",
    "Counter",
    "Gauge",
    "Histogram",
]
