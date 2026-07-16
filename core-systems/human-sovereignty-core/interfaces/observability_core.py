# human-sovereignty-core/interfaces/observability_core.py
from __future__ import annotations

import abc
import dataclasses
import datetime as _dt
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, runtime_checkable


_TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now_z() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).strftime(_TIME_FMT)


# =========================
# Enumerations (as constants)
# =========================

OBS_EVENT_LEVEL_INFO = "INFO"
OBS_EVENT_LEVEL_WARNING = "WARNING"
OBS_EVENT_LEVEL_ERROR = "ERROR"
OBS_EVENT_LEVEL_CRITICAL = "CRITICAL"

OBS_EVENT_KIND_METRIC = "METRIC"
OBS_EVENT_KIND_EVENT = "EVENT"
OBS_EVENT_KIND_INCIDENT = "INCIDENT"


# =========================
# Data models
# =========================

@dataclass(frozen=True)
class ObservabilityEvent:
    """
    Canonical observability event.

    This structure is intentionally strict to ensure
    deterministic logging and audit compatibility.
    """
    kind: str
    level: str
    name: str
    created_utc: str
    source: str
    message: str
    attributes: Dict[str, Any]
    correlation_id: Optional[str] = None
    decision_id: Optional[str] = None
    anchor_id: Optional[str] = None


@dataclass(frozen=True)
class MetricPoint:
    """
    Single metric observation.
    """
    name: str
    value: float
    unit: str
    created_utc: str
    labels: Dict[str, str]


@dataclass(frozen=True)
class IncidentRecord:
    """
    High-severity incident representation.
    """
    incident_id: str
    created_utc: str
    severity: str
    summary: str
    details: Dict[str, Any]
    decision_id: Optional[str] = None
    anchor_id: Optional[str] = None


# =========================
# Validation helpers
# =========================

def _validate_event(ev: ObservabilityEvent) -> None:
    if ev.kind not in {OBS_EVENT_KIND_EVENT, OBS_EVENT_KIND_METRIC, OBS_EVENT_KIND_INCIDENT}:
        raise ValueError(f"Invalid event kind: {ev.kind}")
    if ev.level not in {
        OBS_EVENT_LEVEL_INFO,
        OBS_EVENT_LEVEL_WARNING,
        OBS_EVENT_LEVEL_ERROR,
        OBS_EVENT_LEVEL_CRITICAL,
    }:
        raise ValueError(f"Invalid event level: {ev.level}")
    if not ev.name or not isinstance(ev.name, str):
        raise ValueError("Event name must be non-empty string")
    if not ev.source or not isinstance(ev.source, str):
        raise ValueError("Event source must be non-empty string")
    if not isinstance(ev.attributes, dict):
        raise ValueError("Event attributes must be a dict")


def _validate_metric(mp: MetricPoint) -> None:
    if not mp.name or not isinstance(mp.name, str):
        raise ValueError("Metric name must be non-empty string")
    if not isinstance(mp.value, (int, float)):
        raise ValueError("Metric value must be numeric")
    if not isinstance(mp.unit, str):
        raise ValueError("Metric unit must be string")
    if not isinstance(mp.labels, dict):
        raise ValueError("Metric labels must be dict")


def _validate_incident(ir: IncidentRecord) -> None:
    if not ir.incident_id or not isinstance(ir.incident_id, str):
        raise ValueError("Incident id must be non-empty string")
    if not ir.summary or not isinstance(ir.summary, str):
        raise ValueError("Incident summary must be non-empty string")
    if not isinstance(ir.details, dict):
        raise ValueError("Incident details must be dict")


# =========================
# Observability interface
# =========================

class ObservabilityCore(abc.ABC):
    """
    Abstract observability core interface.

    All system components MUST depend on this interface only.
    Concrete implementations may forward data to logs, metrics
    backends, tracing systems or audit stores.
    """

    @abc.abstractmethod
    def emit_event(self, event: ObservabilityEvent) -> None:
        """
        Emit a generic observability event.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def emit_metric(self, metric: MetricPoint) -> None:
        """
        Emit a single metric point.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def emit_incident(self, incident: IncidentRecord) -> None:
        """
        Emit a high-severity incident.
        """
        raise NotImplementedError


# =========================
# No-op reference implementation
# =========================

class NullObservabilityCore(ObservabilityCore):
    """
    Safe default implementation.

    Performs full validation but does not persist or export data.
    Useful for tests and for explicitly disabling observability.
    """

    def emit_event(self, event: ObservabilityEvent) -> None:
        _validate_event(event)

    def emit_metric(self, metric: MetricPoint) -> None:
        _validate_metric(metric)

    def emit_incident(self, incident: IncidentRecord) -> None:
        _validate_incident(incident)


# =========================
# Factory helpers
# =========================

def make_event(
    *,
    kind: str,
    level: str,
    name: str,
    source: str,
    message: str,
    attributes: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    decision_id: Optional[str] = None,
    anchor_id: Optional[str] = None,
) -> ObservabilityEvent:
    return ObservabilityEvent(
        kind=kind,
        level=level,
        name=name,
        created_utc=_utc_now_z(),
        source=source,
        message=message,
        attributes=attributes or {},
        correlation_id=correlation_id,
        decision_id=decision_id,
        anchor_id=anchor_id,
    )


def make_metric(
    *,
    name: str,
    value: float,
    unit: str,
    labels: Optional[Dict[str, str]] = None,
) -> MetricPoint:
    return MetricPoint(
        name=name,
        value=float(value),
        unit=unit,
        created_utc=_utc_now_z(),
        labels=labels or {},
    )


def make_incident(
    *,
    incident_id: str,
    severity: str,
    summary: str,
    details: Optional[Dict[str, Any]] = None,
    decision_id: Optional[str] = None,
    anchor_id: Optional[str] = None,
) -> IncidentRecord:
    return IncidentRecord(
        incident_id=incident_id,
        created_utc=_utc_now_z(),
        severity=severity,
        summary=summary,
        details=details or {},
        decision_id=decision_id,
        anchor_id=anchor_id,
    )
