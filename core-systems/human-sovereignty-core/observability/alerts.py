# human-sovereignty-core/observability/alerts.py
from __future__ import annotations

import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

__all__ = [
    "AlertSeverity",
    "AlertStatus",
    "Alert",
    "AlertPolicy",
    "AlertEvent",
    "AlertSink",
    "AlertStore",
    "InMemoryAlertStore",
    "AlertEngine",
]


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    severity: AlertSeverity
    source: str
    message: str
    created_unix: int
    status: AlertStatus
    fingerprint: str
    labels: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AlertPolicy:
    dedup_window_seconds: int = 300
    suppression_window_seconds: int = 120
    escalation_after_seconds: int = 600
    fail_closed: bool = True

    def validate(self) -> None:
        if self.dedup_window_seconds <= 0:
            raise ValueError("dedup_window_seconds must be positive")
        if self.suppression_window_seconds < 0:
            raise ValueError("suppression_window_seconds must be >= 0")
        if self.escalation_after_seconds <= 0:
            raise ValueError("escalation_after_seconds must be positive")


@dataclass(frozen=True, slots=True)
class AlertEvent:
    ts_unix: int
    alert_id: str
    severity: AlertSeverity
    status: AlertStatus
    message: str
    fields: Mapping[str, Any] = field(default_factory=dict)


class AlertSink(Protocol):
    async def emit(self, event: AlertEvent) -> None: ...


class AlertStore(Protocol):
    async def get_by_fingerprint(self, fingerprint: str) -> Optional[Alert]: ...
    async def save(self, alert: Alert) -> None: ...
    async def update_status(self, alert_id: str, status: AlertStatus) -> None: ...
    async def list_open(self) -> Iterable[Alert]: ...


def _now_unix() -> int:
    return int(time.time())


def _fingerprint(source: str, message: str, labels: Mapping[str, str]) -> str:
    h = hashlib.sha256()
    h.update(source.encode("utf-8"))
    h.update(message.encode("utf-8"))
    for k in sorted(labels.keys()):
        h.update(k.encode("utf-8"))
        h.update(labels[k].encode("utf-8"))
    return h.hexdigest()


class InMemoryAlertStore:
    def __init__(self) -> None:
        self._alerts: Dict[str, Alert] = {}
        self._by_fingerprint: Dict[str, str] = {}

    async def get_by_fingerprint(self, fingerprint: str) -> Optional[Alert]:
        alert_id = self._by_fingerprint.get(fingerprint)
        if alert_id is None:
            return None
        return self._alerts.get(alert_id)

    async def save(self, alert: Alert) -> None:
        self._alerts[alert.id] = alert
        self._by_fingerprint[alert.fingerprint] = alert.id

    async def update_status(self, alert_id: str, status: AlertStatus) -> None:
        alert = self._alerts.get(alert_id)
        if alert is None:
            return
        self._alerts[alert_id] = Alert(
            id=alert.id,
            severity=alert.severity,
            source=alert.source,
            message=alert.message,
            created_unix=alert.created_unix,
            status=status,
            fingerprint=alert.fingerprint,
            labels=alert.labels,
            metadata=alert.metadata,
        )

    async def list_open(self) -> Iterable[Alert]:
        return [a for a in self._alerts.values() if a.status == AlertStatus.OPEN]


class AlertEngine:
    def __init__(
        self,
        *,
        store: AlertStore,
        sinks: Iterable[AlertSink],
        policy: Optional[AlertPolicy] = None,
    ) -> None:
        self._store = store
        self._sinks = list(sinks)
        self._policy = policy or AlertPolicy()
        self._policy.validate()

    async def emit(
        self,
        *,
        severity: AlertSeverity,
        source: str,
        message: str,
        labels: Optional[Mapping[str, str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Alert:
        labels = labels or {}
        metadata = metadata or {}
        now = _now_unix()

        fp = _fingerprint(source, message, labels)
        existing = await self._store.get_by_fingerprint(fp)

        if existing:
            age = now - existing.created_unix
            if age <= self._policy.dedup_window_seconds:
                return existing

        alert = Alert(
            id=fp[:16],
            severity=severity,
            source=source,
            message=message,
            created_unix=now,
            status=AlertStatus.OPEN,
            fingerprint=fp,
            labels=dict(labels),
            metadata=dict(metadata),
        )

        await self._store.save(alert)

        event = AlertEvent(
            ts_unix=now,
            alert_id=alert.id,
            severity=alert.severity,
            status=alert.status,
            message=alert.message,
            fields={
                "source": alert.source,
                "labels": alert.labels,
                "metadata": alert.metadata,
            },
        )

        for sink in self._sinks:
            await sink.emit(event)

        return alert

    async def acknowledge(self, alert_id: str) -> None:
        await self._store.update_status(alert_id, AlertStatus.ACKNOWLEDGED)

    async def resolve(self, alert_id: str) -> None:
        await self._store.update_status(alert_id, AlertStatus.RESOLVED)
