# human-sovereignty-core/observability/security_events.py

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple


class SecurityEventError(Exception):
    """Base error for security events."""


class SecurityEventValidationError(SecurityEventError):
    """Raised when an event fails validation."""


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _safe_str(x: Any, limit: int) -> str:
    s = str(x) if x is not None else ""
    if len(s) > limit:
        return s[:limit] + "..."
    return s


@dataclass(frozen=True)
class SecurityContext:
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    environment: Optional[str] = None
    service: Optional[str] = None
    route: Optional[str] = None
    method: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        return {k: v for k, v in d.items() if v is not None}


class SecurityEventSink(Protocol):
    def emit(self, event: Mapping[str, Any]) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class SecurityEventPolicy:
    """
    Industrial constraints for security events.
    """

    max_text_len: int = 8192
    max_payload_bytes: int = 96_000
    max_tags: int = 64
    max_evidence_items: int = 256

    redact_enabled: bool = True
    redact_fields: Tuple[str, ...] = (
        "password",
        "pass",
        "secret",
        "token",
        "authorization",
        "private_key",
        "seed",
        "mnemonic",
        "api_key",
        "cookie",
        "set-cookie",
    )

    # Deduplication
    dedupe_ttl_seconds: int = 300

    # Event taxonomy constraints
    allowed_types: Tuple[str, ...] = (
        "auth.failure",
        "auth.lockout",
        "auth.mfa.failure",
        "csrf.block",
        "rate_limit.hit",
        "anomaly.detected",
        "anomaly.suspected",
    )
    allowed_severities: Tuple[str, ...] = ("info", "warning", "critical")


@dataclass(frozen=True)
class SecurityEvent:
    """
    Canonical security event.

    event_hash: sha256(canonical_json(event_without_hash))
    event_id: stable ID derived from canonical content for dedupe/forensics
    """

    event_id: str
    event_type: str
    severity: str
    created_at_utc: str
    title: str
    message: str
    context: SecurityContext = field(default_factory=SecurityContext)
    tags: Tuple[str, ...] = ()
    payload: Dict[str, Any] = field(default_factory=dict)
    evidence: Tuple[Dict[str, Any], ...] = ()
    event_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "created_at_utc": self.created_at_utc,
            "title": self.title,
            "message": self.message,
            "context": self.context.to_dict(),
            "tags": list(self.tags),
            "payload": dict(self.payload),
            "evidence": list(self.evidence),
        }
        if self.event_hash is not None:
            d["event_hash"] = self.event_hash
        return d

    def compute_hash(self) -> str:
        d = self.to_dict()
        d.pop("event_hash", None)
        return _sha256_hex(_canonical_json_bytes(d))


class InMemoryDedupe:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, float] = {}

    def seen(self, key: str, *, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            self._gc(now, ttl_seconds)
            if key in self._items:
                return True
            self._items[key] = now
            return False

    def _gc(self, now: float, ttl_seconds: int) -> None:
        expired = [k for k, ts in self._items.items() if (now - ts) > ttl_seconds]
        for k in expired:
            self._items.pop(k, None)


def _redact(obj: Any, *, policy: SecurityEventPolicy) -> Any:
    if not policy.redact_enabled:
        return obj

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in policy.redact_fields):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact(v, policy=policy)
        return out

    if isinstance(obj, list):
        return [_redact(x, policy=policy) for x in obj]

    if isinstance(obj, str):
        return _safe_str(obj, policy.max_text_len)

    return obj


def _validate_taxonomy(event_type: str, severity: str, *, policy: SecurityEventPolicy) -> None:
    if event_type not in policy.allowed_types:
        raise SecurityEventValidationError("Unsupported event_type")
    if severity not in policy.allowed_severities:
        raise SecurityEventValidationError("Unsupported severity")


def _normalize_tags(tags: Iterable[str], *, policy: SecurityEventPolicy) -> Tuple[str, ...]:
    out: List[str] = []
    for t in tags:
        if not isinstance(t, str):
            continue
        tt = t.strip()
        if not tt:
            continue
        if len(tt) > 128:
            tt = tt[:128]
        out.append(tt)
        if len(out) >= policy.max_tags:
            break
    return tuple(out)


def _stable_event_id(event_dict: Mapping[str, Any]) -> str:
    # stable identifier derived from canonical content
    digest = _sha256_hex(_canonical_json_bytes(event_dict))
    return f"sev_{digest[:24]}"


def _ensure_payload_size(event_dict: Mapping[str, Any], *, policy: SecurityEventPolicy) -> None:
    raw = _canonical_json_bytes(event_dict)
    if len(raw) > policy.max_payload_bytes:
        raise SecurityEventValidationError("Event payload too large")


@dataclass
class SecurityEvents:
    """
    Factory + emitter with dedupe.

    This module never approves actions; it only emits security observability events.
    """

    policy: SecurityEventPolicy = field(default_factory=SecurityEventPolicy)
    sink: Optional[SecurityEventSink] = None
    dedupe: InMemoryDedupe = field(default_factory=InMemoryDedupe)

    def emit(self, event: SecurityEvent) -> SecurityEvent:
        event_dict = event.to_dict()
        event_dict = _redact(event_dict, policy=self.policy)

        _validate_taxonomy(event.event_type, event.severity, policy=self.policy)
        _ensure_payload_size(event_dict, policy=self.policy)

        # event_id stabilization (if caller used random)
        if not isinstance(event_dict.get("event_id"), str) or not event_dict["event_id"]:
            event_dict["event_id"] = _stable_event_id(event_dict)

        # compute hash
        event_dict.pop("event_hash", None)
        event_hash = _sha256_hex(_canonical_json_bytes(event_dict))
        event_dict["event_hash"] = event_hash

        # dedupe based on event_hash
        if self.dedupe.seen(event_hash, ttl_seconds=self.policy.dedupe_ttl_seconds):
            # return as-is with hash (treated as emitted recently)
            return SecurityEvent(
                event_id=str(event_dict["event_id"]),
                event_type=str(event_dict["event_type"]),
                severity=str(event_dict["severity"]),
                created_at_utc=str(event_dict["created_at_utc"]),
                title=str(event_dict["title"]),
                message=str(event_dict["message"]),
                context=SecurityContext(**event_dict.get("context", {})),
                tags=tuple(event_dict.get("tags", [])),
                payload=dict(event_dict.get("payload", {})),
                evidence=tuple(event_dict.get("evidence", [])),
                event_hash=event_hash,
            )

        if self.sink is not None:
            self.sink.emit(event_dict)

        return SecurityEvent(
            event_id=str(event_dict["event_id"]),
            event_type=str(event_dict["event_type"]),
            severity=str(event_dict["severity"]),
            created_at_utc=str(event_dict["created_at_utc"]),
            title=str(event_dict["title"]),
            message=str(event_dict["message"]),
            context=SecurityContext(**event_dict.get("context", {})),
            tags=tuple(event_dict.get("tags", [])),
            payload=dict(event_dict.get("payload", {})),
            evidence=tuple(event_dict.get("evidence", [])),
            event_hash=event_hash,
        )

    def auth_failure(
        self,
        *,
        title: str = "Authentication failure",
        message: str,
        context: Optional[SecurityContext] = None,
        reason: Optional[str] = None,
        tags: Iterable[str] = (),
        payload: Optional[Mapping[str, Any]] = None,
    ) -> SecurityEvent:
        ctx = context or SecurityContext()
        ev = SecurityEvent(
            event_id=f"sev_{uuid.uuid4().hex}",
            event_type="auth.failure",
            severity="warning",
            created_at_utc=_iso(_utc_now()),
            title=_safe_str(title, self.policy.max_text_len),
            message=_safe_str(message, self.policy.max_text_len),
            context=ctx,
            tags=_normalize_tags(tags, policy=self.policy),
            payload=dict(payload or {}),
            evidence=(),
        )
        if reason is not None:
            ev.payload["reason"] = _safe_str(reason, self.policy.max_text_len)
        return self.emit(ev)

    def csrf_block(
        self,
        *,
        message: str,
        context: Optional[SecurityContext] = None,
        tags: Iterable[str] = (),
        payload: Optional[Mapping[str, Any]] = None,
    ) -> SecurityEvent:
        ctx = context or SecurityContext()
        ev = SecurityEvent(
            event_id=f"sev_{uuid.uuid4().hex}",
            event_type="csrf.block",
            severity="warning",
            created_at_utc=_iso(_utc_now()),
            title="CSRF blocked",
            message=_safe_str(message, self.policy.max_text_len),
            context=ctx,
            tags=_normalize_tags(tags, policy=self.policy),
            payload=dict(payload or {}),
            evidence=(),
        )
        return self.emit(ev)

    def rate_limit_hit(
        self,
        *,
        message: str,
        context: Optional[SecurityContext] = None,
        limit_name: Optional[str] = None,
        tags: Iterable[str] = (),
        payload: Optional[Mapping[str, Any]] = None,
    ) -> SecurityEvent:
        ctx = context or SecurityContext()
        ev = SecurityEvent(
            event_id=f"sev_{uuid.uuid4().hex}",
            event_type="rate_limit.hit",
            severity="info",
            created_at_utc=_iso(_utc_now()),
            title="Rate limit hit",
            message=_safe_str(message, self.policy.max_text_len),
            context=ctx,
            tags=_normalize_tags(tags, policy=self.policy),
            payload=dict(payload or {}),
            evidence=(),
        )
        if limit_name is not None:
            ev.payload["limit_name"] = _safe_str(limit_name, 256)
        return self.emit(ev)

    def anomaly_detected(
        self,
        *,
        message: str,
        severity: str = "critical",
        context: Optional[SecurityContext] = None,
        anomaly_type: Optional[str] = None,
        score: Optional[float] = None,
        tags: Iterable[str] = (),
        payload: Optional[Mapping[str, Any]] = None,
        evidence: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> SecurityEvent:
        if severity not in self.policy.allowed_severities:
            raise SecurityEventValidationError("Unsupported severity")

        ctx = context or SecurityContext()
        ev_evidence: List[Dict[str, Any]] = []
        if evidence is not None:
            for i, item in enumerate(evidence):
                if i >= self.policy.max_evidence_items:
                    break
                if isinstance(item, Mapping):
                    ev_evidence.append(dict(item))

        ev = SecurityEvent(
            event_id=f"sev_{uuid.uuid4().hex}",
            event_type="anomaly.detected" if severity == "critical" else "anomaly.suspected",
            severity=severity,
            created_at_utc=_iso(_utc_now()),
            title="Security anomaly",
            message=_safe_str(message, self.policy.max_text_len),
            context=ctx,
            tags=_normalize_tags(tags, policy=self.policy),
            payload=dict(payload or {}),
            evidence=tuple(ev_evidence),
        )
        if anomaly_type is not None:
            ev.payload["anomaly_type"] = _safe_str(anomaly_type, 256)
        if score is not None:
            if not isinstance(score, (int, float)):
                raise SecurityEventValidationError("score must be numeric")
            ev.payload["score"] = float(score)
        return self.emit(ev)


class StdoutJsonSink:
    def emit(self, event: Mapping[str, Any]) -> None:
        print(json.dumps(dict(event), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
