# agent_mash/core/contracts.py
from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import hashlib
import json
import re
import typing as t
import uuid

__all__ = [
    # Errors
    "ContractError",
    "ValidationError",
    "SerializationError",
    # Helpers
    "utc_now",
    "is_utc",
    "canonical_json_dumps",
    "sha256_hex",
    "new_id",
    "new_correlation_id",
    # Enums
    "Severity",
    "WorkStatus",
    "Decision",
    "PacketKind",
    # Core contracts
    "EnvelopeMeta",
    "Envelope",
    "WorkItem",
    "WorkResult",
    "DecisionPacket",
    "AuditRecord",
    "HealthPing",
    "HealthPong",
    # Typing
    "JSONValue",
    "JSONObject",
    "Headers",
]


# -------------------------
# Typing primitives
# -------------------------

JSONPrimitive = t.Union[str, int, float, bool, None]
JSONValue = t.Union[JSONPrimitive, t.List["JSONValue"], t.Dict[str, "JSONValue"]]
JSONObject = t.Dict[str, JSONValue]
Headers = t.Dict[str, str]


# -------------------------
# Errors
# -------------------------

class ContractError(RuntimeError):
    """Base class for contract-level failures."""


class ValidationError(ContractError):
    """Raised when a contract instance fails validation."""


class SerializationError(ContractError):
    """Raised when serialization/deserialization fails."""


# -------------------------
# Time helpers
# -------------------------

def utc_now() -> _dt.datetime:
    """Timezone-aware UTC now()."""
    return _dt.datetime.now(tz=_dt.timezone.utc)


def is_utc(dt: _dt.datetime) -> bool:
    """True iff dt is timezone-aware and UTC."""
    return dt.tzinfo is not None and dt.utcoffset() == _dt.timedelta(0)


def _ensure_utc(dt: _dt.datetime) -> _dt.datetime:
    if not is_utc(dt):
        raise ValidationError("datetime must be timezone-aware UTC")
    return dt


# -------------------------
# ID helpers
# -------------------------

_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]{7,127}$")


def new_id(prefix: str = "pkt") -> str:
    """
    Creates a stable, URL-safe identifier suitable for logs and routing keys.
    Example: pkt_2f3c9a1e7b0a4a6c9f0c8d9f5a3d2b1c
    """
    raw = uuid.uuid4().hex
    return f"{prefix}_{raw}"


def new_correlation_id() -> str:
    return new_id("corr")


def _validate_id(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    if not _ID_RE.match(value):
        raise ValidationError(f"{field} has invalid format: {value!r}")
    return value


# -------------------------
# Serialization helpers
# -------------------------

def canonical_json_dumps(obj: JSONValue) -> str:
    """
    Canonical JSON for hashing and signatures:
    - UTF-8 safe (ensure_ascii=False)
    - sorted keys
    - no whitespace
    """
    try:
        return json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as e:
        raise SerializationError(f"canonical_json_dumps failed: {e}") from e


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _dt_to_iso(dt: _dt.datetime) -> str:
    _ensure_utc(dt)
    # Ensure RFC3339-ish with 'Z'
    s = dt.isoformat(timespec="milliseconds")
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s


def _iso_to_dt(value: str) -> _dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError("timestamp must be a non-empty string")
    try:
        # Accept Z suffix
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = _dt.datetime.fromisoformat(value)
    except ValueError as e:
        raise ValidationError(f"invalid timestamp format: {value!r}") from e
    return _ensure_utc(dt)


# -------------------------
# Enums
# -------------------------

class Severity(str, enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class WorkStatus(str, enum.Enum):
    ACCEPTED = "accepted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class Decision(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    DEFER = "defer"


class PacketKind(str, enum.Enum):
    WORK_ITEM = "work_item"
    WORK_RESULT = "work_result"
    DECISION = "decision"
    AUDIT = "audit"
    HEALTH_PING = "health_ping"
    HEALTH_PONG = "health_pong"


# -------------------------
# Pydantic compatibility (optional)
# -------------------------

_HAS_PYDANTIC_V2 = False
try:
    import pydantic  # type: ignore
    from pydantic import BaseModel as _PBaseModel  # type: ignore
    from pydantic import ConfigDict as _PConfigDict  # type: ignore

    # Detect v2 by presence of model_validate / model_dump
    _HAS_PYDANTIC_V2 = hasattr(_PBaseModel, "model_validate") and hasattr(_PBaseModel, "model_dump")
except Exception:  # pragma: no cover
    _HAS_PYDANTIC_V2 = False


# -------------------------
# Core dataclasses (dependency-free)
# -------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class EnvelopeMeta:
    """
    Metadata carried with every envelope to enable tracing, routing and audit.

    - id: unique packet id
    - kind: PacketKind
    - schema: schema identifier
    - schema_version: semantic-ish version string
    - created_at: UTC timestamp
    - correlation_id: ties together a workflow
    - causation_id: previous packet that caused this one
    - source: subsystem name (e.g. "routing", "lifecycle", "governance")
    - tenant_id / actor_id: optional multi-tenant identity and initiating principal
    - headers: additional routing hints (string->string)
    """
    id: str
    kind: PacketKind
    schema: str
    schema_version: str
    created_at: _dt.datetime
    correlation_id: str
    causation_id: t.Optional[str] = None
    source: str = "unknown"
    tenant_id: t.Optional[str] = None
    actor_id: t.Optional[str] = None
    headers: Headers = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.id, "meta.id")
        _validate_id(self.correlation_id, "meta.correlation_id")
        if self.causation_id is not None:
            _validate_id(self.causation_id, "meta.causation_id")

        if not isinstance(self.schema, str) or not self.schema:
            raise ValidationError("meta.schema must be a non-empty string")
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise ValidationError("meta.schema_version must be a non-empty string")

        if not isinstance(self.source, str) or not self.source:
            raise ValidationError("meta.source must be a non-empty string")

        _ensure_utc(self.created_at)

        if self.tenant_id is not None:
            _validate_id(self.tenant_id, "meta.tenant_id")
        if self.actor_id is not None:
            _validate_id(self.actor_id, "meta.actor_id")

        if not isinstance(self.headers, dict):
            raise ValidationError("meta.headers must be a dict[str,str]")
        for k, v in self.headers.items():
            if not isinstance(k, str) or not k:
                raise ValidationError("meta.headers keys must be non-empty strings")
            if not isinstance(v, str):
                raise ValidationError("meta.headers values must be strings")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "id": self.id,
            "kind": self.kind.value,
            "schema": self.schema,
            "schema_version": self.schema_version,
            "created_at": _dt_to_iso(self.created_at),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "headers": dict(self.headers),
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "EnvelopeMeta":
        if not isinstance(data, dict):
            raise ValidationError("EnvelopeMeta.from_dict expects a dict")

        try:
            kind = PacketKind(str(data["kind"]))
        except Exception as e:
            raise ValidationError(f"invalid meta.kind: {data.get('kind')!r}") from e

        meta = EnvelopeMeta(
            id=str(data["id"]),
            kind=kind,
            schema=str(data["schema"]),
            schema_version=str(data["schema_version"]),
            created_at=_iso_to_dt(str(data["created_at"])),
            correlation_id=str(data["correlation_id"]),
            causation_id=(str(data["causation_id"]) if data.get("causation_id") is not None else None),
            source=str(data.get("source") or "unknown"),
            tenant_id=(str(data["tenant_id"]) if data.get("tenant_id") is not None else None),
            actor_id=(str(data["actor_id"]) if data.get("actor_id") is not None else None),
            headers=_coerce_headers(data.get("headers")),
        )
        meta.validate()
        return meta


def _coerce_headers(value: t.Any) -> Headers:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError("headers must be a dict[str,str]")
    out: Headers = {}
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            raise ValidationError("headers keys must be non-empty strings")
        if not isinstance(v, str):
            # Coerce common types safely to string
            if isinstance(v, (int, float, bool)):
                v = str(v)
            else:
                raise ValidationError("headers values must be strings")
        out[k] = v
    return out


@dataclasses.dataclass(frozen=True, slots=True)
class Envelope:
    """
    Universal transport envelope.

    digest is computed from canonical JSON of (meta + payload).
    signature is intentionally optional; signing belongs to security-core/identity-access-core.
    """
    meta: EnvelopeMeta
    payload: JSONObject
    digest: str
    signature: t.Optional[str] = None  # detached or inline signature (implementation-specific)

    def validate(self) -> None:
        if not isinstance(self.meta, EnvelopeMeta):
            raise ValidationError("envelope.meta must be EnvelopeMeta")
        self.meta.validate()

        if not isinstance(self.payload, dict):
            raise ValidationError("envelope.payload must be a dict")

        if not isinstance(self.digest, str) or not self.digest or not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise ValidationError("envelope.digest must be a 64-char hex sha256")

        expected = self.compute_digest(self.meta, self.payload)
        if self.digest != expected:
            raise ValidationError("envelope.digest mismatch (payload/meta integrity failed)")

        if self.signature is not None and not isinstance(self.signature, str):
            raise ValidationError("envelope.signature must be a string or None")

    @staticmethod
    def compute_digest(meta: EnvelopeMeta, payload: JSONObject) -> str:
        meta_dict = meta.to_dict()
        data: JSONObject = {"meta": meta_dict, "payload": payload}
        canonical = canonical_json_dumps(data)
        return sha256_hex(canonical)

    @staticmethod
    def create(
        *,
        kind: PacketKind,
        schema: str,
        schema_version: str,
        payload: JSONObject,
        source: str,
        correlation_id: t.Optional[str] = None,
        causation_id: t.Optional[str] = None,
        tenant_id: t.Optional[str] = None,
        actor_id: t.Optional[str] = None,
        headers: t.Optional[Headers] = None,
        packet_id: t.Optional[str] = None,
        created_at: t.Optional[_dt.datetime] = None,
        signature: t.Optional[str] = None,
    ) -> "Envelope":
        meta = EnvelopeMeta(
            id=_validate_id(packet_id or new_id("pkt"), "packet_id"),
            kind=kind,
            schema=schema,
            schema_version=schema_version,
            created_at=_ensure_utc(created_at or utc_now()),
            correlation_id=_validate_id(correlation_id or new_correlation_id(), "correlation_id"),
            causation_id=causation_id,
            source=source,
            tenant_id=tenant_id,
            actor_id=actor_id,
            headers=dict(headers or {}),
        )
        meta.validate()

        if not isinstance(payload, dict):
            raise ValidationError("payload must be a dict")

        digest = Envelope.compute_digest(meta, payload)
        env = Envelope(meta=meta, payload=payload, digest=digest, signature=signature)
        env.validate()
        return env

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "meta": self.meta.to_dict(),
            "payload": self.payload,
            "digest": self.digest,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "Envelope":
        if not isinstance(data, dict):
            raise ValidationError("Envelope.from_dict expects a dict")
        meta = EnvelopeMeta.from_dict(t.cast(dict, data.get("meta")))
        payload = data.get("payload")
        if not isinstance(payload, dict):
            raise ValidationError("Envelope.payload must be a dict")
        digest = str(data.get("digest") or "")
        signature = data.get("signature")
        env = Envelope(meta=meta, payload=t.cast(JSONObject, payload), digest=digest, signature=signature)
        env.validate()
        return env

    def to_json(self) -> str:
        return canonical_json_dumps(self.to_dict())


# -------------------------
# Domain contracts
# -------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class WorkItem:
    """
    Represents a unit of work assigned to an agent/worker.
    """
    work_id: str
    task_type: str
    params: JSONObject
    priority: int = 100
    deadline_at: t.Optional[_dt.datetime] = None
    idempotency_key: t.Optional[str] = None

    def validate(self) -> None:
        _validate_id(self.work_id, "work_id")
        if not isinstance(self.task_type, str) or not self.task_type:
            raise ValidationError("task_type must be a non-empty string")
        if not isinstance(self.params, dict):
            raise ValidationError("params must be a dict")
        if not isinstance(self.priority, int) or not (0 <= self.priority <= 1000):
            raise ValidationError("priority must be int in [0..1000]")
        if self.deadline_at is not None:
            _ensure_utc(self.deadline_at)
        if self.idempotency_key is not None:
            if not isinstance(self.idempotency_key, str) or not self.idempotency_key:
                raise ValidationError("idempotency_key must be a non-empty string or None")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "work_id": self.work_id,
            "task_type": self.task_type,
            "params": self.params,
            "priority": self.priority,
            "deadline_at": (_dt_to_iso(self.deadline_at) if self.deadline_at is not None else None),
            "idempotency_key": self.idempotency_key,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "WorkItem":
        if not isinstance(data, dict):
            raise ValidationError("WorkItem.from_dict expects a dict")
        deadline = data.get("deadline_at")
        item = WorkItem(
            work_id=str(data["work_id"]),
            task_type=str(data["task_type"]),
            params=t.cast(JSONObject, data.get("params") or {}),
            priority=int(data.get("priority", 100)),
            deadline_at=(_iso_to_dt(str(deadline)) if deadline is not None else None),
            idempotency_key=(str(data["idempotency_key"]) if data.get("idempotency_key") is not None else None),
        )
        item.validate()
        return item


@dataclasses.dataclass(frozen=True, slots=True)
class WorkResult:
    """
    Result of a WorkItem execution.
    """
    work_id: str
    status: WorkStatus
    output: JSONObject = dataclasses.field(default_factory=dict)
    error_code: t.Optional[str] = None
    error_message: t.Optional[str] = None
    started_at: t.Optional[_dt.datetime] = None
    finished_at: t.Optional[_dt.datetime] = None
    metrics: JSONObject = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.work_id, "work_id")
        if not isinstance(self.status, WorkStatus):
            raise ValidationError("status must be WorkStatus")
        if not isinstance(self.output, dict):
            raise ValidationError("output must be a dict")
        if self.error_code is not None and (not isinstance(self.error_code, str) or not self.error_code):
            raise ValidationError("error_code must be a non-empty string or None")
        if self.error_message is not None and (not isinstance(self.error_message, str) or not self.error_message):
            raise ValidationError("error_message must be a non-empty string or None")
        if self.started_at is not None:
            _ensure_utc(self.started_at)
        if self.finished_at is not None:
            _ensure_utc(self.finished_at)
        if self.started_at is not None and self.finished_at is not None:
            if self.finished_at < self.started_at:
                raise ValidationError("finished_at must be >= started_at")
        if not isinstance(self.metrics, dict):
            raise ValidationError("metrics must be a dict")

        # Consistency rules
        if self.status in (WorkStatus.FAILED, WorkStatus.REJECTED, WorkStatus.TIMEOUT) and not self.error_message:
            # allow error_code-only in rare cases, but error_message is recommended
            pass

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "work_id": self.work_id,
            "status": self.status.value,
            "output": self.output,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "started_at": (_dt_to_iso(self.started_at) if self.started_at is not None else None),
            "finished_at": (_dt_to_iso(self.finished_at) if self.finished_at is not None else None),
            "metrics": self.metrics,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "WorkResult":
        if not isinstance(data, dict):
            raise ValidationError("WorkResult.from_dict expects a dict")
        try:
            status = WorkStatus(str(data["status"]))
        except Exception as e:
            raise ValidationError(f"invalid status: {data.get('status')!r}") from e

        started = data.get("started_at")
        finished = data.get("finished_at")

        res = WorkResult(
            work_id=str(data["work_id"]),
            status=status,
            output=t.cast(JSONObject, data.get("output") or {}),
            error_code=(str(data["error_code"]) if data.get("error_code") is not None else None),
            error_message=(str(data["error_message"]) if data.get("error_message") is not None else None),
            started_at=(_iso_to_dt(str(started)) if started is not None else None),
            finished_at=(_iso_to_dt(str(finished)) if finished is not None else None),
            metrics=t.cast(JSONObject, data.get("metrics") or {}),
        )
        res.validate()
        return res


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionPacket:
    """
    Governance/Policy decision for a work item or action.
    """
    decision_id: str
    decision: Decision
    subject_id: str
    reason: str
    severity: Severity = Severity.INFO
    policy_ref: t.Optional[str] = None
    evidence: JSONObject = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.decision_id, "decision_id")
        _validate_id(self.subject_id, "subject_id")
        if not isinstance(self.decision, Decision):
            raise ValidationError("decision must be Decision enum")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValidationError("reason must be a non-empty string")
        if not isinstance(self.severity, Severity):
            raise ValidationError("severity must be Severity enum")
        if self.policy_ref is not None and (not isinstance(self.policy_ref, str) or not self.policy_ref):
            raise ValidationError("policy_ref must be a non-empty string or None")
        if not isinstance(self.evidence, dict):
            raise ValidationError("evidence must be a dict")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "decision_id": self.decision_id,
            "decision": self.decision.value,
            "subject_id": self.subject_id,
            "reason": self.reason,
            "severity": self.severity.value,
            "policy_ref": self.policy_ref,
            "evidence": self.evidence,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "DecisionPacket":
        if not isinstance(data, dict):
            raise ValidationError("DecisionPacket.from_dict expects a dict")
        try:
            decision = Decision(str(data["decision"]))
        except Exception as e:
            raise ValidationError(f"invalid decision: {data.get('decision')!r}") from e
        try:
            severity = Severity(str(data.get("severity", Severity.INFO.value)))
        except Exception as e:
            raise ValidationError(f"invalid severity: {data.get('severity')!r}") from e

        pkt = DecisionPacket(
            decision_id=str(data["decision_id"]),
            decision=decision,
            subject_id=str(data["subject_id"]),
            reason=str(data["reason"]),
            severity=severity,
            policy_ref=(str(data["policy_ref"]) if data.get("policy_ref") is not None else None),
            evidence=t.cast(JSONObject, data.get("evidence") or {}),
        )
        pkt.validate()
        return pkt


@dataclasses.dataclass(frozen=True, slots=True)
class AuditRecord:
    """
    Minimal audit record suitable for append-only sinks.
    """
    audit_id: str
    at: _dt.datetime
    severity: Severity
    action: str
    subject_id: t.Optional[str] = None
    correlation_id: t.Optional[str] = None
    envelope_digest: t.Optional[str] = None
    details: JSONObject = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.audit_id, "audit_id")
        _ensure_utc(self.at)
        if not isinstance(self.severity, Severity):
            raise ValidationError("severity must be Severity enum")
        if not isinstance(self.action, str) or not self.action:
            raise ValidationError("action must be a non-empty string")

        if self.subject_id is not None:
            _validate_id(self.subject_id, "subject_id")
        if self.correlation_id is not None:
            _validate_id(self.correlation_id, "correlation_id")

        if self.envelope_digest is not None:
            if not isinstance(self.envelope_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.envelope_digest):
                raise ValidationError("envelope_digest must be sha256 hex or None")

        if not isinstance(self.details, dict):
            raise ValidationError("details must be a dict")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "audit_id": self.audit_id,
            "at": _dt_to_iso(self.at),
            "severity": self.severity.value,
            "action": self.action,
            "subject_id": self.subject_id,
            "correlation_id": self.correlation_id,
            "envelope_digest": self.envelope_digest,
            "details": self.details,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "AuditRecord":
        if not isinstance(data, dict):
            raise ValidationError("AuditRecord.from_dict expects a dict")
        try:
            severity = Severity(str(data["severity"]))
        except Exception as e:
            raise ValidationError(f"invalid severity: {data.get('severity')!r}") from e

        rec = AuditRecord(
            audit_id=str(data["audit_id"]),
            at=_iso_to_dt(str(data["at"])),
            severity=severity,
            action=str(data["action"]),
            subject_id=(str(data["subject_id"]) if data.get("subject_id") is not None else None),
            correlation_id=(str(data["correlation_id"]) if data.get("correlation_id") is not None else None),
            envelope_digest=(str(data["envelope_digest"]) if data.get("envelope_digest") is not None else None),
            details=t.cast(JSONObject, data.get("details") or {}),
        )
        rec.validate()
        return rec


@dataclasses.dataclass(frozen=True, slots=True)
class HealthPing:
    ping_id: str
    at: _dt.datetime
    source: str
    details: JSONObject = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.ping_id, "ping_id")
        _ensure_utc(self.at)
        if not isinstance(self.source, str) or not self.source:
            raise ValidationError("source must be a non-empty string")
        if not isinstance(self.details, dict):
            raise ValidationError("details must be a dict")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {"ping_id": self.ping_id, "at": _dt_to_iso(self.at), "source": self.source, "details": self.details}

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "HealthPing":
        if not isinstance(data, dict):
            raise ValidationError("HealthPing.from_dict expects a dict")
        pkt = HealthPing(
            ping_id=str(data["ping_id"]),
            at=_iso_to_dt(str(data["at"])),
            source=str(data["source"]),
            details=t.cast(JSONObject, data.get("details") or {}),
        )
        pkt.validate()
        return pkt


@dataclasses.dataclass(frozen=True, slots=True)
class HealthPong:
    ping_id: str
    pong_id: str
    at: _dt.datetime
    ok: bool
    node: str
    details: JSONObject = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        _validate_id(self.ping_id, "ping_id")
        _validate_id(self.pong_id, "pong_id")
        _ensure_utc(self.at)
        if not isinstance(self.ok, bool):
            raise ValidationError("ok must be bool")
        if not isinstance(self.node, str) or not self.node:
            raise ValidationError("node must be a non-empty string")
        if not isinstance(self.details, dict):
            raise ValidationError("details must be a dict")

    def to_dict(self) -> JSONObject:
        self.validate()
        return {
            "ping_id": self.ping_id,
            "pong_id": self.pong_id,
            "at": _dt_to_iso(self.at),
            "ok": self.ok,
            "node": self.node,
            "details": self.details,
        }

    @staticmethod
    def from_dict(data: t.Mapping[str, t.Any]) -> "HealthPong":
        if not isinstance(data, dict):
            raise ValidationError("HealthPong.from_dict expects a dict")
        pkt = HealthPong(
            ping_id=str(data["ping_id"]),
            pong_id=str(data["pong_id"]),
            at=_iso_to_dt(str(data["at"])),
            ok=bool(data["ok"]),
            node=str(data["node"]),
            details=t.cast(JSONObject, data.get("details") or {}),
        )
        pkt.validate()
        return pkt


# -------------------------
# Optional pydantic mirror models (v2 only)
# -------------------------

if _HAS_PYDANTIC_V2:
    class PEnvelopeMeta(_PBaseModel):  # pragma: no cover
        model_config = _PConfigDict(extra="forbid", frozen=True)

        id: str
        kind: PacketKind
        schema: str
        schema_version: str
        created_at: _dt.datetime
        correlation_id: str
        causation_id: t.Optional[str] = None
        source: str = "unknown"
        tenant_id: t.Optional[str] = None
        actor_id: t.Optional[str] = None
        headers: Headers = {}

        def to_dc(self) -> EnvelopeMeta:
            return EnvelopeMeta(
                id=self.id,
                kind=self.kind,
                schema=self.schema,
                schema_version=self.schema_version,
                created_at=_ensure_utc(self.created_at),
                correlation_id=self.correlation_id,
                causation_id=self.causation_id,
                source=self.source,
                tenant_id=self.tenant_id,
                actor_id=self.actor_id,
                headers=dict(self.headers or {}),
            )

    class PEnvelope(_PBaseModel):  # pragma: no cover
        model_config = _PConfigDict(extra="forbid", frozen=True)

        meta: PEnvelopeMeta
        payload: JSONObject
        digest: str
        signature: t.Optional[str] = None

        def to_dc(self) -> Envelope:
            return Envelope(
                meta=self.meta.to_dc(),
                payload=dict(self.payload),
                digest=self.digest,
                signature=self.signature,
            )


# -------------------------
# Schema constants
# -------------------------

SCHEMA_ENVELOPE = "agent_mash.envelope"
SCHEMA_WORK_ITEM = "agent_mash.work_item"
SCHEMA_WORK_RESULT = "agent_mash.work_result"
SCHEMA_DECISION = "agent_mash.decision"
SCHEMA_AUDIT = "agent_mash.audit"
SCHEMA_HEALTH_PING = "agent_mash.health_ping"
SCHEMA_HEALTH_PONG = "agent_mash.health_pong"

SCHEMA_VERSION_V1 = "1.0.0"


# -------------------------
# Envelope factories
# -------------------------

def envelope_for_work_item(
    item: WorkItem,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    tenant_id: t.Optional[str] = None,
    actor_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    item.validate()
    return Envelope.create(
        kind=PacketKind.WORK_ITEM,
        schema=SCHEMA_WORK_ITEM,
        schema_version=SCHEMA_VERSION_V1,
        payload=item.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        tenant_id=tenant_id,
        actor_id=actor_id,
        headers=headers,
    )


def envelope_for_work_result(
    result: WorkResult,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    tenant_id: t.Optional[str] = None,
    actor_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    result.validate()
    return Envelope.create(
        kind=PacketKind.WORK_RESULT,
        schema=SCHEMA_WORK_RESULT,
        schema_version=SCHEMA_VERSION_V1,
        payload=result.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        tenant_id=tenant_id,
        actor_id=actor_id,
        headers=headers,
    )


def envelope_for_decision(
    decision: DecisionPacket,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    tenant_id: t.Optional[str] = None,
    actor_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    decision.validate()
    return Envelope.create(
        kind=PacketKind.DECISION,
        schema=SCHEMA_DECISION,
        schema_version=SCHEMA_VERSION_V1,
        payload=decision.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        tenant_id=tenant_id,
        actor_id=actor_id,
        headers=headers,
    )


def envelope_for_audit(
    record: AuditRecord,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    tenant_id: t.Optional[str] = None,
    actor_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    record.validate()
    return Envelope.create(
        kind=PacketKind.AUDIT,
        schema=SCHEMA_AUDIT,
        schema_version=SCHEMA_VERSION_V1,
        payload=record.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        tenant_id=tenant_id,
        actor_id=actor_id,
        headers=headers,
    )


def envelope_for_health_ping(
    ping: HealthPing,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    ping.validate()
    return Envelope.create(
        kind=PacketKind.HEALTH_PING,
        schema=SCHEMA_HEALTH_PING,
        schema_version=SCHEMA_VERSION_V1,
        payload=ping.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        headers=headers,
    )


def envelope_for_health_pong(
    pong: HealthPong,
    *,
    source: str,
    correlation_id: t.Optional[str] = None,
    causation_id: t.Optional[str] = None,
    headers: t.Optional[Headers] = None,
) -> Envelope:
    pong.validate()
    return Envelope.create(
        kind=PacketKind.HEALTH_PONG,
        schema=SCHEMA_HEALTH_PONG,
        schema_version=SCHEMA_VERSION_V1,
        payload=pong.to_dict(),
        source=source,
        correlation_id=correlation_id,
        causation_id=causation_id,
        headers=headers,
    )
