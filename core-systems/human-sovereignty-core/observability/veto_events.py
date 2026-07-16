# human-sovereignty-core/observability/veto_events.py
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID, uuid4

try:
    # pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
    _PYDANTIC_V2 = True
except Exception:  # pragma: no cover
    # pydantic v1 fallback
    from pydantic import BaseModel, Field, validator as field_validator, root_validator as model_validator  # type: ignore
    _PYDANTIC_V2 = False

try:
    from human_sovereignty_core.decision_packets.redaction import redact as redact_value  # type: ignore
except Exception:  # pragma: no cover
    redact_value = None  # type: ignore


JsonPrimitive = Union[str, int, float, bool, None]
JsonValue = Union[JsonPrimitive, List["JsonValue"], Dict[str, "JsonValue"]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:  # pragma: no cover
        return "<unprintable>"


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return _ensure_utc(obj).isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Mapping):
        return {str(k): _canonicalize(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(x) for x in obj]
    return obj


def _canonical_json_bytes(obj: Any) -> bytes:
    data = _canonicalize(obj)
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64url_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    # urlsafe base64 without padding
    import base64
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _redact(obj: Any) -> Any:
    if redact_value is None:
        return obj
    try:
        return redact_value(obj)
    except Exception:
        return obj


class VetoEventKind(str, Enum):
    VETO_RAISED = "veto_raised"
    VETO_CONFIRMED = "veto_confirmed"
    VETO_OVERRIDDEN = "veto_overridden"
    VETO_RELEASED = "veto_released"
    VETO_DENIED = "veto_denied"


class VetoScope(str, Enum):
    DECISION = "decision"
    EXECUTION = "execution"
    POLICY = "policy"
    ACTION = "action"


class VetoReasonCode(str, Enum):
    # safety / integrity
    SAFETY_RISK = "safety_risk"
    INTEGRITY_RISK = "integrity_risk"
    SECURITY_RISK = "security_risk"

    # governance / compliance
    POLICY_VIOLATION = "policy_violation"
    COMPLIANCE_REQUIREMENT = "compliance_requirement"
    DUAL_CONTROL_REQUIRED = "dual_control_required"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"

    # quality / correctness
    INSUFFICIENT_CONTEXT = "insufficient_context"
    LOW_CONFIDENCE = "low_confidence"
    CONTRADICTION_DETECTED = "contradiction_detected"
    UNVERIFIED_ASSUMPTION = "unverified_assumption"

    # operational
    MAINTENANCE_WINDOW = "maintenance_window"
    CHANGE_FREEZE = "change_freeze"
    EMERGENCY_MODE = "emergency_mode"

    # other
    OTHER = "other"


class ActorType(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"
    SYSTEM = "system"


class DecisionRef(BaseModel):
    decision_id: str = Field(..., min_length=1, max_length=256)
    packet_id: Optional[UUID] = Field(default=None)
    request_id: Optional[str] = Field(default=None, max_length=256)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", frozen=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            allow_mutation = False


class ExecutionRef(BaseModel):
    execution_id: str = Field(..., min_length=1, max_length=256)
    action_id: Optional[str] = Field(default=None, max_length=256)
    step_id: Optional[str] = Field(default=None, max_length=256)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", frozen=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            allow_mutation = False


class TraceContext(BaseModel):
    trace_id: Optional[str] = Field(default=None, max_length=128)
    span_id: Optional[str] = Field(default=None, max_length=128)
    correlation_id: Optional[str] = Field(default=None, max_length=256)
    causation_id: Optional[str] = Field(default=None, max_length=256)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", frozen=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            allow_mutation = False


class Actor(BaseModel):
    actor_id: str = Field(..., min_length=1, max_length=256)
    actor_type: ActorType = Field(default=ActorType.HUMAN)
    display_name: Optional[str] = Field(default=None, max_length=256)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    roles: List[str] = Field(default_factory=list)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", frozen=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            allow_mutation = False


class VetoReason(BaseModel):
    code: VetoReasonCode = Field(...)
    message: str = Field(default="", max_length=2048)
    details: Dict[str, JsonValue] = Field(default_factory=dict)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", frozen=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            allow_mutation = False


class VetoEvent(BaseModel):
    schema_version: str = Field(default="1.0.0", min_length=1, max_length=32)

    event_id: UUID = Field(default_factory=uuid4)
    kind: VetoEventKind = Field(...)
    scope: VetoScope = Field(default=VetoScope.DECISION)

    created_at: datetime = Field(default_factory=_utcnow)

    actor: Actor = Field(...)
    reason: VetoReason = Field(...)

    decision: Optional[DecisionRef] = Field(default=None)
    execution: Optional[ExecutionRef] = Field(default=None)

    status_before: Optional[str] = Field(default=None, max_length=128)
    status_after: Optional[str] = Field(default=None, max_length=128)

    # Минимизируем утечки: only-safe context for logs (redaction happens on export)
    context: Dict[str, JsonValue] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

    trace: TraceContext = Field(default_factory=TraceContext)

    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)
    else:  # pragma: no cover
        class Config:
            extra = "forbid"
            validate_assignment = True
            anystr_strip_whitespace = True

    if _PYDANTIC_V2:
        @field_validator("created_at")
        @classmethod
        def _v_created_at(cls, v: datetime) -> datetime:
            return _ensure_utc(v)
    else:  # pragma: no cover
        @field_validator("created_at")
        def _v_created_at(cls, v: datetime) -> datetime:
            return _ensure_utc(v)

    if _PYDANTIC_V2:
        @model_validator(mode="after")
        def _validate_refs(self) -> "VetoEvent":
            # At least one reference should be present depending on scope
            if self.scope in (VetoScope.DECISION, VetoScope.POLICY) and self.decision is None:
                raise ValueError("decision reference is required for scope=decision/policy")
            if self.scope in (VetoScope.EXECUTION, VetoScope.ACTION) and self.execution is None:
                raise ValueError("execution reference is required for scope=execution/action")
            return self
    else:  # pragma: no cover
        @model_validator
        def _validate_refs(cls, values: Dict[str, Any]) -> Dict[str, Any]:
            scope = values.get("scope")
            decision = values.get("decision")
            execution = values.get("execution")
            if scope in (VetoScope.DECISION, VetoScope.POLICY) and decision is None:
                raise ValueError("decision reference is required for scope=decision/policy")
            if scope in (VetoScope.EXECUTION, VetoScope.ACTION) and execution is None:
                raise ValueError("execution reference is required for scope=execution/action")
            return values

    def canonical_dict(self) -> Dict[str, Any]:
        if _PYDANTIC_V2:
            data = self.model_dump(mode="python")
        else:  # pragma: no cover
            data = self.dict()
        return _canonicalize(data)

    def content_hash(self) -> str:
        return _b64url_sha256(_canonical_json_bytes(self.canonical_dict()))

    def to_log_record(self, *, redact: bool = True) -> Dict[str, Any]:
        """
        Возвращает запись для логирования/экспорта.
        redact=True применяет редактирование секретов/PII для UI и логов.
        """
        if _PYDANTIC_V2:
            data = self.model_dump(mode="python")
        else:  # pragma: no cover
            data = self.dict()

        data["event_id"] = str(self.event_id)
        data["created_at"] = _ensure_utc(self.created_at).isoformat()
        data["content_hash"] = self.content_hash()

        if redact:
            data = _redact(data)

        return data

    def to_json(self, *, redact: bool = True) -> str:
        return json.dumps(self.to_log_record(redact=redact), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: Union[str, bytes]) -> "VetoEvent":
        if isinstance(raw, (bytes, bytearray)):
            obj = json.loads(raw.decode("utf-8"))
        else:
            obj = json.loads(raw)
        return cls.model_validate(obj) if _PYDANTIC_V2 else cls.parse_obj(obj)  # type: ignore


def build_veto_raised(
    *,
    actor: Actor,
    reason: VetoReason,
    decision_id: str,
    packet_id: Optional[UUID] = None,
    request_id: Optional[str] = None,
    status_before: Optional[str] = None,
    status_after: Optional[str] = None,
    context: Optional[Dict[str, JsonValue]] = None,
    tags: Optional[List[str]] = None,
    trace: Optional[TraceContext] = None,
) -> VetoEvent:
    return VetoEvent(
        kind=VetoEventKind.VETO_RAISED,
        scope=VetoScope.DECISION,
        actor=actor,
        reason=reason,
        decision=DecisionRef(decision_id=decision_id, packet_id=packet_id, request_id=request_id),
        status_before=status_before,
        status_after=status_after,
        context=context or {},
        tags=tags or [],
        trace=trace or TraceContext(),
    )


def build_veto_confirmed(
    *,
    actor: Actor,
    reason: VetoReason,
    decision_id: str,
    packet_id: Optional[UUID] = None,
    request_id: Optional[str] = None,
    context: Optional[Dict[str, JsonValue]] = None,
    tags: Optional[List[str]] = None,
    trace: Optional[TraceContext] = None,
) -> VetoEvent:
    return VetoEvent(
        kind=VetoEventKind.VETO_CONFIRMED,
        scope=VetoScope.DECISION,
        actor=actor,
        reason=reason,
        decision=DecisionRef(decision_id=decision_id, packet_id=packet_id, request_id=request_id),
        context=context or {},
        tags=tags or [],
        trace=trace or TraceContext(),
    )


def build_veto_overridden(
    *,
    actor: Actor,
    reason: VetoReason,
    decision_id: str,
    packet_id: Optional[UUID] = None,
    request_id: Optional[str] = None,
    context: Optional[Dict[str, JsonValue]] = None,
    tags: Optional[List[str]] = None,
    trace: Optional[TraceContext] = None,
) -> VetoEvent:
    return VetoEvent(
        kind=VetoEventKind.VETO_OVERRIDDEN,
        scope=VetoScope.DECISION,
        actor=actor,
        reason=reason,
        decision=DecisionRef(decision_id=decision_id, packet_id=packet_id, request_id=request_id),
        context=context or {},
        tags=tags or [],
        trace=trace or TraceContext(),
    )


def build_veto_released(
    *,
    actor: Actor,
    reason: VetoReason,
    execution_id: str,
    action_id: Optional[str] = None,
    step_id: Optional[str] = None,
    context: Optional[Dict[str, JsonValue]] = None,
    tags: Optional[List[str]] = None,
    trace: Optional[TraceContext] = None,
) -> VetoEvent:
    return VetoEvent(
        kind=VetoEventKind.VETO_RELEASED,
        scope=VetoScope.EXECUTION,
        actor=actor,
        reason=reason,
        execution=ExecutionRef(execution_id=execution_id, action_id=action_id, step_id=step_id),
        context=context or {},
        tags=tags or [],
        trace=trace or TraceContext(),
    )
