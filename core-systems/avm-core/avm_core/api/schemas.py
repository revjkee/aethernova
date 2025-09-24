# -*- coding: utf-8 -*-
"""
Aethernova / NeuroCity
Path: core-systems/avm_core/engine/api/schemas.py

Industrial API schemas for AVM Engine:
- Pydantic v2 models with strict types and validation
- Envelopes (success/error), pagination, problem details
- Domain entities: Job/Task/Event/Node with audit mixins
- Security principals, token/introspection claims
- Monetary/metrics fields with Decimal and bounded numbers
- Helper factories for pages and errors
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum, IntEnum
from typing import Any, Dict, Generic, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator, computed_field
from pydantic.types import PositiveInt, NonNegativeInt, conint, conlist, conbytes, StrictBool, StrictInt, StrictStr

# ---------------------------------------------------------------------------
# Common constants and utilities
# ---------------------------------------------------------------------------

ISO_8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

Money = Decimal  # alias for clarity

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class JobStatus(str, Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"
    timeout = "timeout"
    deferred = "deferred"

class Priority(IntEnum):
    low = 10
    normal = 20
    high = 30
    critical = 40

class ErrorCode(str, Enum):
    validation_error = "validation_error"
    unauthorized = "unauthorized"
    forbidden = "forbidden"
    not_found = "not_found"
    conflict = "conflict"
    rate_limited = "rate_limited"
    timeout = "timeout"
    internal_error = "internal_error"
    dependency_error = "dependency_error"
    unsupported = "unsupported"

class EventKind(str, Enum):
    job_created = "job.created"
    job_started = "job.started"
    job_completed = "job.completed"
    job_failed = "job.failed"
    job_cancelled = "job.cancelled"
    node_heartbeat = "node.heartbeat"
    node_registered = "node.registered"
    node_unhealthy = "node.unhealthy"

# ---------------------------------------------------------------------------
# Base mixins and core models
# ---------------------------------------------------------------------------

class ModelBase(BaseModel):
    model_config = ConfigDict(
        frozen=False,
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="forbid",
        ser_json_bytes="base64",
        json_encoders={
            Decimal: lambda v: format(v, "f"),
            datetime: lambda v: v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )

class AuditMixin(ModelBase):
    created_at: datetime = Field(default_factory=utcnow, description="Creation timestamp, UTC")
    updated_at: datetime = Field(default_factory=utcnow, description="Update timestamp, UTC")

    @model_validator(mode="before")
    def _ensure_tz(cls, values: Any) -> Any:
        for k in ("created_at", "updated_at"):
            val = values.get(k)
            if isinstance(val, datetime):
                if val.tzinfo is None:
                    values[k] = val.replace(tzinfo=timezone.utc)
                else:
                    values[k] = val.astimezone(timezone.utc)
        return values

class IdMixin(ModelBase):
    id: UUID = Field(default_factory=uuid4, description="Stable UUID")

class TenantMixin(ModelBase):
    tenant_id: UUID = Field(..., description="Tenant/Project identifier")

class PaginationMeta(ModelBase):
    total: NonNegativeInt
    page: conint(ge=1) = 1
    size: conint(ge=1, le=500) = 50
    pages: NonNegativeInt

    @field_validator("pages")
    @classmethod
    def _pages_nonzero(cls, v: int, info) -> int:
        return v

T = TypeVar("T")

class Page(Generic[T], ModelBase):
    items: List[T]
    meta: PaginationMeta

class Envelope(Generic[T], ModelBase):
    ok: StrictBool = True
    result: Optional[T] = None
    error: Optional["ErrorResponse"] = None

    @model_validator(mode="after")
    def _coherence(self) -> "Envelope[T]":
        if self.ok:
            if self.error is not None:
                raise ValueError("ok=True must not have error")
            if self.result is None:
                # allow empty result only if explicitly set; otherwise force empty container
                self.result = self.result
        else:
            if self.error is None:
                raise ValueError("ok=False must have error")
        return self

class ErrorDetail(ModelBase):
    loc: List[StrictStr] = Field(default_factory=list, description="Field or path")
    msg: StrictStr = Field(..., description="Human-readable message")
    type: StrictStr = Field(..., description="Machine-readable type")

class ErrorResponse(ModelBase):
    code: ErrorCode
    message: StrictStr
    details: List[ErrorDetail] = Field(default_factory=list)
    request_id: Optional[StrictStr] = None
    retry_after_ms: Optional[NonNegativeInt] = None

# ---------------------------------------------------------------------------
# Security models
# ---------------------------------------------------------------------------

class PrincipalKind(str, Enum):
    user = "user"
    service = "service"

class Principal(ModelBase):
    kind: PrincipalKind
    subject: StrictStr = Field(..., description="Opaque subject (sub)")
    scopes: List[StrictStr] = Field(default_factory=list)
    tenant_id: Optional[UUID] = None

class TokenIntrospection(ModelBase):
    active: StrictBool
    sub: Optional[StrictStr] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    scope: Optional[StrictStr] = None
    client_id: Optional[StrictStr] = None
    username: Optional[StrictStr] = None
    token_type: Optional[StrictStr] = None

# ---------------------------------------------------------------------------
# Domain: Engine Node / Job / Task / Event
# ---------------------------------------------------------------------------

class NodeSpec(ModelBase):
    name: StrictStr = Field(..., max_length=128)
    version: StrictStr = Field(..., max_length=32)
    capabilities: List[StrictStr] = Field(default_factory=list, description="Supported capability tags")
    region: Optional[StrictStr] = Field(None, max_length=64)
    az: Optional[StrictStr] = Field(None, max_length=64)

class NodeStatus(ModelBase):
    online: StrictBool = True
    cpu_load: float = Field(ge=0.0, le=100.0, default=0.0)
    mem_used_mb: NonNegativeInt = 0
    queue_depth: NonNegativeInt = 0
    last_heartbeat_at: datetime = Field(default_factory=utcnow)

class EngineNode(IdMixin, AuditMixin, TenantMixin):
    spec: NodeSpec
    status: NodeStatus

class JobConstraints(ModelBase):
    timeout_sec: conint(ge=1, le=86_400) = 900
    max_retries: conint(ge=0, le=20) = 3
    priority: Priority = Priority.normal

class JobInput(ModelBase):
    kind: StrictStr = Field(..., description="Job kind identifier")
    payload_b64: Optional[str] = Field(None, description="Opaque base64 payload")
    ref: Optional[StrictStr] = Field(None, description="External correlation id")

    @field_validator("payload_b64")
    @classmethod
    def _valid_b64(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            base64.b64decode(v, validate=True)
        except Exception as e:
            raise ValueError("payload_b64 must be valid base64") from e
        return v

class JobOutput(ModelBase):
    ok: StrictBool = True
    result_b64: Optional[str] = None
    error_message: Optional[StrictStr] = None

class EngineJob(IdMixin, AuditMixin, TenantMixin):
    status: JobStatus = JobStatus.pending
    constraints: JobConstraints = Field(default_factory=JobConstraints)
    input: JobInput
    output: Optional[JobOutput] = None
    picked_by: Optional[UUID] = Field(None, description="Node id that picked the job")
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @computed_field  # type: ignore[pydantic-field]
    @property
    def duration_ms(self) -> Optional[int]:
        if self.started_at and self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds() * 1000)
        return None

class JobCreateRequest(ModelBase):
    tenant_id: UUID
    input: JobInput
    constraints: Optional[JobConstraints] = None

class JobUpdateRequest(ModelBase):
    status: JobStatus
    output: Optional[JobOutput] = None
    picked_by: Optional[UUID] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @model_validator(mode="after")
    def _status_output_consistency(self) -> "JobUpdateRequest":
        if self.status in {JobStatus.succeeded, JobStatus.failed, JobStatus.cancelled, JobStatus.timeout}:
            if self.finished_at is None:
                raise ValueError("finished_at is required for terminal statuses")
        return self

class JobQuery(ModelBase):
    page: conint(ge=1) = 1
    size: conint(ge=1, le=500) = 50
    status: Optional[JobStatus] = None
    ref: Optional[StrictStr] = None
    created_from: Optional[datetime] = None
    created_to: Optional[datetime] = None

class EngineEvent(IdMixin, AuditMixin, TenantMixin):
    kind: EventKind
    subject_id: UUID = Field(..., description="Related entity id, e.g., job id or node id")
    data: Dict[str, Any] = Field(default_factory=dict)

# ---------------------------------------------------------------------------
# Metrics and accounting schemas
# ---------------------------------------------------------------------------

class MetricPoint(ModelBase):
    ts: datetime = Field(default_factory=utcnow)
    name: StrictStr
    value: float
    labels: Dict[StrictStr, StrictStr] = Field(default_factory=dict)

class BillingLine(ModelBase):
    job_id: UUID
    cost: Money = Field(..., ge=Decimal("0"))
    currency: StrictStr = Field(default="USD", pattern=r"^[A-Z]{3}$")

# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class JobResponse(ModelBase):
    job: EngineJob

class JobsPage(Page[EngineJob]):
    pass

class NodeResponse(ModelBase):
    node: EngineNode

class NodesPage(Page[EngineNode]):
    pass

class EventsPage(Page[EngineEvent]):
    pass

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def make_page(items: Sequence[T], total: int, page: int, size: int) -> Page[T]:
    pages = (total + size - 1) // size if size > 0 else 0
    meta = PaginationMeta(total=total, page=page, size=size, pages=pages)
    return Page[T](items=list(items), meta=meta)

def ok(result: T) -> Envelope[T]:
    return Envelope[T](ok=True, result=result)

def err(code: ErrorCode, message: str, *, details: Optional[List[ErrorDetail]] = None, request_id: Optional[str] = None, retry_after_ms: Optional[int] = None) -> Envelope[Any]:
    return Envelope[Any](
        ok=False,
        error=ErrorResponse(code=code, message=message, details=details or [], request_id=request_id, retry_after_ms=retry_after_ms),
    )

# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------

__all__ = [
    # base
    "ModelBase",
    "AuditMixin",
    "IdMixin",
    "TenantMixin",
    "PaginationMeta",
    "Page",
    "Envelope",
    "ErrorDetail",
    "ErrorResponse",
    # enums
    "JobStatus",
    "Priority",
    "ErrorCode",
    "EventKind",
    # security
    "PrincipalKind",
    "Principal",
    "TokenIntrospection",
    # domain
    "NodeSpec",
    "NodeStatus",
    "EngineNode",
    "JobConstraints",
    "JobInput",
    "JobOutput",
    "EngineJob",
    "JobCreateRequest",
    "JobUpdateRequest",
    "JobQuery",
    "EngineEvent",
    # metrics/billing
    "MetricPoint",
    "BillingLine",
    # responses
    "JobResponse",
    "JobsPage",
    "NodeResponse",
    "NodesPage",
    "EventsPage",
    # factories
    "make_page",
    "ok",
    "err",
]
