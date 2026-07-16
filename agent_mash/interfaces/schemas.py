# agent_mash/interfaces/schemas.py
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

try:
    # Pydantic v2
    from pydantic import BaseModel, ConfigDict, Field
    from pydantic import field_validator as _field_validator
    from pydantic import model_validator as _model_validator

    _PydANTIC_V2 = True
except Exception:
    # Pydantic v1 fallback (best-effort)
    from pydantic import BaseModel, Field, validator as _field_validator  # type: ignore

    ConfigDict = dict  # type: ignore
    _model_validator = None  # type: ignore
    _PydANTIC_V2 = False


T = TypeVar("T")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_dt(value: datetime) -> datetime:
    # Force timezone-aware UTC
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:[a-z0-9\-_.]{0,62}[a-z0-9])?$")


class SortOrder(str, Enum):
    asc = "asc"
    desc = "desc"


class ErrorCode(str, Enum):
    validation_error = "validation_error"
    unauthorized = "unauthorized"
    forbidden = "forbidden"
    not_found = "not_found"
    conflict = "conflict"
    rate_limited = "rate_limited"
    timeout = "timeout"
    upstream_error = "upstream_error"
    internal_error = "internal_error"


class CorrelationId(str):
    """
    CorrelationId для трассировки (можно прокидывать из gateway).
    Разрешаем UUID4 и ULID.
    """

    @classmethod
    def new(cls) -> "CorrelationId":
        return cls(str(uuid.uuid4()))

    @classmethod
    def _validate(cls, v: Any) -> "CorrelationId":
        if isinstance(v, cls):
            return v
        if not isinstance(v, str):
            raise TypeError("CorrelationId must be a string")
        s = v.strip()
        if not s:
            raise ValueError("CorrelationId must not be empty")
        # UUID
        try:
            uuid.UUID(s)
            return cls(s)
        except Exception:
            pass
        # ULID
        if _ULID_RE.fullmatch(s):
            return cls(s)
        raise ValueError("CorrelationId must be UUID or ULID")

    if _PydANTIC_V2:
        @classmethod
        def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
            from pydantic_core import core_schema

            return core_schema.no_info_plain_validator_function(cls._validate)
    else:
        @classmethod
        def __get_validators__(cls):
            yield cls._validate


class EntityId(str):
    """
    Универсальный идентификатор сущностей. Разрешаем UUID, ULID, а также slug.
    """

    @classmethod
    def _validate(cls, v: Any) -> "EntityId":
        if isinstance(v, cls):
            return v
        if not isinstance(v, str):
            raise TypeError("EntityId must be a string")
        s = v.strip()
        if not s:
            raise ValueError("EntityId must not be empty")
        # UUID
        try:
            uuid.UUID(s)
            return cls(s)
        except Exception:
            pass
        # ULID
        if _ULID_RE.fullmatch(s):
            return cls(s)
        # slug
        if _SLUG_RE.fullmatch(s):
            return cls(s)
        raise ValueError("EntityId must be UUID, ULID, or slug")

    if _PydANTIC_V2:
        @classmethod
        def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
            from pydantic_core import core_schema

            return core_schema.no_info_plain_validator_function(cls._validate)
    else:
        @classmethod
        def __get_validators__(cls):
            yield cls._validate


class StrictBaseModel(BaseModel):
    """
    База всех DTO: строгая валидация, запрет лишних полей, стабильная сериализация.
    """

    if _PydANTIC_V2:
        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="forbid",
            frozen=False,
            validate_assignment=True,
            str_strip_whitespace=True,
            use_enum_values=True,
            populate_by_name=True,
        )
    else:
        class Config:
            extra = "forbid"
            allow_mutation = True
            validate_assignment = True
            anystr_strip_whitespace = True
            use_enum_values = True
            allow_population_by_field_name = True


class TraceContext(StrictBaseModel):
    """
    Метаданные трассировки/наблюдаемости.
    """

    correlation_id: CorrelationId = Field(default_factory=CorrelationId.new)
    request_id: Optional[CorrelationId] = Field(default=None)
    span_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    tenant_id: Optional[EntityId] = Field(default=None)
    actor_id: Optional[EntityId] = Field(default=None)
    source: Optional[str] = Field(default=None, min_length=1, max_length=128)


class Timestamped(StrictBaseModel):
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    if _PydANTIC_V2:
        @_field_validator("created_at", "updated_at", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v

        @_model_validator(mode="after")
        def _v_order(self) -> "Timestamped":
            if self.updated_at < self.created_at:
                raise ValueError("updated_at must be >= created_at")
            return self
    else:
        @_field_validator("created_at", "updated_at", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v

        @_field_validator("updated_at")  # type: ignore
        def _v_order(cls, v: datetime, values: Dict[str, Any]) -> datetime:
            ca = values.get("created_at")
            if isinstance(ca, datetime) and v < ca:
                raise ValueError("updated_at must be >= created_at")
            return v


class ErrorDetail(StrictBaseModel):
    """
    Машинно-обрабатываемая детализация ошибки.
    """

    loc: List[Union[str, int]] = Field(default_factory=list)
    msg: str = Field(..., min_length=1, max_length=2048)
    type: Optional[str] = Field(default=None, min_length=1, max_length=128)
    ctx: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(StrictBaseModel):
    """
    Единый формат ошибки для всех интерфейсов.
    """

    ok: bool = Field(default=False)
    code: ErrorCode = Field(default=ErrorCode.internal_error)
    message: str = Field(..., min_length=1, max_length=2048)
    details: List[ErrorDetail] = Field(default_factory=list)
    trace: TraceContext = Field(default_factory=TraceContext)
    occurred_at: datetime = Field(default_factory=_utcnow)

    if _PydANTIC_V2:
        @_field_validator("occurred_at", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v
    else:
        @_field_validator("occurred_at", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class SuccessResponse(Generic[T], StrictBaseModel):
    """
    Единая обёртка успешного ответа.
    """

    ok: bool = Field(default=True)
    data: T
    trace: TraceContext = Field(default_factory=TraceContext)
    server_time: datetime = Field(default_factory=_utcnow)

    if _PydANTIC_V2:
        @_field_validator("server_time", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v
    else:
        @_field_validator("server_time", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class PageInfo(StrictBaseModel):
    """
    Параметры страницы (offset pagination).
    """

    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    total: Optional[int] = Field(default=None, ge=0)


class SortSpec(StrictBaseModel):
    field: str = Field(..., min_length=1, max_length=64)
    order: SortOrder = Field(default=SortOrder.desc)


class Page(Generic[T], StrictBaseModel):
    items: List[T] = Field(default_factory=list)
    page: PageInfo = Field(default_factory=PageInfo)
    sort: List[SortSpec] = Field(default_factory=list)


class HealthStatus(str, Enum):
    ok = "ok"
    degraded = "degraded"
    down = "down"


class HealthCheck(StrictBaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    status: HealthStatus = Field(default=HealthStatus.ok)
    message: Optional[str] = Field(default=None, max_length=512)
    latency_ms: Optional[float] = Field(default=None, ge=0)
    checked_at: datetime = Field(default_factory=_utcnow)

    if _PydANTIC_V2:
        @_field_validator("checked_at", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v
    else:
        @_field_validator("checked_at", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class HealthReport(StrictBaseModel):
    service: str = Field(..., min_length=1, max_length=128)
    version: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: HealthStatus = Field(default=HealthStatus.ok)
    checks: List[HealthCheck] = Field(default_factory=list)
    trace: TraceContext = Field(default_factory=TraceContext)
    server_time: datetime = Field(default_factory=_utcnow)

    if _PydANTIC_V2:
        @_field_validator("server_time", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v

        @_model_validator(mode="after")
        def _v_status(self) -> "HealthReport":
            # status выводится из checks (down > degraded > ok)
            if not self.checks:
                return self
            worst = HealthStatus.ok
            for c in self.checks:
                if c.status == HealthStatus.down:
                    worst = HealthStatus.down
                    break
                if c.status == HealthStatus.degraded:
                    worst = HealthStatus.degraded
            self.status = worst
            return self
    else:
        @_field_validator("server_time", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class AuditMeta(StrictBaseModel):
    """
    Унифицированные метаданные аудита для событий/команд/ответов.
    """

    trace: TraceContext = Field(default_factory=TraceContext)
    ip: Optional[str] = Field(default=None, min_length=1, max_length=64)
    user_agent: Optional[str] = Field(default=None, min_length=1, max_length=256)
    tags: Dict[str, str] = Field(default_factory=dict)


class CommandEnvelope(Generic[T], StrictBaseModel):
    """
    Контракт для команд в очередях/шине.
    """

    name: str = Field(..., min_length=1, max_length=128)
    id: CorrelationId = Field(default_factory=CorrelationId.new)
    issued_at: datetime = Field(default_factory=_utcnow)
    meta: AuditMeta = Field(default_factory=AuditMeta)
    payload: T

    if _PydANTIC_V2:
        @_field_validator("issued_at", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v
    else:
        @_field_validator("issued_at", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class EventEnvelope(Generic[T], StrictBaseModel):
    """
    Контракт для событий в очередях/шине.
    """

    name: str = Field(..., min_length=1, max_length=128)
    id: CorrelationId = Field(default_factory=CorrelationId.new)
    occurred_at: datetime = Field(default_factory=_utcnow)
    meta: AuditMeta = Field(default_factory=AuditMeta)
    payload: T

    if _PydANTIC_V2:
        @_field_validator("occurred_at", mode="before")
        @classmethod
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v
    else:
        @_field_validator("occurred_at", pre=True)  # type: ignore
        def _v_dt(cls, v: Any) -> Any:
            if isinstance(v, datetime):
                return _normalize_dt(v)
            return v


class Empty(StrictBaseModel):
    """
    Явная пустая модель для ответов без payload.
    """

    pass


@dataclass(frozen=True)
class SchemaExport:
    """
    Программный экспорт схем (удобно для генерации OpenAPI/AsyncAPI).
    """

    pydantic_v2: bool
    base_model: Type[BaseModel]


SCHEMA_EXPORT = SchemaExport(
    pydantic_v2=_PydANTIC_V2,
    base_model=StrictBaseModel,
)
