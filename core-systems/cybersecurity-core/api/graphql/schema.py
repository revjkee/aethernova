# cybersecurity-core/api/graphql/schema.py
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import logging
import math
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, TypeVar

import strawberry
from pydantic import BaseModel, Field, ValidationError as PydValidationError
from strawberry.dataloader import DataLoader
from strawberry.types import Info

logger = logging.getLogger("graphql.cybersecurity")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# =============================================================================
# Security / Principal
# =============================================================================

@dataclass(frozen=True)
class Principal:
    subject: str           # "svc:edr" | "agent:<uuid>" | "user:<id>"
    kind: str              # "service" | "agent" | "user"
    tenant_id: Optional[str]
    scopes: Tuple[str, ...]


def require_scope(info: Info, *required: str) -> None:
    ctx: RequestContext = info.context
    if ctx.principal is None:
        raise ForbiddenError("auth.required")
    ps = set(ctx.principal.scopes or ())
    for s in required:
        if s not in ps:
            raise ForbiddenError(f"auth.missing_scope:{s}")


# =============================================================================
# Repository Protocols (Async)
# =============================================================================

class Pagination(BaseModel):
    offset: int = Field(ge=0, default=0)
    limit: int = Field(ge=1, le=1000, default=50)


class SensorModel(BaseModel):
    sensor_id: uuid.UUID
    name: str
    vendor: str
    model: str
    version: str
    ip_address: str
    location: Optional[str] = None
    tags: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    created_at: datetime
    updated_at: datetime


class RuleModel(BaseModel):
    rule_id: uuid.UUID
    engine: str
    sid: int
    rev: int
    classification: Optional[str] = None
    severity: int
    enabled: bool
    rule_text: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class EventModel(BaseModel):
    event_id: int
    event_time: datetime
    sensor_id: uuid.UUID
    rule_id: Optional[uuid.UUID] = None
    action: str
    category: Optional[str] = None
    severity: int
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    transport: Optional[str] = None
    app_proto: Optional[str] = None
    signature: Optional[str] = None
    flow_id: Optional[int] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    payload_size: Optional[int] = None
    http_host: Optional[str] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    file_hash: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class SensorRepo(Protocol):
    async def get(self, sensor_id: uuid.UUID) -> Optional[SensorModel]: ...
    async def list(
        self,
        *,
        name_q: Optional[str],
        vendor: Optional[str],
        model: Optional[str],
        is_active: Optional[bool],
        pagination: Pagination,
        sort: Optional[str],
    ) -> Tuple[Sequence[SensorModel], int]: ...


class RuleRepo(Protocol):
    async def get(self, rule_id: uuid.UUID) -> Optional[RuleModel]: ...
    async def list(
        self,
        *,
        engine: Optional[str],
        enabled: Optional[bool],
        severity_gte: Optional[int],
        severity_lte: Optional[int],
        pagination: Pagination,
        sort: Optional[str],
    ) -> Tuple[Sequence[RuleModel], int]: ...


class EventRepo(Protocol):
    async def get(self, event_id: int) -> Optional[EventModel]: ...
    async def list(
        self,
        *,
        time_from: Optional[datetime],
        time_to: Optional[datetime],
        severity_gte: Optional[int],
        severity_lte: Optional[int],
        actions: Optional[List[str]],
        sensor_ids: Optional[List[uuid.UUID]],
        rule_ids: Optional[List[uuid.UUID]],
        ip_q: Optional[str],
        signature_q: Optional[str],
        pagination: Pagination,
        sort: Optional[str],
    ) -> Tuple[Sequence[EventModel], int]: ...


class ActionBus(Protocol):
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None: ...


class PubSub(Protocol):
    async def subscribe_events(self, **filters: Any) -> Iterable[EventModel]: ...


@dataclass
class RepoContainer:
    sensors: SensorRepo
    rules: RuleRepo
    events: EventRepo
    bus: Optional[ActionBus] = None
    pubsub: Optional[PubSub] = None


# =============================================================================
# GraphQL Helpers: Relay-like Connection
# =============================================================================

T = TypeVar("T")

def _b64_encode(raw: str) -> str:
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")

def _b64_decode(token: str) -> str:
    return base64.b64decode(token.encode("ascii")).decode("utf-8")

def encode_cursor(offset: int) -> str:
    return _b64_encode(f"ofs:{offset}")

def decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    raw = _b64_decode(cursor)
    if not raw.startswith("ofs:"):
        raise ValueError("invalid cursor")
    return int(raw.split(":", 1)[1])


@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    start_cursor: Optional[str]
    end_cursor: Optional[str]
    total_count: int


@strawberry.type
class Edge(strawberry.Generic[T]):
    node: T
    cursor: str


@strawberry.type
class Connection(strawberry.Generic[T]):
    edges: List[Edge[T]]
    page_info: PageInfo


def make_connection(items: Sequence[Any], total: int, offset: int, limit: int) -> Connection[Any]:
    edges = [Edge(node=i, cursor=encode_cursor(offset + idx)) for idx, i in enumerate(items)]
    start = encode_cursor(offset) if items else None
    end = encode_cursor(offset + len(items) - 1) if items else None
    has_prev = offset > 0
    has_next = (offset + len(items)) < total
    return Connection(
        edges=edges,
        page_info=PageInfo(
            has_next_page=has_next,
            has_previous_page=has_prev,
            start_cursor=start,
            end_cursor=end,
            total_count=total,
        ),
    )

# =============================================================================
# GraphQL Types
# =============================================================================

@strawberry.type(description="Registered IDS sensors/probes inventory.")
class Sensor:
    sensor_id: strawberry.ID
    name: str
    vendor: str
    model: str
    version: str
    ip_address: str
    location: Optional[str]
    tags: strawberry.scalars.JSON
    is_active: bool
    created_at: datetime
    updated_at: datetime


@strawberry.type(description="IDS/IPS rules, signatures and metadata.")
class Rule:
    rule_id: strawberry.ID
    engine: str
    sid: int
    rev: int
    classification: Optional[str]
    severity: int
    enabled: bool
    rule_text: str
    metadata: strawberry.scalars.JSON
    created_at: datetime
    updated_at: datetime


@strawberry.type(description="High-volume IDS/IPS events (partitioned by time in storage).")
class IdsEvent:
    event_id: strawberry.ID
    event_time: datetime
    sensor_id: strawberry.ID
    rule_id: Optional[strawberry.ID]
    action: str
    category: Optional[str]
    severity: int
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    transport: Optional[str]
    app_proto: Optional[str]
    signature: Optional[str]
    flow_id: Optional[int]
    bytes_in: Optional[int]
    bytes_out: Optional[int]
    payload_size: Optional[int]
    http_host: Optional[str]
    url: Optional[str]
    user_agent: Optional[str]
    file_hash: Optional[str]
    extra: strawberry.scalars.JSON
    created_at: datetime
    updated_at: datetime

    @strawberry.field(description="Load linked sensor via DataLoader.")
    async def sensor(self, info: Info) -> Optional[Sensor]:
        loader: DataLoader[uuid.UUID, Optional[SensorModel]] = info.context.loaders["sensor_by_id"]
        model = await loader.load(uuid.UUID(str(self.sensor_id)))
        return map_sensor(model) if model else None

    @strawberry.field(description="Load linked rule via DataLoader.")
    async def rule(self, info: Info) -> Optional[Rule]:
        if self.rule_id is None:
            return None
        loader: DataLoader[uuid.UUID, Optional[RuleModel]] = info.context.loaders["rule_by_id"]
        model = await loader.load(uuid.UUID(str(self.rule_id)))
        return map_rule(model) if model else None


# =============================================================================
# Input types: filters/sort
# =============================================================================

@strawberry.input
class SensorFilter:
    q: Optional[str] = strawberry.field(description="Search in name")
    vendor: Optional[str] = None
    model: Optional[str] = None
    is_active: Optional[bool] = None


@strawberry.enum
class SensorSort(str):
    NAME_ASC = "name_asc"
    NAME_DESC = "name_desc"
    CREATED_DESC = "created_desc"
    CREATED_ASC = "created_asc"


@strawberry.input
class RuleFilter:
    engine: Optional[str] = None
    enabled: Optional[bool] = None
    severity_gte: Optional[int] = None
    severity_lte: Optional[int] = None


@strawberry.enum
class RuleSort(str):
    SEVERITY_DESC = "severity_desc"
    SEVERITY_ASC = "severity_asc"
    CREATED_DESC = "created_desc"


@strawberry.input
class EventFilter:
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    severity_gte: Optional[int] = None
    severity_lte: Optional[int] = None
    actions: Optional[List[str]] = None
    sensor_ids: Optional[List[strawberry.ID]] = None
    rule_ids: Optional[List[strawberry.ID]] = None
    ip_q: Optional[str] = strawberry.field(
        default=None, description="Search IP in src/dst"
    )
    signature_q: Optional[str] = None


@strawberry.enum
class EventSort(str):
    TIME_DESC = "time_desc"
    TIME_ASC = "time_asc"
    SEVERITY_DESC = "severity_desc"
    SEVERITY_ASC = "severity_asc"


# =============================================================================
# Action mutations inputs
# =============================================================================

@strawberry.input
class IsolateInput:
    agent_id: strawberry.ID
    reason: str


@strawberry.input
class KillProcessInput:
    agent_id: strawberry.ID
    pid: int
    reason: str
    process_name: Optional[str] = None


@strawberry.input
class QuarantineInput:
    agent_id: strawberry.ID
    file_path: str
    reason: str
    file_hash: Optional[str] = None


@strawberry.type
class ActionAck:
    action_id: strawberry.ID
    status: str


# =============================================================================
# Mapping helpers from models
# =============================================================================

def map_sensor(m: SensorModel) -> Sensor:
    return Sensor(
        sensor_id=strawberry.ID(str(m.sensor_id)),
        name=m.name,
        vendor=m.vendor,
        model=m.model,
        version=m.version,
        ip_address=m.ip_address,
        location=m.location,
        tags=m.tags,
        is_active=m.is_active,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


def map_rule(m: RuleModel) -> Rule:
    return Rule(
        rule_id=strawberry.ID(str(m.rule_id)),
        engine=m.engine,
        sid=m.sid,
        rev=m.rev,
        classification=m.classification,
        severity=m.severity,
        enabled=m.enabled,
        rule_text=m.rule_text,
        metadata=m.metadata,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


def map_event(m: EventModel) -> IdsEvent:
    return IdsEvent(
        event_id=strawberry.ID(str(m.event_id)),
        event_time=m.event_time,
        sensor_id=strawberry.ID(str(m.sensor_id)),
        rule_id=strawberry.ID(str(m.rule_id)) if m.rule_id else None,
        action=m.action,
        category=m.category,
        severity=m.severity,
        src_ip=m.src_ip,
        src_port=m.src_port,
        dst_ip=m.dst_ip,
        dst_port=m.dst_port,
        transport=m.transport,
        app_proto=m.app_proto,
        signature=m.signature,
        flow_id=m.flow_id,
        bytes_in=m.bytes_in,
        bytes_out=m.bytes_out,
        payload_size=m.payload_size,
        http_host=m.http_host,
        url=m.url,
        user_agent=m.user_agent,
        file_hash=m.file_hash,
        extra=m.extra,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


# =============================================================================
# Context and DataLoaders
# =============================================================================

@dataclass
class RequestContext:
    principal: Optional[Principal]
    repos: RepoContainer
    loaders: Dict[str, Any]


async def _batch_sensors_by_id(keys: List[uuid.UUID], info: Info) -> List[Optional[SensorModel]]:
    repo: SensorRepo = info.context.repos.sensors
    # naive batching: individual gets; recommend replacing with repo.batch_get
    results: Dict[uuid.UUID, SensorModel] = {}
    for k in keys:
        item = await repo.get(k)
        if item:
            results[k] = item
    return [results.get(k) for k in keys]


async def _batch_rules_by_id(keys: List[uuid.UUID], info: Info) -> List[Optional[RuleModel]]:
    repo: RuleRepo = info.context.repos.rules
    results: Dict[uuid.UUID, RuleModel] = {}
    for k in keys:
        item = await repo.get(k)
        if item:
            results[k] = item
    return [results.get(k) for k in keys]


def build_context(principal: Optional[Principal], repos: RepoContainer) -> RequestContext:
    # Init dataloaders once per request
    dummy_info = type("I", (), {})()  # used to bind Info in loaders
    loaders: Dict[str, Any] = {}
    loaders["sensor_by_id"] = DataLoader(lambda keys: _batch_sensors_by_id(keys, dummy_info))  # Info will be replaced by strawberry
    loaders["rule_by_id"] = DataLoader(lambda keys: _batch_rules_by_id(keys, dummy_info))
    return RequestContext(principal=principal, repos=repos, loaders=loaders)


# =============================================================================
# Query
# =============================================================================

@strawberry.type
class Query:

    @strawberry.field
    async def sensor(self, info: Info, id: strawberry.ID) -> Optional[Sensor]:
        require_scope(info, "edr:read")
        model = await info.context.repos.sensors.get(uuid.UUID(str(id)))
        return map_sensor(model) if model else None

    @strawberry.field
    async def sensors(
        self,
        info: Info,
        filter: Optional[SensorFilter] = None,
        sort: Optional[SensorSort] = SensorSort.CREATED_DESC,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Connection[Sensor]:
        require_scope(info, "edr:read")
        first = max(1, min(first, 1000))
        offset = decode_cursor(after)
        items, total = await info.context.repos.sensors.list(
            name_q=(filter.q if filter else None),
            vendor=(filter.vendor if filter else None),
            model=(filter.model if filter else None),
            is_active=(filter.is_active if filter else None),
            pagination=Pagination(offset=offset, limit=first),
            sort=sort.value if sort else None,
        )
        return make_connection([map_sensor(i) for i in items], total, offset, first)

    @strawberry.field
    async def rule(self, info: Info, id: strawberry.ID) -> Optional[Rule]:
        require_scope(info, "edr:read")
        model = await info.context.repos.rules.get(uuid.UUID(str(id)))
        return map_rule(model) if model else None

    @strawberry.field
    async def rules(
        self,
        info: Info,
        filter: Optional[RuleFilter] = None,
        sort: Optional[RuleSort] = RuleSort.SEVERITY_DESC,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Connection[Rule]:
        require_scope(info, "edr:read")
        first = max(1, min(first, 1000))
        offset = decode_cursor(after)
        items, total = await info.context.repos.rules.list(
            engine=(filter.engine if filter else None),
            enabled=(filter.enabled if filter else None),
            severity_gte=(filter.severity_gte if filter else None),
            severity_lte=(filter.severity_lte if filter else None),
            pagination=Pagination(offset=offset, limit=first),
            sort=sort.value if sort else None,
        )
        return make_connection([map_rule(i) for i in items], total, offset, first)

    @strawberry.field
    async def event(self, info: Info, id: strawberry.ID) -> Optional[IdsEvent]:
        require_scope(info, "edr:read")
        model = await info.context.repos.events.get(int(str(id)))
        return map_event(model) if model else None

    @strawberry.field
    async def events(
        self,
        info: Info,
        filter: Optional[EventFilter] = None,
        sort: Optional[EventSort] = EventSort.TIME_DESC,
        first: int = 100,
        after: Optional[str] = None,
    ) -> Connection[IdsEvent]:
        require_scope(info, "edr:read")
        first = max(1, min(first, 2000))
        offset = decode_cursor(after)
        f = filter or EventFilter()
        items, total = await info.context.repos.events.list(
            time_from=f.time_from,
            time_to=f.time_to,
            severity_gte=f.severity_gte,
            severity_lte=f.severity_lte,
            actions=f.actions,
            sensor_ids=[uuid.UUID(str(x)) for x in (f.sensor_ids or [])],
            rule_ids=[uuid.UUID(str(x)) for x in (f.rule_ids or [])],
            ip_q=f.ip_q,
            signature_q=f.signature_q,
            pagination=Pagination(offset=offset, limit=first),
            sort=sort.value if sort else None,
        )
        return make_connection([map_event(i) for i in items], total, offset, first)


# =============================================================================
# Mutation
# =============================================================================

@strawberry.type
class Mutation:

    @strawberry.mutation
    async def isolate_agent(self, info: Info, input: IsolateInput) -> ActionAck:
        require_scope(info, "edr:write")
        bus = info.context.repos.bus
        if bus is None:
            raise InternalError("bus.not_configured")
        action_id = uuid.uuid4()
        await bus.publish(
            "edr.actions",
            {
                "type": "isolate",
                "action_id": str(action_id),
                "payload": dataclasses.asdict(input) if dataclasses.is_dataclass(input) else {"agent_id": str(input.agent_id), "reason": input.reason},
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )
        return ActionAck(action_id=strawberry.ID(str(action_id)), status="queued")

    @strawberry.mutation
    async def kill_process(self, info: Info, input: KillProcessInput) -> ActionAck:
        require_scope(info, "edr:write")
        bus = info.context.repos.bus
        if bus is None:
            raise InternalError("bus.not_configured")
        action_id = uuid.uuid4()
        await bus.publish(
            "edr.actions",
            {
                "type": "kill-process",
                "action_id": str(action_id),
                "payload": {
                    "agent_id": str(input.agent_id),
                    "pid": input.pid,
                    "reason": input.reason,
                    "process_name": input.process_name,
                },
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )
        return ActionAck(action_id=strawberry.ID(str(action_id)), status="queued")

    @strawberry.mutation
    async def quarantine_file(self, info: Info, input: QuarantineInput) -> ActionAck:
        require_scope(info, "edr:write")
        bus = info.context.repos.bus
        if bus is None:
            raise InternalError("bus.not_configured")
        action_id = uuid.uuid4()
        await bus.publish(
            "edr.actions",
            {
                "type": "quarantine",
                "action_id": str(action_id),
                "payload": {
                    "agent_id": str(input.agent_id),
                    "file_path": input.file_path,
                    "file_hash": input.file_hash,
                    "reason": input.reason,
                },
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )
        return ActionAck(action_id=strawberry.ID(str(action_id)), status="queued")


# =============================================================================
# Subscription (optional; requires pubsub integration)
# =============================================================================

@strawberry.type
class Subscription:

    @strawberry.subscription
    async def eventStream(
        self,
        info: Info,
        filter: Optional[EventFilter] = None,
    ) -> IdsEvent:
        require_scope(info, "edr:read")
        ps = info.context.repos.pubsub
        if ps is None:
            raise ForbiddenError("pubsub.not_configured")
        f = (filter or EventFilter())
        async for ev in ps.subscribe_events(
            time_from=f.time_from,
            time_to=f.time_to,
            severity_gte=f.severity_gte,
            severity_lte=f.severity_lte,
            actions=f.actions,
            sensor_ids=[uuid.UUID(str(x)) for x in (f.sensor_ids or [])] if f.sensor_ids else None,
            rule_ids=[uuid.UUID(str(x)) for x in (f.rule_ids or [])] if f.rule_ids else None,
            ip_q=f.ip_q,
            signature_q=f.signature_q,
        ):
            yield map_event(ev)


# =============================================================================
# Errors
# =============================================================================

class GqlError(Exception):
    code: str = "error"

    def __init__(self, code: str, message: Optional[str] = None):
        super().__init__(message or code)
        self.code = code


class ForbiddenError(GqlError):
    def __init__(self, code: str = "forbidden", message: Optional[str] = None):
        super().__init__(code, message or "forbidden")


class NotFoundError(GqlError):
    def __init__(self, code: str = "not_found", message: Optional[str] = None):
        super().__init__(code, message or "not found")


class InternalError(GqlError):
    def __init__(self, code: str = "internal", message: Optional[str] = None):
        super().__init__(code, message or "internal error")


# =============================================================================
# Schema
# =============================================================================

schema = strawberry.Schema(query=Query, mutation=Mutation, subscription=Subscription)
