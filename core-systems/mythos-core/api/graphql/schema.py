# mythos-core/api/graphql/schema.py
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Protocol, Tuple, cast

import strawberry
from strawberry.dataloader import DataLoader
from strawberry.relay import Node, GlobalID, Connection, Edge
from strawberry.types import Info
from strawberry.scalars import JSON
from strawberry.subscription import GRAPHQL_TRANSPORT_WS_PROTOCOL, GRAPHQL_WS_PROTOCOL
from graphql import GraphQLError

# =========================
# СКАЛЯРЫ И ВСПОМОГАТЕЛЬНЫЕ
# =========================

@strawberry.scalar(description="Метка времени в миллисекундах UNIX epoch")
class TimestampMs(int):
    @staticmethod
    def serialize(v: int) -> int:
        return int(v)

    @staticmethod
    def parse_value(v: Any) -> int:
        try:
            return int(v)
        except Exception:
            raise GraphQLError("Invalid TimestampMs")

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def encode_cursor(payload: Dict[str, Any]) -> str:
    return b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())

def decode_cursor(token: Optional[str]) -> Dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(b64u_dec(token).decode())
    except Exception:
        raise GraphQLError("Invalid cursor")

# =========================
# ENUM'Ы
# =========================

@strawberry.enum
class EventKind:
    EVENT_KIND_UNSPECIFIED = 0
    EVENT_KIND_BUSINESS = 1
    EVENT_KIND_TECHNICAL = 2
    EVENT_KIND_SECURITY = 3
    EVENT_KIND_AUDIT = 4

@strawberry.enum
class Severity:
    SEVERITY_UNSPECIFIED = 0
    SEVERITY_TRACE = 1
    SEVERITY_DEBUG = 2
    SEVERITY_INFO = 3
    SEVERITY_NOTICE = 4
    SEVERITY_WARN = 5
    SEVERITY_ERROR = 6
    SEVERITY_CRITICAL = 7
    SEVERITY_ALERT = 8
    SEVERITY_EMERGENCY = 9

@strawberry.enum
class Visibility:
    VISIBILITY_UNSPECIFIED = 0
    VIS_PUBLIC = 1
    VIS_INTERNAL = 2
    VIS_CONFIDENTIAL = 3
    VIS_PRIVATE = 4

# =========================
# ДОМЕННЫЕ ТИПЫ
# =========================

@strawberry.type
class ResourceRefType:
    type: str
    id: str
    name: Optional[str] = None
    uri: Optional[str] = None

@strawberry.type
class ActorType:
    subject_id: str
    subject_type: str
    display_name: Optional[str] = None
    roles: List[str] = strawberry.field(default_factory=list)
    org_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

# Внешняя модель события для сервиса
@dataclass
class TimelineEventModel:
    id: str
    tenant_id: str
    stream: str
    event_time: int
    ingested_at: int
    sequence: int
    version: int
    kind: int
    severity: int
    title: Optional[str]
    message: Optional[str]
    labels: Dict[str, str]
    attributes: Dict[str, Any]
    text: Optional[str]
    json: Optional[Dict[str, Any]]
    binary_b64: Optional[str]
    uri: Optional[str]
    correlation_id: Optional[str]
    causation_id: Optional[str]
    trace_id: Optional[str]
    actor: Optional[Dict[str, Any]]
    resource: Optional[Dict[str, Any]]
    visibility: int
    deleted: bool
    etag: Optional[str]

# =========================
# ПРОТОКОЛ СЕРВИСА
# =========================

class TimelineService(Protocol):
    async def get_timeline(
        self,
        req: "GetTimelineRequestIn",
    ) -> Tuple[List[TimelineEventModel], Optional[str], Optional["CursorIn"]]:
        ...

    async def append_event(
        self, req: "AppendEventRequestIn", idem_key: Optional[str]
    ) -> TimelineEventModel:
        ...

    async def batch_append(
        self, req: "BatchAppendRequestIn", idem_key: Optional[str]
    ) -> List["BatchAppendResultIn"]:
        ...

    async def get_event(self, tenant_id: str, event_id: str, with_deleted: bool) -> Optional[TimelineEventModel]:
        ...

    async def update_event(
        self, tenant_id: str, event_id: str, patch: "UpdateEventRequestIn"
    ) -> TimelineEventModel:
        ...

    async def delete_event(self, tenant_id: str, event_id: str, hard: bool, expected_version: int) -> "DeleteEventResultIn":
        ...

    def stream(self, req: "StreamTimelineRequestIn") -> AsyncIterator[TimelineEventModel]:
        ...

# =========================
# ВХОДНЫЕ/СЛУЖЕБНЫЕ МОДЕЛИ ДЛЯ СЕРВИСА
# =========================

@dataclass
class CursorIn:
    stream: str
    sequence: int
    opaque: Optional[str] = None

@dataclass
class GetTimelineRequestIn:
    tenant_id: str
    stream: Optional[str]
    kind_filter: List[int]
    severity_filter: List[int]
    label_equals: Dict[str, str]
    since: Optional[int]
    until: Optional[int]
    inclusive: bool
    page_size: int
    page_token: Optional[str]
    reverse: bool
    with_deleted: bool

@dataclass
class AppendEventRequestIn:
    event: Dict[str, Any]
    return_after_commit: bool = False

@dataclass
class BatchAppendRequestIn:
    tenant_id: str
    stream: str
    events: List[Dict[str, Any]]
    return_after_commit: bool = False

@dataclass
class BatchAppendResultIn:
    event: Optional[TimelineEventModel]
    status: str
    error: Optional[str] = None

@dataclass
class UpdateEventRequestIn:
    expected_version: int
    update_mask: List[str]
    event: Dict[str, Any]

@dataclass
class DeleteEventResultIn:
    deleted: bool
    hard: bool
    version: Optional[int]

@dataclass
class StreamTimelineRequestIn:
    tenant_id: str
    stream: Optional[str]
    kind_filter: List[int]
    severity_filter: List[int]
    label_equals: Dict[str, str]
    since: Optional[int]
    follow: bool
    heartbeat_seconds: int
    with_deleted: bool

# =========================
# GraphQL NODE / TYPE
# =========================

@strawberry.type
class TimelineEvent(Node):
    # Relay-глобальный ID
    id: GlobalID

    # Поля домена
    event_id: strawberry.ID
    tenant_id: str
    stream: str
    event_time: TimestampMs
    ingested_at: TimestampMs
    sequence: int
    version: int
    kind: EventKind
    severity: Severity
    title: Optional[str]
    message: Optional[str]
    labels: JSON
    attributes: JSON
    text: Optional[str] = None
    json: Optional[JSON] = None
    binary_b64: Optional[str] = None
    uri: Optional[str] = None
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    trace_id: Optional[str] = None
    actor: Optional[ActorType] = None
    resource: Optional[ResourceRefType] = None
    visibility: Visibility = Visibility.VIS_INTERNAL
    deleted: bool = False
    etag: Optional[str] = None

    @classmethod
    def resolve_node(cls, node_id: GlobalID, info: Info) -> Optional["TimelineEvent"]:
        # node_id содержит тип/значение; значение — event_id
        event_id = node_id.node_id
        tenant = info.context.tenant_id if getattr(info.context, "tenant_id", None) else None
        if not tenant:
            return None
        svc: TimelineService = info.context.timeline_service
        # Strawberry разрешает sync, но у нас async — вернем None здесь,
        # а поиск по node делаем через Query.node
        return None

    @staticmethod
    def from_model(m: TimelineEventModel) -> "TimelineEvent":
        gid = GlobalID("TimelineEvent", m.id)
        actor = ActorType(**m.actor) if m.actor else None
        resource = ResourceRefType(**m.resource) if m.resource else None
        return TimelineEvent(
            id=gid,
            event_id=strawberry.ID(m.id),
            tenant_id=m.tenant_id,
            stream=m.stream,
            event_time=TimestampMs(m.event_time),
            ingested_at=TimestampMs(m.ingested_at),
            sequence=m.sequence,
            version=m.version,
            kind=EventKind(m.kind),
            severity=Severity(m.severity),
            title=m.title,
            message=m.message,
            labels=m.labels or {},
            attributes=m.attributes or {},
            text=m.text,
            json=m.json,
            binary_b64=m.binary_b64,
            uri=m.uri,
            correlation_id=m.correlation_id,
            causation_id=m.causation_id,
            trace_id=m.trace_id,
            actor=actor,
            resource=resource,
            visibility=Visibility(m.visibility),
            deleted=m.deleted,
            etag=m.etag,
        )

# Relay соединения
@strawberry.type
class TimelineEventEdge(Edge[TimelineEvent]):
    pass

@strawberry.type
class TimelineConnection(Connection[TimelineEvent]):
    # Доп. поле для возобновления чтения
    resume_stream: Optional[str] = None  # stream name
    resume_sequence: Optional[int] = None

# ================
# ВХОДНЫЕ ТИПЫ GQL
# ================

@strawberry.input
class LabelEqualsInput:
    key: str
    value: str

@strawberry.input
class AppendEventInput:
    tenant_id: str
    stream: str
    kind: EventKind = EventKind.EVENT_KIND_UNSPECIFIED
    severity: Severity = Severity.SEVERITY_INFO
    title: Optional[str] = None
    message: Optional[str] = None
    labels: Optional[JSON] = None
    attributes: Optional[JSON] = None
    text: Optional[str] = None
    json: Optional[JSON] = None
    binary_b64: Optional[str] = None
    uri: Optional[str] = None
    event_time: Optional[TimestampMs] = None
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    trace_id: Optional[str] = None
    visibility: Visibility = Visibility.VIS_INTERNAL
    actor: Optional[JSON] = None
    resource: Optional[JSON] = None
    client_event_id: Optional[str] = None  # для идемпотентности

@strawberry.type
class AppendEventPayload:
    event: TimelineEvent
    etag: Optional[str]
    location: str

@strawberry.input
class BatchAppendInput:
    tenant_id: str
    stream: str
    events: List[AppendEventInput]
    return_after_commit: bool = False

@strawberry.type
class BatchAppendResult:
    status: str
    error: Optional[str] = None
    event: Optional[TimelineEvent] = None

@strawberry.input
class UpdateEventPatchInput:
    title: Optional[str] = None
    message: Optional[str] = None
    labels: Optional[JSON] = None
    attributes: Optional[JSON] = None
    visibility: Optional[Visibility] = None

@strawberry.input
class UpdateEventInput:
    tenant_id: str
    event_id: strawberry.ID
    expected_version: int = 0
    if_match: Optional[str] = None
    update_mask: List[str] = strawberry.field(default_factory=list)
    patch: UpdateEventPatchInput = strawberry.field(default_factory=UpdateEventPatchInput)

@strawberry.type
class DeleteEventPayload:
    deleted: bool
    hard: bool
    version: Optional[int] = None

# ============
# КОНТЕКСТ
# ============

@dataclass
class Context:
    timeline_service: TimelineService
    tenant_id: Optional[str] = None
    request: Any = None
    request_id: Optional[str] = None
    idem_key: Optional[str] = None

# ===================
# DATALOADER'Ы
# ===================

async def _batch_events_by_id(keys: List[Tuple[str, str]], info: Info) -> List[Optional[TimelineEvent]]:
    # keys: [(tenant_id, event_id)]
    svc: TimelineService = info.context.timeline_service
    # Простая батч-загрузка; в реальной БД — одним запросом
    out: List[Optional[TimelineEvent]] = []
    for tenant_id, event_id in keys:
        m = await svc.get_event(tenant_id, event_id, with_deleted=True)
        out.append(TimelineEvent.from_model(m) if m else None)
    return out

def events_loader(info: Info) -> DataLoader[Tuple[str, str], Optional[TimelineEvent]]:
    if not hasattr(info.context, "_events_loader"):
        info.context._events_loader = DataLoader(load_fn=lambda keys: _batch_events_by_id(keys, info))
    return cast(DataLoader[Tuple[str, str], Optional[TimelineEvent]], info.context._events_loader)

# ============
# QUERY
# ============

@strawberry.type
class Query:

    @strawberry.field(description="Relay Node")
    async def node(self, info: Info, id: GlobalID) -> Optional[Node]:
        if id.type_name == "TimelineEvent":
            # Требуется tenant_id в контексте
            tenant = info.context.tenant_id
            if not tenant:
                raise GraphQLError("tenant_id is required in context")
            ev = await events_loader(info).load((tenant, id.node_id))
            return ev
        return None

    @strawberry.field(description="Список событий таймлайна с курсорной пагинацией")
    async def timeline_events(
        self,
        info: Info,
        tenant_id: str,
        stream: Optional[str] = None,
        kind: Optional[List[EventKind]] = None,
        severity: Optional[List[Severity]] = None,
        label_equals: Optional[List[LabelEqualsInput]] = None,
        since: Optional[TimestampMs] = None,
        until: Optional[TimestampMs] = None,
        inclusive: bool = False,
        first: int = 100,
        after: Optional[str] = None,
        reverse: bool = False,
        with_deleted: bool = False,
    ) -> TimelineConnection:
        if first < 1 or first > 1000:
            raise GraphQLError("first must be 1..1000")
        labels = {le.key: le.value for le in (label_equals or [])}
        page = decode_cursor(after)
        page_token = page.get("t")
        req = GetTimelineRequestIn(
            tenant_id=tenant_id,
            stream=stream,
            kind_filter=[k.value for k in (kind or [])],
            severity_filter=[s.value for s in (severity or [])],
            label_equals=labels,
            since=int(since) if since is not None else None,
            until=int(until) if until is not None else None,
            inclusive=inclusive,
            page_size=first,
            page_token=page_token,
            reverse=reverse,
            with_deleted=with_deleted,
        )
        svc: TimelineService = info.context.timeline_service
        events, next_token, resume = await svc.get_timeline(req)

        edges: List[TimelineEventEdge] = []
        for ev in events:
            node = TimelineEvent.from_model(ev)
            cursor = encode_cursor({"t": page_token or 0, "i": ev.sequence})
            edges.append(TimelineEventEdge(node=node, cursor=cursor))

        has_next = next_token is not None
        end_cursor = encode_cursor({"t": next_token}) if next_token else None
        conn = TimelineConnection(
            edges=edges,
            page_info=strawberry.relay.PageInfo(
                has_next_page=has_next,
                has_previous_page=False,
                start_cursor=edges[0].cursor if edges else None,
                end_cursor=end_cursor,
            ),
            resume_stream=resume.stream if resume else None,
            resume_sequence=resume.sequence if resume else None,
        )
        return conn

    @strawberry.field(description="Получить событие таймлайна по ID")
    async def event(
        self, info: Info, tenant_id: str, event_id: strawberry.ID, with_deleted: bool = False
    ) -> Optional[TimelineEvent]:
        svc: TimelineService = info.context.timeline_service
        m = await svc.get_event(tenant_id, str(event_id), with_deleted=with_deleted)
        return TimelineEvent.from_model(m) if m else None

# =============
# MUTATION
# =============

@strawberry.type
class Mutation:

    @strawberry.mutation(description="Добавить событие (идемпотентно по client_event_id/Idempotency-Key в контексте)")
    async def append_event(
        self,
        info: Info,
        input: AppendEventInput,
        return_after_commit: bool = False,
    ) -> AppendEventPayload:
        svc: TimelineService = info.context.timeline_service
        idem_key = info.context.idem_key
        # Собираем payload для сервиса
        event_dict: Dict[str, Any] = {
            "id": input.client_event_id or str(uuid.uuid4()),
            "tenant_id": input.tenant_id,
            "stream": input.stream,
            "kind": input.kind.value,
            "severity": input.severity.value,
            "title": input.title,
            "message": input.message,
            "labels": input.labels or {},
            "attributes": input.attributes or {},
            "text": input.text,
            "json": input.json,
            "binary_b64": input.binary_b64,
            "uri": input.uri,
            "event_time": int(input.event_time) if input.event_time is not None else int(time.time() * 1000),
            "correlation_id": input.correlation_id,
            "causation_id": input.causation_id,
            "trace_id": input.trace_id,
            "visibility": input.visibility.value,
            "actor": input.actor or None,
            "resource": input.resource or None,
        }
        req = AppendEventRequestIn(event=event_dict, return_after_commit=return_after_commit)
        m = await svc.append_event(req, idem_key=idem_key)
        node = TimelineEvent.from_model(m)
        location = f"/v1/timeline/{m.id}"
        return AppendEventPayload(event=node, etag=m.etag, location=location)

    @strawberry.mutation(description="Пакетная запись событий (идемпотентность на стороне сервиса)")
    async def batch_append(
        self,
        info: Info,
        input: BatchAppendInput,
    ) -> List[BatchAppendResult]:
        svc: TimelineService = info.context.timeline_service
        idem_key = info.context.idem_key
        events: List[Dict[str, Any]] = []
        now_ms = int(time.time() * 1000)
        for e in input.events:
            events.append(
                {
                    "id": e.client_event_id or str(uuid.uuid4()),
                    "tenant_id": input.tenant_id,
                    "stream": input.stream,
                    "kind": e.kind.value,
                    "severity": e.severity.value,
                    "title": e.title,
                    "message": e.message,
                    "labels": e.labels or {},
                    "attributes": e.attributes or {},
                    "text": e.text,
                    "json": e.json,
                    "binary_b64": e.binary_b64,
                    "uri": e.uri,
                    "event_time": int(e.event_time) if e.event_time is not None else now_ms,
                    "correlation_id": e.correlation_id,
                    "causation_id": e.causation_id,
                    "trace_id": e.trace_id,
                    "visibility": e.visibility.value,
                    "actor": e.actor or None,
                    "resource": e.resource or None,
                }
            )
        req = BatchAppendRequestIn(
            tenant_id=input.tenant_id,
            stream=input.stream,
            events=events,
            return_after_commit=input.return_after_commit,
        )
        results_in = await svc.batch_append(req, idem_key=idem_key)
        out: List[BatchAppendResult] = []
        for r in results_in:
            out.append(
                BatchAppendResult(
                    status=r.status,
                    error=r.error,
                    event=TimelineEvent.from_model(r.event) if r.event else None,
                )
            )
        return out

    @strawberry.mutation(description="Частичное обновление события (If-Match/expected_version)")
    async def update_event(self, info: Info, input: UpdateEventInput) -> TimelineEvent:
        svc: TimelineService = info.context.timeline_service
        # If-Match → проверим совпадение ETag вручную, если задан
        if input.if_match:
            current = await svc.get_event(input.tenant_id, str(input.event_id), with_deleted=True)
            if not current:
                raise GraphQLError("not found")
            if current.etag != input.if_match:
                raise GraphQLError("etag mismatch")
            input.expected_version = current.version

        patch_dict: Dict[str, Any] = {}
        if input.patch.title is not None:
            patch_dict["title"] = input.patch.title
        if input.patch.message is not None:
            patch_dict["message"] = input.patch.message
        if input.patch.labels is not None:
            patch_dict["labels"] = input.patch.labels
        if input.patch.attributes is not None:
            patch_dict["attributes"] = input.patch.attributes
        if input.patch.visibility is not None:
            patch_dict["visibility"] = input.patch.visibility.value

        req = UpdateEventRequestIn(
            expected_version=input.expected_version,
            update_mask=input.update_mask or list(patch_dict.keys()),
            event=patch_dict,
        )
        m = await svc.update_event(input.tenant_id, str(input.event_id), req)
        return TimelineEvent.from_model(m)

    @strawberry.mutation(description="Удаление события (soft по умолчанию, hard=true для физического)")
    async def delete_event(
        self,
        info: Info,
        tenant_id: str,
        event_id: strawberry.ID,
        hard: bool = False,
        expected_version: int = 0,
        if_match: Optional[str] = None,
    ) -> DeleteEventPayload:
        svc: TimelineService = info.context.timeline_service
        if if_match:
            current = await svc.get_event(tenant_id, str(event_id), with_deleted=True)
            if not current:
                raise GraphQLError("not found")
            if current.etag != if_match:
                raise GraphQLError("etag mismatch")
            expected_version = current.version
        r = await svc.delete_event(tenant_id, str(event_id), hard=hard, expected_version=expected_version)
        return DeleteEventPayload(deleted=r.deleted, hard=r.hard, version=r.version)

# ===============
# SUBSCRIPTION
# ===============

@strawberry.type
class Subscription:
    @strawberry.subscription(description="Поток событий таймлайна (replay+follow)")
    async def timeline_stream(
        self,
        info: Info,
        tenant_id: str,
        stream: Optional[str] = None,
        kind: Optional[List[EventKind]] = None,
        severity: Optional[List[Severity]] = None,
        label_equals: Optional[List[LabelEqualsInput]] = None,
        since: Optional[TimestampMs] = None,
        with_deleted: bool = False,
        heartbeat_seconds: int = 15,
    ) -> AsyncIterator[TimelineEvent]:
        svc: TimelineService = info.context.timeline_service
        req = StreamTimelineRequestIn(
            tenant_id=tenant_id,
            stream=stream,
            kind_filter=[k.value for k in (kind or [])],
            severity_filter=[s.value for s in (severity or [])],
            label_equals={le.key: le.value for le in (label_equals or [])},
            since=int(since) if since is not None else None,
            follow=True,
            heartbeat_seconds=heartbeat_seconds,
            with_deleted=with_deleted,
        )
        async for m in svc.stream(req):
            yield TimelineEvent.from_model(m)

# =======================
# СХЕМА (экспорт)
# =======================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
)

# Примечания по интеграции:
# - Контекст должен выставлять:
#   context.timeline_service : TimelineService
#   context.tenant_id        : str (если нужен node() и default-tenant)
#   context.idem_key         : str | None (из заголовка Idempotency-Key)
# - Для ASGI используйте Strawberry GraphQLRouter, протоколы WS: GRAPHQL_TRANSPORT_WS_PROTOCOL / GRAPHQL_WS_PROTOCOL.
