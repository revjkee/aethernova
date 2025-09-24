# mythos-core/api/http/routers/v1/timeline.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator, model_validator

# -------------------------
# Pydantic models (align with proto)
# -------------------------

class EventKind(IntEnum):
    EVENT_KIND_UNSPECIFIED = 0
    EVENT_KIND_BUSINESS = 1
    EVENT_KIND_TECHNICAL = 2
    EVENT_KIND_SECURITY = 3
    EVENT_KIND_AUDIT = 4


class Severity(IntEnum):
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


class Visibility(IntEnum):
    VISIBILITY_UNSPECIFIED = 0
    VIS_PUBLIC = 1
    VIS_INTERNAL = 2
    VIS_CONFIDENTIAL = 3
    VIS_PRIVATE = 4


class ResourceRef(BaseModel):
    type: str = Field(..., min_length=1)
    id: str = Field(..., min_length=1)
    name: Optional[str] = None
    uri: Optional[str] = None


class Actor(BaseModel):
    subject_id: str = Field(..., min_length=1)
    subject_type: str = Field(..., min_length=1)
    display_name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    org_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class TimelineEvent(BaseModel):
    # Identification
    id: Optional[str] = Field(
        default=None, description="Client-supplied UUID/ULID for idempotency; server may assign."
    )
    tenant_id: str = Field(..., min_length=1)
    stream: str = Field(..., min_length=1)

    # Time and versions
    event_time: Optional[int] = Field(
        default=None, description="Unix epoch ms of the actual event time."
    )
    ingested_at: Optional[int] = Field(
        default=None, description="Server ingest time (epoch ms)."
    )
    sequence: Optional[int] = Field(default=None, ge=0)
    version: Optional[int] = Field(default=None, ge=0)

    # Classification
    kind: EventKind = EventKind.EVENT_KIND_UNSPECIFIED
    severity: Severity = Severity.SEVERITY_INFO
    title: Optional[str] = None
    message: Optional[str] = None

    # Labels and attributes
    labels: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    # Body (oneof-like)
    text: Optional[str] = None
    json: Optional[Dict[str, Any]] = Field(default=None)
    binary_b64: Optional[str] = Field(
        default=None, description="Base64-encoded body for arbitrary bytes"
    )
    uri: Optional[str] = None

    # Tracing/correlation
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    trace_id: Optional[str] = None

    # Context
    actor: Optional[Actor] = None
    resource: Optional[ResourceRef] = None

    # Access/state
    visibility: Visibility = Visibility.VIS_INTERNAL
    deleted: bool = False
    etag: Optional[str] = None

    @model_validator(mode="after")
    def validate_oneof_body(self) -> "TimelineEvent":
        bodies = [self.text, self.json, self.binary_b64, self.uri]
        if sum(1 for b in bodies if b not in (None, "", {})) > 1:
            raise ValueError("Only one of text/json/binary_b64/uri may be set.")
        return self


class GetTimelineRequest(BaseModel):
    tenant_id: str
    stream: Optional[str] = None
    kind_filter: List[EventKind] = Field(default_factory=list)
    severity_filter: List[Severity] = Field(default_factory=list)
    label_equals: Dict[str, str] = Field(default_factory=dict)
    since: Optional[int] = None
    until: Optional[int] = None
    inclusive: bool = False
    page_size: int = Field(default=100, ge=1, le=1000)
    page_token: Optional[str] = None
    reverse: bool = False
    with_deleted: bool = False


class GetTimelineResponse(BaseModel):
    events: List[TimelineEvent]
    next_page_token: Optional[str] = None
    resume_cursor: Optional["Cursor"] = None


class Cursor(BaseModel):
    stream: str
    sequence: int
    opaque: Optional[str] = None


class StreamTimelineRequest(BaseModel):
    tenant_id: str
    stream: Optional[str] = None
    kind_filter: List[EventKind] = Field(default_factory=list)
    severity_filter: List[Severity] = Field(default_factory=list)
    label_equals: Dict[str, str] = Field(default_factory=dict)
    since: Optional[int] = None
    follow: bool = True
    heartbeat_seconds: int = Field(default=15, ge=1, le=120)
    with_deleted: bool = False


class AppendEventRequest(BaseModel):
    event: TimelineEvent
    return_after_commit: bool = False


class AppendEventResponse(BaseModel):
    event: TimelineEvent


class BatchAppendRequest(BaseModel):
    tenant_id: str
    stream: str
    events: List[TimelineEvent]
    return_after_commit: bool = False


class BatchAppendResult(BaseModel):
    event: Optional[TimelineEvent] = None
    status: Literal["OK", "IDEMPOTENT_REPLAY", "INVALID", "FAILED"]
    error: Optional[str] = None


class BatchAppendResponse(BaseModel):
    results: List[BatchAppendResult]


class UpdateEventRequest(BaseModel):
    expected_version: int = Field(default=0, ge=0)
    update_mask: List[str] = Field(default_factory=list)
    event: TimelineEvent


class DeleteEventResponse(BaseModel):
    deleted: bool
    hard: bool
    version: Optional[int] = None


# -------------------------
# Service protocol / DI
# -------------------------

class TimelineService(Protocol):
    async def get_timeline(self, req: GetTimelineRequest) -> Tuple[List[TimelineEvent], Optional[str], Optional[Cursor]]: ...
    async def append_event(self, req: AppendEventRequest, idem_key: Optional[str]) -> TimelineEvent: ...
    async def batch_append(self, req: BatchAppendRequest, idem_key: Optional[str]) -> List[BatchAppendResult]: ...
    async def get_event(self, tenant_id: str, event_id: str, with_deleted: bool) -> Optional[TimelineEvent]: ...
    async def update_event(self, tenant_id: str, event_id: str, patch: UpdateEventRequest) -> TimelineEvent: ...
    async def delete_event(self, tenant_id: str, event_id: str, hard: bool, expected_version: int) -> DeleteEventResponse: ...
    def stream(self, req: StreamTimelineRequest) -> AsyncIterator[TimelineEvent]: ...


# -------------------------
# Minimal in-memory stub (for local/dev)
# -------------------------

@dataclass
class _SeqState:
    last_seq: int = 0


class InMemoryTimelineService:
    def __init__(self) -> None:
        self._events: Dict[str, Dict[str, TimelineEvent]] = {}  # tenant -> id -> event
        self._by_stream: Dict[str, Dict[str, List[str]]] = {}   # tenant -> stream -> [ids]
        self._seq: Dict[str, Dict[str, _SeqState]] = {}         # tenant -> stream -> state
        self._subscribers: Dict[str, List[asyncio.Queue[TimelineEvent]]] = {}  # tenant|stream -> queues
        self._lock = asyncio.Lock()

    def _key(self, tenant: str, stream: Optional[str]) -> str:
        return f"{tenant}|{stream or '*'}"

    async def _next_seq(self, tenant: str, stream: str) -> int:
        st = self._seq.setdefault(tenant, {}).setdefault(stream, _SeqState())
        st.last_seq += 1
        return st.last_seq

    def _etag(self, ev: TimelineEvent) -> str:
        payload = ev.model_dump(mode="json", exclude={"etag"})
        j = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(j).hexdigest()

    async def get_timeline(self, req: GetTimelineRequest) -> Tuple[List[TimelineEvent], Optional[str], Optional[Cursor]]:
        # Decode page token
        start_index = 0
        if req.page_token:
            try:
                payload = json.loads(base64.urlsafe_b64decode(req.page_token.encode()).decode())
                start_index = int(payload.get("i", 0))
            except Exception:
                raise HTTPException(status_code=400, detail="invalid page_token")
        stream_map = self._by_stream.get(req.tenant_id, {})
        ids: List[str] = []
        if req.stream:
            ids = list(stream_map.get(req.stream, []))
        else:
            for _, id_list in stream_map.items():
                ids.extend(id_list)
            # order across streams by ingested_at
            ids.sort(key=lambda _id: self._events[req.tenant_id][_id].ingested_at or 0, reverse=req.reverse)

        # Filter
        out: List[TimelineEvent] = []
        for _id in ids[start_index:]:
            ev = self._events[req.tenant_id][_id]
            if not req.with_deleted and ev.deleted:
                continue
            if req.kind_filter and ev.kind not in req.kind_filter:
                continue
            if req.severity_filter and ev.severity not in req.severity_filter:
                continue
            if req.label_equals:
                ok = all(ev.labels.get(k) == v for k, v in req.label_equals.items())
                if not ok:
                    continue
            if req.since is not None:
                t = ev.event_time or 0
                if req.inclusive:
                    if t < req.since:
                        continue
                else:
                    if t <= req.since:
                        continue
            if req.until is not None:
                t = ev.event_time or 0
                if req.inclusive:
                    if t > req.until:
                        continue
                else:
                    if t >= req.until:
                        continue
            out.append(ev)
            if len(out) >= req.page_size:
                break

        next_token = None
        if len(out) == req.page_size:
            next_index = start_index + req.page_size
            next_token = base64.urlsafe_b64encode(json.dumps({"i": next_index}).encode()).decode()

        resume = None
        if out:
            last = out[-1]
            resume = Cursor(stream=last.stream, sequence=last.sequence or 0, opaque=None)
        return out, next_token, resume

    async def append_event(self, req: AppendEventRequest, idem_key: Optional[str]) -> TimelineEvent:
        ev = req.event
        if not ev.id:
            ev.id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)
        if not ev.event_time:
            ev.event_time = now_ms
        ev.ingested_at = now_ms
        ev.sequence = await self._next_seq(ev.tenant_id, ev.stream)
        ev.version = (ev.version or 0) + 1
        ev.deleted = False
        ev.etag = self._etag(ev)
        async with self._lock:
            tmap = self._events.setdefault(ev.tenant_id, {})
            if ev.id in tmap:
                # Idempotent replay if payload is the same
                existing = tmap[ev.id]
                if existing.etag == ev.etag:
                    return existing
                raise HTTPException(status_code=409, detail="event id already exists with different payload")
            tmap[ev.id] = ev
            self._by_stream.setdefault(ev.tenant_id, {}).setdefault(ev.stream, []).append(ev.id)
            # Publish to subscribers
            key = self._key(ev.tenant_id, ev.stream)
            for q in self._subscribers.get(key, []):
                q.put_nowait(ev)
            for q in self._subscribers.get(self._key(ev.tenant_id, None), []):
                q.put_nowait(ev)
        return ev

    async def batch_append(self, req: BatchAppendRequest, idem_key: Optional[str]) -> List[BatchAppendResult]:
        results: List[BatchAppendResult] = []
        for e in req.events:
            e.tenant_id = req.tenant_id
            e.stream = req.stream
            try:
                ev = await self.append_event(AppendEventRequest(event=e, return_after_commit=req.return_after_commit), idem_key=None)
                results.append(BatchAppendResult(event=ev, status="OK"))
            except HTTPException as ex:
                if ex.status_code == 409:
                    results.append(BatchAppendResult(status="FAILED", error=ex.detail))
                else:
                    results.append(BatchAppendResult(status="FAILED", error=str(ex.detail)))
            except Exception as e:
                results.append(BatchAppendResult(status="FAILED", error=str(e)))
        return results

    async def get_event(self, tenant_id: str, event_id: str, with_deleted: bool) -> Optional[TimelineEvent]:
        ev = self._events.get(tenant_id, {}).get(event_id)
        if not ev:
            return None
        if ev.deleted and not with_deleted:
            return None
        return ev

    async def update_event(self, tenant_id: str, event_id: str, patch: UpdateEventRequest) -> TimelineEvent:
        ev = await self.get_event(tenant_id, event_id, with_deleted=True)
        if not ev:
            raise HTTPException(status_code=404, detail="not found")
        if patch.expected_version and (ev.version or 0) != patch.expected_version:
            raise HTTPException(status_code=409, detail="version mismatch")
        # Apply update mask (only safe fields)
        allowed = {"title", "message", "labels", "attributes", "visibility"}
        for field in patch.update_mask or []:
            if field not in allowed:
                raise HTTPException(status_code=400, detail=f"field not updatable: {field}")
        data = patch.event.model_dump()
        for field in patch.update_mask or []:
            setattr(ev, field, data.get(field))
        ev.version = (ev.version or 0) + 1
        ev.etag = self._etag(ev)
        return ev

    async def delete_event(self, tenant_id: str, event_id: str, hard: bool, expected_version: int) -> DeleteEventResponse:
        ev = await self.get_event(tenant_id, event_id, with_deleted=True)
        if not ev:
            raise HTTPException(status_code=404, detail="not found")
        if expected_version and (ev.version or 0) != expected_version:
            raise HTTPException(status_code=409, detail="version mismatch")
        if hard:
            self._events[tenant_id].pop(event_id, None)
            # also remove from stream index
            ids = self._by_stream.get(tenant_id, {}).get(ev.stream, [])
            self._by_stream.get(tenant_id, {}).update({ev.stream: [i for i in ids if i != ev.id]})
            return DeleteEventResponse(deleted=True, hard=True)
        ev.deleted = True
        ev.version = (ev.version or 0) + 1
        ev.etag = self._etag(ev)
        return DeleteEventResponse(deleted=True, hard=False, version=ev.version)

    async def _subscribe(self, tenant_id: str, stream: Optional[str]) -> asyncio.Queue[TimelineEvent]:
        key = self._key(tenant_id, stream)
        q: asyncio.Queue[TimelineEvent] = asyncio.Queue(maxsize=1024)
        self._subscribers.setdefault(key, []).append(q)
        return q

    async def _unsubscribe(self, tenant_id: str, stream: Optional[str], q: asyncio.Queue[TimelineEvent]) -> None:
        key = self._key(tenant_id, stream)
        subs = self._subscribers.get(key, [])
        if q in subs:
            subs.remove(q)

    async def _replay_since(self, tenant_id: str, stream: Optional[str], since_ms: Optional[int], with_deleted: bool) -> Iterable[TimelineEvent]:
        ids: List[str] = []
        if stream:
            ids = list(self._by_stream.get(tenant_id, {}).get(stream, []))
        else:
            for v in self._by_stream.get(tenant_id, {}).values():
                ids.extend(v)
        # sort by time
        ids.sort(key=lambda _id: self._events[tenant_id][_id].ingested_at or 0)
        for _id in ids:
            ev = self._events[tenant_id][_id]
            if not with_deleted and ev.deleted:
                continue
            if since_ms is not None and (ev.event_time or 0) < since_ms:
                continue
            yield ev

    async def _stream_iter(self, req: StreamTimelineRequest) -> AsyncIterator[TimelineEvent]:
        # Replay
        async for ev in _aiter(self._replay_since(req.tenant_id, req.stream, req.since, req.with_deleted)):
            yield ev
        if not req.follow:
            return
        # Subscribe
        q = await self._subscribe(req.tenant_id, req.stream)
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=req.heartbeat_seconds)
                    yield ev
                except asyncio.TimeoutError:
                    # heartbeat represented as no-event; SSE layer will send comment
                    yield from ()
        finally:
            await self._unsubscribe(req.tenant_id, req.stream, q)

    def stream(self, req: StreamTimelineRequest) -> AsyncIterator[TimelineEvent]:
        return self._stream_iter(req)


async def _aiter(it: Iterable[TimelineEvent]) -> AsyncIterator[TimelineEvent]:
    for item in it:
        yield item
        await asyncio.sleep(0)

# -------------------------
# Dependencies
# -------------------------

router = APIRouter(prefix="/v1/timeline", tags=["timeline"])

def get_service(request: Request) -> TimelineService:
    svc = getattr(request.app.state, "timeline_service", None)
    if svc is None:
        svc = InMemoryTimelineService()
        request.app.state.timeline_service = svc
    return svc

class IdemCache:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, Any]] = {}
        self.ttl = 600.0
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, value: Any) -> Any:
        now = time.time()
        async with self._lock:
            # purge
            for k, (ts, _) in list(self._store.items()):
                if now - ts > self.ttl:
                    self._store.pop(k, None)
            if key in self._store:
                return self._store[key][1]
            self._store[key] = (now, value)
            return value

def get_idem_cache(request: Request) -> IdemCache:
    cache = getattr(request.app.state, "timeline_idem_cache", None)
    if cache is None:
        cache = IdemCache()
        request.app.state.timeline_idem_cache = cache
    return cache

# -------------------------
# Helpers
# -------------------------

def _parse_labels(labels: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in labels:
        if ":" not in item:
            raise HTTPException(status_code=400, detail=f"label must be key:value, got {item}")
        k, v = item.split(":", 1)
        out[k] = v
    return out

def _etag_from_event(ev: TimelineEvent) -> str:
    # If service already provided etag — reuse
    if ev.etag:
        return ev.etag
    payload = ev.model_dump(mode="json", exclude={"etag"})
    j = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(j).hexdigest()

# -------------------------
# Endpoints
# -------------------------

@router.get("", response_model=GetTimelineResponse)
async def get_timeline(
    tenant_id: str = Query(..., min_length=1),
    stream: Optional[str] = Query(None),
    kind: List[EventKind] = Query(default_factory=list, description="Repeatable kind filter"),
    severity: List[Severity] = Query(default_factory=list, description="Repeatable severity filter"),
    label: List[str] = Query(default_factory=list, description="Repeatable key:value"),
    since: Optional[int] = Query(None, description="Epoch ms (exclusive by default)"),
    until: Optional[int] = Query(None, description="Epoch ms (exclusive by default)"),
    inclusive: bool = Query(False),
    page_size: int = Query(100, ge=1, le=1000),
    page_token: Optional[str] = Query(None),
    reverse: bool = Query(False),
    with_deleted: bool = Query(False),
    svc: TimelineService = Depends(get_service),
):
    req = GetTimelineRequest(
        tenant_id=tenant_id,
        stream=stream,
        kind_filter=kind,
        severity_filter=severity,
        label_equals=_parse_labels(label),
        since=since,
        until=until,
        inclusive=inclusive,
        page_size=page_size,
        page_token=page_token,
        reverse=reverse,
        with_deleted=with_deleted,
    )
    events, next_token, resume = await svc.get_timeline(req)
    return GetTimelineResponse(events=events, next_page_token=next_token, resume_cursor=resume)


@router.get("/stream", response_class=StreamingResponse)
async def stream_timeline(
    tenant_id: str = Query(..., min_length=1),
    stream: Optional[str] = Query(None),
    kind: List[EventKind] = Query(default_factory=list),
    severity: List[Severity] = Query(default_factory=list),
    label: List[str] = Query(default_factory=list),
    since: Optional[int] = Query(None),
    follow: bool = Query(True),
    heartbeat_seconds: int = Query(15, ge=1, le=120),
    with_deleted: bool = Query(False),
    svc: TimelineService = Depends(get_service),
):
    req = StreamTimelineRequest(
        tenant_id=tenant_id,
        stream=stream,
        kind_filter=kind,
        severity_filter=severity,
        label_equals=_parse_labels(label),
        since=since,
        follow=follow,
        heartbeat_seconds=heartbeat_seconds,
        with_deleted=with_deleted,
    )

    async def sse() -> AsyncIterator[bytes]:
        # Server-Sent Events (text/event-stream)
        last_heartbeat = time.time()
        async for ev in svc.stream(req):
            # heartbeat gap
            now = time.time()
            if now - last_heartbeat >= heartbeat_seconds:
                yield b": heartbeat\n\n"
                last_heartbeat = now
            data = json.dumps(ev.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
            yield b"event: timeline\n"
            yield b"data: " + data + b"\n\n"
        # final heartbeat
        yield b": end\n\n"

    return StreamingResponse(sse(), media_type="text/event-stream")


@router.post("", response_model=AppendEventResponse, status_code=status.HTTP_201_CREATED)
async def append_event(
    payload: AppendEventRequest,
    response: Response,
    request: Request,
    idem_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    svc: TimelineService = Depends(get_service),
    idem_cache: IdemCache = Depends(get_idem_cache),
):
    # Compose scoped idempotency key
    scoped_key = f"{payload.event.tenant_id}:{payload.event.stream}:{idem_key}" if idem_key else None

    if scoped_key:
        cached = await idem_cache.get_or_set(scoped_key, value=None)
        if isinstance(cached, AppendEventResponse):
            # replay
            ev = cached.event
            response.headers["ETag"] = _etag_from_event(ev)
            response.headers["Location"] = f"/v1/timeline/{ev.id}"
            return cached

    ev = await svc.append_event(payload, idem_key=idem_key)
    resp = AppendEventResponse(event=ev)
    response.headers["ETag"] = _etag_from_event(ev)
    response.headers["Location"] = f"/v1/timeline/{ev.id}"

    if scoped_key:
        await idem_cache.get_or_set(scoped_key, resp)

    return resp


@router.post(":batch-append", response_model=BatchAppendResponse, status_code=status.HTTP_200_OK)
async def batch_append(
    payload: BatchAppendRequest,
    idem_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    svc: TimelineService = Depends(get_service),
):
    results = await svc.batch_append(payload, idem_key=idem_key)
    return BatchAppendResponse(results=results)


@router.get("/{event_id}", response_model=TimelineEvent)
async def get_event(
    event_id: str = Path(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    with_deleted: bool = Query(False),
    response: Response = None,
    svc: TimelineService = Depends(get_service),
):
    ev = await svc.get_event(tenant_id, event_id, with_deleted=with_deleted)
    if not ev:
        raise HTTPException(status_code=404, detail="not found")
    response.headers["ETag"] = _etag_from_event(ev)
    return ev


@router.patch("/{event_id}", response_model=TimelineEvent)
async def update_event(
    event_id: str = Path(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    payload: UpdateEventRequest = ...,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    svc: TimelineService = Depends(get_service),
    response: Response = None,
):
    # If-Match wins over expected_version when both present
    if if_match:
        current = await svc.get_event(tenant_id, event_id, with_deleted=True)
        if not current:
            raise HTTPException(status_code=404, detail="not found")
        et = _etag_from_event(current)
        if et != if_match:
            raise HTTPException(status_code=412, detail="etag mismatch")
        # ensure expected_version matches or set it
        payload.expected_version = current.version or 0

    ev = await svc.update_event(tenant_id, event_id, payload)
    response.headers["ETag"] = _etag_from_event(ev)
    return ev


@router.delete("/{event_id}", response_model=DeleteEventResponse, status_code=status.HTTP_200_OK)
async def delete_event(
    event_id: str = Path(..., min_length=1),
    tenant_id: str = Query(..., min_length=1),
    hard: bool = Query(False),
    expected_version: int = Query(0, ge=0),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    svc: TimelineService = Depends(get_service),
):
    if if_match:
        current = await svc.get_event(tenant_id, event_id, with_deleted=True)
        if not current:
            raise HTTPException(status_code=404, detail="not found")
        et = _etag_from_event(current)
        if et != if_match:
            raise HTTPException(status_code=412, detail="etag mismatch")
        expected_version = current.version or 0
    return await svc.delete_event(tenant_id, event_id, hard=hard, expected_version=expected_version)


# -------------------------
# Notes:
# - Для продакшна внедрите реальный TimelineService (БД/шина) в app.state.timeline_service.
# - Подключение: app.include_router(router) в основном приложении.
# -------------------------
