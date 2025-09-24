# path: ops/api/http/routers/v1/agent.py
# License: MIT
# Industrial-grade FastAPI router for "Agent" resource in NeuroCity/OPS.
# Features:
# - Pydantic schemas (strict), validation, normalized error model
# - RBAC scopes ("agents:read", "agents:write", "agents:manage")
# - Idempotency via "Idempotency-Key" header (safe create/update actions)
# - ETag + If-None-Match for GET caching and update preconditions
# - Cursor pagination for listing with deterministic ordering
# - Rate limiting (token bucket; in-memory, pluggable to Redis)
# - Tracing headers (traceparent) propagation
# - Soft delete with deleted_at
# - Repository Protocol to swap storage (DB/ORM) later without touching handlers

from __future__ import annotations

import hashlib
import hmac
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, TypedDict, Union
from uuid import UUID, uuid4

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
from pydantic import BaseModel, Field, constr, ConfigDict, field_validator

# =========================
# Security / RBAC
# =========================

class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sub: UUID
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)

def _has_scope(principal: Principal, required: str) -> bool:
    return required in principal.scopes or "admin" in principal.roles

# Placeholder dependency: replace with real auth (JWT/OIDC)
async def get_principal(authorization: Optional[str] = Header(None)) -> Principal:
    # WARNING: replace with real verification (JWT). Here we parse demo header:
    # Authorization: Bearer demo-admin or demo-user
    sub = uuid4()
    if authorization and "demo-admin" in authorization:
        return Principal(sub=sub, roles=["admin"], scopes=["agents:read", "agents:write", "agents:manage"])
    return Principal(sub=sub, roles=["user"], scopes=["agents:read"])

def require_scope(required: str):
    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not _has_scope(principal, required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_scope")
        return principal
    return _dep

# =========================
# Rate Limiting (Token Bucket)
# =========================

class _Bucket:
    __slots__ = ("capacity", "tokens", "fill_rate", "timestamp")

    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.fill_rate = fill_rate  # tokens per second
        self.timestamp = time.monotonic()

    def consume(self, amount: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

_BUCKETS: Dict[str, _Bucket] = {}

def rate_limit(limit: int = 30, per_seconds: int = 60):
    fill_rate = limit / per_seconds
    async def _dep(request: Request) -> None:
        key = request.headers.get("x-api-key") or request.client.host or "anonymous"
        bucket = _BUCKETS.get(key)
        if bucket is None:
            bucket = _Bucket(capacity=limit, fill_rate=fill_rate)
            _BUCKETS[key] = bucket
        if not bucket.consume(1):
            raise HTTPException(status_code=429, detail="rate_limited")
    return _dep

# =========================
# Idempotency Cache (in-memory)
# =========================

class _IdemRecord(TypedDict):
    status: int
    headers: Dict[str, str]
    body: Dict[str, Any]
    ts: float

_IDEMPOTENCY_CACHE: Dict[str, _IdemRecord] = {}
_IDEMPOTENCY_TTL = int(os.getenv("IDEMPOTENCY_TTL_SEC", "3600"))

def _cleanup_idem() -> None:
    now = time.time()
    stale = [k for k, v in _IDEMPOTENCY_CACHE.items() if now - v["ts"] > _IDEMPOTENCY_TTL]
    for k in stale:
        _IDEMPOTENCY_CACHE.pop(k, None)

def idem_key(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    # Normalize and hash to fixed key
    return hashlib.sha256(header.strip().encode("utf-8")).hexdigest()

# =========================
# Schemas
# =========================

AgentKind = Literal["service", "worker", "trader", "guardian", "custom"]
AgentStatus = Literal["inactive", "active", "error", "paused"]

NameStr = constr(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
TagStr = constr(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.\-]+$")

class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)
    name: NameStr
    kind: AgentKind
    version: constr(min_length=1, max_length=32) = "1.0.0"
    tags: List[TagStr] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("tags")
    @classmethod
    def _tags_unique(cls, v: List[str]) -> List[str]:
        if len(v) != len(set(v)):
            raise ValueError("tags must be unique")
        return v

class AgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Optional[constr(min_length=1, max_length=32)] = None
    tags: Optional[List[TagStr]] = None
    config: Optional[Dict[str, Any]] = None
    status: Optional[AgentStatus] = None

class AgentDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    kind: AgentKind
    version: str
    status: AgentStatus
    tags: List[str]
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None
    etag: str

class ErrorModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    detail: Optional[Union[str, Dict[str, Any]]] = None

# Listing models
class AgentListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    kind: AgentKind
    version: str
    status: AgentStatus
    tags: List[str]
    updated_at: datetime
    etag: str

class CursorPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: List[AgentListItem]
    next_cursor: Optional[str] = None
    total: Optional[int] = None  # optional: can be None for performance

# =========================
# Repository Protocol (swap with DB later)
# =========================

class AgentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    kind: AgentKind
    version: str
    status: AgentStatus
    tags: List[str]
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None

class AgentRepository(Protocol):
    def create(self, data: AgentCreate) -> AgentRecord: ...
    def get(self, agent_id: UUID) -> Optional[AgentRecord]: ...
    def get_by_name(self, name: str) -> Optional[AgentRecord]: ...
    def update(self, agent_id: UUID, patch: AgentUpdate) -> Optional[AgentRecord]: ...
    def soft_delete(self, agent_id: UUID) -> bool: ...
    def list(
        self,
        cursor: Optional[str],
        limit: int,
        kind: Optional[AgentKind],
        status: Optional[AgentStatus],
        tag: Optional[str],
        q: Optional[str],
    ) -> Tuple[List[AgentRecord], Optional[str], Optional[int]]: ...
    def set_status(self, agent_id: UUID, status: AgentStatus) -> Optional[AgentRecord]: ...

# In-memory repository for bootstrap
class InMemoryAgentRepo:
    def __init__(self):
        self._store: Dict[UUID, AgentRecord] = {}
        self._by_name: Dict[str, UUID] = {}

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def create(self, data: AgentCreate) -> AgentRecord:
        if data.name in self._by_name:
            raise ValueError("name_already_exists")
        rec = AgentRecord(
            id=uuid4(),
            name=data.name,
            kind=data.kind,
            version=data.version,
            status="inactive",
            tags=data.tags,
            config=data.config,
            created_at=self._now(),
            updated_at=self._now(),
            deleted_at=None,
        )
        self._store[rec.id] = rec
        self._by_name[rec.name] = rec.id
        return rec

    def get(self, agent_id: UUID) -> Optional[AgentRecord]:
        return self._store.get(agent_id)

    def get_by_name(self, name: str) -> Optional[AgentRecord]:
        aid = self._by_name.get(name)
        return self._store.get(aid) if aid else None

    def update(self, agent_id: UUID, patch: AgentUpdate) -> Optional[AgentRecord]:
        rec = self._store.get(agent_id)
        if not rec or rec.deleted_at:
            return None
        data = rec.model_dump()
        if patch.version is not None:
            data["version"] = patch.version
        if patch.tags is not None:
            # ensure unique
            if len(patch.tags) != len(set(patch.tags)):
                raise ValueError("tags_not_unique")
            data["tags"] = patch.tags
        if patch.config is not None:
            data["config"] = patch.config
        if patch.status is not None:
            data["status"] = patch.status
        data["updated_at"] = self._now()
        self._store[agent_id] = AgentRecord(**data)
        return self._store[agent_id]

    def soft_delete(self, agent_id: UUID) -> bool:
        rec = self._store.get(agent_id)
        if not rec or rec.deleted_at:
            return False
        data = rec.model_dump()
        data["deleted_at"] = self._now()
        data["updated_at"] = self._now()
        self._store[agent_id] = AgentRecord(**data)
        return True

    def list(
        self,
        cursor: Optional[str],
        limit: int,
        kind: Optional[AgentKind],
        status: Optional[AgentStatus],
        tag: Optional[str],
        q: Optional[str],
    ) -> Tuple[List[AgentRecord], Optional[str], Optional[int]]:
        # Order by updated_at desc, id asc for determinism
        items = [r for r in self._store.values() if not r.deleted_at]
        if kind:
            items = [r for r in items if r.kind == kind]
        if status:
            items = [r for r in items if r.status == status]
        if tag:
            items = [r for r in items if tag in r.tags]
        if q:
            qq = q.lower()
            items = [r for r in items if qq in r.name.lower()]
        items.sort(key=lambda r: (r.updated_at, r.id.hex), reverse=True)

        start = 0
        if cursor:
            # cursor = "{updated_at_ts}:{id}"
            try:
                ts_s, hex_id = cursor.split(":")
                ts = float(ts_s)
                # find first element with updated_at_ts < ts or ==ts and id < hex_id (desc order)
                def _cmp(r: AgentRecord) -> Tuple[float, str]:
                    return (r.updated_at.timestamp(), r.id.hex)
                for idx, r in enumerate(items):
                    if _cmp(r) == (ts, hex_id):
                        start = idx + 1
                        break
            except Exception:
                start = 0

        page = items[start:start + limit]
        next_cursor = None
        if len(items) > start + limit:
            last = page[-1]
            next_cursor = f"{last.updated_at.timestamp()}:{last.id.hex}"
        total = len(items)
        return page, next_cursor, total

    def set_status(self, agent_id: UUID, status: AgentStatus) -> Optional[AgentRecord]:
        rec = self._store.get(agent_id)
        if not rec or rec.deleted_at:
            return None
        data = rec.model_dump()
        data["status"] = status
        data["updated_at"] = self._now()
        self._store[agent_id] = AgentRecord(**data)
        return self._store[agent_id]

# =========================
# Utilities
# =========================

def _strong_etag(payload: bytes) -> str:
    secret = os.getenv("ETAG_SECRET", "local-secret").encode()
    return hashlib.sha256(b"ETAG" + secret + payload).hexdigest()

def _dto(rec: AgentRecord) -> AgentDTO:
    etag_src = f"{rec.id}:{rec.updated_at.isoformat()}:{rec.version}".encode()
    return AgentDTO(
        id=rec.id,
        name=rec.name,
        kind=rec.kind,
        version=rec.version,
        status=rec.status,
        tags=rec.tags,
        config=rec.config,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        deleted_at=rec.deleted_at,
        etag=_strong_etag(etag_src),
    )

def _list_item(rec: AgentRecord) -> AgentListItem:
    etag_src = f"{rec.id}:{rec.updated_at.isoformat()}:{rec.version}".encode()
    return AgentListItem(
        id=rec.id,
        name=rec.name,
        kind=rec.kind,
        version=rec.version,
        status=rec.status,
        tags=rec.tags,
        updated_at=rec.updated_at,
        etag=_strong_etag(etag_src),
    )

def _idem_store(key: str, status_code: int, headers: Dict[str, str], body: Dict[str, Any]) -> None:
    _cleanup_idem()
    _IDEMPOTENCY_CACHE[key] = {
        "status": status_code, "headers": headers, "body": body, "ts": time.time()
    }

def _idem_replay(key: str) -> Optional[_IdemRecord]:
    _cleanup_idem()
    return _IDEMPOTENCY_CACHE.get(key)

# repo DI
_repo_singleton: AgentRepository = InMemoryAgentRepo()

def get_repo() -> AgentRepository:
    return _repo_singleton

# =========================
# Router
# =========================

router = APIRouter(prefix="/v1/agents", tags=["agents"])

# --- Create -------------------------------------------------
@router.post(
    "",
    response_model=AgentDTO,
    responses={
        201: {"model": AgentDTO},
        400: {"model": ErrorModel},
        401: {"model": ErrorModel},
        403: {"model": ErrorModel},
        409: {"model": ErrorModel},
        429: {"model": ErrorModel},
    },
    status_code=201,
)
async def create_agent(
    payload: AgentCreate,
    response: Response,
    principal: Principal = Depends(require_scope("agents:write")),
    repo: AgentRepository = Depends(get_repo),
    idempotency_key_hdr: Optional[str] = Header(None, alias="Idempotency-Key"),
    _: None = Depends(rate_limit(20, 60)),
    traceparent: Optional[str] = Header(None),
):
    idem = idem_key(idempotency_key_hdr)
    if idem:
        cached = _idem_replay(idem)
        if cached:
            for k, v in cached["headers"].items():
                response.headers[k] = v
            response.status_code = cached["status"]
            return cached["body"]

    existing = repo.get_by_name(payload.name)
    if existing:
        raise HTTPException(status_code=409, detail="name_already_exists")

    rec = repo.create(payload)
    dto = _dto(rec)
    body = dto.model_dump()
    etag = dto.etag
    response.headers["ETag"] = etag
    if traceparent:
        response.headers["traceparent"] = traceparent
    if idem:
        _idem_store(idem, 201, dict(response.headers), body)
    return body

# --- Get by ID with ETag -----------------------------------
@router.get(
    "/{agent_id}",
    response_model=AgentDTO,
    responses={
        200: {"model": AgentDTO},
        304: {"description": "Not Modified"},
        404: {"model": ErrorModel},
    },
)
async def get_agent(
    agent_id: UUID = Path(...),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    response: Response = None,  # type: ignore
    principal: Principal = Depends(require_scope("agents:read")),
    repo: AgentRepository = Depends(get_repo),
    traceparent: Optional[str] = Header(None),
):
    rec = repo.get(agent_id)
    if not rec or rec.deleted_at:
        raise HTTPException(status_code=404, detail="not_found")

    dto = _dto(rec)
    if if_none_match and if_none_match.strip('"') == dto.etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED  # type: ignore
        return

    response.headers["ETag"] = dto.etag
    if traceparent:
        response.headers["traceparent"] = traceparent
    return dto

# --- List with cursor pagination ----------------------------
@router.get(
    "",
    response_model=CursorPage,
    responses={200: {"model": CursorPage}},
)
async def list_agents(
    cursor: Optional[str] = Query(None, description="Opaque cursor from previous page"),
    limit: int = Query(25, ge=1, le=200),
    kind: Optional[AgentKind] = Query(None),
    status_q: Optional[AgentStatus] = Query(None, alias="status"),
    tag: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Search by name (contains)"),
    principal: Principal = Depends(require_scope("agents:read")),
    repo: AgentRepository = Depends(get_repo),
    _: None = Depends(rate_limit(60, 60)),
):
    items, next_cursor, total = repo.list(cursor, limit, kind, status_q, tag, q)
    return CursorPage(items=[_list_item(r) for r in items], next_cursor=next_cursor, total=total)

# --- Update with If-Match precondition ----------------------
class _IfMatchError(HTTPException):
    pass

def _require_if_match(current_etag: str, if_match_hdr: Optional[str]):
    if if_match_hdr is None:
        raise _IfMatchError(status_code=428, detail="precondition_required")  # 428 Precondition Required
    client = if_match_hdr.strip('"')
    if client != current_etag:
        raise _IfMatchError(status_code=412, detail="precondition_failed")  # 412 Precondition Failed

@router.patch(
    "/{agent_id}",
    response_model=AgentDTO,
    responses={
        200: {"model": AgentDTO},
        404: {"model": ErrorModel},
        412: {"model": ErrorModel},
        428: {"model": ErrorModel},
    },
)
async def update_agent(
    agent_id: UUID,
    patch: AgentUpdate,
    response: Response,
    principal: Principal = Depends(require_scope("agents:write")),
    repo: AgentRepository = Depends(get_repo),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    idempotency_key_hdr: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    rec = repo.get(agent_id)
    if not rec or rec.deleted_at:
        raise HTTPException(status_code=404, detail="not_found")
    current = _dto(rec)
    try:
        _require_if_match(current.etag, if_match)
    except _IfMatchError as e:
        raise e

    idem = idem_key(idempotency_key_hdr)
    if idem:
        cached = _idem_replay(idem)
        if cached:
            for k, v in cached["headers"].items():
                response.headers[k] = v
            response.status_code = cached["status"]
            return cached["body"]

    try:
        updated = repo.update(agent_id, patch)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    if not updated:
        raise HTTPException(status_code=404, detail="not_found")

    dto = _dto(updated)
    body = dto.model_dump()
    response.headers["ETag"] = dto.etag
    if idem:
        _idem_store(idem, 200, dict(response.headers), body)
    return body

# --- Soft delete -------------------------------------------
@router.delete(
    "/{agent_id}",
    status_code=204,
    responses={
        204: {"description": "deleted"},
        404: {"model": ErrorModel},
    },
)
async def delete_agent(
    agent_id: UUID,
    principal: Principal = Depends(require_scope("agents:manage")),
    repo: AgentRepository = Depends(get_repo),
):
    ok = repo.soft_delete(agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not_found")
    return Response(status_code=204)

# --- Run action (activate/pause/error) ----------------------
class AgentActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["activate", "pause", "error"]

class AgentActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    status: AgentStatus
    updated_at: datetime
    etag: str

@router.post(
    "/{agent_id}:run",
    response_model=AgentActionResponse,
    responses={
        200: {"model": AgentActionResponse},
        400: {"model": ErrorModel},
        404: {"model": ErrorModel},
    },
)
async def run_agent_action(
    agent_id: UUID,
    req: AgentActionRequest,
    response: Response,
    principal: Principal = Depends(require_scope("agents:write")),
    repo: AgentRepository = Depends(get_repo),
    idempotency_key_hdr: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    rec = repo.get(agent_id)
    if not rec or rec.deleted_at:
        raise HTTPException(status_code=404, detail="not_found")

    new_status: AgentStatus
    if req.action == "activate":
        new_status = "active"
    elif req.action == "pause":
        new_status = "paused"
    elif req.action == "error":
        new_status = "error"
    else:
        raise HTTPException(status_code=400, detail="unknown_action")

    idem = idem_key(idempotency_key_hdr)
    if idem:
        cached = _idem_replay(idem)
        if cached:
            for k, v in cached["headers"].items():
                response.headers[k] = v
            response.status_code = cached["status"]
            return cached["body"]

    updated = repo.set_status(agent_id, new_status)
    if not updated:
        raise HTTPException(status_code=404, detail="not_found")

    etag_src = f"{updated.id}:{updated.updated_at.isoformat()}:{updated.version}".encode()
    etag = _strong_etag(etag_src)
    body = AgentActionResponse(id=updated.id, status=updated.status, updated_at=updated.updated_at, etag=etag).model_dump()
    response.headers["ETag"] = etag
    if idem:
        _idem_store(idem, 200, dict(response.headers), body)
    return body

# --- Status endpoint ---------------------------------------
class AgentStatusDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    status: AgentStatus
    updated_at: datetime
    etag: str

@router.get(
    "/{agent_id}/status",
    response_model=AgentStatusDTO,
    responses={
        200: {"model": AgentStatusDTO},
        404: {"model": ErrorModel},
        304: {"description": "Not Modified"},
    },
)
async def get_status(
    agent_id: UUID,
    response: Response,
    repo: AgentRepository = Depends(get_repo),
    principal: Principal = Depends(require_scope("agents:read")),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    rec = repo.get(agent_id)
    if not rec or rec.deleted_at:
        raise HTTPException(status_code=404, detail="not_found")
    etag_src = f"{rec.id}:{rec.updated_at.isoformat()}:{rec.version}".encode()
    etag = _strong_etag(etag_src)
    if if_none_match and if_none_match.strip('"') == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return
    response.headers["ETag"] = etag
    return AgentStatusDTO(id=rec.id, status=rec.status, updated_at=rec.updated_at, etag=etag)
