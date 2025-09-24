# zero-trust-core/api/http/routers/v1/session.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, PositiveInt, constr, validator

# Optional Redis support
try:
    from redis import asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover - optional
    aioredis = None  # type: ignore

logger = logging.getLogger("zt.session")

# =========================
# Models
# =========================

SessionDecision = Literal["active", "warn", "blocked", "quarantine"]

class SessionBinding(BaseModel):
    ip: Optional[str] = Field(default=None, description="Забинденный IP")
    user_agent: Optional[str] = Field(default=None)
    device_id: Optional[str] = Field(default=None)
    strict: bool = Field(default=True, description="Строгое сравнение привязок при проверках")

class SessionSecurity(BaseModel):
    mfa_level: Literal["none", "webauthn", "totp", "hwkey"] = "none"
    step_up_expires_at: Optional[int] = None  # unix seconds until which step-up считается свежим
    risk_score: float = 0.0
    risk_level: Literal["LOW","MEDIUM","HIGH","CRITICAL","UNKNOWN"] = "UNKNOWN"

class SessionData(BaseModel):
    id: str
    subject: str
    tenant: Optional[str] = None
    created_at: int
    absolute_expires_at: int
    idle_expires_at: int
    refresh_expires_at: Optional[int] = None
    decision: SessionDecision = "active"
    binding: SessionBinding = Field(default_factory=SessionBinding)
    security: SessionSecurity = Field(default_factory=SessionSecurity)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    revoked: bool = False
    last_seen_at: Optional[int] = None
    # opaque для расширений рантайма (не попадает в ответы, если не запрошено явно)
    _ext: Dict[str, Any] = Field(default_factory=dict, repr=False)

    @validator("id")
    def _validate_id(cls, v: str) -> str:
        if not v or len(v) < 16:
            raise ValueError("invalid session id")
        return v

class CreateSessionRequest(BaseModel):
    subject: constr(min_length=1, max_length=256)
    tenant: Optional[constr(min_length=1, max_length=128)] = None
    device_id: Optional[constr(min_length=1, max_length=256)] = None
    idle_ttl_seconds: PositiveInt = 1800
    absolute_ttl_seconds: PositiveInt = 8 * 3600
    refresh_ttl_seconds: Optional[PositiveInt] = 8 * 3600
    attributes: Dict[str, Any] = Field(default_factory=dict)
    strict_binding: bool = True

class RefreshRequest(BaseModel):
    session_id: constr(min_length=16)
    # Опционально обновить привязки при refresh
    rebind_ip: Optional[str] = None
    rebind_user_agent: Optional[str] = None
    rebind_device_id: Optional[str] = None

class BindRequest(BaseModel):
    session_id: constr(min_length=16)
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None
    strict: Optional[bool] = None

class UpdateAttrsRequest(BaseModel):
    session_id: constr(min_length=16)
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Полная замена под-дерева attributes")

class StepUpRequest(BaseModel):
    session_id: constr(min_length=16)
    mfa_level: Literal["webauthn","totp","hwkey"]
    ttl_seconds: PositiveInt = 3600

class RevokeRequest(BaseModel):
    session_id: Optional[constr(min_length=16)] = None
    subject: Optional[constr(min_length=1, max_length=256)] = None
    reason: Optional[str] = None

class SearchQuery(BaseModel):
    subject: Optional[str] = None
    tenant: Optional[str] = None
    limit: PositiveInt = 100

class SessionView(BaseModel):
    id: str
    subject: str
    tenant: Optional[str]
    created_at: int
    absolute_expires_at: int
    idle_expires_at: int
    refresh_expires_at: Optional[int]
    decision: SessionDecision
    binding: SessionBinding
    security: SessionSecurity
    attributes: Dict[str, Any]
    revoked: bool
    last_seen_at: Optional[int]

    @classmethod
    def from_session(cls, s: SessionData) -> "SessionView":
        return cls(**s.dict(exclude={"_ext"}))

class HealthView(BaseModel):
    ok: bool
    store: str
    now: int

# =========================
# Store Abstraction
# =========================

class SessionStore:
    async def put(self, s: SessionData) -> None: ...
    async def get(self, sid: str) -> Optional[SessionData]: ...
    async def delete(self, sid: str) -> None: ...
    async def touch(self, sid: str, now: int, idle_ttl_s: int) -> Optional[SessionData]: ...
    async def by_subject(self, subject: str, tenant: Optional[str], limit: int = 100) -> List[SessionData]: ...
    async def revoke_by_subject(self, subject: str, tenant: Optional[str]) -> int: ...
    async def ping(self) -> bool: ...

@dataclass
class _LockRef:
    lock: asyncio.Lock
    cnt: int = 0

class MemorySessionStore(SessionStore):
    def __init__(self) -> None:
        self._data: Dict[str, SessionData] = {}
        self._idx_subj: Dict[Tuple[str, Optional[str]], set] = {}
        self._locks: Dict[str, _LockRef] = {}

    def _now(self) -> int:
        return int(time.time())

    def _get_lock(self, sid: str) -> asyncio.Lock:
        ref = self._locks.get(sid)
        if not ref:
            ref = _LockRef(lock=asyncio.Lock(), cnt=0)
            self._locks[sid] = ref
        ref.cnt += 1
        return ref.lock

    def _release_lock(self, sid: str) -> None:
        ref = self._locks.get(sid)
        if not ref:
            return
        ref.cnt -= 1
        if ref.cnt <= 0:
            self._locks.pop(sid, None)

    async def put(self, s: SessionData) -> None:
        self._data[s.id] = s
        key = (s.subject, s.tenant)
        self._idx_subj.setdefault(key, set()).add(s.id)

    async def get(self, sid: str) -> Optional[SessionData]:
        s = self._data.get(sid)
        if not s:
            return None
        now = self._now()
        if s.revoked or now >= s.absolute_expires_at or now >= s.idle_expires_at:
            return None
        return s

    async def delete(self, sid: str) -> None:
        s = self._data.pop(sid, None)
        if s:
            key = (s.subject, s.tenant)
            ids = self._idx_subj.get(key)
            if ids:
                ids.discard(sid)
                if not ids:
                    self._idx_subj.pop(key, None)

    async def touch(self, sid: str, now: int, idle_ttl_s: int) -> Optional[SessionData]:
        s = self._data.get(sid)
        if not s:
            return None
        if s.revoked or now >= s.absolute_expires_at:
            return None
        s.idle_expires_at = now + idle_ttl_s
        s.last_seen_at = now
        return s

    async def by_subject(self, subject: str, tenant: Optional[str], limit: int = 100) -> List[SessionData]:
        ids = list(self._idx_subj.get((subject, tenant), set()))
        out: List[SessionData] = []
        for sid in ids[:limit]:
            s = await self.get(sid)
            if s:
                out.append(s)
        return out

    async def revoke_by_subject(self, subject: str, tenant: Optional[str]) -> int:
        ids = list(self._idx_subj.get((subject, tenant), set()))
        cnt = 0
        for sid in ids:
            s = self._data.get(sid)
            if s:
                s.revoked = True
                cnt += 1
        return cnt

    async def ping(self) -> bool:
        return True

class RedisSessionStore(SessionStore):  # pragma: no cover - requires redis
    def __init__(self, client: "aioredis.Redis", prefix: str = "zt:sess") -> None:
        self.r = client
        self.pref = prefix

    def _key(self, sid: str) -> str:
        return f"{self.pref}:{sid}"

    def _idx(self, subject: str, tenant: Optional[str]) -> str:
        t = tenant or "-"
        return f"{self.pref}:idx:{hashlib.sha1((subject+'|'+t).encode()).hexdigest()[:16]}"

    async def put(self, s: SessionData) -> None:
        k = self._key(s.id)
        data = json.dumps(s.dict()).encode("utf-8")
        ttl_abs = max(1, s.absolute_expires_at - int(time.time()))
        await self.r.set(k, data, ex=ttl_abs)
        await self.r.sadd(self._idx(s.subject, s.tenant), s.id)

    async def get(self, sid: str) -> Optional[SessionData]:
        raw = await self.r.get(self._key(sid))
        if not raw:
            return None
        s = SessionData(**json.loads(raw))
        now = int(time.time())
        if s.revoked or now >= s.absolute_expires_at or now >= s.idle_expires_at:
            return None
        return s

    async def delete(self, sid: str) -> None:
        raw = await self.r.get(self._key(sid))
        if raw:
            s = SessionData(**json.loads(raw))
            await self.r.srem(self._idx(s.subject, s.tenant), sid)
        await self.r.delete(self._key(sid))

    async def touch(self, sid: str, now: int, idle_ttl_s: int) -> Optional[SessionData]:
        k = self._key(sid)
        tr = self.r.pipeline()
        raw = await self.r.get(k)
        if not raw:
            return None
        s = SessionData(**json.loads(raw))
        if s.revoked or now >= s.absolute_expires_at:
            return None
        s.idle_expires_at = now + idle_ttl_s
        s.last_seen_at = now
        ttl_abs = max(1, s.absolute_expires_at - now)
        tr.set(k, json.dumps(s.dict()).encode("utf-8"), ex=ttl_abs)
        await tr.execute()
        return s

    async def by_subject(self, subject: str, tenant: Optional[str], limit: int = 100) -> List[SessionData]:
        ids = await self.r.smembers(self._idx(subject, tenant))
        out: List[SessionData] = []
        for sid in list(ids)[:limit]:
            s = await self.get(sid)  # respects idle/abs checks
            if s:
                out.append(s)
        return out

    async def revoke_by_subject(self, subject: str, tenant: Optional[str]) -> int:
        ids = await self.r.smembers(self._idx(subject, tenant))
        cnt = 0
        for sid in ids:
            raw = await self.r.get(self._key(sid))
            if raw:
                s = SessionData(**json.loads(raw))
                s.revoked = True
                await self.put(s)
                cnt += 1
        return cnt

    async def ping(self) -> bool:
        try:
            pong = await self.r.ping()
            return bool(pong)
        except Exception:
            return False

# =========================
# Dependencies / helpers
# =========================

def _now() -> int:
    return int(time.time())

def _gen_id(nbytes: int = 18) -> str:
    return secrets.token_urlsafe(nbytes)

def _client_ip(req: Request) -> Optional[str]:
    xf = req.headers.get("X-Forwarded-For")
    if xf:
        # берём первый IP
        return xf.split(",")[0].strip()
    return req.client.host if req.client else None

def _ua(req: Request) -> Optional[str]:
    return req.headers.get("User-Agent")

async def _get_store(request: Request) -> SessionStore:
    # Приложение может положить store в app.state.session_store
    store = getattr(request.app.state, "session_store", None)
    if store:
        return store
    # Попытка подключиться к Redis, если есть переменные окружения (но не обязательно)
    if aioredis and os.getenv("REDIS_URL"):
        try:
            client = aioredis.from_url(os.environ["REDIS_URL"], encoding="utf-8", decode_responses=False)
            store = RedisSessionStore(client)  # type: ignore
            request.app.state.session_store = store
            return store
        except Exception as e:  # pragma: no cover
            logger.warning("redis unavailable, fallback to memory: %s", e)
    # Fallback: in-memory
    store = MemorySessionStore()
    request.app.state.session_store = store
    return store

# =========================
# Router
# =========================

router = APIRouter(prefix="/v1/session", tags=["session"])

@router.get("/health", response_model=HealthView)
async def health(store: SessionStore = Depends(_get_store)) -> HealthView:
    ok = await store.ping()
    return HealthView(ok=ok, store=store.__class__.__name__, now=_now())

# ---------- Create ----------

@router.post("/create", response_model=SessionView, status_code=201)
async def create_session(
    req: Request,
    body: CreateSessionRequest,
    store: SessionStore = Depends(_get_store),
) -> SessionView:
    now = _now()
    sid = _gen_id()
    binding = SessionBinding(
        ip=body.device_id and None or _client_ip(req),  # если указан device_id — IP можно отложить
        user_agent=_ua(req),
        device_id=body.device_id,
        strict=body.strict_binding,
    )
    s = SessionData(
        id=sid,
        subject=body.subject,
        tenant=body.tenant,
        created_at=now,
        absolute_expires_at=now + int(body.absolute_ttl_seconds),
        idle_expires_at=now + int(body.idle_ttl_seconds),
        refresh_expires_at=now + int(body.refresh_ttl_seconds or body.absolute_ttl_seconds),
        binding=binding,
        attributes=body.attributes or {},
        last_seen_at=now,
    )
    await store.put(s)
    logger.info("session.create subject=%s tenant=%s sid=%s", s.subject, s.tenant, s.id)
    return SessionView.from_session(s)

# ---------- Get / Me ----------

class GetRequest(BaseModel):
    session_id: constr(min_length=16)

@router.get("/{session_id}", response_model=SessionView)
async def get_session(session_id: str, store: SessionStore = Depends(_get_store)) -> SessionView:
    s = await store.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionView.from_session(s)

@router.get("/me/by-header", response_model=SessionView)
async def get_me_by_header(
    request: Request,
    store: SessionStore = Depends(_get_store),
) -> SessionView:
    sid = request.headers.get("X-Session-Id")
    if not sid:
        raise HTTPException(status_code=400, detail="X-Session-Id header required")
    s = await store.get(sid)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    # Обновим idle TTL и last_seen
    touched = await store.touch(sid, _now(), max(60, s.idle_expires_at - _now()))
    return SessionView.from_session(touched or s)

# ---------- Bind / Attributes ----------

@router.post("/bind", response_model=SessionView)
async def bind_session(
    request: Request,
    body: BindRequest,
    store: SessionStore = Depends(_get_store),
) -> SessionView:
    s = await store.get(body.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    ip = body.ip or _client_ip(request)
    ua = body.user_agent or _ua(request)
    if ip:
        s.binding.ip = ip
    if ua:
        s.binding.user_agent = ua
    if body.device_id:
        s.binding.device_id = body.device_id
    if body.strict is not None:
        s.binding.strict = body.strict
    s.last_seen_at = _now()
    # перезапишем idle TTL (используем текущее окно idle)
    idle_window = max(60, s.idle_expires_at - _now())
    touched = await store.touch(s.id, _now(), idle_window)
    # put чтобы сохранить изменённые binding/привязки
    await store.put(touched or s)
    logger.info("session.bind sid=%s ip=%s device=%s", s.id, s.binding.ip, s.binding.device_id)
    return SessionView.from_session(touched or s)

@router.post("/attributes", response_model=SessionView)
async def update_attributes(body: UpdateAttrsRequest, store: SessionStore = Depends(_get_store)) -> SessionView:
    s = await store.get(body.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    s.attributes = dict(body.attributes or {})
    s.last_seen_at = _now()
    await store.put(s)
    return SessionView.from_session(s)

# ---------- Step-Up MFA ----------

@router.post("/step_up", response_model=SessionView)
async def step_up(body: StepUpRequest, store: SessionStore = Depends(_get_store)) -> SessionView:
    s = await store.get(body.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    now = _now()
    s.security.mfa_level = body.mfa_level
    s.security.step_up_expires_at = now + int(body.ttl_seconds)
    s.last_seen_at = now
    await store.put(s)
    logger.info("session.stepup sid=%s level=%s ttl=%ss", s.id, body.mfa_level, body.ttl_seconds)
    return SessionView.from_session(s)

# ---------- Refresh (rotate) ----------

@router.post("/refresh", response_model=SessionView)
async def refresh(body: RefreshRequest, store: SessionStore = Depends(_get_store)) -> SessionView:
    s = await store.get(body.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    now = _now()
    if s.refresh_expires_at and now >= s.refresh_expires_at:
        raise HTTPException(status_code=401, detail="refresh expired")
    # Ротация session id (anti-fixation)
    new_id = _gen_id()
    s_new = s.copy(update={"id": new_id})
    # Обновление привязок по запросу
    if body.rebind_ip:
        s_new.binding.ip = body.rebind_ip
    if body.rebind_user_agent:
        s_new.binding.user_agent = body.rebind_user_agent
    if body.rebind_device_id:
        s_new.binding.device_id = body.rebind_device_id
    # Продление idle; absolute не продлеваем, refresh — тоже не продлеваем по умолчанию
    idle_window = max(60, s.idle_expires_at - now)
    s_new.idle_expires_at = now + idle_window
    s_new.last_seen_at = now
    # Сохраняем новую, старую удаляем
    await store.put(s_new)
    await store.delete(s.id)
    logger.info("session.refresh rotated old=%s new=%s", s.id, s_new.id)
    return SessionView.from_session(s_new)

# ---------- Revoke ----------

@router.delete("/{session_id}", status_code=204)
async def revoke_by_id(session_id: str, store: SessionStore = Depends(_get_store)) -> Response:
    s = await store.get(session_id)
    if not s:
        # идемпотентность
        return Response(status_code=204)
    s.revoked = True
    await store.put(s)
    logger.info("session.revoke sid=%s subject=%s", s.id, s.subject)
    return Response(status_code=204)

@router.post("/revoke", status_code=200)
async def revoke(body: RevokeRequest, store: SessionStore = Depends(_get_store)) -> Dict[str, Any]:
    if body.session_id:
        s = await store.get(body.session_id)
        if s:
            s.revoked = True
            await store.put(s)
            return {"revoked": 1}
        return {"revoked": 0}
    if body.subject:
        n = await store.revoke_by_subject(body.subject, None)
        return {"revoked": n}
    raise HTTPException(status_code=400, detail="session_id or subject required")

# ---------- Search ----------

@router.get("/search", response_model=List[SessionView])
async def search(subject: Optional[str] = None, tenant: Optional[str] = None, limit: int = 100, store: SessionStore = Depends(_get_store)) -> List[SessionView]:
    if not subject:
        return []
    xs = await store.by_subject(subject, tenant, limit=limit)
    return [SessionView.from_session(s) for s in xs]

# ---------- Middleware-like helper (optional) ----------

class CheckBindingRequest(BaseModel):
    session_id: constr(min_length=16)
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None

class CheckBindingResponse(BaseModel):
    ok: bool
    reason: Optional[str] = None
    session: Optional[SessionView] = None

@router.post("/check_binding", response_model=CheckBindingResponse)
async def check_binding(
    request: Request,
    body: CheckBindingRequest,
    store: SessionStore = Depends(_get_store),
) -> CheckBindingResponse:
    s = await store.get(body.session_id)
    if not s:
        return CheckBindingResponse(ok=False, reason="not_found")
    ip = body.ip or _client_ip(request)
    ua = body.user_agent or _ua(request)
    did = body.device_id
    # Сопоставление
    if s.binding.strict:
        if s.binding.ip and ip and s.binding.ip != ip:
            return CheckBindingResponse(ok=False, reason="ip_mismatch", session=SessionView.from_session(s))
        if s.binding.user_agent and ua and s.binding.user_agent != ua:
            return CheckBindingResponse(ok=False, reason="ua_mismatch", session=SessionView.from_session(s))
        if s.binding.device_id and did and s.binding.device_id != did:
            return CheckBindingResponse(ok=False, reason="device_mismatch", session=SessionView.from_session(s))
    # Успех -> touch
    now = _now()
    idle_window = max(60, s.idle_expires_at - now)
    await store.touch(s.id, now, idle_window)
    return CheckBindingResponse(ok=True, session=SessionView.from_session(s))
