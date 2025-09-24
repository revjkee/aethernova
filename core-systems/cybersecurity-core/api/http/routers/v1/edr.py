# cybersecurity-core/api/http/routers/v1/edr.py
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    File,
    Header,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl, conint, constr, validator

# -----------------------------------------------------------------------------
# Logger (structured-friendly)
# -----------------------------------------------------------------------------
logger = logging.getLogger("edr.api")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Security & Config
# -----------------------------------------------------------------------------
EDR_API_KEY = os.getenv("EDR_API_KEY")  # for service-to-service
EDR_HMAC_SECRET = (os.getenv("EDR_HMAC_SECRET") or "change-me").encode("utf-8")
MAX_BATCH = int(os.getenv("EDR_MAX_BATCH") or "1000")
MAX_BODY_BYTES = int(os.getenv("EDR_MAX_BODY_BYTES") or str(2 * 1024 * 1024))  # 2MB
RATE_LIMIT_PER_MINUTE = int(os.getenv("EDR_RATE_PER_MIN") or "600")  # per subject
IDEMPOTENCY_TTL_SEC = int(os.getenv("EDR_IDEMP_TTL") or "900")  # 15m

# -----------------------------------------------------------------------------
# Simple in-process idempotency cache (for external store, swap to Redis/KV)
# -----------------------------------------------------------------------------
class _IdemEntry(BaseModel):
    ts: float
    status_code: int
    payload: Dict[str, Any]


class _IdempotencyCache:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self._ttl = ttl_seconds
        self._store: Dict[str, _IdemEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[_IdemEntry]:
        async with self._lock:
            entry = self._store.get(key)
            now = time.time()
            if entry and (now - entry.ts) <= self._ttl:
                return entry
            if entry:
                # expire
                self._store.pop(key, None)
            return None

    async def set(self, key: str, status_code: int, payload: Dict[str, Any]) -> None:
        async with self._lock:
            self._store[key] = _IdemEntry(ts=time.time(), status_code=status_code, payload=payload)
            # soft cleanup
            if len(self._store) > 8192:
                now = time.time()
                for k, v in list(self._store.items()):
                    if now - v.ts > self._ttl:
                        self._store.pop(k, None)


IDEMP_CACHE = _IdempotencyCache(IDEMPOTENCY_TTL_SEC)

# -----------------------------------------------------------------------------
# Simple per-process rate limiter (token bucket per subject)
# -----------------------------------------------------------------------------
class _Bucket:
    __slots__ = ("tokens", "updated_at")

    def __init__(self) -> None:
        self.tokens = RATE_LIMIT_PER_MINUTE
        self.updated_at = time.time()


class _RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_min = per_minute
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    async def check(self, subject: str) -> None:
        now = time.time()
        async with self._lock:
            b = self._buckets.get(subject)
            if b is None:
                b = _Bucket()
                self._buckets[subject] = b
            # refill once per minute window
            if now - b.updated_at >= 60:
                b.tokens = self.per_min
                b.updated_at = now
            if b.tokens <= 0:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
            b.tokens -= 1


RL = _RateLimiter(RATE_LIMIT_PER_MINUTE)

# -----------------------------------------------------------------------------
# Principal & Auth
# -----------------------------------------------------------------------------
@dataclass
class Principal:
    subject: str
    kind: Literal["agent", "service"]
    tenant_id: Optional[str] = None
    scopes: Tuple[str, ...] = ()

def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

async def get_principal(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Principal:
    # Service: via API Key
    if x_api_key:
        if not EDR_API_KEY:
            raise HTTPException(status_code=500, detail="server misconfigured: missing EDR_API_KEY")
        if _constant_time_eq(x_api_key, EDR_API_KEY):
            return Principal(subject="svc:edr", kind="service", tenant_id=None, scopes=("edr:write", "edr:read"))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")

    # Agent: Bearer token "agent:<agent_id>:<hmac>"
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        parts = token.split(":")
        if len(parts) == 3 and parts[0] == "agent":
            agent_id, sig = parts[1], parts[2]
            mac = hmac.new(EDR_HMAC_SECRET, agent_id.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()
            if hmac.compare_digest(mac, sig):
                return Principal(subject=f"agent:{agent_id}", kind="agent", tenant_id=None, scopes=("edr:ingest",))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing credentials")

# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class EnrollRequest(BaseModel):
    hostname: constr(strip_whitespace=True, min_length=1, max_length=255)
    platform: Literal["windows", "linux", "darwin"]
    architecture: Literal["x86_64", "arm64", "armv7", "i386"]
    agent_version: constr(strip_whitespace=True, min_length=1, max_length=64)
    public_key_pem: constr(strip_whitespace=True, min_length=24, max_length=8192)
    nonce: constr(strip_whitespace=True, min_length=8, max_length=128)
    tags: Dict[str, constr(strip_whitespace=True, min_length=1, max_length=128)] = Field(default_factory=dict)

class EnrollResponse(BaseModel):
    agent_id: uuid.UUID
    enrollment_token: str = Field(description="use as Bearer token part: agent:<agent_id>:<hmac>")
    expires_at: datetime

class HeartbeatRequest(BaseModel):
    agent_id: uuid.UUID
    hostname: constr(strip_whitespace=True, min_length=1, max_length=255)
    agent_version: constr(strip_whitespace=True, min_length=1, max_length=64)
    uptime_sec: conint(ge=0)
    cpu_pct: float = Field(ge=0.0, le=100.0)
    mem_pct: float = Field(ge=0.0, le=100.0)
    disk_pct: float = Field(ge=0.0, le=100.0)
    last_seen_tasks: conint(ge=0) = 0
    health: Literal["ok", "degraded", "error"] = "ok"

class HeartbeatResponse(BaseModel):
    server_time: datetime
    next_poll_sec: conint(ge=1, le=300)
    pending_tasks: conint(ge=0)

class EdrEvent(BaseModel):
    event_time: datetime
    agent_id: uuid.UUID
    hostname: constr(strip_whitespace=True, min_length=1, max_length=255)
    username: Optional[constr(strip_whitespace=True, min_length=1, max_length=255)] = None
    severity: conint(ge=0, le=10)
    category: Literal["malware", "ransomware", "lateral_movement", "persistence", "exfil", "policy", "other"] = "other"
    action: Literal["alert", "block", "quarantine", "allow"] = "alert"

    process_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=512)] = None
    process_id: Optional[conint(ge=0)] = None
    parent_process_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=512)] = None
    parent_process_id: Optional[conint(ge=0)] = None

    file_path: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None
    file_hash: Optional[constr(strip_whitespace=True, min_length=7, max_length=128)] = None  # sha1/sha256/etc

    src_ip: Optional[constr(strip_whitespace=True, min_length=3, max_length=64)] = None
    dst_ip: Optional[constr(strip_whitespace=True, min_length=3, max_length=64)] = None
    src_port: Optional[conint(ge=0, le=65535)] = None
    dst_port: Optional[conint(ge=0, le=65535)] = None
    protocol: Optional[Literal["tcp", "udp", "icmp", "other"]] = None

    signature: Optional[constr(strip_whitespace=True, min_length=1, max_length=512)] = None
    rule_ref: Optional[constr(strip_whitespace=True, min_length=1, max_length=256)] = None

    payload_size: Optional[conint(ge=0)] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    @validator("event_time")
    def _ensure_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            # Normalize to UTC if naive
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

class BulkIngestRequest(BaseModel):
    events: List[EdrEvent] = Field(min_items=1, max_items=MAX_BATCH)

class BulkIngestResult(BaseModel):
    accepted: int
    rejected: int
    errors: List[str] = Field(default_factory=list)

class ApiError(BaseModel):
    detail: str

class ActionBase(BaseModel):
    agent_id: uuid.UUID
    reason: constr(strip_whitespace=True, min_length=1, max_length=512)

class IsolateRequest(ActionBase):
    mode: Literal["network"] = "network"

class KillProcessRequest(ActionBase):
    pid: conint(ge=0)
    process_name: Optional[str] = None

class QuarantineRequest(ActionBase):
    file_path: constr(strip_whitespace=True, min_length=1, max_length=2048)
    file_hash: Optional[constr(strip_whitespace=True, min_length=7, max_length=128)] = None

class ActionAck(BaseModel):
    action_id: uuid.UUID
    status: Literal["queued", "accepted"]

class FileSubmitResponse(BaseModel):
    upload_id: uuid.UUID
    stored: bool

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def _uuid() -> uuid.UUID:
    return uuid.uuid4()

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _mk_hmac(agent_id: uuid.UUID) -> str:
    return hmac.new(EDR_HMAC_SECRET, str(agent_id).encode("utf-8"), hashlib.sha256).hexdigest()

def _event_uid(e: EdrEvent) -> str:
    # Stable content hash for deduplication
    h = hashlib.sha256()
    h.update(str(e.agent_id).encode())
    h.update(e.event_time.isoformat().encode())
    if e.process_name:
        h.update(e.process_name.encode())
    if e.file_hash:
        h.update(e.file_hash.encode())
    if e.signature:
        h.update(e.signature.encode())
    return h.hexdigest()

async def _enqueue(topic: str, payload: Dict[str, Any]) -> None:
    # Placeholder for real bus (Kafka/NATS/Redis). Here we just log.
    logger.info("enqueue", extra={"topic": topic, "payload": payload})

# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/edr", tags=["edr"])

# -----------------------------------------------------------------------------
# Enrollment
# -----------------------------------------------------------------------------
@router.post(
    "/enroll",
    response_model=EnrollResponse,
    responses={401: {"model": ApiError}, 429: {"model": ApiError}},
)
async def enroll(
    req: EnrollRequest,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> EnrollResponse:
    await RL.check(principal.subject)
    # Only service is allowed to enroll new agents (e.g., provisioning system)
    if principal.kind != "service":
        raise HTTPException(status_code=403, detail="only service principal can enroll agents")

    agent_id = _uuid()
    token_sig = _mk_hmac(agent_id)
    enrollment_token = f"agent:{agent_id}:{token_sig}"
    expires_at = _now() + timedelta(hours=12)

    # Publish audit
    await _enqueue(
        "audit.enroll",
        {"agent_id": str(agent_id), "hostname": req.hostname, "platform": req.platform, "request_id": x_request_id},
    )

    return EnrollResponse(agent_id=agent_id, enrollment_token=enrollment_token, expires_at=expires_at)

# -----------------------------------------------------------------------------
# Heartbeat
# -----------------------------------------------------------------------------
@router.post(
    "/heartbeat",
    response_model=HeartbeatResponse,
    responses={401: {"model": ApiError}, 429: {"model": ApiError}},
)
async def heartbeat(
    req: HeartbeatRequest,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> HeartbeatResponse:
    await RL.check(principal.subject)
    if principal.kind != "agent":
        raise HTTPException(status_code=403, detail="only agents can call heartbeat")

    # Lightweight telemetry push
    await _enqueue(
        "edr.heartbeat",
        {
            "agent_id": str(req.agent_id),
            "hostname": req.hostname,
            "agent_version": req.agent_version,
            "uptime": req.uptime_sec,
            "cpu": req.cpu_pct,
            "mem": req.mem_pct,
            "disk": req.disk_pct,
            "health": req.health,
            "request_id": x_request_id,
            "ts": _now().isoformat(),
        },
    )

    return HeartbeatResponse(server_time=_now(), next_poll_sec=15, pending_tasks=0)

# -----------------------------------------------------------------------------
# Bulk events ingest with idempotency
# -----------------------------------------------------------------------------
def _validate_size(content_length: Optional[int]) -> None:
    if content_length is not None and content_length > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

@router.post(
    "/events",
    response_model=BulkIngestResult,
    responses={
        400: {"model": ApiError},
        401: {"model": ApiError},
        413: {"model": ApiError},
        422: {"model": ApiError},
        429: {"model": ApiError},
        500: {"model": ApiError},
    },
)
async def ingest_events(
    req: BulkIngestRequest,
    response: Response,
    background: BackgroundTasks,
    principal: Principal = Depends(get_principal),
    content_length: Optional[int] = Header(default=None, alias="Content-Length"),
    idempotency_key: Optional[constr(min_length=8, max_length=128)] = Header(default=None, alias="Idempotency-Key"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> BulkIngestResult:
    await RL.check(principal.subject)
    _validate_size(content_length)

    if principal.kind != "agent" and principal.kind != "service":
        raise HTTPException(status_code=403, detail="forbidden")

    # Idempotency: return cached result if exists
    if idempotency_key:
        cached = await IDEMP_CACHE.get(idempotency_key)
        if cached:
            response.headers["Idempotent-Replay"] = "true"
            return BulkIngestResult(**cached.payload)

    accepted = 0
    rejected = 0
    errors: List[str] = []

    # Hard validation: stable uid & sanity checks
    seen_uids: set[str] = set()
    for idx, e in enumerate(req.events):
        uid = _event_uid(e)
        if uid in seen_uids:
            rejected += 1
            errors.append(f"{idx}: duplicate in batch")
            continue
        seen_uids.add(uid)

        if e.agent_id is None or e.hostname is None:
            rejected += 1
            errors.append(f"{idx}: missing mandatory fields")
            continue

        # queue per event
        payload = e.dict()
        payload.update({"uid": uid, "request_id": x_request_id, "received_at": _now().isoformat()})
        background.add_task(_enqueue, "edr.events", payload)
        accepted += 1

    result = BulkIngestResult(accepted=accepted, rejected=rejected, errors=errors)

    if idempotency_key:
        await IDEMP_CACHE.set(idempotency_key, 200, result.dict())
        response.headers["Idempotency-Key"] = idempotency_key

    return result

# -----------------------------------------------------------------------------
# Response actions
# -----------------------------------------------------------------------------
@router.post(
    "/actions/isolate",
    response_model=ActionAck,
    responses={401: {"model": ApiError}, 403: {"model": ApiError}, 429: {"model": ApiError}},
)
async def action_isolate(
    req: IsolateRequest,
    background: BackgroundTasks,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> ActionAck:
    await RL.check(principal.subject)
    if principal.kind not in ("service",):
        raise HTTPException(status_code=403, detail="only service can issue isolate")
    action_id = _uuid()
    background.add_task(
        _enqueue,
        "edr.actions",
        {"type": "isolate", "action_id": str(action_id), "payload": req.dict(), "request_id": x_request_id, "ts": _now().isoformat()},
    )
    return ActionAck(action_id=action_id, status="queued")

@router.post(
    "/actions/kill-process",
    response_model=ActionAck,
    responses={401: {"model": ApiError}, 403: {"model": ApiError}, 429: {"model": ApiError}},
)
async def action_kill_process(
    req: KillProcessRequest,
    background: BackgroundTasks,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> ActionAck:
    await RL.check(principal.subject)
    if principal.kind not in ("service",):
        raise HTTPException(status_code=403, detail="only service can issue kill-process")
    action_id = _uuid()
    background.add_task(
        _enqueue,
        "edr.actions",
        {"type": "kill-process", "action_id": str(action_id), "payload": req.dict(), "request_id": x_request_id, "ts": _now().isoformat()},
    )
    return ActionAck(action_id=action_id, status="queued")

@router.post(
    "/actions/quarantine",
    response_model=ActionAck,
    responses={401: {"model": ApiError}, 403: {"model": ApiError}, 429: {"model": ApiError}},
)
async def action_quarantine(
    req: QuarantineRequest,
    background: BackgroundTasks,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> ActionAck:
    await RL.check(principal.subject)
    if principal.kind not in ("service",):
        raise HTTPException(status_code=403, detail="only service can issue quarantine")
    action_id = _uuid()
    background.add_task(
        _enqueue,
        "edr.actions",
        {"type": "quarantine", "action_id": str(action_id), "payload": req.dict(), "request_id": x_request_id, "ts": _now().isoformat()},
    )
    return ActionAck(action_id=action_id, status="queued")

# -----------------------------------------------------------------------------
# Artifact upload (form-data or URL)
# -----------------------------------------------------------------------------
@router.post(
    "/files/submit",
    response_model=FileSubmitResponse,
    responses={401: {"model": ApiError}, 413: {"model": ApiError}, 429: {"model": ApiError}},
)
async def submit_file(
    background: BackgroundTasks,
    principal: Principal = Depends(get_principal),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    file: Optional[UploadFile] = File(default=None),
    file_url: Optional[HttpUrl] = Form(default=None),
    hint_hash: Optional[str] = Form(default=None),
) -> FileSubmitResponse:
    await RL.check(principal.subject)
    upload_id = _uuid()

    if not file and not file_url:
        raise HTTPException(status_code=400, detail="either file or file_url is required")

    if file and file.size and file.size > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="file too large")

    if file:
        content = await file.read()
        sha256 = hashlib.sha256(content).hexdigest()
        background.add_task(
            _enqueue,
            "edr.artifacts",
            {"upload_id": str(upload_id), "source": "inline", "sha256": sha256, "size": len(content), "request_id": x_request_id},
        )
    else:
        background.add_task(
            _enqueue,
            "edr.artifacts",
            {"upload_id": str(upload_id), "source": "url", "url": str(file_url), "hint_hash": hint_hash, "request_id": x_request_id},
        )

    return FileSubmitResponse(upload_id=upload_id, stored=True)

# -----------------------------------------------------------------------------
# Health check (for LB)
# -----------------------------------------------------------------------------
@router.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {"status": "ok", "ts": _now().isoformat()}
