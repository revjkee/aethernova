from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, ValidationError, constr

log = logging.getLogger("chronowatch.heartbeats")

router = APIRouter(prefix="/v1", tags=["heartbeats"])


# =========================
# Helpers & shared deps
# =========================

UTC = timezone.utc
TENANT_HDR = "X-Tenant-ID"
REQ_ID_HDR = "X-Request-ID"
SIG_HDR = "X-Signature-SHA256"
IDEMP_HDR = "Idempotency-Key"


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


class TenantContext(BaseModel):
    tenant_id: uuid.UUID
    request_id: str


async def tenant_ctx_dep(
    x_tenant_id: Optional[str] = Header(default=None, alias=TENANT_HDR),
    x_request_id: Optional[str] = Header(default=None, alias=REQ_ID_HDR),
) -> TenantContext:
    """
    Extracts tenant and request correlation id from headers.
    """
    if not x_tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-Tenant-ID is required")
    try:
        tenant = uuid.UUID(x_tenant_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="X-Tenant-ID must be UUID")
    req_id = x_request_id or str(uuid.uuid4())
    return TenantContext(tenant_id=tenant, request_id=req_id)


# =========================
# Domain models
# =========================

HeartbeatStatus = Literal["ok", "degraded", "down"]


class HeartbeatIn(BaseModel):
    service: constr(strip_whitespace=True, min_length=1, max_length=128) = Field(..., description="Service name")
    instance_id: constr(strip_whitespace=True, min_length=1, max_length=128) = Field(..., description="Instance ID")
    status: HeartbeatStatus = Field(..., description="Reported status")
    ts: datetime = Field(default_factory=now_utc, description="Event time (UTC or with tz)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Optional details payload")

    class Config:
        extra = "forbid"


class HeartbeatOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    service: str
    instance_id: str
    status: HeartbeatStatus
    ts: datetime
    received_at: datetime
    details: Dict[str, Any]


class HeartbeatLatestOut(BaseModel):
    service: str
    instance_id: Optional[str]
    latest: Optional[HeartbeatOut]
    freshness_seconds: Optional[int]


class ListHeartbeatsOut(BaseModel):
    items: List[HeartbeatOut]
    next_offset: Optional[str] = None


# =========================
# Repository protocol + in-memory impl
# =========================

class HeartbeatRepository(Protocol):
    async def record(
        self,
        tenant_id: uuid.UUID,
        hb: HeartbeatIn,
        idem_key: Optional[str],
    ) -> Tuple[HeartbeatOut, bool]:
        """
        Save heartbeat. Returns (saved_obj, created_new)
        If idem_key is provided and seen, must return previous object with created_new=False.
        """
        ...

    async def get_latest(
        self, tenant_id: uuid.UUID, service: str, instance_id: Optional[str]
    ) -> Optional[HeartbeatOut]:
        ...

    async def list(
        self,
        tenant_id: uuid.UUID,
        service: Optional[str],
        instance_id: Optional[str],
        limit: int,
        offset: Optional[str],
    ) -> Tuple[List[HeartbeatOut], Optional[str]]:
        ...

    async def health(self) -> bool:
        ...


class _InMemoryRepo(HeartbeatRepository):
    """
    Production code SHOULD replace this with a DB-backed repository.
    This impl is concurrency-safe and good for tests/dev.
    """
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # storage: tenant -> list[HeartbeatOut]
        self._store: Dict[uuid.UUID, List[HeartbeatOut]] = {}
        # idem cache with TTL: (tenant, key) -> (HeartbeatOut, expire_epoch)
        self._idem: Dict[Tuple[uuid.UUID, str], Tuple[HeartbeatOut, float]] = {}

    async def record(
        self, tenant_id: uuid.UUID, hb: HeartbeatIn, idem_key: Optional[str]
    ) -> Tuple[HeartbeatOut, bool]:
        async with self._lock:
            # idempotency check (~10 minutes TTL by default)
            if idem_key:
                key = (tenant_id, idem_key)
                hit = self._idem.get(key)
                if hit and hit[1] > time.time():
                    return hit[0], False

            out = HeartbeatOut(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                service=hb.service,
                instance_id=hb.instance_id,
                status=hb.status,
                ts=hb.ts.astimezone(UTC),
                received_at=now_utc(),
                details=hb.details or {},
            )
            self._store.setdefault(tenant_id, []).append(out)

            if idem_key:
                self._idem[(tenant_id, idem_key)] = (out, time.time() + 600.0)  # 10 min TTL

            return out, True

    async def get_latest(
        self, tenant_id: uuid.UUID, service: str, instance_id: Optional[str]
    ) -> Optional[HeartbeatOut]:
        async with self._lock:
            items = self._store.get(tenant_id, [])
            filtered = [x for x in items if x.service == service and (instance_id is None or x.instance_id == instance_id)]
            if not filtered:
                return None
            return max(filtered, key=lambda x: (x.ts, x.received_at))

    async def list(
        self,
        tenant_id: uuid.UUID,
        service: Optional[str],
        instance_id: Optional[str],
        limit: int,
        offset: Optional[str],
    ) -> Tuple[List[HeartbeatOut], Optional[str]]:
        async with self._lock:
            items = self._store.get(tenant_id, [])
            if service:
                items = [x for x in items if x.service == service]
            if instance_id:
                items = [x for x in items if x.instance_id == instance_id]
            # naive offset: encoded as ISO timestamp + id
            items.sort(key=lambda x: (x.ts, x.received_at), reverse=True)
            start = 0
            if offset:
                try:
                    ts_str, id_str = offset.split("|", 1)
                    mark_ts = datetime.fromisoformat(ts_str)
                    mark_id = uuid.UUID(id_str)
                    for idx, x in enumerate(items):
                        if x.ts == mark_ts and x.id == mark_id:
                            start = idx + 1
                            break
                except Exception:
                    start = 0
            page = items[start : start + limit]
            next_off = None
            if len(items) > start + limit:
                last = page[-1]
                next_off = f"{last.ts.isoformat()}|{last.id}"
            return page, next_off

    async def health(self) -> bool:
        return True


# Dependency factory (in prod replace with DB repository provider)
_repo_singleton: Optional[HeartbeatRepository] = None


async def get_repository() -> HeartbeatRepository:
    global _repo_singleton
    if _repo_singleton is None:
        _repo_singleton = _InMemoryRepo()
    return _repo_singleton


# =========================
# Rate limiter (per-tenant+service)
# =========================

class SimpleRateLimiter:
    """
    In-memory sliding window limiter for small-scale use.
    In prod, replace with Redis/Cluster limiter.
    """
    def __init__(self, max_events: int, window_sec: int) -> None:
        self.max_events = max_events
        self.window = window_sec
        self._lock = asyncio.Lock()
        self._buckets: Dict[str, List[float]] = {}  # key -> timestamps

    async def check(self, key: str) -> bool:
        now = time.time()
        async with self._lock:
            buf = self._buckets.setdefault(key, [])
            # drop old
            cutoff = now - self.window
            i = 0
            for i in range(len(buf)):
                if buf[i] >= cutoff:
                    break
            if i > 0:
                del buf[:i]
            if len(buf) >= self.max_events:
                return False
            buf.append(now)
            return True


_limiter = SimpleRateLimiter(max_events=int(os.getenv("HB_RATE_MAX", "30")), window_sec=int(os.getenv("HB_RATE_WIN", "5")))


async def rate_limit_dep(ctx: TenantContext, body: HeartbeatIn) -> None:
    key = f"{ctx.tenant_id}:{body.service}"
    allowed = await _limiter.check(key)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


# =========================
# Security: HMAC verification (optional)
# =========================

def verify_hmac(body_bytes: bytes, provided_sig: Optional[str]) -> None:
    """
    If env HB_HMAC_SECRET is present, require valid X-Signature-SHA256.
    """
    secret = os.getenv("HB_HMAC_SECRET")
    if not secret:
        return  # signature not required
    if not provided_sig:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{SIG_HDR} required")
    try:
        mac = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="HMAC computation failed")
    # constant-time compare
    if not hmac.compare_digest(mac, provided_sig.lower()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")


# =========================
# ETag utilities
# =========================

def etag_for_payload(payload: Any) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# =========================
# Health endpoints
# =========================

@router.get("/healthz", summary="Liveness probe", tags=["health"])
async def healthz() -> Dict[str, str]:
    return {"status": "ok", "ts": now_utc().isoformat()}


@router.get("/readyz", summary="Readiness probe", tags=["health"])
async def readyz(repo: HeartbeatRepository = Depends(get_repository)) -> Dict[str, str]:
    ok = await repo.health()
    if not ok:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="repository not ready")
    return {"status": "ready", "ts": now_utc().isoformat()}


# =========================
# Heartbeats API
# =========================

def _validate_ts(ts: datetime, skew_sec: int = 300) -> None:
    """
    Ensures ts is not too far from 'now' (±skew), prevents bogus clocks.
    """
    now = now_utc()
    # Normalize to aware UTC
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    ts = ts.astimezone(UTC)
    if ts > now + timedelta(seconds=skew_sec):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ts is in the future")
    if ts < now - timedelta(days=365 * 5):  # 5 years back guard
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ts too old")


@router.post(
    "/heartbeats",
    status_code=status.HTTP_201_CREATED,
    summary="Submit a heartbeat",
    response_model=HeartbeatOut,
)
async def submit_heartbeat(
    request: Request,
    response: Response,
    ctx: TenantContext = Depends(tenant_ctx_dep),
    repo: HeartbeatRepository = Depends(get_repository),
    _rl: None = Depends(rate_limit_dep),
    idem_key: Optional[str] = Header(default=None, alias=IDEMP_HDR),
    signature: Optional[str] = Header(default=None, alias=SIG_HDR),
) -> HeartbeatOut:
    """
    Accepts a heartbeat event from a service instance.
    Enforces optional HMAC, idempotency, time skew, and rate limits.
    """
    raw = await request.body()
    verify_hmac(raw, signature)

    try:
        payload = HeartbeatIn.model_validate_json(raw)  # pydantic v2
    except AttributeError:
        # pydantic v1 fallback
        try:
            payload = HeartbeatIn.parse_raw(raw)  # type: ignore[attr-defined]
        except ValidationError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())

    _validate_ts(payload.ts)

    saved, created = await repo.record(ctx.tenant_id, payload, idem_key)
    response.headers[REQ_ID_HDR] = ctx.request_id
    response.headers["ETag"] = etag_for_payload(saved.model_dump())
    if not created:
        # Idempotent replay -> 200 OK
        response.status_code = status.HTTP_200_OK
    return saved


@router.get(
    "/heartbeats/{service}/latest",
    response_model=HeartbeatLatestOut,
    summary="Get latest heartbeat for a service (optionally specific instance)",
)
async def get_latest_heartbeat(
    service: str,
    response: Response,
    ctx: TenantContext = Depends(tenant_ctx_dep),
    repo: HeartbeatRepository = Depends(get_repository),
    instance_id: Optional[str] = None,
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
) -> HeartbeatLatestOut:
    latest = await repo.get_latest(ctx.tenant_id, service, instance_id)
    body = HeartbeatLatestOut(
        service=service,
        instance_id=instance_id,
        latest=latest,
        freshness_seconds=(int((now_utc() - latest.ts).total_seconds()) if latest else None),
    )
    payload = body.model_dump()
    etag = etag_for_payload(payload)
    if if_none_match and if_none_match.strip('"') == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return body
    response.headers["ETag"] = f'"{etag}"'
    response.headers[REQ_ID_HDR] = ctx.request_id
    return body


@router.get(
    "/heartbeats",
    response_model=ListHeartbeatsOut,
    summary="List heartbeats with filters and pagination",
)
async def list_heartbeats(
    ctx: TenantContext = Depends(tenant_ctx_dep),
    repo: HeartbeatRepository = Depends(get_repository),
    service: Optional[str] = None,
    instance_id: Optional[str] = None,
    limit: int = 50,
    offset: Optional[str] = None,
) -> ListHeartbeatsOut:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="limit must be 1..500")
    items, next_off = await repo.list(ctx.tenant_id, service, instance_id, limit, offset)
    return ListHeartbeatsOut(items=items, next_offset=next_off)
