# physical-integration-core/api/http/routers/v1/telemetry.py
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

# -----------------------------------------------------------------------------
# Constants and knobs (tune per environment)
# -----------------------------------------------------------------------------

MAX_BATCH_POINTS = 10_000
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB
CLOCK_SKEW_ALLOW = timedelta(minutes=5)
DEFAULT_DOWNSAMPLE = "1m"  # server-side default interval
RATE_LIMIT_RPS = 500  # per tenant per process (coarse)
RATE_LIMIT_BURST = 1000

# -----------------------------------------------------------------------------
# Utilities: Tenant extraction, Request ID, Rate limiting, Idempotency
# -----------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def extract_tenant_id(
    request: Request,
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-ID"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> str:
    """
    Tries to extract tenant id from (priority):
      1) X-Tenant-ID header
      2) JWT in Authorization: Bearer <token> with 'tid' or 'tenant_id' claim (UNVERIFIED parsing)
    """
    if x_tenant_id:
        return x_tenant_id

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        parts = token.split(".")
        if len(parts) == 3:
            try:
                # Unverified decode of JWT payload (base64url)
                import base64
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "===")
                    .decode("utf-8", errors="ignore")
                )
                tid = payload.get("tid") or payload.get("tenant_id")
                if isinstance(tid, str) and tid:
                    return tid
            except Exception:
                pass
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_id is required")

# Simple in-process token buckets per tenant
_rate_buckets: Dict[str, Tuple[float, float]] = {}  # tenant -> (tokens, last_ts)

def rate_limit(tenant_id: str) -> None:
    now = time.monotonic()
    tokens, last = _rate_buckets.get(tenant_id, (RATE_LIMIT_BURST, now))
    elapsed = max(0.0, now - last)
    tokens = min(RATE_LIMIT_BURST, tokens + elapsed * RATE_LIMIT_RPS)
    if tokens < 1.0:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
    _rate_buckets[tenant_id] = (tokens - 1.0, now)

# Idempotency memory (per-process). For prod, back with Redis.
_idem_store: Dict[str, Tuple[float, str]] = {}  # key -> (expires_at_monotonic, response_hash)
IDEM_TTL_SECONDS = 15 * 60

def check_idempotency(idem_key: Optional[str], body_bytes: bytes) -> Optional[JSONResponse]:
    if not idem_key:
        return None
    # Body hash to ensure same request returns same response; different -> 409
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    entry = _idem_store.get(idem_key)
    now = time.monotonic()
    # purge expired
    if entry and entry[0] < now:
        _idem_store.pop(idem_key, None)
        entry = None
    if entry:
        stored_hash = entry[1]
        if stored_hash != body_hash:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Idempotency-Key conflict")
        # Return 202 cached acknowledgement (empty body to avoid heavy payload caching here)
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"status": "duplicate", "detail": "Already processed"})
    # Reserve slot, actual response hash is same body hash for acknowledgement
    _idem_store[idem_key] = (now + IDEM_TTL_SECONDS, body_hash)
    return None

# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------

class Quantity(BaseModel):
    value: float
    unit_ucum: str

class TelemetryPoint(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_\-:\.]+$")
    sensor_id: Optional[str] = Field(default=None, max_length=256)
    ts: datetime = Field(..., description="RFC3339 timestamp with timezone")
    values: Dict[str, float] = Field(..., min_items=1, description="Map of measurement fields")
    tags: Dict[str, str] = Field(default_factory=dict, description="Optional key/value tags")
    seq: Optional[int] = Field(default=None, ge=0, description="Monotonic sequence number per device")

    @field_validator("ts", mode="before")
    @classmethod
    def _ensure_tz(cls, v: Any) -> Any:
        # Parse string and ensure timezone-aware
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError("timestamp must be timezone-aware")
            return dt
        if isinstance(v, datetime) and v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v

class TelemetryBatch(BaseModel):
    points: List[TelemetryPoint] = Field(..., min_items=1, max_items=MAX_BATCH_POINTS)
    source: Optional[str] = Field(default=None, max_length=128)
    schema_version: Optional[str] = Field(default="1.0")
    compress: Optional[bool] = False

class IngestResult(BaseModel):
    accepted: int
    rejected: int
    errors: List[str] = Field(default_factory=list)

class SeriesQuery(BaseModel):
    device_id: str
    sensor_id: Optional[str] = None
    start: datetime
    end: datetime
    limit: int = Field(default=10_000, ge=1, le=100_000)
    fields: Optional[List[str]] = None
    downsample: Optional[str] = Field(default=None, description="e.g. 10s, 1m, 5m")

class SeriesPoint(BaseModel):
    ts: datetime
    values: Dict[str, float]

class SeriesResponse(BaseModel):
    device_id: str
    sensor_id: Optional[str] = None
    field_set: List[str]
    points: List[SeriesPoint]
    next_page_token: Optional[str] = None

# -----------------------------------------------------------------------------
# Repository interface (to be implemented/adapted in your app)
# -----------------------------------------------------------------------------

class TelemetryRepository:
    """Abstract repository for telemetry persistence and queries."""

    async def insert_points(self, tenant_id: str, batch: TelemetryBatch) -> IngestResult:
        """
        Persist points atomically or in chunks with internal deduplication by (tenant, device, ts, sensor, field-set, seq?).
        Implement retries and partial failure handling inside.
        """
        raise NotImplementedError

    async def query_series(
        self,
        tenant_id: str,
        q: SeriesQuery,
        page_token: Optional[str],
    ) -> SeriesResponse:
        """
        Return series points for the selection. The page_token can be an encoded cursor (e.g., base64 of last ts/offset).
        Handle downsample on DB side when supported (e.g., Timescale bucket + agg).
        """
        raise NotImplementedError

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------

async def get_repo() -> TelemetryRepository:
    # Wire your concrete repository here (DI container, app.state, etc.)
    # Example:
    # return request.app.state.telemetry_repo
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Repository not wired")

# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/v1/telemetry", tags=["telemetry"])

@router.get("/healthz", response_class=PlainTextResponse)
async def healthz() -> str:
    return "ok"

@router.get("/readyz", response_class=PlainTextResponse)
async def readyz(repo: TelemetryRepository = Depends(get_repo)) -> str:
    # Optionally perform a lightweight repo check (e.g., SELECT 1)
    return "ready"

# -----------------------------------------------------------------------------
# Ingest JSON batch
# -----------------------------------------------------------------------------

@router.post(
    "/ingest",
    response_model=IngestResult,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Accepted for processing"},
        400: {"description": "Validation or size error"},
        401: {"description": "Unauthorized"},
        409: {"description": "Idempotency conflict"},
        429: {"description": "Rate limited"},
        500: {"description": "Server error"},
    },
)
async def ingest_batch(
    request: Request,
    *,
    idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    tenant_id: str = Depends(extract_tenant_id),
    repo: TelemetryRepository = Depends(get_repo),
    batch: TelemetryBatch = Body(..., embed=False),
) -> IngestResult:
    # Rate limiting
    rate_limit(tenant_id)

    # Basic body size check (for non-streaming JSON)
    if request.headers.get("content-length"):
        try:
            if int(request.headers["content-length"]) > MAX_BODY_BYTES:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Body too large")
        except ValueError:
            pass

    # Idempotency pre-check (use the exact request body again if you prefer strict cache)
    # Here we approximate by hashing the parsed batch for simplicity.
    body_bytes = json.dumps(batch.model_dump(mode="json")).encode("utf-8")
    idem_resp = check_idempotency(idem_key, body_bytes)
    if idem_resp:
        # duplicate request; we respond with generic acknowledgement
        return IngestResult(accepted=0, rejected=0, errors=["duplicate"])

    # Validate timestamps and skew
    now = _utc_now()
    errors: List[str] = []
    for idx, p in enumerate(batch.points):
        if p.ts > now + CLOCK_SKEW_ALLOW:
            errors.append(f"point[{idx}]: future timestamp beyond allowed skew")
        if p.ts < now - timedelta(days=365 * 5):  # 5y old guardrail
            errors.append(f"point[{idx}]: timestamp too old")
    if errors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"errors": errors})

    # Persist via repository
    result = await repo.insert_points(tenant_id, batch)
    return result

# -----------------------------------------------------------------------------
# Ingest NDJSON (one JSON per line), for streaming collectors
# -----------------------------------------------------------------------------

@router.post(
    "/ingest/ndjson",
    response_model=IngestResult,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_ndjson(
    request: Request,
    *,
    idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    tenant_id: str = Depends(extract_tenant_id),
    repo: TelemetryRepository = Depends(get_repo),
) -> IngestResult:
    rate_limit(tenant_id)

    # Stream-read with manual size guard
    total = 0
    points: List[TelemetryPoint] = []
    async for raw_line in _iter_lines(request):
        total += len(raw_line)
        if total > MAX_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Body too large")
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            p = TelemetryPoint(**obj)
            points.append(p)
            if len(points) > MAX_BATCH_POINTS:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Too many points (> {MAX_BATCH_POINTS})")
        except ValidationError as ve:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"errors": ve.errors()})
        except json.JSONDecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid NDJSON line")

    batch = TelemetryBatch(points=points, source="ndjson")
    body_bytes = b"\n".join(json.dumps(p.model_dump(mode='json')).encode("utf-8") for p in points)
    idem_resp = check_idempotency(idem_key, body_bytes)
    if idem_resp:
        return IngestResult(accepted=0, rejected=0, errors=["duplicate"])

    now = _utc_now()
    for idx, p in enumerate(points):
        if p.ts > now + CLOCK_SKEW_ALLOW:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"point[{idx}]: future timestamp")

    return await repo.insert_points(tenant_id, batch)

async def _iter_lines(request: Request) -> AsyncIterator[bytes]:
    buf = bytearray()
    async for chunk in request.stream():
        if not isinstance(chunk, (bytes, bytearray)):
            continue
        for b in chunk:
            if b == 0x0A:  # '\n'
                yield bytes(buf)
                buf.clear()
            else:
                buf.append(b)
    if buf:
        yield bytes(buf)

# -----------------------------------------------------------------------------
# Query series
# -----------------------------------------------------------------------------

@router.get(
    "/series",
    response_model=SeriesResponse,
    status_code=status.HTTP_200_OK,
)
async def get_series(
    tenant_id: str = Depends(extract_tenant_id),
    repo: TelemetryRepository = Depends(get_repo),
    device_id: str = "",
    sensor_id: Optional[str] = None,
    start: datetime = Depends(),
    end: datetime = Depends(),
    limit: int = 10_000,
    fields: Optional[str] = None,
    downsample: Optional[str] = None,
    page_token: Optional[str] = None,
) -> SeriesResponse:
    rate_limit(tenant_id)
    if not device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id is required")
    if end <= start:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="end must be after start")
    field_list = [f.strip() for f in fields.split(",")] if fields else None
    q = SeriesQuery(
        device_id=device_id,
        sensor_id=sensor_id,
        start=start,
        end=end,
        limit=limit,
        fields=field_list,
        downsample=downsample or DEFAULT_DOWNSAMPLE,
    )
    return await repo.query_series(tenant_id, q, page_token)

# -----------------------------------------------------------------------------
# Error handlers (optional customization)
# -----------------------------------------------------------------------------

@router.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    # Attach correlation if present
    rid = request.headers.get("X-Request-ID")
    payload: Dict[str, Any] = {"detail": exc.detail}
    if rid:
        payload["request_id"] = rid
    return JSONResponse(status_code=exc.status_code, content=payload)

# -----------------------------------------------------------------------------
# How to include this router in your app:
#
# from fastapi import FastAPI
# from api.http.routers.v1.telemetry import router as telemetry_router
#
# app = FastAPI()
# app.include_router(telemetry_router)
#
# Implement TelemetryRepository and wire it in get_repo().
# -----------------------------------------------------------------------------
