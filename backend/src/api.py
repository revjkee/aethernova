# backend/src/api.py
"""
Industrial-grade FastAPI API router.

Features:
- Typed APIRouter with OpenAPI-friendly models and tags.
- Health/Readiness/Version endpoints with stable JSON envelopes.
- Request correlation: X-Request-ID propagation (generate if missing).
- Optional API key auth via env (APP_API_KEY). If not set, auth is bypassed.
- Idempotency support: X-Idempotency-Key is echoed in responses.
- Deterministic compute endpoint (sha256) and structured echo for diagnostics.
- Pagination helpers with strict validation and RFC 7231 friendly headers.

This module exposes: `router` for inclusion in the main FastAPI app.
"""

from __future__ import annotations

import hashlib
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, NonNegativeInt, PositiveInt, constr, validator

# ---------------------------
# Utilities & constants
# ---------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _service_name_default() -> str:
    return os.getenv("APP_NAME", "backend")

def _service_version_default() -> str:
    return os.getenv("APP_VERSION", "0.1.0")

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"

# ---------------------------
# Security / Dependencies
# ---------------------------

class SecurityContext(BaseModel):
    request_id: str
    api_key_authenticated: bool = False
    idempotency_key: Optional[str] = None

def _gen_request_id() -> str:
    return str(uuid.uuid4())

async def security_dependency(
    response: Response,
    x_request_id: Annotated[Optional[str], Header(alias="X-Request-ID")] = None,
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    x_idempotency_key: Annotated[Optional[str], Header(alias="X-Idempotency-Key")] = None,
) -> SecurityContext:
    """
    - Ensures a request id exists and is returned.
    - If APP_API_KEY is set, requires matching X-API-Key.
    - Echoes idempotency key if present.
    """
    req_id = x_request_id or _gen_request_id()
    response.headers["X-Request-ID"] = req_id
    if x_idempotency_key:
        response.headers["X-Idempotency-Key"] = x_idempotency_key

    expected_api_key = os.getenv("APP_API_KEY")
    authed = True
    if expected_api_key:
        authed = (x_api_key == expected_api_key)
        if not authed:
            # Do not reveal whether key is configured; generic 401 with WWW-Authenticate
            response.headers["WWW-Authenticate"] = "API-Key"
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized",
            )

    return SecurityContext(
        request_id=req_id,
        api_key_authenticated=authed,
        idempotency_key=x_idempotency_key,
    )

Sec = Annotated[SecurityContext, Depends(security_dependency)]

# ---------------------------
# Schemas
# ---------------------------

class Meta(BaseModel):
    request_id: str = Field(..., description="Correlation ID for tracing")
    idempotency_key: Optional[str] = Field(
        None, description="Echo of X-Idempotency-Key if provided"
    )
    timestamp: str = Field(..., description="Response UTC ISO-8601 timestamp")

class HealthResponse(BaseModel):
    status: constr(regex="^(ok|degraded|fail)$") = "ok"
    service: str = Field(default_factory=_service_name_default)
    version: str = Field(default_factory=_service_version_default)
    hostname: str = Field(default_factory=_hostname)
    meta: Meta

class ReadinessProbe(BaseModel):
    name: str
    ready: bool
    detail: Optional[str] = None

class ReadinessResponse(BaseModel):
    ready: bool
    checks: list[ReadinessProbe]
    meta: Meta

class VersionResponse(BaseModel):
    service: str = Field(default_factory=_service_name_default)
    version: str = Field(default_factory=_service_version_default)
    build_hash: Optional[str] = Field(
        default=os.getenv("APP_BUILD_HASH"), description="Git SHA or CI build hash"
    )
    meta: Meta

class EchoRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    note: Optional[str] = None

class EchoResponse(BaseModel):
    received: Dict[str, Any]
    note: Optional[str] = None
    meta: Meta

class Sha256Response(BaseModel):
    algorithm: str = "sha256"
    hex_digest: str
    length_bytes: NonNegativeInt
    meta: Meta

class PaginatedParams(BaseModel):
    page: PositiveInt = Field(1, ge=1)
    size: PositiveInt = Field(20, ge=1, le=int(os.getenv("PAGE_SIZE_MAX", "200")))
    @validator("size")
    def _ensure_bounds(cls, v: int) -> int:
        # Explicitly cap size at PAGE_SIZE_MAX to prevent abuse.
        cap = int(os.getenv("PAGE_SIZE_MAX", "200"))
        return min(v, cap)

class PaginatedResponse(BaseModel):
    items: list[Dict[str, Any]]
    page: PositiveInt
    size: PositiveInt
    total: NonNegativeInt
    meta: Meta

# ---------------------------
# Router
# ---------------------------

router = APIRouter()

def _meta(ctx: SecurityContext) -> Meta:
    return Meta(request_id=ctx.request_id, idempotency_key=ctx.idempotency_key, timestamp=_utc_now_iso())

# ---------- Health ----------

@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["ops"],
    summary="Liveness probe",
)
async def health(_: Sec) -> HealthResponse:
    return HealthResponse(
        status="ok",
        meta=_meta(_),
    )

# --------- Readiness --------

async def _check_dependencies() -> list[ReadinessProbe]:
    """
    Placeholders for real checks (DB, cache, broker, external APIs).
    Each check is granular and non-blocking where possible.
    """
    checks: list[ReadinessProbe] = []
    # Example checks (return ready=True by default to avoid false negatives):
    checks.append(ReadinessProbe(name="process", ready=True))
    if os.getenv("APP_API_KEY"):
        checks.append(ReadinessProbe(name="api_key_configured", ready=True))
    else:
        checks.append(ReadinessProbe(name="api_key_configured", ready=True, detail="not required"))
    return checks

@router.get(
    "/ready",
    response_model=ReadinessResponse,
    tags=["ops"],
    summary="Readiness probe",
)
async def ready(_: Sec) -> ReadinessResponse:
    checks = await _check_dependencies()
    all_ready = all(c.ready for c in checks)
    return ReadinessResponse(ready=all_ready, checks=checks, meta=_meta(_))

# --------- Version ----------

@router.get(
    "/version",
    response_model=VersionResponse,
    tags=["ops"],
    summary="Service version and build info",
)
async def version(_: Sec) -> VersionResponse:
    return VersionResponse(meta=_meta(_))

# -------- Diagnostics -------

@router.post(
    "/api/v1/echo",
    response_model=EchoResponse,
    tags=["v1", "diagnostics"],
    summary="Echo payload for debugging and contract tests",
)
async def echo(data: EchoRequest, _: Sec, request: Request) -> EchoResponse:
    # Include a minimal set of request headers for contract tests
    received = dict(data.payload or {})
    # Prevent accidental sensitive header leakage; expose only whitelisted headers
    safe_headers = {h: request.headers.get(h) for h in ("user-agent", "x-request-id") if h in request.headers}
    received["_headers"] = safe_headers
    return EchoResponse(received=received, note=data.note, meta=_meta(_))

# --------- Compute ----------

@router.get(
    "/api/v1/compute/sha256",
    response_model=Sha256Response,
    tags=["v1", "compute"],
    summary="Compute SHA-256 hex digest of provided input",
)
async def compute_sha256(
    _: Sec,
    data: Annotated[str, Query(min_length=1, max_length=1024, description="Arbitrary small string to hash")],
) -> Sha256Response:
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return Sha256Response(hex_digest=digest, length_bytes=len(data.encode("utf-8")), meta=_meta(_))

# -------- Pagination demo ----

@router.get(
    "/api/v1/items",
    response_model=PaginatedResponse,
    tags=["v1", "examples"],
    summary="List items (example with strict pagination)",
)
async def list_items(
    _: Sec,
    page: Annotated[int, Query(ge=1, description="Page number starting from 1")] = 1,
    size: Annotated[int, Query(ge=1, le=int(os.getenv("PAGE_SIZE_MAX", "200")), description="Page size")] = 20,
    background: BackgroundTasks = None,  # placeholder for async tasks like audit logging
) -> PaginatedResponse:
    # In real code, fetch from DB with LIMIT/OFFSET and total count
    params = PaginatedParams(page=page, size=size)
    items: list[Dict[str, Any]] = []
    total = 0
    # Example background hook
    if background is not None:
        # No-op placeholder (e.g., write audit record)
        background.add_task(lambda: None)
    return PaginatedResponse(items=items, page=params.page, size=params.size, total=total, meta=_meta(_))

# ------------- Root ----------

@router.get(
    "/",
    tags=["public"],
    summary="Root endpoint",
)
async def root(_: Sec) -> Dict[str, Any]:
    return {
        "service": _service_name_default(),
        "version": _service_version_default(),
        "endpoints": ["/health", "/ready", "/version", "/api/v1/echo", "/api/v1/compute/sha256", "/api/v1/items"],
        "meta": _meta(_).dict(),
    }

# ---------------------------
# Public export
# ---------------------------

__all__ = ["router"]
