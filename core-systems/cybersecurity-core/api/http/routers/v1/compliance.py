# cybersecurity-core/api/http/routers/v1/compliance.py
# -*- coding: utf-8 -*-
"""
FastAPI router for Compliance API (v1).

Industrial features:
- Strict Pydantic models (create/update/view)
- OAuth2-like scopes check via Security dependency
- RFC7807 Problem+JSON error responses
- Optimistic concurrency via ETag/If-Match (revision)
- Idempotency-Key passthrough for mutating requests
- Cursorless pagination (limit/offset) with sane caps
- Filtering (status/severity/tags/search)
- Evidence upload (multipart) with background processing hook
- Aggregated summary endpoint
- Correlation IDs via X-Correlation-ID (generated if absent)

This router is persistence-agnostic: all storage is delegated to service layer
via Protocols. Wire real implementations in app startup or test overrides.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Protocol, Sequence, Tuple, Union

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    Security,
    UploadFile,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, UUID4, constr, validator

# -----------------------------------------------------------------------------
# Logging (structured-friendly)
# -----------------------------------------------------------------------------
logger = logging.getLogger("compliance_router")
if not logger.handlers:
    _h = logging.StreamHandler()
    _fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    _h.setFormatter(_fmt)
    logger.addHandler(_h)
    logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Common constants & helpers
# -----------------------------------------------------------------------------
MAX_LIMIT = 200
DEFAULT_LIMIT = 50


def _coalesce_correlation(correlation_id: Optional[str]) -> str:
    return correlation_id or str(uuid.uuid4())


def _etag_from_revision(revision: int) -> str:
    # Weak ETag by convention: W/"<rev>"
    return f'W/"{revision}"'


# -----------------------------------------------------------------------------
# RFC7807 Problem Details
# -----------------------------------------------------------------------------
class Problem(BaseModel):
    type: Optional[str] = Field(default="about:blank")
    title: Optional[str] = None
    status: Optional[int] = None
    detail: Optional[str] = None
    instance: Optional[str] = None
    trace_id: Optional[str] = None
    errors: Optional[Dict[str, Any]] = None


def problem_exc(
    status_code: int,
    title: str,
    *,
    detail: Optional[str] = None,
    trace_id: Optional[str] = None,
    errors: Optional[Dict[str, Any]] = None,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=Problem(title=title, status=status_code, detail=detail, trace_id=trace_id, errors=errors).dict(),
    )


# -----------------------------------------------------------------------------
# Security (scopes)
# -----------------------------------------------------------------------------
bearer = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    sub: str
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)


async def get_principal(
    creds: Optional[HTTPAuthorizationCredentials] = Security(bearer),
    x_scopes: Optional[str] = Header(default=None, alias="X-Scopes"),
) -> Principal:
    """
    Minimal, pluggable principal resolver.
    In production, replace via app.dependency_overrides with JWT validation.
    Dev fallback:
      - Any bearer token accepted.
      - Scopes are taken from X-Scopes header as space- or comma-separated list.
    """
    if creds is None:
        # Anonymous principal with read-only scope for non-sensitive endpoints, or reject on write
        return Principal(sub="anonymous", scopes=[])
    token_value = creds.credentials.strip()
    scopes: List[str] = []
    if x_scopes:
        scopes = [s.strip() for s in x_scopes.replace(",", " ").split() if s.strip()]
    # NOTE: Replace with real JWT decode & scope extraction.
    return Principal(sub=f"token:{hashlib.sha256(token_value.encode()).hexdigest()[:12]}", scopes=scopes)


def require_scopes(required: Sequence[str]):
    async def _checker(principal: Principal = Depends(get_principal)) -> Principal:
        missing = [s for s in required if s not in principal.scopes]
        if missing:
            raise problem_exc(
                status.HTTP_403_FORBIDDEN,
                title="Insufficient scope",
                detail=f"Required scopes: {', '.join(required)}",
            )
        return principal

    return _checker


# -----------------------------------------------------------------------------
# Domain models (API schemas)
# -----------------------------------------------------------------------------
Severity = Literal["low", "medium", "high", "critical"]
ControlStatus = Literal["not_covered", "partial", "full", "waived"]
EvidenceStatus = Literal["pending", "verified", "rejected"]
AuditStatus = Literal["planned", "in_progress", "completed"]

Tag = constr(strip_whitespace=True, min_length=1, max_length=48, regex=r"^[a-z0-9_\-\.]+$")


class PageMeta(BaseModel):
    limit: int = Field(ge=1, le=MAX_LIMIT)
    offset: int = Field(ge=0)
    total: Optional[int] = None


class FrameworkBase(BaseModel):
    key: constr(strip_whitespace=True, min_length=2, max_length=64, regex=r"^[a-z0-9_\-\.]+$")
    name: constr(strip_whitespace=True, min_length=2, max_length=200)
    version: constr(strip_whitespace=True, min_length=1, max_length=40)
    description: Optional[constr(strip_whitespace=True, max_length=4000)] = None
    tags: List[Tag] = Field(default_factory=list)


class FrameworkCreate(FrameworkBase):
    pass


class FrameworkUpdate(BaseModel):
    name: Optional[FrameworkBase.__fields__["name"].type_] = None  # type: ignore
    version: Optional[FrameworkBase.__fields__["version"].type_] = None  # type: ignore
    description: Optional[FrameworkBase.__fields__["description"].type_] = None  # type: ignore
    tags: Optional[List[Tag]] = None


class FrameworkView(FrameworkBase):
    id: UUID4
    created_at: datetime
    updated_at: datetime
    revision: int = Field(ge=0)


class ControlBase(BaseModel):
    key: constr(strip_whitespace=True, min_length=2, max_length=64, regex=r"^[A-Z0-9_\-\.]+$")
    title: constr(strip_whitespace=True, min_length=2, max_length=300)
    description: Optional[constr(strip_whitespace=True, max_length=4000)] = None
    severity: Severity = "medium"
    status: ControlStatus = "not_covered"
    owner: Optional[constr(strip_whitespace=True, max_length=120)] = None
    mappings: List[constr(strip_whitespace=True, max_length=128)] = Field(default_factory=list)
    tags: List[Tag] = Field(default_factory=list)
    evidence_required: bool = False

    @validator("mappings", each_item=True)
    def _non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("mapping cannot be empty")
        return v


class ControlCreate(ControlBase):
    pass


class ControlUpdate(BaseModel):
    title: Optional[ControlBase.__fields__["title"].type_] = None  # type: ignore
    description: Optional[ControlBase.__fields__["description"].type_] = None  # type: ignore
    severity: Optional[Severity] = None
    status: Optional[ControlStatus] = None
    owner: Optional[ControlBase.__fields__["owner"].type_] = None  # type: ignore
    mappings: Optional[List[str]] = None
    tags: Optional[List[Tag]] = None
    evidence_required: Optional[bool] = None


class ControlView(ControlBase):
    id: UUID4
    framework_id: UUID4
    created_at: datetime
    updated_at: datetime
    revision: int = Field(ge=0)


class EvidenceMeta(BaseModel):
    description: Optional[constr(strip_whitespace=True, max_length=2000)] = None
    tags: List[Tag] = Field(default_factory=list)


class EvidenceView(BaseModel):
    id: UUID4
    control_id: UUID4
    filename: str
    content_type: str
    size: int
    hash_sha256: Optional[str] = None
    uploaded_by: str
    uploaded_at: datetime
    status: EvidenceStatus = "pending"
    notes: Optional[str] = None
    storage_url: Optional[str] = None


class AuditBase(BaseModel):
    title: constr(strip_whitespace=True, min_length=2, max_length=200)
    framework_id: UUID4
    description: Optional[constr(strip_whitespace=True, max_length=4000)] = None
    scheduled_at: Optional[datetime] = None


class AuditCreate(AuditBase):
    pass


class AuditUpdate(BaseModel):
    title: Optional[AuditBase.__fields__["title"].type_] = None  # type: ignore
    description: Optional[AuditBase.__fields__["description"].type_] = None  # type: ignore
    scheduled_at: Optional[datetime] = None
    status: Optional[AuditStatus] = None


class AuditView(AuditBase):
    id: UUID4
    status: AuditStatus = "planned"
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    revision: int = Field(ge=0)


class ListResponse(BaseModel):
    items: List[Any]
    page: PageMeta


class SummaryView(BaseModel):
    frameworks: int
    controls_total: int
    controls_by_status: Dict[ControlStatus, int]
    controls_by_severity: Dict[Severity, int]
    open_audits: int


# -----------------------------------------------------------------------------
# Service protocols (to be implemented elsewhere and injected via Depends)
# -----------------------------------------------------------------------------
class FrameworkService(Protocol):
    async def list(
        self, *, limit: int, offset: int, search: Optional[str], tags: Optional[List[str]]
    ) -> Tuple[List[FrameworkView], int]:
        ...

    async def create(self, *, payload: FrameworkCreate, correlation_id: str, idempotency_key: Optional[str]) -> FrameworkView:
        ...

    async def get(self, *, framework_id: UUID4) -> FrameworkView:
        ...

    async def update(
        self, *, framework_id: UUID4, patch: FrameworkUpdate, if_match: Optional[str]
    ) -> FrameworkView:
        ...

    async def delete(self, *, framework_id: UUID4, if_match: Optional[str]) -> None:
        ...


class ControlService(Protocol):
    async def list(
        self,
        *,
        framework_id: UUID4,
        limit: int,
        offset: int,
        status: Optional[ControlStatus],
        severity: Optional[Severity],
        tags: Optional[List[str]],
        search: Optional[str],
    ) -> Tuple[List[ControlView], int]:
        ...

    async def create(
        self, *, framework_id: UUID4, payload: ControlCreate, correlation_id: str, idempotency_key: Optional[str]
    ) -> ControlView:
        ...

    async def get(self, *, control_id: UUID4) -> ControlView:
        ...

    async def update(self, *, control_id: UUID4, patch: ControlUpdate, if_match: Optional[str]) -> ControlView:
        ...

    async def delete(self, *, control_id: UUID4, if_match: Optional[str]) -> None:
        ...


class EvidenceService(Protocol):
    async def ingest_stream(
        self,
        *,
        control_id: UUID4,
        filename: str,
        content_type: str,
        size: int,
        meta: EvidenceMeta,
        data_iter: Iterable[bytes],
        uploaded_by: str,
        correlation_id: str,
    ) -> EvidenceView:
        ...

    async def set_status(self, *, evidence_id: UUID4, status: EvidenceStatus, notes: Optional[str]) -> EvidenceView:
        ...

    async def list_for_control(self, *, control_id: UUID4, limit: int, offset: int) -> Tuple[List[EvidenceView], int]:
        ...


class AuditService(Protocol):
    async def list(self, *, limit: int, offset: int, status: Optional[AuditStatus]) -> Tuple[List[AuditView], int]:
        ...

    async def create(self, *, payload: AuditCreate, correlation_id: str, idempotency_key: Optional[str]) -> AuditView:
        ...

    async def get(self, *, audit_id: UUID4) -> AuditView:
        ...

    async def update(self, *, audit_id: UUID4, patch: AuditUpdate, if_match: Optional[str]) -> AuditView:
        ...

    async def delete(self, *, audit_id: UUID4, if_match: Optional[str]) -> None:
        ...


class SummaryService(Protocol):
    async def get_summary(self) -> SummaryView:
        ...


# -----------------------------------------------------------------------------
# Dependency providers (replace in app wiring)
# -----------------------------------------------------------------------------
async def get_framework_service() -> FrameworkService:
    raise problem_exc(status.HTTP_501_NOT_IMPLEMENTED, title="FrameworkService is not wired")


async def get_control_service() -> ControlService:
    raise problem_exc(status.HTTP_501_NOT_IMPLEMENTED, title="ControlService is not wired")


async def get_evidence_service() -> EvidenceService:
    raise problem_exc(status.HTTP_501_NOT_IMPLEMENTED, title="EvidenceService is not wired")


async def get_audit_service() -> AuditService:
    raise problem_exc(status.HTTP_501_NOT_IMPLEMENTED, title="AuditService is not wired")


async def get_summary_service() -> SummaryService:
    raise problem_exc(status.HTTP_501_NOT_IMPLEMENTED, title="SummaryService is not wired")


# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/compliance", tags=["Compliance"])


# Health / summary -------------------------------------------------------------
@router.get(
    "/summary",
    response_model=SummaryView,
    responses={403: {"model": Problem}, 500: {"model": Problem}},
)
async def get_summary(
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: SummaryService = Depends(get_summary_service),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-ID"),
):
    correlation_id = _coalesce_correlation(x_correlation_id)
    logger.info("Get compliance summary", extra={"correlation_id": correlation_id})
    return await svc.get_summary()


# Frameworks -------------------------------------------------------------------
@router.get(
    "/frameworks",
    response_model=ListResponse,
    responses={403: {"model": Problem}},
)
async def list_frameworks(
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: FrameworkService = Depends(get_framework_service),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(default=None, min_length=1, max_length=200),
    tags: Optional[List[str]] = Query(default=None),
):
    items, total = await svc.list(limit=limit, offset=offset, search=search, tags=tags)
    return ListResponse(items=items, page=PageMeta(limit=limit, offset=offset, total=total))


@router.post(
    "/frameworks",
    response_model=FrameworkView,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 409: {"model": Problem}},
)
async def create_framework(
    payload: FrameworkCreate,
    background: BackgroundTasks,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: FrameworkService = Depends(get_framework_service),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-ID"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    correlation_id = _coalesce_correlation(x_correlation_id)
    fw = await svc.create(payload=payload, correlation_id=correlation_id, idempotency_key=idempotency_key)
    return fw


@router.get(
    "/frameworks/{framework_id}",
    response_model=FrameworkView,
    responses={404: {"model": Problem}, 403: {"model": Problem}},
)
async def get_framework(
    framework_id: UUID4 = Path(...),
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: FrameworkService = Depends(get_framework_service),
    response: Response = None,
):
    fw = await svc.get(framework_id=framework_id)
    response.headers["ETag"] = _etag_from_revision(fw.revision)
    return fw


@router.patch(
    "/frameworks/{framework_id}",
    response_model=FrameworkView,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def update_framework(
    framework_id: UUID4,
    patch: FrameworkUpdate,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: FrameworkService = Depends(get_framework_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    response: Response = None,
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    fw = await svc.update(framework_id=framework_id, patch=patch, if_match=if_match)
    response.headers["ETag"] = _etag_from_revision(fw.revision)
    return fw


@router.delete(
    "/frameworks/{framework_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def delete_framework(
    framework_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:admin"])),
    svc: FrameworkService = Depends(get_framework_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    await svc.delete(framework_id=framework_id, if_match=if_match)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Controls ---------------------------------------------------------------------
@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=ListResponse,
    responses={403: {"model": Problem}, 404: {"model": Problem}},
)
async def list_controls(
    framework_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: ControlService = Depends(get_control_service),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    status_f: Optional[ControlStatus] = Query(default=None, alias="status"),
    severity: Optional[Severity] = Query(default=None),
    tags: Optional[List[str]] = Query(default=None),
    search: Optional[str] = Query(default=None, min_length=1, max_length=200),
):
    items, total = await svc.list(
        framework_id=framework_id,
        limit=limit,
        offset=offset,
        status=status_f,
        severity=severity,
        tags=tags,
        search=search,
    )
    return ListResponse(items=items, page=PageMeta(limit=limit, offset=offset, total=total))


@router.post(
    "/frameworks/{framework_id}/controls",
    response_model=ControlView,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}},
)
async def create_control(
    framework_id: UUID4,
    payload: ControlCreate,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: ControlService = Depends(get_control_service),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-ID"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    correlation_id = _coalesce_correlation(x_correlation_id)
    ctrl = await svc.create(
        framework_id=framework_id,
        payload=payload,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )
    return ctrl


@router.get(
    "/controls/{control_id}",
    response_model=ControlView,
    responses={403: {"model": Problem}, 404: {"model": Problem}},
)
async def get_control(
    control_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: ControlService = Depends(get_control_service),
    response: Response = None,
):
    ctrl = await svc.get(control_id=control_id)
    response.headers["ETag"] = _etag_from_revision(ctrl.revision)
    return ctrl


@router.patch(
    "/controls/{control_id}",
    response_model=ControlView,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def update_control(
    control_id: UUID4,
    patch: ControlUpdate,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: ControlService = Depends(get_control_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    response: Response = None,
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    ctrl = await svc.update(control_id=control_id, patch=patch, if_match=if_match)
    response.headers["ETag"] = _etag_from_revision(ctrl.revision)
    return ctrl


@router.delete(
    "/controls/{control_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def delete_control(
    control_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:admin"])),
    svc: ControlService = Depends(get_control_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    await svc.delete(control_id=control_id, if_match=if_match)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Evidence ---------------------------------------------------------------------
@router.get(
    "/controls/{control_id}/evidence",
    response_model=ListResponse,
    responses={403: {"model": Problem}, 404: {"model": Problem}},
)
async def list_evidence(
    control_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: EvidenceService = Depends(get_evidence_service),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
):
    items, total = await svc.list_for_control(control_id=control_id, limit=limit, offset=offset)
    return ListResponse(items=items, page=PageMeta(limit=limit, offset=offset, total=total))


@router.post(
    "/controls/{control_id}/evidence:upload",
    response_model=EvidenceView,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}},
)
async def upload_evidence(
    control_id: UUID4,
    file: UploadFile = File(...),
    meta: EvidenceMeta = Depends(),  # accepts form fields for meta
    background: BackgroundTasks = None,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: EvidenceService = Depends(get_evidence_service),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-ID"),
):
    correlation_id = _coalesce_correlation(x_correlation_id)

    async def _iter_file() -> Iterable[bytes]:
        chunk = await file.read(1024 * 1024)
        while chunk:
            yield chunk
            chunk = await file.read(1024 * 1024)

    # Stream to service (service decides on storage: S3, MinIO, filesystem)
    view = await svc.ingest_stream(
        control_id=control_id,
        filename=file.filename or "evidence.bin",
        content_type=file.content_type or "application/octet-stream",
        size=-1,
        meta=meta,
        data_iter=_iter_file(),
        uploaded_by=principal.sub,
        correlation_id=correlation_id,
    )
    return view


class EvidenceStatusUpdate(BaseModel):
    status: EvidenceStatus
    notes: Optional[constr(strip_whitespace=True, max_length=2000)] = None


@router.patch(
    "/evidence/{evidence_id}",
    response_model=EvidenceView,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}},
)
async def set_evidence_status(
    evidence_id: UUID4,
    payload: EvidenceStatusUpdate,
    principal: Principal = Depends(require_scopes(["compliance:admin"])),
    svc: EvidenceService = Depends(get_evidence_service),
):
    return await svc.set_status(evidence_id=evidence_id, status=payload.status, notes=payload.notes)


# Audits -----------------------------------------------------------------------
@router.get(
    "/audits",
    response_model=ListResponse,
    responses={403: {"model": Problem}},
)
async def list_audits(
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: AuditService = Depends(get_audit_service),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    status_f: Optional[AuditStatus] = Query(default=None, alias="status"),
):
    items, total = await svc.list(limit=limit, offset=offset, status=status_f)
    return ListResponse(items=items, page=PageMeta(limit=limit, offset=offset, total=total))


@router.post(
    "/audits",
    response_model=AuditView,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": Problem}, 403: {"model": Problem}},
)
async def create_audit(
    payload: AuditCreate,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: AuditService = Depends(get_audit_service),
    x_correlation_id: Optional[str] = Header(default=None, alias="X-Correlation-ID"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    correlation_id = _coalesce_correlation(x_correlation_id)
    return await svc.create(payload=payload, correlation_id=correlation_id, idempotency_key=idempotency_key)


@router.get(
    "/audits/{audit_id}",
    response_model=AuditView,
    responses={403: {"model": Problem}, 404: {"model": Problem}},
)
async def get_audit(
    audit_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:read"])),
    svc: AuditService = Depends(get_audit_service),
    response: Response = None,
):
    view = await svc.get(audit_id=audit_id)
    response.headers["ETag"] = _etag_from_revision(view.revision)
    return view


@router.patch(
    "/audits/{audit_id}",
    response_model=AuditView,
    responses={400: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def update_audit(
    audit_id: UUID4,
    patch: AuditUpdate,
    principal: Principal = Depends(require_scopes(["compliance:write"])),
    svc: AuditService = Depends(get_audit_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    response: Response = None,
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    view = await svc.update(audit_id=audit_id, patch=patch, if_match=if_match)
    response.headers["ETag"] = _etag_from_revision(view.revision)
    return view


@router.delete(
    "/audits/{audit_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}},
)
async def delete_audit(
    audit_id: UUID4,
    principal: Principal = Depends(require_scopes(["compliance:admin"])),
    svc: AuditService = Depends(get_audit_service),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    if not if_match:
        raise problem_exc(status.HTTP_428_PRECONDITION_REQUIRED, title="If-Match header required")
    await svc.delete(audit_id=audit_id, if_match=if_match)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -----------------------------------------------------------------------------
# Error handling notes for service implementers
# -----------------------------------------------------------------------------
"""
Service layer SHOULD raise HTTPException with Problem details in cases:
- 404 NOT FOUND when entity missing
- 409 CONFLICT for idempotency violation (duplicate with different payload)
- 412 PRECONDITION FAILED when If-Match does not match current revision
- 400 BAD REQUEST for validation at business level
Router transparently forwards these as-is.
"""

__all__ = ["router"]
