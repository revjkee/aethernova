# File: neuroforge-core/api/http/routers/v1/eval.py
# Production-grade Evaluation API router for FastAPI/Starlette.
# Features:
# - Idempotent create (Idempotency-Key header or run_key in body)
# - Strong validation (Pydantic), tenant scoping via headers
# - ETag/Last-Modified with 304 for GET by id and report
# - Robust list filtering (time window, status, ids, tags), pagination (page/limit or cursor)
# - Cancel and retry actions with 202 Accepted semantics
# - Sparse fieldsets (fields=...) to cut payload size
# - Clean separation: service layer injected via app.state.eval_service
# - Consistent error responses

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, Union
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, UUID4, constr, conint, root_validator, validator

# Optional: if SQLAlchemy is used for db session injection
try:
    from sqlalchemy.orm import Session  # type: ignore
except Exception:  # pragma: no cover
    Session = Any  # type: ignore


# ----------------------------- Security / Tenancy -----------------------------

class TenantContext(BaseModel):
    tenant_id: UUID4 = Field(..., description="Tenant UUID")
    actor: Optional[constr(strip_whitespace=True, min_length=1, max_length=256)] = Field(
        None, description="User or service principal"
    )

def get_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
    x_actor: Optional[str] = Header(None, alias="X-Actor"),
) -> TenantContext:
    try:
        tid = UUID(x_tenant_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid X-Tenant-ID")
    return TenantContext(tenant_id=UUID4(str(tid)), actor=x_actor or "anonymous")


# ----------------------------- Service Protocol ------------------------------

class EvalStatus(str):
    pass

class EvalService(Protocol):
    """
    Service layer contract expected by this router.
    The concrete implementation should be attached to app.state.eval_service.
    """

    # Create or return existing by idempotency key (tenant_id, run_key)
    def create_eval(
        self,
        db: Session,
        tenant_id: UUID,
        payload: Dict[str, Any],
        run_key: Optional[str],
        idempotency_key: Optional[str],
        actor: Optional[str],
        background: Optional[BackgroundTasks] = None,
    ) -> Dict[str, Any]:
        ...

    # Get single evaluation by id with tenant isolation
    def get_eval(self, db: Session, tenant_id: UUID, eval_id: UUID) -> Optional[Dict[str, Any]]:
        ...

    # Return a JSON-like report view for the evaluation (metrics, summary, artifacts)
    def get_eval_report(self, db: Session, tenant_id: UUID, eval_id: UUID) -> Optional[Dict[str, Any]]:
        ...

    # List evaluations with filters and pagination, returns items and next cursor (if any)
    def list_evals(
        self,
        db: Session,
        tenant_id: UUID,
        filters: Dict[str, Any],
        pagination: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        ...

    # Cancel a running evaluation
    def cancel_eval(self, db: Session, tenant_id: UUID, eval_id: UUID, actor: Optional[str]) -> Dict[str, Any]:
        ...

    # Retry a finished/failed evaluation (new run with linkage)
    def retry_eval(
        self, db: Session, tenant_id: UUID, eval_id: UUID, actor: Optional[str], background: Optional[BackgroundTasks]
    ) -> Dict[str, Any]:
        ...

    # Optional: attach or update artifacts URI
    def set_artifacts_uri(
        self, db: Session, tenant_id: UUID, eval_id: UUID, artifacts_uri: str, actor: Optional[str]
    ) -> Dict[str, Any]:
        ...


def _get_eval_service(request: Request) -> EvalService:
    svc = getattr(request.app.state, "eval_service", None)
    if svc is None:
        raise HTTPException(status_code=500, detail="Evaluation service is not configured")
    return svc


# ----------------------------- Pydantic Schemas ------------------------------

EvalStatusEnum = Literal["queued", "running", "succeeded", "failed", "canceled"]

class EvalCreateRequest(BaseModel):
    model_id: Optional[UUID4] = Field(None)
    dataset_id: Optional[UUID4] = Field(None)
    model_version: Optional[str] = Field(None, max_length=128)
    artifact_version: Optional[str] = Field(None, max_length=128)
    tags: List[constr(strip_whitespace=True, min_length=1, max_length=64)] = Field(default_factory=list)
    params: Dict[str, Any] = Field(default_factory=dict, description="Evaluation parameters")
    run_key: Optional[constr(strip_whitespace=True, min_length=1, max_length=200)] = Field(
        None, description="Idempotency key unique per tenant; overrides header if provided"
    )

class EvalItem(BaseModel):
    eval_id: UUID4
    tenant_id: UUID4
    status: EvalStatusEnum
    started_at: datetime
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    model_id: Optional[UUID4]
    dataset_id: Optional[UUID4]
    model_version: Optional[str]
    artifact_version: Optional[str]
    tags: List[str] = []
    artifact_uri: Optional[str] = Field(None, alias="artifacts_uri")
    evidence_uri: Optional[str]
    commit_sha: Optional[str]
    summary: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None
    slsa_provenance: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        allow_population_by_field_name = True

class EvalListResponse(BaseModel):
    items: List[EvalItem]
    next_cursor: Optional[str] = None
    total: Optional[int] = Field(None, description="Optional total if service provides it")

class EvalReportResponse(BaseModel):
    eval: EvalItem
    report: Dict[str, Any]

class SetArtifactsRequest(BaseModel):
    artifacts_uri: constr(strip_whitespace=True, min_length=1, max_length=2048)


# ----------------------------- Helpers ---------------------------------------

def _dt(dt: Union[str, datetime, None]) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, str):
        return datetime.fromisoformat(dt.replace("Z", "+00:00")).astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)

def _etag_from(obj: Dict[str, Any]) -> str:
    # Strong ETag from id + updated_at + status to ensure freshness
    eid = str(obj.get("eval_id", ""))
    upd = _dt(obj.get("updated_at"))
    st = obj.get("status", "")
    payload = f"{eid}|{st}|{upd.isoformat() if upd else ''}".encode()
    return '"' + hashlib.sha256(payload).hexdigest() + '"'

def _last_modified_from(obj: Dict[str, Any]) -> Optional[str]:
    upd = _dt(obj.get("updated_at"))
    return upd.strftime("%a, %d %b %Y %H:%M:%S GMT") if upd else None

def _apply_sparse_fields(item: Dict[str, Any], fields: Optional[List[str]]) -> Dict[str, Any]:
    if not fields:
        return item
    return {k: v for k, v in item.items() if k in fields}


# ----------------------------- Router ----------------------------------------

router = APIRouter(prefix="/api/v1/evals", tags=["evals"])


# Create evaluation (idempotent)
@router.post(
    "",
    response_model=EvalItem,
    status_code=status.HTTP_201_CREATED,
    summary="Start or register model evaluation (idempotent)",
)
def create_eval(
    request: Request,
    payload: EvalCreateRequest = Body(...),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),  # adapt to your DI
    background: BackgroundTasks = Depends(),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    run_key = payload.run_key or idempotency_key
    item = svc.create_eval(
        db=db,
        tenant_id=UUID(str(tenant.tenant_id)),
        payload=payload.dict(exclude_unset=True),
        run_key=run_key,
        idempotency_key=idempotency_key,
        actor=tenant.actor,
        background=background,
    )
    return item


# Get evaluation by id with cache semantics
@router.get(
    "/{eval_id}",
    response_model=EvalItem,
    summary="Get evaluation status by id",
)
def get_eval(
    request: Request,
    response: Response,
    eval_id: UUID4 = Path(...),
    fields: Optional[str] = Query(None, description="Comma-separated field names for sparse response"),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    if_modified_since: Optional[str] = Header(None, alias="If-Modified-Since"),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
):
    obj = svc.get_eval(db, UUID(str(tenant.tenant_id)), UUID(str(eval_id)))
    if not obj:
        raise HTTPException(status_code=404, detail="Evaluation not found")

    etag = _etag_from(obj)
    last_mod = _last_modified_from(obj)

    # Conditional GET
    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        if last_mod:
            response.headers["Last-Modified"] = last_mod
        response.headers["ETag"] = etag
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    # If-Modified-Since (weak check)
    if if_modified_since and last_mod and if_modified_since == last_mod:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        response.headers["ETag"] = etag
        response.headers["Last-Modified"] = last_mod
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    # Sparse fields
    field_list = [f.strip() for f in fields.split(",")] if fields else None
    data = _apply_sparse_fields(obj, field_list)

    # Set caching headers
    response.headers["Cache-Control"] = "private, max-age=5"
    response.headers["ETag"] = etag
    if last_mod:
        response.headers["Last-Modified"] = last_mod
    return data


# Get evaluation report
@router.get(
    "/{eval_id}/report",
    response_model=EvalReportResponse,
    summary="Get evaluation report (metrics, summary, artifacts)",
)
def get_eval_report(
    request: Request,
    response: Response,
    eval_id: UUID4 = Path(...),
    fields: Optional[str] = Query(None, description="Eval fields to include (comma-separated)"),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    if_modified_since: Optional[str] = Header(None, alias="If-Modified-Since"),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
):
    obj = svc.get_eval(db, UUID(str(tenant.tenant_id)), UUID(str(eval_id)))
    if not obj:
        raise HTTPException(status_code=404, detail="Evaluation not found")

    report = svc.get_eval_report(db, UUID(str(tenant.tenant_id)), UUID(str(eval_id))) or {}
    etag = _etag_from(obj)  # tie cache to eval updated_at/status
    last_mod = _last_modified_from(obj)

    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        response.headers["ETag"] = etag
        if last_mod:
            response.headers["Last-Modified"] = last_mod
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    if if_modified_since and last_mod and if_modified_since == last_mod:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        response.headers["ETag"] = etag
        response.headers["Last-Modified"] = last_mod
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    field_list = [f.strip() for f in fields.split(",")] if fields else None
    eval_data = _apply_sparse_fields(obj, field_list)

    response.headers["Cache-Control"] = "private, max-age=5"
    response.headers["ETag"] = etag
    if last_mod:
        response.headers["Last-Modified"] = last_mod

    return {"eval": eval_data, "report": report}


# List evaluations with filters and pagination
@router.get(
    "",
    response_model=EvalListResponse,
    summary="List evaluations with filters and pagination",
)
def list_evals(
    request: Request,
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
    # Filters
    status_in: Optional[str] = Query(None, description="Comma-separated statuses"),
    model_id: Optional[UUID4] = Query(None),
    dataset_id: Optional[UUID4] = Query(None),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    q: Optional[str] = Query(None, description="Free-text search in summary/metrics"),
    started_from: Optional[datetime] = Query(None),
    started_to: Optional[datetime] = Query(None),
    # Pagination (either page/limit or cursor)
    page: Optional[conint(ge=1)] = Query(None),
    limit: conint(ge=1, le=200) = Query(50),
    cursor: Optional[str] = Query(None, description="Opaque cursor from previous response"),
    fields: Optional[str] = Query(None, description="Comma-separated field names to include"),
):
    filters: Dict[str, Any] = {}
    if status_in:
        statuses = [s.strip() for s in status_in.split(",") if s.strip()]
        filters["status_in"] = statuses
    if model_id:
        filters["model_id"] = str(model_id)
    if dataset_id:
        filters["dataset_id"] = str(dataset_id)
    if tag:
        filters["tag"] = tag
    if q:
        filters["query"] = q
    if started_from:
        filters["started_from"] = _dt(started_from).isoformat()
    if started_to:
        filters["started_to"] = _dt(started_to).isoformat()

    pagination: Dict[str, Any] = {"limit": int(limit)}
    if cursor:
        pagination["cursor"] = cursor
    elif page:
        pagination["page"] = int(page)

    items, next_cursor = svc.list_evals(
        db, UUID(str(tenant.tenant_id)), filters=filters, pagination=pagination
    )

    field_list = [f.strip() for f in fields.split(",")] if fields else None
    if field_list:
        items = [_apply_sparse_fields(i, field_list) for i in items]

    return {"items": items, "next_cursor": next_cursor}


# Cancel evaluation
@router.post(
    "/{eval_id}/cancel",
    response_model=EvalItem,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Cancel a running evaluation",
)
def cancel_eval(
    request: Request,
    eval_id: UUID4 = Path(...),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
):
    try:
        item = svc.cancel_eval(db, UUID(str(tenant.tenant_id)), UUID(str(eval_id)), actor=tenant.actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    except ValueError as e:
        # e.g., invalid state transition
        raise HTTPException(status_code=409, detail=str(e))
    return item


# Retry evaluation
@router.post(
    "/{eval_id}/retry",
    response_model=EvalItem,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Retry evaluation (new run linked to original)",
)
def retry_eval(
    request: Request,
    background: BackgroundTasks,
    eval_id: UUID4 = Path(...),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
):
    try:
        item = svc.retry_eval(
            db, UUID(str(tenant.tenant_id)), UUID(str(eval_id)), actor=tenant.actor, background=background
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return item


# Set or update artifacts URI
@router.put(
    "/{eval_id}/artifacts",
    response_model=EvalItem,
    summary="Attach or update artifacts URI for the evaluation",
)
def set_artifacts(
    request: Request,
    eval_id: UUID4 = Path(...),
    body: SetArtifactsRequest = Body(...),
    tenant: TenantContext = Depends(get_tenant_context),
    svc: EvalService = Depends(_get_eval_service),
    db: Session = Depends(lambda: getattr(request.app.state, "db_session", None)),
):
    try:
        item = svc.set_artifacts_uri(
            db, UUID(str(tenant.tenant_id)), UUID(str(eval_id)), artifacts_uri=body.artifacts_uri, actor=tenant.actor
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    return item


# ----------------------------- Error schema ----------------------------------

class ErrorResponse(BaseModel):
    detail: str

# FastAPI uses {"detail": "..."} by default; kept for documentation completeness.
