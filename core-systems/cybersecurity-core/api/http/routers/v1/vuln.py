# cybersecurity-core/api/http/routers/v1/vuln.py
# -*- coding: utf-8 -*-
"""
V1 Vulnerabilities Router (industrial-grade)

Requirements:
- Python 3.11+
- FastAPI 0.110+
- SQLAlchemy 2.0+ (async)
- Pydantic v2

Key features:
- Async SQLAlchemy session (imports project session if available; falls back to env DATABASE_URL)
- Per-request tenant isolation via `SET LOCAL app.current_org = :uuid` (RLS-compatible)
- Table autodiscovery (first match among: vuln_findings, vulnerabilities, security_vulnerabilities)
- Filtering (cve_id, severity, status, asset_id, time range, search), sorting, pagination
- Conditional GET with strong ETag and 304
- Safe INSERT/PATCH with column whitelisting based on live table reflection
- Clean error model and consistent responses
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, ConfigDict, UUID4
from sqlalchemy import MetaData, Table, func, inspect, select, text
from sqlalchemy.engine import Result
from sqlalchemy.exc import NoSuchTableError, ProgrammingError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/vuln", tags=["vuln"])

# -----------------------------------------------------------------------------
# Session provider (use project session if available, otherwise fallback)
# -----------------------------------------------------------------------------
_AsyncSessionMaker: Optional[async_sessionmaker[AsyncSession]] = None
_Engine: Optional[AsyncEngine] = None

try:
    # Preferred: project-wide session factory
    from core.db.session import get_async_session as _project_get_session  # type: ignore

    async def get_session() -> AsyncSession:
        return await _project_get_session()

    log.info("vuln.py: using project get_async_session")
except Exception:  # pragma: no cover - fallback path
    DB_URL = os.getenv("DATABASE_URL")
    if not DB_URL:
        log.warning("DATABASE_URL not set; router will raise 500 on first DB access")

    def _ensure_engine() -> Tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
        global _AsyncSessionMaker, _Engine
        if _Engine is None:
            if not DB_URL:
                raise RuntimeError("DATABASE_URL is required for fallback session")
            _Engine = create_async_engine(DB_URL, pool_pre_ping=True, future=True)
            _AsyncSessionMaker = async_sessionmaker(_Engine, expire_on_commit=False)
        return _Engine, _AsyncSessionMaker  # type: ignore

    async def get_session() -> AsyncSession:
        _, maker = _ensure_engine()
        async with maker() as session:  # type: ignore
            yield session

# -----------------------------------------------------------------------------
# RBAC/Scopes (hook to project RBAC if available)
# -----------------------------------------------------------------------------
class Principal(BaseModel):
    sub: str
    scopes: List[str] = Field(default_factory=list)


async def _project_principal_dep() -> Principal:
    """
    Try import project's auth principal, otherwise allow-all (for internal tests).
    """
    try:
        from core.auth.depends import get_principal  # type: ignore

        return await get_principal(required_scopes=None)  # type: ignore
    except Exception:  # pragma: no cover - fallback
        return Principal(sub="anonymous", scopes=["vuln:read", "vuln:write"])


def require_scopes(required: List[str]):
    async def _dep(principal: Principal = Depends(_project_principal_dep)) -> Principal:
        missing = [s for s in required if s not in principal.scopes]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"insufficient scopes: missing {missing}",
            )
        return principal

    return _dep


# -----------------------------------------------------------------------------
# Tenant (org) dependency: requires X-Org-Id header (UUID)
# -----------------------------------------------------------------------------
class OrgContext(BaseModel):
    org_id: UUID4


async def org_ctx(
    x_org_id: str = Header(..., alias="X-Org-Id")
) -> OrgContext:  # RLS binding
    try:
        return OrgContext(org_id=UUID4(x_org_id))
    except Exception:
        raise HTTPException(status_code=400, detail="X-Org-Id must be a valid UUID")


async def _apply_rls(session: AsyncSession, org: OrgContext) -> None:
    # Ensure RLS session GUC in the current transaction
    await session.execute(text("SET LOCAL app.current_org = :org::uuid").bindparams(org=str(org.org_id)))


# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class VulnSortField(str):
    pass


AllowedSort = Literal[
    "created_at",
    "-created_at",
    "updated_at",
    "-updated_at",
    "severity",
    "-severity",
    "risk_score",
    "-risk_score",
]


class VulnerabilityRead(BaseModel):
    """
    Flexible read model; allows extra fields present in DB.
    """
    model_config = ConfigDict(extra="allow")

    id: Optional[UUID4] = Field(None, description="Primary UUID")
    org_id: Optional[UUID4] = None
    cve_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    asset_id: Optional[UUID4] = None
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    discovered_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=64)
    title: Optional[str] = Field(None, max_length=2048)
    severity: Optional[str] = Field(None, description="e.g., info|low|medium|high|critical")
    status: Optional[str] = Field(None, description="e.g., open|in_progress|fixed|accepted|suppressed")
    asset_id: Optional[UUID4] = None
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    discovered_at: Optional[datetime] = None
    labels: Optional[Dict[str, Any]] = None
    attributes: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None


class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=2048)
    severity: Optional[str] = None
    status: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    discovered_at: Optional[datetime] = None
    labels: Optional[Dict[str, Any]] = None
    attributes: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None


class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int


class PageVuln(BaseModel):
    items: List[VulnerabilityRead]
    meta: PageMeta


# -----------------------------------------------------------------------------
# Table reflection and helpers
# -----------------------------------------------------------------------------
_METADATA = MetaData()
_VULN_TABLE: Optional[Table] = None
_CANDIDATE_TABLES = ("vuln_findings", "vulnerabilities", "security_vulnerabilities")


async def _discover_vuln_table(session: AsyncSession) -> Table:
    global _VULN_TABLE
    if _VULN_TABLE is not None:
        return _VULN_TABLE

    async def _sync_discover(sync_conn) -> Table:
        insp = inspect(sync_conn)
        existing = set(insp.get_table_names())
        for name in _CANDIDATE_TABLES:
            if name in existing:
                return Table(name, _METADATA, autoload_with=sync_conn)
        # try schema-qualified lookup via information_schema as a fallback
        return None  # type: ignore

    engine: AsyncEngine = session.get_bind()  # type: ignore
    table: Optional[Table] = await engine.run_sync(_sync_discover)

    if table is None:
        raise HTTPException(
            status_code=500,
            detail="Vulnerability table not found. Expected one of: "
            + ", ".join(_CANDIDATE_TABLES),
        )
    _VULN_TABLE = table
    log.info("vuln.py: using table %s", table.name)
    return _VULN_TABLE


def _etag_for_payload(payload: Any) -> str:
    raw = json.dumps(payload, default=str, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return '"' + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=") + '"'


def _row_to_dict(row: Any) -> Dict[str, Any]:
    # SA 2.0 Row -> dict
    data = dict(row._mapping)
    # Normalize Decimals to float for JSON compliance
    for k, v in list(data.items()):
        if hasattr(v, "as_tuple") and hasattr(v, "normalize"):  # Decimal
            data[k] = float(v)
    return data


def _has_col(tbl: Table, name: str) -> bool:
    return name in tbl.c


def _whitelist_payload(tbl: Table, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in payload.items() if _has_col(tbl, k)}


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@router.get(
    "",
    response_model=PageVuln,
    summary="List vulnerabilities with filters, pagination and sorting",
)
async def list_vulns(
    request: Request,
    response: Response,
    org: OrgContext = Depends(org_ctx),
    _: Principal = Depends(require_scopes(["vuln:read"])),
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    cve_id: Optional[str] = Query(None, min_length=1),
    severity: Optional[List[str]] = Query(None),
    status_: Optional[List[str]] = Query(None, alias="status"),
    asset_id: Optional[UUID4] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    search: Optional[str] = Query(None, description="Search in cve_id/title"),
    sort: AllowedSort = Query("-updated_at"),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    await _apply_rls(session, org)
    tbl = await _discover_vuln_table(session)

    # Build WHERE
    where = []
    if cve_id and _has_col(tbl, "cve_id"):
        where.append(tbl.c.cve_id == cve_id)
    if severity and _has_col(tbl, "severity"):
        where.append(tbl.c.severity.in_(severity))
    if status_ and _has_col(tbl, "status"):
        where.append(tbl.c.status.in_(status_))
    if asset_id and _has_col(tbl, "asset_id"):
        where.append(tbl.c.asset_id == str(asset_id))
    if since and _has_col(tbl, "created_at"):
        where.append(tbl.c.created_at >= since)
    if until and _has_col(tbl, "created_at"):
        where.append(tbl.c.created_at < until)
    if search:
        # Prefer title if exists, else cve_id
        if _has_col(tbl, "title"):
            where.append(func.coalesce(tbl.c.title, tbl.c.cve_id).ilike(f"%{search}%"))
        elif _has_col(tbl, "cve_id"):
            where.append(tbl.c.cve_id.ilike(f"%{search}%"))

    # Total count
    q_count = select(func.count()).select_from(tbl)
    for cond in where:
        q_count = q_count.where(cond)
    total = (await session.execute(q_count)).scalar_one()

    # Order by
    order_col = tbl.c.updated_at if sort in ("updated_at", "-updated_at") and _has_col(tbl, "updated_at") \
        else tbl.c.created_at if sort in ("created_at", "-created_at") and _has_col(tbl, "created_at") \
        else tbl.c.risk_score if sort in ("risk_score", "-risk_score") and _has_col(tbl, "risk_score") \
        else tbl.c.severity if sort in ("severity", "-severity") and _has_col(tbl, "severity") \
        else tbl.c.created_at if _has_col(tbl, "created_at") else list(tbl.c)[0]
    order_by = order_col.desc() if sort.startswith("-") else order_col.asc()

    # Page
    offset = (page - 1) * page_size
    q = select(tbl)
    for cond in where:
        q = q.where(cond)
    q = q.order_by(order_by).offset(offset).limit(page_size)

    rows: Result = await session.execute(q)
    items = [_row_to_dict(r) for r in rows]

    # ETag (based on max(updated_at/created_at) + count + first/last ids snapshot)
    max_time = None
    if _has_col(tbl, "updated_at"):
        max_time = (await session.execute(
            select(func.max(tbl.c.updated_at)).where(*where) if where else select(func.max(tbl.c.updated_at))
        )).scalar()
    if not max_time and _has_col(tbl, "created_at"):
        max_time = (await session.execute(
            select(func.max(tbl.c.created_at)).where(*where) if where else select(func.max(tbl.c.created_at))
        )).scalar()
    etag_payload = {
        "total": total,
        "max_time": str(max_time) if max_time else None,
        "first_id": items[0].get("id") if items else None,
        "last_id": items[-1].get("id") if items else None,
        "page": page,
        "page_size": page_size,
    }
    etag = _etag_for_payload(etag_payload)
    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["X-Total-Count"] = str(total)

    # Cast into model (keeps extra fields)
    payload = PageVuln(items=[VulnerabilityRead(**it) for it in items], meta=PageMeta(page=page, page_size=page_size, total=total))
    return payload


@router.get(
    "/{vuln_id}",
    response_model=VulnerabilityRead,
    summary="Get vulnerability by UUID (or compatible identifier column)",
)
async def get_vuln(
    response: Response,
    vuln_id: str,
    org: OrgContext = Depends(org_ctx),
    _: Principal = Depends(require_scopes(["vuln:read"])),
    session: AsyncSession = Depends(get_session),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    await _apply_rls(session, org)
    tbl = await _discover_vuln_table(session)

    # Choose identifier column
    id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
    if not id_col:
        raise HTTPException(500, detail="No identifier column found (expected id|uid|finding_id)")

    q = select(tbl).where(id_col == vuln_id)
    row = (await session.execute(q)).first()
    if not row:
        raise HTTPException(status_code=404, detail="vulnerability not found")

    item = _row_to_dict(row)
    etag = _etag_for_payload(item)
    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return VulnerabilityRead(**item)


@router.post(
    "",
    response_model=VulnerabilityRead,
    status_code=201,
    summary="Create vulnerability (safe column whitelist, RLS via org_id session GUC)",
)
async def create_vuln(
    payload: VulnerabilityCreate,
    org: OrgContext = Depends(org_ctx),
    _: Principal = Depends(require_scopes(["vuln:write"])),
    session: AsyncSession = Depends(get_session),
):
    await _apply_rls(session, org)
    tbl = await _discover_vuln_table(session)

    data = payload.model_dump(exclude_none=True)
    # Force org_id if column exists
    if _has_col(tbl, "org_id"):
        data["org_id"] = str(org.org_id)
    # Auto id if needed
    if _has_col(tbl, "id"):
        data.setdefault("id", str(uuid.uuid4()))
    # Timestamps
    now = datetime.utcnow()
    if _has_col(tbl, "created_at"):
        data.setdefault("created_at", now)
    if _has_col(tbl, "updated_at"):
        data.setdefault("updated_at", now)

    data = _whitelist_payload(tbl, data)
    if not data:
        raise HTTPException(400, detail="no valid columns to insert")

    stmt = tbl.insert().values(**data).returning(tbl)
    try:
        row = (await session.execute(stmt)).first()
        await session.commit()
    except ProgrammingError as e:
        await session.rollback()
        raise HTTPException(400, detail=f"insert failed: {e.orig}")  # type: ignore

    return VulnerabilityRead(**_row_to_dict(row))


@router.patch(
    "/{vuln_id}",
    response_model=VulnerabilityRead,
    summary="Update vulnerability by id (safe column whitelist)",
)
async def update_vuln(
    vuln_id: str,
    payload: VulnerabilityUpdate,
    org: OrgContext = Depends(org_ctx),
    _: Principal = Depends(require_scopes(["vuln:write"])),
    session: AsyncSession = Depends(get_session),
):
    await _apply_rls(session, org)
    tbl = await _discover_vuln_table(session)

    id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
    if not id_col:
        raise HTTPException(500, detail="No identifier column found (expected id|uid|finding_id)")

    data = payload.model_dump(exclude_none=True)
    if _has_col(tbl, "updated_at"):
        data["updated_at"] = datetime.utcnow()

    data = _whitelist_payload(tbl, data)
    if not data:
        raise HTTPException(400, detail="no valid columns to update")

    stmt = tbl.update().where(id_col == vuln_id).values(**data).returning(tbl)
    res = (await session.execute(stmt)).first()
    if not res:
        await session.rollback()
        raise HTTPException(404, detail="vulnerability not found")
    await session.commit()
    return VulnerabilityRead(**_row_to_dict(res))


@router.delete(
    "/{vuln_id}",
    status_code=204,
    summary="Delete vulnerability by id (soft delete if deleted_at exists, else hard delete)",
)
async def delete_vuln(
    vuln_id: str,
    org: OrgContext = Depends(org_ctx),
    _: Principal = Depends(require_scopes(["vuln:write"])),
    session: AsyncSession = Depends(get_session),
):
    await _apply_rls(session, org)
    tbl = await _discover_vuln_table(session)

    id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
    if not id_col:
        raise HTTPException(500, detail="No identifier column found (expected id|uid|finding_id)")

    if _has_col(tbl, "deleted_at"):
        stmt = tbl.update().where(id_col == vuln_id).values(deleted_at=datetime.utcnow())
    else:
        stmt = tbl.delete().where(id_col == vuln_id)

    res = await session.execute(stmt)
    if res.rowcount == 0:
        await session.rollback()
        raise HTTPException(404, detail="vulnerability not found")
    await session.commit()
    return Response(status_code=204)
