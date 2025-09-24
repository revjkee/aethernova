# cybersecurity-core/api/graphql/server.py
# -*- coding: utf-8 -*-
"""
Industrial GraphQL server for cybersecurity-core

Stack:
- Strawberry GraphQL (async)
- SQLAlchemy 2.0 (async Core)
- Optional OpenTelemetry tracing if OTEL is available
- Works standalone or mounted into FastAPI via GraphQLRouter

Features:
- Tenant isolation via Row-Level Security: SET LOCAL app.current_org = :uuid
- Safe table autodiscovery for vulnerabilities table
- Pagination + filters + sorting for vulnerabilities
- Strict Pydantic-free GraphQL types (dataclasses from strawberry)
- Robust error formatter (hides internals, shows stable error codes)
- Optional GraphiQL + introspection toggles via env
- Minimal coupling: no ORM models required; Core SQL + reflection only

ENV:
- DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/dbname
- GRAPHQL_ENABLE_GRAPHIQL=true|false (default true)
- GRAPHQL_ENABLE_INTROSPECTION=true|false (default true)

Mount into FastAPI:
    from fastapi import FastAPI
    from cybersecurity_core.api.graphql.server import get_graphql_router

    app = FastAPI()
    app.include_router(get_graphql_router(path="/graphql"))

Note:
I cannot verify this: точные имена и состав колонок ваших таблиц.
Код использует рефлексию и корректно деградирует, если доступна любая из таблиц:
    "vuln_findings", "vulnerabilities", "security_vulnerabilities".
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import strawberry
from strawberry.types import Info
from strawberry.fastapi import GraphQLRouter

from sqlalchemy import MetaData, Table, func, inspect, select, text
from sqlalchemy.engine import Result
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# -----------------------------------------------------------------------------
# DB Session & Engine (lazy, module-wide)
# -----------------------------------------------------------------------------
_DB_URL = os.getenv("DATABASE_URL")
_ENGINE: Optional[AsyncEngine] = None
_SESSION_MAKER: Optional[async_sessionmaker[AsyncSession]] = None


def _ensure_engine() -> Tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    global _ENGINE, _SESSION_MAKER
    if _ENGINE is None or _SESSION_MAKER is None:
        if not _DB_URL:
            raise RuntimeError("DATABASE_URL env is required for GraphQL DB access")
        _ENGINE = create_async_engine(_DB_URL, pool_pre_ping=True, future=True)
        _SESSION_MAKER = async_sessionmaker(_ENGINE, expire_on_commit=False)
        log.info("GraphQL: async engine initialized")
    return _ENGINE, _SESSION_MAKER  # type: ignore


@asynccontextmanager
async def db_session() -> AsyncSession:
    """Short-lived session per resolver to ensure proper close and RLS boundary."""
    _, maker = _ensure_engine()
    async with maker() as session:  # type: ignore
        try:
            yield session
        finally:
            await session.close()


# -----------------------------------------------------------------------------
# Context & Security
# -----------------------------------------------------------------------------
@strawberry.type
class Error:
    code: str
    message: str


class GQLContext:
    def __init__(self, org_id: Optional[str], request_headers: Dict[str, str]):
        self.org_id = org_id
        self.headers = request_headers


async def _context_getter(request) -> GQLContext:
    # Expect X-Org-Id header (UUID). If not present -> None -> resolvers will reject.
    org_id = request.headers.get("x-org-id") or request.headers.get("X-Org-Id")
    # Basic sanity check
    if org_id:
        try:
            uuid.UUID(org_id)
        except Exception:
            org_id = None
    return GQLContext(org_id=org_id, request_headers=dict(request.headers))


async def _apply_rls(session: AsyncSession, org_id: str) -> None:
    # Must be called inside a transaction block for SET LOCAL to be effective
    await session.execute(
        text("SET LOCAL app.current_org = :org::uuid").bindparams(org=org_id)
    )


# -----------------------------------------------------------------------------
# Table discovery (vulnerabilities)
# -----------------------------------------------------------------------------
_METADATA = MetaData()
_VULN_TABLE: Optional[Table] = None
_CANDIDATE_VULN = ("vuln_findings", "vulnerabilities", "security_vulnerabilities")


async def _discover_vuln_table(session: AsyncSession) -> Table:
    global _VULN_TABLE

    if _VULN_TABLE is not None:
        return _VULN_TABLE

    async def _sync_discover(sync_conn) -> Optional[Table]:
        insp = inspect(sync_conn)
        existing = set(insp.get_table_names())
        for name in _CANDIDATE_VULN:
            if name in existing:
                return Table(name, _METADATA, autoload_with=sync_conn)
        return None

    engine: AsyncEngine = session.get_bind()  # type: ignore
    table: Optional[Table] = await engine.run_sync(_sync_discover)

    if not table:
        raise RuntimeError(
            "Vulnerability table not found. Expected one of: " + ", ".join(_CANDIDATE_VULN)
        )

    _VULN_TABLE = table
    log.info("GraphQL: vulnerabilities table resolved -> %s", table.name)
    return _VULN_TABLE


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _row_to_dict(row: Any) -> Dict[str, Any]:
    data = dict(row._mapping)
    # normalize Decimal -> float
    for k, v in list(data.items()):
        if hasattr(v, "as_tuple") and hasattr(v, "normalize"):
            data[k] = float(v)
    return data


def _b64sha256(obj: Any) -> str:
    raw = json.dumps(obj, default=str, sort_keys=True).encode("utf-8")
    import hashlib, base64  # local import to keep global imports minimal

    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def _has_col(tbl: Table, name: str) -> bool:
    return name in tbl.c


# -----------------------------------------------------------------------------
# GraphQL Types
# -----------------------------------------------------------------------------
@strawberry.type
class PageMeta:
    page: int
    page_size: int
    total: int
    etag: Optional[str] = None


@strawberry.type
class Vulnerability:
    id: Optional[strawberry.ID]
    org_id: Optional[str]
    cve_id: Optional[str]
    title: Optional[str]
    severity: Optional[str]
    status: Optional[str]
    asset_id: Optional[str]
    risk_score: Optional[float]
    discovered_at: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    # passthrough JSON fields (labels/attributes/evidence) if present
    labels: Optional[strawberry.scalars.JSON] = None
    attributes: Optional[strawberry.scalars.JSON] = None
    evidence: Optional[strawberry.scalars.JSON] = None


@strawberry.input
class VulnerabilityFilter:
    cve_id: Optional[str] = None
    severity: Optional[List[str]] = None
    status: Optional[List[str]] = None
    asset_id: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    search: Optional[str] = None


@strawberry.type
class VulnerabilityConnection:
    items: List[Vulnerability]
    meta: PageMeta


@strawberry.input
class VulnerabilityCreateInput:
    cve_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    asset_id: Optional[str] = None
    risk_score: Optional[float] = None
    discovered_at: Optional[datetime] = None
    labels: Optional[strawberry.scalars.JSON] = None
    attributes: Optional[strawberry.scalars.JSON] = None
    evidence: Optional[strawberry.scalars.JSON] = None


@strawberry.input
class VulnerabilityUpdateInput:
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    risk_score: Optional[float] = None
    discovered_at: Optional[datetime] = None
    labels: Optional[strawberry.scalars.JSON] = None
    attributes: Optional[strawberry.scalars.JSON] = None
    evidence: Optional[strawberry.scalars.JSON] = None


# -----------------------------------------------------------------------------
# Resolvers
# -----------------------------------------------------------------------------
async def _require_org(info: Info) -> str:
    ctx: GQLContext = info.context
    if not ctx.org_id:
        raise RuntimeError("Missing or invalid X-Org-Id header")
    return ctx.org_id


@strawberry.type
class Query:
    @strawberry.field(description="Lightweight healthcheck")
    async def health(self) -> str:
        return "ok"

    @strawberry.field(description="Get vulnerability by ID/UID")
    async def vulnerability(self, info: Info, id: strawberry.ID) -> Optional[Vulnerability]:
        org_id = await _require_org(info)
        async with db_session() as session:
            async with session.begin():
                await _apply_rls(session, org_id)
                tbl = await _discover_vuln_table(session)
                id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
                if not id_col:
                    raise RuntimeError("No identifier column in vulnerabilities table")
                row = (await session.execute(select(tbl).where(id_col == str(id)))).first()
                if not row:
                    return None
                data = _row_to_dict(row)
                return Vulnerability(**data)

    @strawberry.field(description="List vulnerabilities with filters, pagination and sorting")
    async def vulnerabilities(
        self,
        info: Info,
        filters: Optional[VulnerabilityFilter] = None,
        page: int = 1,
        page_size: int = 50,
        sort: str = "-updated_at",
    ) -> VulnerabilityConnection:
        org_id = await _require_org(info)
        page = max(1, page)
        page_size = max(1, min(page_size, 1000))
        async with db_session() as session:
            async with session.begin():
                await _apply_rls(session, org_id)
                tbl = await _discover_vuln_table(session)

                where = []
                f = filters or VulnerabilityFilter()
                if f.cve_id and _has_col(tbl, "cve_id"):
                    where.append(tbl.c.cve_id == f.cve_id)
                if f.severity and _has_col(tbl, "severity"):
                    where.append(tbl.c.severity.in_(f.severity))
                if f.status and _has_col(tbl, "status"):
                    where.append(tbl.c.status.in_(f.status))
                if f.asset_id and _has_col(tbl, "asset_id"):
                    where.append(tbl.c.asset_id == f.asset_id)
                if f.since and _has_col(tbl, "created_at"):
                    where.append(tbl.c.created_at >= f.since)
                if f.until and _has_col(tbl, "created_at"):
                    where.append(tbl.c.created_at < f.until)
                if f.search:
                    if _has_col(tbl, "title"):
                        where.append(func.coalesce(tbl.c.title, tbl.c.cve_id).ilike(f"%{f.search}%"))
                    elif _has_col(tbl, "cve_id"):
                        where.append(tbl.c.cve_id.ilike(f"%{f.search}%"))

                # count
                q_count = select(func.count()).select_from(tbl)
                for cond in where:
                    q_count = q_count.where(cond)
                total = (await session.execute(q_count)).scalar_one()

                # order
                sort_map = {
                    "updated_at": tbl.c.updated_at if _has_col(tbl, "updated_at") else None,
                    "created_at": tbl.c.created_at if _has_col(tbl, "created_at") else None,
                    "risk_score": tbl.c.risk_score if _has_col(tbl, "risk_score") else None,
                    "severity": tbl.c.severity if _has_col(tbl, "severity") else None,
                }
                desc = sort.startswith("-")
                key = sort[1:] if desc else sort
                order_col = sort_map.get(key) or (tbl.c.created_at if _has_col(tbl, "created_at") else list(tbl.c)[0])
                order_by = order_col.desc() if desc else order_col.asc()

                # page
                offset = (page - 1) * page_size
                q = select(tbl).order_by(order_by).offset(offset).limit(page_size)
                for cond in where:
                    q = q.where(cond)

                rows: Result = await session.execute(q)
                items = [_row_to_dict(r) for r in rows]

                # etag
                max_time = None
                if _has_col(tbl, "updated_at"):
                    max_time = (await session.execute(
                        select(func.max(tbl.c.updated_at)).where(*where) if where else select(func.max(tbl.c.updated_at))
                    )).scalar()
                if not max_time and _has_col(tbl, "created_at"):
                    max_time = (await session.execute(
                        select(func.max(tbl.c.created_at)).where(*where) if where else select(func.max(tbl.c.created_at))
                    )).scalar()
                etag = _b64sha256({
                    "total": total,
                    "max_time": str(max_time) if max_time else None,
                    "first": items[0].get("id") if items else None,
                    "last": items[-1].get("id") if items else None,
                    "page": page,
                    "page_size": page_size,
                })

                return VulnerabilityConnection(
                    items=[Vulnerability(**it) for it in items],
                    meta=PageMeta(page=page, page_size=page_size, total=total, etag=etag),
                )


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Create vulnerability")
    async def create_vulnerability(self, info: Info, input: VulnerabilityCreateInput) -> Vulnerability:
        org_id = await _require_org(info)
        async with db_session() as session:
            async with session.begin():
                await _apply_rls(session, org_id)
                tbl = await _discover_vuln_table(session)

                data: Dict[str, Any] = {
                    "cve_id": input.cve_id,
                    "title": input.title,
                    "severity": input.severity,
                    "status": input.status,
                    "asset_id": input.asset_id,
                    "risk_score": input.risk_score,
                    "discovered_at": input.discovered_at,
                    "labels": input.labels,
                    "attributes": input.attributes,
                    "evidence": input.evidence,
                }
                # enforce org_id and timestamps if columns exist
                if _has_col(tbl, "org_id"):
                    data["org_id"] = org_id
                now = datetime.utcnow()
                if _has_col(tbl, "created_at"):
                    data.setdefault("created_at", now)
                if _has_col(tbl, "updated_at"):
                    data.setdefault("updated_at", now)
                if _has_col(tbl, "id"):
                    data.setdefault("id", str(uuid.uuid4()))

                # whitelist cols
                data = {k: v for k, v in data.items() if _has_col(tbl, k) and v is not None}
                if not data:
                    raise RuntimeError("No valid columns to insert")

                stmt = tbl.insert().values(**data).returning(tbl)
                row = (await session.execute(stmt)).first()
                return Vulnerability(**_row_to_dict(row))

    @strawberry.mutation(description="Update vulnerability")
    async def update_vulnerability(
        self, info: Info, id: strawberry.ID, input: VulnerabilityUpdateInput
    ) -> Vulnerability:
        org_id = await _require_org(info)
        async with db_session() as session:
            async with session.begin():
                await _apply_rls(session, org_id)
                tbl = await _discover_vuln_table(session)
                id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
                if not id_col:
                    raise RuntimeError("No identifier column in vulnerabilities table")

                data: Dict[str, Any] = {
                    "title": input.title,
                    "severity": input.severity,
                    "status": input.status,
                    "risk_score": input.risk_score,
                    "discovered_at": input.discovered_at,
                    "labels": input.labels,
                    "attributes": input.attributes,
                    "evidence": input.evidence,
                }
                if _has_col(tbl, "updated_at"):
                    data["updated_at"] = datetime.utcnow()

                data = {k: v for k, v in data.items() if _has_col(tbl, k) and v is not None}
                if not data:
                    raise RuntimeError("No valid columns to update")

                stmt = tbl.update().where(id_col == str(id)).values(**data).returning(tbl)
                row = (await session.execute(stmt)).first()
                if not row:
                    raise RuntimeError("Vulnerability not found")
                return Vulnerability(**_row_to_dict(row))

    @strawberry.mutation(description="Delete vulnerability (soft if deleted_at exists)")
    async def delete_vulnerability(self, info: Info, id: strawberry.ID) -> bool:
        org_id = await _require_org(info)
        async with db_session() as session:
            async with session.begin():
                await _apply_rls(session, org_id)
                tbl = await _discover_vuln_table(session)
                id_col = tbl.c.id if _has_col(tbl, "id") else tbl.c.get("uid") or tbl.c.get("finding_id")
                if not id_col:
                    raise RuntimeError("No identifier column in vulnerabilities table")

                if _has_col(tbl, "deleted_at"):
                    stmt = tbl.update().where(id_col == str(id)).values(deleted_at=datetime.utcnow())
                else:
                    stmt = tbl.delete().where(id_col == str(id))
                res = await session.execute(stmt)
                return res.rowcount > 0


# -----------------------------------------------------------------------------
# Schema, error formatter, router factory
# -----------------------------------------------------------------------------
_SCHEMA = strawberry.Schema(Query, Mutation)


def _error_formatter(error: strawberry.types.GraphQLError, debug: bool = False):
    # Hide raw tracebacks; return stable codes based on exception text
    message = "Internal error"
    code = "INTERNAL"
    try:
        original = error.original_error
        if isinstance(original, RuntimeError):
            message = str(original)
            # Map some common messages to stable codes
            if "X-Org-Id" in message or "Missing or invalid" in message:
                code = "ORG_HEADER_MISSING"
            elif "not found" in message.lower():
                code = "NOT_FOUND"
            elif "No valid columns" in message:
                code = "INVALID_INPUT"
            elif "identifier column" in message:
                code = "SCHEMA_MISCONFIG"
            else:
                code = "RUNTIME_ERROR"
        else:
            # Fallback to GraphQL error message, but sanitized
            message = error.message or "Bad request"
            code = "GRAPHQL_ERROR"
    except Exception:
        pass

    return strawberry.types.ExecutionResult(  # type: ignore
        errors=[
            {
                "message": message if debug else message,
                "path": error.path,
                "locations": [{"line": loc.line, "column": loc.column} for loc in error.locations or []],
                "extensions": {"code": code},
            }
        ]
    )


def get_graphql_router(path: str = "/graphql") -> GraphQLRouter:
    enable_graphiql = os.getenv("GRAPHQL_ENABLE_GRAPHIQL", "true").lower() == "true"
    enable_introspection = os.getenv("GRAPHQL_ENABLE_INTROSPECTION", "true").lower() == "true"

    # Note: Strawberry GraphQLRouter handles ASGI integration with FastAPI
    router = GraphQLRouter(
        schema=_SCHEMA,
        path=path,
        graphiql=enable_graphiql,
        allow_queries_via_get=True,
        context_getter=_context_getter,
        subscription_protocols=[],  # can be enabled if needed
        keep_alive=False,
        root_value=None,
        extensions=[],  # custom extensions can be added here
        enable_introspection=enable_introspection,
        # error formatter keeps internals private
        error_formatter=_error_formatter,
    )
    return router


# Optional: standalone ASGI app (if you want to run this module directly)
try:
    # Only import FastAPI if run standalone
    from fastapi import FastAPI

    _STANDALONE = os.getenv("GRAPHQL_STANDALONE", "false").lower() == "true"
    if _STANDALONE:
        _app = FastAPI(title="cybersecurity-core GraphQL")
        _app.include_router(get_graphql_router(path="/graphql"))
        app = _app  # expose as module-level ASGI app
except Exception:
    pass
