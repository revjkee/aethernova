from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import (
    Table, Column, text, select, insert, update, delete, and_, or_, func, literal_column, String, Text
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID, ENUM as PGENUM
from sqlalchemy.ext.asyncio import AsyncSession

# --------- Аутентификация / авторизация (совместимо с ранее выданным auth.py) ---------
try:
    # Предполагаем размещение зависимостей в проекте, как в примерах
    from ops.api.http.middleware.auth import current_principal, require_scopes, Principal  # type: ignore
except Exception:  # упрощение для статического анализа/линта
    def current_principal(required: bool = True):  # type: ignore
        async def _dep():
            return None
        return _dep
    def require_scopes(*args, **kwargs):  # type: ignore
        def _decor(f): return f
        return _decor
    class Principal:  # type: ignore
        subject: str = "anonymous"

# --------- Доступ к БД: ожидаем get_session в проекте ---------
# Замените импорт на фактический путь вашего приложения
try:
    from ops.api.db import get_session  # type: ignore
except Exception:
    async def get_session() -> AsyncSession:  # type: ignore
        raise RuntimeError("Provide ops.api.db.get_session dependency returning AsyncSession")

# --------- SQLAlchemy метаданные (минимально необходимые объекты таблиц) ---------

# Привязываем к существующим enum-типам PostgreSQL, созданным миграцией 0001_init.sql
tool_type_enum = PGENUM("MODEL", "CONNECTOR", "WORKFLOW", "JOB", name="tool_type", schema="app", create_type=False)
tool_state_enum = PGENUM("INACTIVE", "ACTIVE", "DEPRECATED", "DISABLED", name="tool_state", schema="app", create_type=False)

project_tbl = Table(
    "project",
    # "metadata" создаётся динамически через Table(...); в Core можно не объявлять объект MetaData,
    # т.к. мы не выполняем create_all. SQLAlchemy создаст временное MetaData.
    # noinspection PyTypeChecker
    type("Meta", (), {})(),  # dummy MetaData
    Column("id", PGUUID(as_uuid=True), primary_key=True),
    Column("key", String, nullable=False),
    schema="app",
)

location_tbl = Table(
    "location",
    type("Meta", (), {})(),
    Column("id", PGUUID(as_uuid=True), primary_key=True),
    Column("project_id", PGUUID(as_uuid=True), nullable=False),
    Column("key", String, nullable=False),
    schema="app",
)

tool_tbl = Table(
    "tool",
    type("Meta", (), {})(),
    Column("id", PGUUID(as_uuid=True), primary_key=True),
    Column("project_id", PGUUID(as_uuid=True), nullable=False),
    Column("location_id", PGUUID(as_uuid=True), nullable=False),
    Column("name_key", String, nullable=False),
    Column("display_name", String, nullable=False),
    Column("description", Text),
    Column("type", tool_type_enum, nullable=False),
    Column("state", tool_state_enum, nullable=False),
    Column("config", JSONB, nullable=False),
    Column("labels", JSONB, nullable=False),
    Column("annotations", JSONB, nullable=False),
    Column("owner", String),
    Column("etag", String, nullable=False),
    Column("created_at", literal_column("timestamptz"), nullable=False),
    Column("updated_at", literal_column("timestamptz"), nullable=False),
    Column("deleted_at", literal_column("timestamptz")),
    schema="app",
)

alias_tbl = Table(
    "tool_alias",
    type("Meta", (), {})(),
    Column("tool_id", PGUUID(as_uuid=True), primary_key=True),
    Column("alias", String, primary_key=True),
    schema="app",
)

# --------- Pydantic модели (выравнены с tool.proto) ---------

class ToolState(str):
    INACTIVE = "INACTIVE"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"

class ToolType(str):
    MODEL = "MODEL"
    CONNECTOR = "CONNECTOR"
    WORKFLOW = "WORKFLOW"
    JOB = "JOB"

class ToolBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=10000)
    type: ToolType = Field(...)
    config: Dict[str, Any] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    owner: Optional[str] = Field(None, max_length=255)
    aliases: List[str] = Field(default_factory=list)

class ToolCreate(ToolBase):
    tool_id: Optional[str] = Field(None, pattern=r"^[a-z0-9][a-z0-9\-_.]{1,254}$")

class ToolUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=10000)
    type: Optional[ToolType] = None
    state: Optional[ToolState] = None
    config: Optional[Dict[str, Any]] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    owner: Optional[str] = Field(None, max_length=255)
    aliases: Optional[List[str]] = None

class ToolOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    display_name: str
    description: Optional[str]
    type: ToolType
    state: ToolState
    config: Dict[str, Any]
    labels: Dict[str, str]
    annotations: Dict[str, str]
    owner: Optional[str]
    etag: str
    create_time: datetime = Field(alias="created_at")
    update_time: datetime = Field(alias="updated_at")
    aliases: List[str] = Field(default_factory=list)

class ListResponse(BaseModel):
    tools: List[ToolOut]
    next_page_token: Optional[str] = None
    total_size: Optional[int] = None

# --------- Утилиты ---------

router = APIRouter(prefix="/v1", tags=["tools"])

_slug_re = re.compile(r"[^a-z0-9\-_.]+")

def slugify(value: str) -> str:
    v = value.strip().lower().replace(" ", "-")
    v = _slug_re.sub("-", v)
    v = re.sub(r"-{2,}", "-", v).strip("-")
    if not re.match(r"^[a-z0-9][a-z0-9\-_.]{1,254}$", v):
        v = f"tool-{uuid.uuid4().hex[:12]}"
    return v

def resource_name(project: str, location: str, tool: str) -> str:
    return f"projects/{project}/locations/{location}/tools/{tool}"

def encode_page_token(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode()

def decode_page_token(token: Optional[str]) -> int:
    if not token:
        return 0
    try:
        data = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
        return int(data.get("o", 0))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid page_token")

_label_filter_re = re.compile(r'labels\.([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"')

def apply_filter(
    stmt, 
    project_id: uuid.UUID, 
    location_id: uuid.UUID, 
    filter_str: Optional[str], 
    q: Optional[str]
):
    conds = [
        tool_tbl.c.project_id == project_id,
        tool_tbl.c.location_id == location_id,
        tool_tbl.c.deleted_at.is_(None),
    ]
    if filter_str:
        # Поддержка: state=ACTIVE, type=CONNECTOR, labels.env="prod"
        for m in _label_filter_re.finditer(filter_str):
            k, v = m.group(1), m.group(2)
            conds.append(tool_tbl.c.labels[func.cast(k, Text)].astext == v)
        state_m = re.search(r'\bstate\s*=\s*"(INACTIVE|ACTIVE|DEPRECATED|DISABLED)"', filter_str)
        if state_m:
            conds.append(tool_tbl.c.state == state_m.group(1))
        type_m = re.search(r'\btype\s*=\s*"(MODEL|CONNECTOR|WORKFLOW|JOB)"', filter_str)
        if type_m:
            conds.append(tool_tbl.c.type == type_m.group(1))
    if q:
        like = f"%{q.lower()}%"
        conds.append(func.lower(tool_tbl.c.display_name).like(like))
    return stmt.where(and_(*conds))

def apply_order_by(stmt, order_by: Optional[str]):
    if not order_by:
        return stmt.order_by(tool_tbl.c.updated_at.desc(), tool_tbl.c.name_key.asc())
    parts = [p.strip() for p in order_by.split(",") if p.strip()]
    order_cols = []
    for p in parts:
        m = re.match(r"^(display_name|update_time|created_at|name_key)\s+(asc|desc)$", p, re.I)
        if not m:
            continue
        col, direction = m.group(1), m.group(2).lower()
        colmap = {
            "display_name": tool_tbl.c.display_name,
            "update_time": tool_tbl.c.updated_at,
            "created_at": tool_tbl.c.created_at,
            "name_key": tool_tbl.c.name_key,
        }
        c = colmap[col]
        order_cols.append(c.asc() if direction == "asc" else c.desc())
    if order_cols:
        return stmt.order_by(*order_cols)
    return stmt

async def get_parent_ids(db: AsyncSession, project_key: str, location_key: str) -> Tuple[uuid.UUID, uuid.UUID]:
    proj_id = await db.scalar(select(project_tbl.c.id).where(project_tbl.c.key == project_key))
    if not proj_id:
        raise HTTPException(status_code=404, detail="project not found")
    loc_id = await db.scalar(
        select(location_tbl.c.id).where(
            location_tbl.c.project_id == proj_id,
            location_tbl.c.key == location_key,
        )
    )
    if not loc_id:
        raise HTTPException(status_code=404, detail="location not found")
    return proj_id, loc_id

async def load_aliases(db: AsyncSession, tool_ids: Sequence[uuid.UUID]) -> Dict[uuid.UUID, List[str]]:
    if not tool_ids:
        return {}
    rows = (await db.execute(
        select(alias_tbl.c.tool_id, alias_tbl.c.alias).where(alias_tbl.c.tool_id.in_(list(tool_ids)))
    )).all()
    res: Dict[uuid.UUID, List[str]] = {}
    for tid, alias in rows:
        res.setdefault(tid, []).append(alias)
    return res

def row_to_out(row: Any, project_key: str, location_key: str, aliases: List[str]) -> ToolOut:
    return ToolOut(
        name=resource_name(project_key, location_key, row.name_key),
        display_name=row.display_name,
        description=row.description,
        type=row.type,
        state=row.state,
        config=row.config or {},
        labels=row.labels or {},
        annotations=row.annotations or {},
        owner=row.owner,
        etag=row.etag,
        created_at=row.created_at,
        updated_at=row.updated_at,
        aliases=aliases,
    )

# --------- Endpoints ---------

@router.get(
    "/projects/{project}/locations/{location}/tools",
    response_model=ListResponse,
    summary="List Tools",
)
@require_scopes("tools.read")
async def list_tools(
    project: str = Path(..., min_length=1),
    location: str = Path(..., min_length=1),
    page_size: int = Query(50, ge=1, le=500),
    page_token: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, description='e.g., state="ACTIVE" AND labels.env="prod"'),
    order_by: Optional[str] = Query(None, description='e.g., "update_time desc, display_name asc"'),
    q: Optional[str] = Query(None, description="case-insensitive match on display_name"),
    include_total: bool = Query(False),
    db: AsyncSession = Depends(get_session),
):
    offset = decode_page_token(page_token)
    proj_id, loc_id = await get_parent_ids(db, project, location)

    base_stmt = select(
        tool_tbl.c.id,
        tool_tbl.c.name_key,
        tool_tbl.c.display_name,
        tool_tbl.c.description,
        tool_tbl.c.type,
        tool_tbl.c.state,
        tool_tbl.c.config,
        tool_tbl.c.labels,
        tool_tbl.c.annotations,
        tool_tbl.c.owner,
        tool_tbl.c.etag,
        tool_tbl.c.created_at,
        tool_tbl.c.updated_at,
    )
    stmt = apply_filter(base_stmt, proj_id, loc_id, filter, q)
    stmt = apply_order_by(stmt, order_by).offset(offset).limit(page_size + 1)

    rows = (await db.execute(stmt)).all()
    tool_ids = [r.id for r in rows[:page_size]]
    aliases_map = await load_aliases(db, tool_ids)

    items = [
        row_to_out(r, project, location, aliases_map.get(r.id, []))
        for r in rows[:page_size]
    ]
    next_token = encode_page_token(offset + page_size) if len(rows) > page_size else None

    total = None
    if include_total:
        cnt_stmt = apply_filter(select(func.count()).select_from(tool_tbl), proj_id, loc_id, filter, q)
        total = int(await db.scalar(cnt_stmt))

    return ListResponse(tools=items, next_page_token=next_token, total_size=total)


@router.get(
    "/projects/{project}/locations/{location}/tools/{tool}",
    response_model=ToolOut,
    summary="Get Tool",
)
@require_scopes("tools.read")
async def get_tool(
    response: Response,
    project: str,
    location: str,
    tool: str,
    db: AsyncSession = Depends(get_session),
):
    proj_id, loc_id = await get_parent_ids(db, project, location)
    stmt = select(tool_tbl).where(
        tool_tbl.c.project_id == proj_id,
        tool_tbl.c.location_id == loc_id,
        tool_tbl.c.name_key == tool,
        tool_tbl.c.deleted_at.is_(None),
    )
    row = (await db.execute(stmt)).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="tool not found")
    aliases_map = await load_aliases(db, [row["id"]])
    response.headers["ETag"] = row["etag"]
    return row_to_out(row, project, location, aliases_map.get(row["id"], []))


@router.post(
    "/projects/{project}/locations/{location}/tools",
    status_code=status.HTTP_201_CREATED,
    response_model=ToolOut,
    summary="Create Tool",
)
@require_scopes("tools.write")
async def create_tool(
    request: Request,
    response: Response,
    payload: ToolCreate,
    project: str,
    location: str,
    db: AsyncSession = Depends(get_session),
):
    proj_id, loc_id = await get_parent_ids(db, project, location)
    tool_id = payload.tool_id or slugify(payload.display_name)

    # Идемпотентность по (project, location, name_key)
    exists_stmt = select(tool_tbl.c.id, tool_tbl.c.etag).where(
        tool_tbl.c.project_id == proj_id,
        tool_tbl.c.location_id == loc_id,
        tool_tbl.c.name_key == tool_id,
        tool_tbl.c.deleted_at.is_(None),
    )
    existing = (await db.execute(exists_stmt)).first()
    if existing:
        # 409 при попытке повторного создания
        raise HTTPException(status_code=409, detail="tool already exists")

    ins = insert(tool_tbl).values(
        id=uuid.uuid4(),
        project_id=proj_id,
        location_id=loc_id,
        name_key=tool_id,
        display_name=payload.display_name,
        description=payload.description,
        type=str(payload.type),
        state="ACTIVE",
        config=payload.config or {},
        labels=payload.labels or {},
        annotations=payload.annotations or {},
        owner=payload.owner,
    ).returning(
        tool_tbl.c.id, tool_tbl.c.etag, tool_tbl.c.created_at, tool_tbl.c.updated_at,
        tool_tbl.c.display_name, tool_tbl.c.description, tool_tbl.c.type, tool_tbl.c.state,
        tool_tbl.c.config, tool_tbl.c.labels, tool_tbl.c.annotations, tool_tbl.c.owner, tool_tbl.c.name_key
    )
    row = (await db.execute(ins)).first()

    # Алиасы
    if payload.aliases:
        await db.execute(
            insert(alias_tbl),
            [{"tool_id": row.id, "alias": a} for a in payload.aliases],
        )

    await db.commit()

    response.headers["Location"] = f"/v1/{resource_name(project, location, tool_id)}"
    response.headers["ETag"] = row.etag
    out = row_to_out(row, project, location, payload.aliases or [])
    return out


@router.patch(
    "/projects/{project}/locations/{location}/tools/{tool}",
    response_model=ToolOut,
    summary="Update Tool (ETag/If-Match)",
)
@require_scopes("tools.write")
async def update_tool(
    response: Response,
    payload: ToolUpdate,
    project: str,
    location: str,
    tool: str,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    allow_missing_etag: bool = Query(False),
    db: AsyncSession = Depends(get_session),
):
    proj_id, loc_id = await get_parent_ids(db, project, location)

    # Загружаем текущую запись
    cur = (await db.execute(
        select(tool_tbl).where(
            tool_tbl.c.project_id == proj_id,
            tool_tbl.c.location_id == loc_id,
            tool_tbl.c.name_key == tool,
            tool_tbl.c.deleted_at.is_(None),
        )
    )).mappings().first()
    if not cur:
        raise HTTPException(status_code=404, detail="tool not found")

    if not allow_missing_etag and not if_match:
        # 428 Precondition Required — требуем If-Match
        raise HTTPException(status_code=428, detail="If-Match header required")

    if if_match and if_match != cur["etag"]:
        raise HTTPException(status_code=412, detail="etag mismatch")

    updates: Dict[str, Any] = {}
    for field in ("display_name", "description", "type", "state", "config", "labels", "annotations", "owner"):
        val = getattr(payload, field)
        if val is not None:
            updates[field] = val

    # Обновление основных полей
    if updates:
        upd = (
            update(tool_tbl)
            .where(tool_tbl.c.id == cur["id"])
            .values(**updates)
            .returning(
                tool_tbl.c.id, tool_tbl.c.etag, tool_tbl.c.created_at, tool_tbl.c.updated_at,
                tool_tbl.c.display_name, tool_tbl.c.description, tool_tbl.c.type, tool_tbl.c.state,
                tool_tbl.c.config, tool_tbl.c.labels, tool_tbl.c.annotations, tool_tbl.c.owner, tool_tbl.c.name_key
            )
        )
        row = (await db.execute(upd)).first()
    else:
        row = cur  # без изменений

    # Обновление алиасов: если aliases передан, переустановить множество
    if payload.aliases is not None:
        await db.execute(delete(alias_tbl).where(alias_tbl.c.tool_id == row.id))
        if payload.aliases:
            await db.execute(
                insert(alias_tbl),
                [{"tool_id": row.id, "alias": a} for a in payload.aliases],
            )

    await db.commit()

    # Загружаем алиасы по факту
    aliases_map = await load_aliases(db, [row.id])
    response.headers["ETag"] = row.etag
    return row_to_out(row, project, location, aliases_map.get(row.id, []))


@router.delete(
    "/projects/{project}/locations/{location}/tools/{tool}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete/Disable Tool (soft delete by default)",
)
@require_scopes("tools.write")
async def delete_tool(
    project: str,
    location: str,
    tool: str,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    disable_only: bool = Query(False, description="If true, set state=DISABLED; else soft-delete (deleted_at)"),
    db: AsyncSession = Depends(get_session),
):
    proj_id, loc_id = await get_parent_ids(db, project, location)

    cur = (await db.execute(
        select(tool_tbl.c.id, tool_tbl.c.etag).where(
            tool_tbl.c.project_id == proj_id,
            tool_tbl.c.location_id == loc_id,
            tool_tbl.c.name_key == tool,
            tool_tbl.c.deleted_at.is_(None),
        )
    )).first()
    if not cur:
        raise HTTPException(status_code=404, detail="tool not found")

    if not if_match:
        raise HTTPException(status_code=428, detail="If-Match header required")
    if if_match != cur.etag:
        raise HTTPException(status_code=412, detail="etag mismatch")

    if disable_only:
        stmt = (
            update(tool_tbl)
            .where(tool_tbl.c.id == cur.id)
            .values(state="DISABLED")
        )
        await db.execute(stmt)
    else:
        # Soft delete: выставляем deleted_at; уникальный индекс уже исключает soft-deleted записи
        await db.execute(
            update(tool_tbl).where(tool_tbl.c.id == cur.id).values(deleted_at=func.now())
        )

    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class BatchEntry(BaseModel):
    name: Optional[str] = Field(None, description='Полное имя ресурса или пусто')
    tool_id: Optional[str] = Field(None, description='Альтернатива name: {tool}')
    state: ToolState
    etag: Optional[str] = None

class BatchUpdateStateRequest(BaseModel):
    entries: List[BatchEntry]

class BatchUpdateStateResponse(BaseModel):
    tools: List[ToolOut]

@router.post(
    "/projects/{project}/locations/{location}/tools:batchUpdateState",
    response_model=BatchUpdateStateResponse,
    summary="Batch Update Tool State",
)
@require_scopes("tools.write")
async def batch_update_state(
    response: Response,
    project: str,
    location: str,
    payload: BatchUpdateStateRequest,
    db: AsyncSession = Depends(get_session),
):
    proj_id, loc_id = await get_parent_ids(db, project, location)
    outs: List[ToolOut] = []

    for entry in payload.entries:
        if entry.name:
            m = re.match(r"^projects/([^/]+)/locations/([^/]+)/tools/([^/]+)$", entry.name)
            if not m or m.group(1) != project or m.group(2) != location:
                raise HTTPException(status_code=400, detail=f"invalid name: {entry.name}")
            key = m.group(3)
        elif entry.tool_id:
            key = entry.tool_id
        else:
            raise HTTPException(status_code=400, detail="entry requires name or tool_id")

        cur = (await db.execute(
            select(tool_tbl.c.id, tool_tbl.c.etag).where(
                tool_tbl.c.project_id == proj_id,
                tool_tbl.c.location_id == loc_id,
                tool_tbl.c.name_key == key,
                tool_tbl.c.deleted_at.is_(None),
            )
        )).first()
        if not cur:
            raise HTTPException(status_code=404, detail=f"tool not found: {key}")
        if entry.etag and entry.etag != cur.etag:
            raise HTTPException(status_code=412, detail=f"etag mismatch: {key}")

        row = (await db.execute(
            update(tool_tbl)
            .where(tool_tbl.c.id == cur.id)
            .values(state=str(entry.state))
            .returning(
                tool_tbl.c.id, tool_tbl.c.etag, tool_tbl.c.created_at, tool_tbl.c.updated_at,
                tool_tbl.c.display_name, tool_tbl.c.description, tool_tbl.c.type, tool_tbl.c.state,
                tool_tbl.c.config, tool_tbl.c.labels, tool_tbl.c.annotations, tool_tbl.c.owner, tool_tbl.c.name_key
            )
        )).first()

        aliases_map = await load_aliases(db, [row.id])
        outs.append(row_to_out(row, project, location, aliases_map.get(row.id, [])))

    await db.commit()
    return BatchUpdateStateResponse(tools=outs)


class ExecuteRequest(BaseModel):
    input: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = Field(None, description="Идемпотентный ID")
    timeout_seconds: Optional[int] = Field(None, ge=1, le=86400)
    validate_only: bool = False

class ExecuteMetadata(BaseModel):
    name: str
    operation_id: str
    start_time: datetime
    progress_percent: int = 0

class ExecuteResponse(BaseModel):
    name: str
    operation_id: str
    output: Dict[str, Any] = Field(default_factory=dict)
    logs: List[Dict[str, Any]] = Field(default_factory=list)

@router.post(
    "/projects/{project}/locations/{location}/tools/{tool}:execute",
    response_model=ExecuteResponse,
    summary="Execute Tool (stub - integrate with your job runner)",
)
@require_scopes("tools.execute")
async def execute_tool(
    project: str,
    location: str,
    tool: str,
    payload: ExecuteRequest,
    db: AsyncSession = Depends(get_session),
):
    # Валидация существования ресурса
    proj_id, loc_id = await get_parent_ids(db, project, location)
    exists = await db.scalar(
        select(func.count()).select_from(tool_tbl).where(
            tool_tbl.c.project_id == proj_id,
            tool_tbl.c.location_id == loc_id,
            tool_tbl.c.name_key == tool,
            tool_tbl.c.deleted_at.is_(None),
            tool_tbl.c.state != "DISABLED",
        )
    )
    if not exists:
        raise HTTPException(status_code=404, detail="tool not found or disabled")

    # Здесь интегрируйте постановку задания в ваш runner/очередь (Celery/Arq/Sidekiq/k8s Job)
    # Для самодостаточного примера возвращаем синхронный stub-ответ
    op_id = uuid.uuid4().hex
    return ExecuteResponse(
        name=resource_name(project, location, tool),
        operation_id=op_id,
        output={"echo": payload.input, "note": "Integrate with your job runner here."},
        logs=[{"time": datetime.utcnow().isoformat() + "Z", "level": "INFO", "message": "Started"}],
    )
