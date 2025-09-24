from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Response, status
from pydantic import BaseModel, Field, ConfigDict, conlist, field_validator, constr, AwareDatetime
from sqlalchemy import (
    and_,
    or_,
    select,
    update,
    insert as sa_insert,
    func,
    text,
    String,
    Integer,
    DateTime,
    JSON,
    ARRAY,
    Boolean,
    MetaData,
    Table,
    Column,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB, insert
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Dependencies (DB session, security). Integrate with your project here.
# ---------------------------------------------------------------------------

async def get_async_session() -> AsyncSession:  # pragma: no cover
    """
    Замените на ваш провайдер сессии, например:
    from core.db.session import get_async_session
    """
    raise RuntimeError("Provide project-specific get_async_session dependency")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Subject(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    sub: str
    scopes: set[str] = set()
    is_admin: bool = False


async def get_current_subject(
    x_actor: Annotated[Optional[str], Header(alias="X-Actor")] = None,
    x_scopes: Annotated[Optional[str], Header(alias="X-Scopes")] = None,
) -> Subject:
    """
    Базовая заглушка субъекта. В реальном проекте интегрируйте OIDC/JWT.
    """
    scopes = set()
    if x_scopes:
        scopes = {s.strip() for s in x_scopes.split(",") if s.strip()}
    return Subject(sub=x_actor or "anonymous", scopes=scopes, is_admin=("admin" in scopes))


def require_scopes(*required: str):
    async def _dep(subject: Subject = Depends(get_current_subject)) -> Subject:
        if not set(required).issubset(subject.scopes) and not subject.is_admin:
            raise HTTPException(status_code=403, detail="forbidden: missing scopes")
        return subject
    return _dep


async def get_tenant_id(
    x_tenant_id: Annotated[Optional[str], Header(alias="X-Tenant-Id")] = None
) -> Optional[uuid.UUID]:
    """
    Возвращает UUID тенанта или None (глобальные объекты).
    """
    if x_tenant_id is None or x_tenant_id == "":
        return None
    try:
        return uuid.UUID(x_tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid X-Tenant-Id") from e


# ---------------------------------------------------------------------------
# SQLAlchemy table declaration (explicit) — используется, если нет ORM-модели.
# База: PostgreSQL, схема cybersecurity, таблица assets.
# ---------------------------------------------------------------------------

metadata = MetaData(schema="cybersecurity")

assets = Table(
    "assets",
    metadata,
    Column("id", PG_UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", PG_UUID(as_uuid=True), nullable=True),
    Column("name", String(255), nullable=False),
    Column("kind", String(32), nullable=False),       # host, service, db, repo, device, ip, domain, ...
    Column("status", String(32), nullable=False),     # active, inactive, quarantined, retired
    Column("risk_score", Integer, nullable=False, server_default=text("0")),  # 0..100
    Column("tags", ARRAY(String), nullable=False, server_default=text("'{}'::text[]")),
    Column("labels", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("props", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("external_ids", JSONB, nullable=False, server_default(text("'{}'::jsonb"))),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("deleted_at", DateTime(timezone=True), nullable=True),
    Column("etag", String(64), nullable=True),
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

AssetStatus = Literal["active", "inactive", "quarantined", "retired"]
AssetKind = Literal[
    "host", "container", "service", "database", "queue", "repository",
    "function", "user", "device", "ip", "domain", "k8s_pod", "k8s_ns", "other"
]
Tag = constr(strip_whitespace=True, min_length=1, max_length=64)
Name = constr(strip_whitespace=True, min_length=1, max_length=255)

class AssetBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name = Field(...)
    kind: AssetKind = Field(...)
    status: AssetStatus = Field(default="active")
    risk_score: int = Field(ge=0, le=100, default=0)
    tags: list[Tag] = Field(default_factory=list)
    labels: dict[str, Any] = Field(default_factory=dict)
    props: dict[str, Any] = Field(default_factory=dict)
    external_ids: dict[str, str] = Field(default_factory=dict)

    @field_validator("tags", mode="before")
    @classmethod
    def ensure_unique_tags(cls, v):
        if v is None:
            return []
        unique = []
        seen = set()
        for t in v:
            t = t.strip()
            if not t:
                continue
            if t not in seen:
                unique.append(t)
                seen.add(t)
        return unique

class AssetCreate(AssetBase):
    id: Optional[uuid.UUID] = None

class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[Name] = None
    status: Optional[AssetStatus] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    tags: Optional[list[Tag]] = None
    labels: Optional[dict[str, Any]] = None
    props: Optional[dict[str, Any]] = None
    external_ids: Optional[dict[str, str]] = None

class AssetOut(AssetBase):
    id: uuid.UUID
    tenant_id: Optional[uuid.UUID] = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    deleted_at: Optional[AwareDatetime] = None
    etag: Optional[str] = None

class Paginated(BaseModel):
    items: list[AssetOut]
    next_cursor: Optional[str] = None
    total: Optional[int] = None  # опционально: может быть выключено для производительности

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_etag(payload: dict[str, Any]) -> str:
    """
    Каноничная сериализация + SHA-256 -> hex (64).
    """
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def encode_cursor(created_at: datetime, id_: uuid.UUID) -> str:
    raw = f"{created_at.isoformat()}|{id_}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        ts_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(ts_str), uuid.UUID(id_str)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="invalid cursor") from e


def row_to_asset_out(row: Any) -> AssetOut:
    return AssetOut(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        kind=row.kind,
        status=row.status,
        risk_score=row.risk_score,
        tags=row.tags or [],
        labels=row.labels or {},
        props=row.props or {},
        external_ids=row.external_ids or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
        deleted_at=row.deleted_at,
        etag=row.etag,
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/assets", tags=["assets"])


# --------------------------- LIST ------------------------------------------
@router.get(
    "",
    response_model=Paginated,
    dependencies=[Depends(require_scopes("assets:read"))],
    summary="Список активов с фильтрами и keyset-пагинацией",
)
async def list_assets(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    limit: Annotated[int, Query(ge=1, le=200, description="Размер страницы")] = 50,
    cursor: Annotated[Optional[str], Query(description="Курсор keyset-пагинации")] = None,
    q: Annotated[Optional[str], Query(description="Поиск по имени (ILIKE)")] = None,
    kind: Annotated[Optional[AssetKind], Query()] = None,
    status_: Annotated[Optional[AssetStatus], Query(alias="status")] = None,
    tag: Annotated[Optional[str], Query(description="Фильтр по тегу")] = None,
    risk_min: Annotated[Optional[int], Query(ge=0, le=100)] = None,
    risk_max: Annotated[Optional[int], Query(ge=0, le=100)] = None,
    created_from: Annotated[Optional[datetime], Query()] = None,
    created_to: Annotated[Optional[datetime], Query()] = None,
    with_total: Annotated[bool, Query(description="Возвращать total (дороже)")] = False,
):
    conds = [assets.c.deleted_at.is_(None)]
    if tenant_id is None:
        conds.append(assets.c.tenant_id.is_(None))
    else:
        conds.append(or_(assets.c.tenant_id == tenant_id, assets.c.tenant_id.is_(None)))

    if q:
        conds.append(assets.c.name.ilike(f"%{q}%"))
    if kind:
        conds.append(assets.c.kind == kind)
    if status_:
        conds.append(assets.c.status == status_)
    if tag:
        conds.append(func.coalesce(assets.c.tags, []).contains([tag]))
    if risk_min is not None:
        conds.append(assets.c.risk_score >= risk_min)
    if risk_max is not None:
        conds.append(assets.c.risk_score <= risk_max)
    if created_from:
        conds.append(assets.c.created_at >= created_from)
    if created_to:
        conds.append(assets.c.created_at < created_to)

    stmt = select(assets).where(and_(*conds)).order_by(assets.c.created_at.desc(), assets.c.id.desc())

    if cursor:
        c_at, c_id = decode_cursor(cursor)
        # keyset: (created_at,id) < (c_at,c_id)
        stmt = stmt.where(
            or_(
                assets.c.created_at < c_at,
                and_(assets.c.created_at == c_at, assets.c.id < c_id),
            )
        )

    stmt = stmt.limit(limit + 1)
    rows = (await session.execute(stmt)).fetchall()

    items = [row_to_asset_out(r) for r in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)

    total = None
    if with_total:
        cnt_stmt = select(func.count()).select_from(assets).where(and_(*conds))
        total = (await session.execute(cnt_stmt)).scalar_one()

    return Paginated(items=items, next_cursor=next_cursor, total=total)


# --------------------------- RETRIEVE ---------------------------------------
@router.get(
    "/{asset_id}",
    response_model=AssetOut,
    dependencies=[Depends(require_scopes("assets:read"))],
    summary="Получить актив по ID",
)
async def get_asset(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    asset_id: Annotated[uuid.UUID, Path()],
    if_none_match: Annotated[Optional[str], Header(alias="If-None-Match")] = None,
):
    conds = [assets.c.id == asset_id, assets.c.deleted_at.is_(None)]
    if tenant_id is None:
        conds.append(assets.c.tenant_id.is_(None))
    else:
        conds.append(or_(assets.c.tenant_id == tenant_id, assets.c.tenant_id.is_(None)))

    row = (await session.execute(select(assets).where(and_(*conds)).limit(1))).first()
    if not row:
        raise HTTPException(status_code=404, detail="asset not found")
    dto = row_to_asset_out(row)

    if dto.etag and if_none_match and dto.etag == if_none_match:
        # 304 Not Modified
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return dto  # тело может игнорироваться клиентом, но оставим совместимость

    if dto.etag:
        response.headers["ETag"] = dto.etag
    return dto


# --------------------------- CREATE -----------------------------------------
@router.post(
    "",
    status_code=201,
    response_model=AssetOut,
    dependencies=[Depends(require_scopes("assets:write"))],
    summary="Создать актив",
)
async def create_asset(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    subject: Annotated[Subject, Depends(get_current_subject)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    payload: AssetCreate,
):
    new_id = payload.id or uuid.uuid4()
    base_dict = payload.model_dump()
    base_dict.pop("id", None)

    record = {
        "id": new_id,
        "tenant_id": tenant_id,
        **base_dict,
        "created_at": now_utc(),
        "updated_at": now_utc(),
        "deleted_at": None,
    }
    record["etag"] = compute_etag(
        {
            k: v
            for k, v in record.items()
            if k
            not in {
                "created_at",
                "updated_at",
                "deleted_at",
            }
        }
    )

    stmt = insert(assets).values(record).on_conflict_do_nothing(index_elements=["id"])
    res = await session.execute(stmt)
    if res.rowcount == 0:
        raise HTTPException(status_code=409, detail="asset already exists")

    # вернуть фактическое состояние
    row = (
        await session.execute(select(assets).where(and_(assets.c.id == new_id, assets.c.deleted_at.is_(None))))
    ).first()
    await session.commit()
    return row_to_asset_out(row)


# --------------------------- UPDATE (PATCH) ----------------------------------
@router.patch(
    "/{asset_id}",
    response_model=AssetOut,
    dependencies=[Depends(require_scopes("assets:write"))],
    summary="Частично обновить актив",
)
async def update_asset(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    asset_id: Annotated[uuid.UUID, Path()],
    payload: AssetUpdate,
):
    # Найти существующий
    conds = [assets.c.id == asset_id, assets.c.deleted_at.is_(None)]
    if tenant_id is None:
        conds.append(assets.c.tenant_id.is_(None))
    else:
        conds.append(or_(assets.c.tenant_id == tenant_id, assets.c.tenant_id.is_(None)))

    row = (await session.execute(select(assets).where(and_(*conds)).limit(1))).first()
    if not row:
        raise HTTPException(status_code=404, detail="asset not found")

    data = payload.model_dump(exclude_unset=True)
    if not data:
        return row_to_asset_out(row)

    # Пересчитать etag на основе будущего состояния
    current = row._mapping  # RowMapping
    merged = {
        "id": current["id"],
        "tenant_id": current["tenant_id"],
        "name": data.get("name", current["name"]),
        "kind": current["kind"],
        "status": data.get("status", current["status"]),
        "risk_score": data.get("risk_score", current["risk_score"]),
        "tags": data.get("tags", current["tags"] or []),
        "labels": data.get("labels", current["labels"] or {}),
        "props": data.get("props", current["props"] or {}),
        "external_ids": data.get("external_ids", current["external_ids"] or {}),
    }
    new_etag = compute_etag(merged)

    upd = (
        update(assets)
        .where(and_(*conds))
        .values(
            **data,
            etag=new_etag,
            updated_at=now_utc(),
        )
        .returning(assets)
    )
    updated_row = (await session.execute(upd)).first()
    await session.commit()
    return row_to_asset_out(updated_row)


# --------------------------- DELETE (SOFT) -----------------------------------
@router.delete(
    "/{asset_id}",
    status_code=204,
    dependencies=[Depends(require_scopes("assets:write"))],
    summary="Мягкое удаление актива (soft-delete)",
)
async def delete_asset(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    asset_id: Annotated[uuid.UUID, Path()],
):
    conds = [assets.c.id == asset_id, assets.c.deleted_at.is_(None)]
    if tenant_id is None:
        conds.append(assets.c.tenant_id.is_(None))
    else:
        conds.append(or_(assets.c.tenant_id == tenant_id, assets.c.tenant_id.is_(None)))

    upd = (
        update(assets)
        .where(and_(*conds))
        .values(
            deleted_at=now_utc(),
            updated_at=now_utc(),
        )
    )
    res = await session.execute(upd)
    if res.rowcount == 0:
        raise HTTPException(status_code=404, detail="asset not found")
    await session.commit()
    return Response(status_code=204)


# --------------------------- TAGS: ADD ---------------------------------------
class TagsPatch(BaseModel):
    add: conlist(Tag, min_length=1) | None = None
    remove: conlist(Tag, min_length=1) | None = None


@router.post(
    "/{asset_id}/tags",
    response_model=AssetOut,
    dependencies=[Depends(require_scopes("assets:write"))],
    summary="Добавить/удалить теги у актива",
)
async def patch_tags(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    asset_id: Annotated[uuid.UUID, Path()],
    payload: TagsPatch,
):
    conds = [assets.c.id == asset_id, assets.c.deleted_at.is_(None)]
    if tenant_id is None:
        conds.append(assets.c.tenant_id.is_(None))
    else:
        conds.append(or_(assets.c.tenant_id == tenant_id, assets.c.tenant_id.is_(None)))

    row = (await session.execute(select(assets).where(and_(*conds)).limit(1))).first()
    if not row:
        raise HTTPException(status_code=404, detail="asset not found")

    current_tags: list[str] = list(row.tags or [])
    add = list(payload.add or [])
    remove = set(payload.remove or [])

    # добавить уникально
    for t in add:
        if t not in current_tags:
            current_tags.append(t)
    # удалить
    current_tags = [t for t in current_tags if t not in remove]

    new_etag = compute_etag(
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "kind": row.kind,
            "status": row.status,
            "risk_score": row.risk_score,
            "tags": current_tags,
            "labels": row.labels or {},
            "props": row.props or {},
            "external_ids": row.external_ids or {},
        }
    )

    upd = (
        update(assets)
        .where(and_(*conds))
        .values(tags=current_tags, etag=new_etag, updated_at=now_utc())
        .returning(assets)
    )
    updated_row = (await session.execute(upd)).first()
    await session.commit()
    return row_to_asset_out(updated_row)


# --------------------------- BULK UPSERT -------------------------------------
class AssetUpsertItem(AssetBase):
    id: Optional[uuid.UUID] = None


class BulkUpsertRequest(BaseModel):
    items: conlist(AssetUpsertItem, min_length=1, max_length=500)


class BulkUpsertResult(BaseModel):
    inserted: int
    updated: int
    items: list[AssetOut]


@router.post(
    "/_bulk",
    response_model=BulkUpsertResult,
    dependencies=[Depends(require_scopes("assets:write"))],
    summary="Массовая загрузка/апдейт активов (upsert)",
)
async def bulk_upsert_assets(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[Optional[uuid.UUID], Depends(get_tenant_id)],
    payload: BulkUpsertRequest,
):
    inserted = 0
    updated = 0
    out_items: list[AssetOut] = []

    for item in payload.items:
        aid = item.id or uuid.uuid4()
        base = item.model_dump()
        base.pop("id", None)
        record = {
            "id": aid,
            "tenant_id": tenant_id,
            **base,
            "deleted_at": None,
        }
        # ETag считается от стабильных полей
        record["etag"] = compute_etag(
            {
                "id": record["id"],
                "tenant_id": record["tenant_id"],
                "name": record["name"],
                "kind": record["kind"],
                "status": record["status"],
                "risk_score": record["risk_score"],
                "tags": record["tags"],
                "labels": record["labels"],
                "props": record["props"],
                "external_ids": record["external_ids"],
            }
        )

        stmt = insert(assets).values(
            **record,
            created_at=func.coalesce(assets.c.created_at, func.now()),
            updated_at=func.now(),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "name": stmt.excluded.name,
                "status": stmt.excluded.status,
                "risk_score": stmt.excluded.risk_score,
                "tags": stmt.excluded.tags,
                "labels": stmt.excluded.labels,
                "props": stmt.excluded.props,
                "external_ids": stmt.excluded.external_ids,
                "tenant_id": stmt.excluded.tenant_id,
                "etag": stmt.excluded.etag,
                "updated_at": func.now(),
                "deleted_at": None,
            },
        ).returning(assets, text("xmax = 0 AS inserted"))  # inserted=true если xmax=0
        row = (await session.execute(stmt)).first()
        if row.inserted:
            inserted += 1
        else:
            updated += 1
        out_items.append(row_to_asset_out(row))

    await session.commit()
    return BulkUpsertResult(inserted=inserted, updated=updated, items=out_items)
