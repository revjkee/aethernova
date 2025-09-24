# datafabric-core/api/http/routers/v1/datasets.py
from __future__ import annotations

import hashlib
import json
import time
import typing as t
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, constr, validator

# Зависимости безопасности из middleware/auth.py
try:
    from ...middleware.auth import require_scopes, Principal
except Exception:  # при статическом анализе/тестах
    def require_scopes(*_args, **_kwargs):  # type: ignore
        async def _dep(request: Request):  # type: ignore
            return None
        return _dep
    Principal = t.Any  # type: ignore


# ============================ Модели домена и DTO ============================

class DatasetStatus(str, Enum):
    draft = "draft"
    active = "active"
    archived = "archived"


class DatasetVisibility(str, Enum):
    private = "private"
    internal = "internal"
    public = "public"


NameStr = constr(strip_whitespace=True, min_length=3, max_length=128, regex=r"^[A-Za-z0-9_\-\s]+$")
DescStr = constr(strip_whitespace=True, min_length=0, max_length=2048)

class DatasetBase(BaseModel):
    name: NameStr = Field(..., description="Имя датасета")
    description: DescStr = Field("", description="Описание")
    schemaId: t.Optional[str] = Field(None, description="$id JSON Schema (URI)")
    status: DatasetStatus = Field(DatasetStatus.draft, description="Статус")
    visibility: DatasetVisibility = Field(DatasetVisibility.private, description="Видимость")
    tags: list[constr(strip_whitespace=True, min_length=2, max_length=64)] = Field(default_factory=list)

    @validator("tags")
    def _uniq_tags(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("tags must be unique")
        return v


class DatasetCreate(DatasetBase):
    pass


class DatasetUpdate(DatasetBase):
    pass


class DatasetPatch(BaseModel):
    name: t.Optional[NameStr] = None
    description: t.Optional[DescStr] = None
    schemaId: t.Optional[str] = None
    status: t.Optional[DatasetStatus] = None
    visibility: t.Optional[DatasetVisibility] = None
    tags: t.Optional[list[constr(strip_whitespace=True, min_length=2, max_length=64)]] = None


class Dataset(DatasetBase):
    id: UUID
    owner: t.Optional[str] = Field(None, description="Идентификатор владельца")
    createdAt: datetime
    updatedAt: datetime
    etag: t.Optional[str] = None


class PageMeta(BaseModel):
    page: int = Field(1, ge=1)
    perPage: int = Field(20, ge=1, le=200)
    total: int = Field(..., ge=0)


class Page(BaseModel, t.Generic[t.TypeVar("T")]):
    items: list[t.Any]
    meta: PageMeta


class ProblemDetails(BaseModel):
    type: str = Field("about:blank")
    title: str
    status: int
    detail: t.Optional[str] = None
    instance: t.Optional[str] = None
    traceId: t.Optional[str] = None
    errors: t.Optional[list[dict]] = None


# ============================ Репозиторий (абстракция) ============================

class DatasetRepository(t.Protocol):
    async def list(
        self,
        *,
        page: int,
        per_page: int,
        sort: t.Optional[str],
        q: t.Optional[str],
        status: t.Optional[DatasetStatus],
        visibility: t.Optional[DatasetVisibility],
        tags: t.Optional[list[str]],
    ) -> tuple[list[Dataset], int]: ...

    async def get(self, dataset_id: UUID) -> t.Optional[Dataset]: ...
    async def create(self, data: DatasetCreate, owner: t.Optional[str]) -> Dataset: ...
    async def replace(self, dataset_id: UUID, data: DatasetUpdate, if_match: t.Optional[str]) -> Dataset: ...
    async def patch(self, dataset_id: UUID, patch: DatasetPatch, if_match: t.Optional[str]) -> Dataset: ...
    async def delete(self, dataset_id: UUID) -> None: ...
    async def get_etag(self, dataset_id: UUID) -> t.Optional[str]: ...


# ============================ Ин‑мемори реализация для dev/test ============================

class InMemoryDatasetRepo(DatasetRepository):
    def __init__(self) -> None:
        self._store: dict[UUID, Dataset] = {}

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _compute_etag(payload: dict) -> str:
        h = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return f'W/"{h[:16]}"'

    async def list(
        self,
        *,
        page: int,
        per_page: int,
        sort: t.Optional[str],
        q: t.Optional[str],
        status: t.Optional[DatasetStatus],
        visibility: t.Optional[DatasetVisibility],
        tags: t.Optional[list[str]],
    ) -> tuple[list[Dataset], int]:
        items = list(self._store.values())

        if q:
            ql = q.lower()
            items = [d for d in items if ql in d.name.lower() or ql in (d.description or "").lower()]
        if status:
            items = [d for d in items if d.status == status]
        if visibility:
            items = [d for d in items if d.visibility == visibility]
        if tags:
            tags_set = set(tags)
            items = [d for d in items if tags_set.issubset(set(d.tags))]

        if sort:
            reverse = sort.startswith("-")
            key = sort[1:] if reverse else sort
            if key in {"createdAt", "updatedAt", "name"}:
                items.sort(key=lambda d: getattr(d, key), reverse=reverse)

        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        return items[start:end], total

    async def get(self, dataset_id: UUID) -> t.Optional[Dataset]:
        return self._store.get(dataset_id)

    async def create(self, data: DatasetCreate, owner: t.Optional[str]) -> Dataset:
        now = self._now()
        ds = Dataset(
            id=uuid4(),
            owner=owner,
            createdAt=now,
            updatedAt=now,
            **data.dict(),
        )
        ds.etag = self._compute_etag(ds.dict(exclude={"etag"}))
        self._store[ds.id] = ds
        return ds

    async def replace(self, dataset_id: UUID, data: DatasetUpdate, if_match: t.Optional[str]) -> Dataset:
        existing = self._store.get(dataset_id)
        if not existing:
            raise KeyError("not-found")
        # ETag match
        if if_match and existing.etag and if_match != existing.etag:
            raise PermissionError("precondition-failed")
        updated = existing.copy(update={**data.dict(), "updatedAt": self._now()})
        updated.etag = self._compute_etag(updated.dict(exclude={"etag"}))
        self._store[dataset_id] = updated
        return updated

    async def patch(self, dataset_id: UUID, patch: DatasetPatch, if_match: t.Optional[str]) -> Dataset:
        existing = self._store.get(dataset_id)
        if not existing:
            raise KeyError("not-found")
        if if_match and existing.etag and if_match != existing.etag:
            raise PermissionError("precondition-failed")
        payload = existing.dict()
        for k, v in patch.dict(exclude_unset=True).items():
            payload[k] = v
        payload["updatedAt"] = self._now()
        updated = Dataset(**payload)
        updated.etag = self._compute_etag(updated.dict(exclude={"etag"}))
        self._store[dataset_id] = updated
        return updated

    async def delete(self, dataset_id: UUID) -> None:
        if dataset_id not in self._store:
            raise KeyError("not-found")
        del self._store[dataset_id]

    async def get_etag(self, dataset_id: UUID) -> t.Optional[str]:
        obj = self._store.get(dataset_id)
        return obj.etag if obj else None


# ============================ Идемпотентность (простая кэш‑карта) ============================

class IdempotencyCache:
    """Простой TTL‑кэш для Idempotency‑Key -> результат операции (201)."""
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._data: dict[str, tuple[float, dict]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> t.Optional[dict]:
        self._gc()
        item = self._data.get(key)
        if not item:
            return None
        ts, payload = item
        if (time.time() - ts) > self._ttl:
            self._data.pop(key, None)
            return None
        return payload

    def set(self, key: str, payload: dict) -> None:
        self._gc()
        self._data[key] = (time.time(), payload)

    def _gc(self) -> None:
        now = time.time()
        expired = [k for k, (ts, _) in self._data.items() if now - ts > self._ttl]
        for k in expired:
            self._data.pop(k, None)


@lru_cache(maxsize=1)
def _idem_cache() -> IdempotencyCache:
    return IdempotencyCache(ttl_seconds=600)


# ============================ Зависимости и утилиты ============================

def get_repo() -> DatasetRepository:
    # Здесь можно внедрить реальный репозиторий (Postgres, etc.)
    return InMemoryDatasetRepo()

def problem(
    *,
    status_code: int,
    title: str,
    detail: t.Optional[str] = None,
    trace_id: t.Optional[str] = None,
    type_uri: str = "about:blank",
    errors: t.Optional[list[dict]] = None,
) -> JSONResponse:
    payload = {
        "type": type_uri,
        "title": title,
        "status": status_code,
    }
    if detail:
        payload["detail"] = detail
    if trace_id:
        payload["traceId"] = trace_id
    if errors:
        payload["errors"] = errors
    return JSONResponse(payload, status_code=status_code)

def set_common_headers(resp: Response, etag: t.Optional[str] = None, vary_extra: t.Optional[str] = None) -> None:
    if etag:
        resp.headers["ETag"] = etag
    # Набор эксплуатационных заголовков (могут переопределяться обратным прокси)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    if vary_extra:
        vary_cur = resp.headers.get("Vary")
        resp.headers["Vary"] = ", ".join(filter(None, {*(vary_cur.split(",") if vary_cur else []), vary_extra}.union({"Accept"})))


router = APIRouter(prefix="/datasets", tags=["datasets"])


# ============================ Endpoints ============================

@router.get(
    "",
    response_model=Page,
    summary="Список датасетов",
    dependencies=[Depends(require_scopes("dataset:read"))],
)
async def list_datasets(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
    sort: t.Optional[str] = Query(None, description="Поле сортировки: name|createdAt|updatedAt, префикс '-' для убывания"),
    q: t.Optional[str] = Query(None, description="Поиск по имени/описанию"),
    status_filter: t.Optional[DatasetStatus] = Query(None, alias="status"),
    visibility: t.Optional[DatasetVisibility] = Query(None),
    tags: t.Optional[str] = Query(None, description="CSV тегов для строгого включения"),
    repo: DatasetRepository = Depends(get_repo),
):
    tags_list = [t.strip() for t in tags.split(",")] if tags else None
    items, total = await repo.list(
        page=page,
        per_page=per_page,
        sort=sort,
        q=q,
        status=status_filter,
        visibility=visibility,
        tags=tags_list,
    )
    resp = JSONResponse(
        {
            "items": [json.loads(Dataset.parse_obj(i).json()) for i in items],
            "meta": {"page": page, "perPage": per_page, "total": total},
        }
    )
    set_common_headers(resp, vary_extra="Accept")
    return resp


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=Dataset,
    summary="Создать датасет",
    dependencies=[Depends(require_scopes("dataset:write"))],
)
async def create_dataset(
    request: Request,
    payload: DatasetCreate,
    response: Response,
    repo: DatasetRepository = Depends(get_repo),
    principal: Principal = Depends(require_scopes("dataset:write")),  # возвращает Principal
    idempotency_key: t.Optional[str] = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    if idempotency_key:
        cached = _idem_cache().get(idempotency_key)
        if cached:
            resp = JSONResponse(cached, status_code=status.HTTP_201_CREATED)
            set_common_headers(resp, etag=cached.get("etag"))
            return resp

    try:
        owner_id = getattr(principal, "subject", None) if principal else None
        created = await repo.create(payload, owner=owner_id)
    except Exception as e:
        return problem(status_code=500, title="Create failed", detail=str(e), trace_id=trace_id, type_uri="urn:problem:dataset:create")

    body = json.loads(Dataset.parse_obj(created).json())
    if idempotency_key:
        _idem_cache().set(idempotency_key, body)

    resp = JSONResponse(body, status_code=status.HTTP_201_CREATED)
    set_common_headers(resp, etag=created.etag)
    resp.headers["Location"] = f"{request.url}/{created.id}"
    return resp


@router.get(
    "/{dataset_id}",
    response_model=Dataset,
    summary="Получить датасет",
    dependencies=[Depends(require_scopes("dataset:read"))],
)
async def get_dataset(
    request: Request,
    dataset_id: UUID = Path(...),
    repo: DatasetRepository = Depends(get_repo),
):
    obj = await repo.get(dataset_id)
    if not obj:
        return problem(status_code=404, title="Not Found", detail="Dataset not found", type_uri="urn:problem:dataset:not-found",
                       trace_id=request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id"))
    resp = JSONResponse(json.loads(Dataset.parse_obj(obj).json()))
    set_common_headers(resp, etag=obj.etag)
    return resp


@router.put(
    "/{dataset_id}",
    response_model=Dataset,
    summary="Полная замена датасета",
    dependencies=[Depends(require_scopes("dataset:write"))],
)
async def replace_dataset(
    request: Request,
    dataset_id: UUID = Path(...),
    payload: DatasetUpdate = ...,
    repo: DatasetRepository = Depends(get_repo),
    if_match: t.Optional[str] = Header(None, alias="If-Match"),
    idempotency_key: t.Optional[str] = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    try:
        updated = await repo.replace(dataset_id, payload, if_match=if_match)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Dataset not found", type_uri="urn:problem:dataset:not-found", trace_id=trace_id)
    except PermissionError:
        return problem(status_code=412, title="Precondition Failed", detail="ETag mismatch", type_uri="urn:problem:dataset:precondition", trace_id=trace_id)
    except Exception as e:
        return problem(status_code=500, title="Replace failed", detail=str(e), type_uri="urn:problem:dataset:replace", trace_id=trace_id)

    body = json.loads(Dataset.parse_obj(updated).json())
    if idempotency_key:
        _idem_cache().set(idempotency_key, body)
    resp = JSONResponse(body)
    set_common_headers(resp, etag=updated.etag)
    return resp


@router.patch(
    "/{dataset_id}",
    response_model=Dataset,
    summary="Частичное обновление датасета",
    dependencies=[Depends(require_scopes("dataset:write"))],
)
async def patch_dataset(
    request: Request,
    dataset_id: UUID = Path(...),
    patch: DatasetPatch = ...,
    repo: DatasetRepository = Depends(get_repo),
    if_match: t.Optional[str] = Header(None, alias="If-Match"),
    idempotency_key: t.Optional[str] = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    try:
        updated = await repo.patch(dataset_id, patch, if_match=if_match)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Dataset not found", type_uri="urn:problem:dataset:not-found", trace_id=trace_id)
    except PermissionError:
        return problem(status_code=412, title="Precondition Failed", detail="ETag mismatch", type_uri="urn:problem:dataset:precondition", trace_id=trace_id)
    except Exception as e:
        return problem(status_code=500, title="Patch failed", detail=str(e), type_uri="urn:problem:dataset:patch", trace_id=trace_id)

    body = json.loads(Dataset.parse_obj(updated).json())
    if idempotency_key:
        _idem_cache().set(idempotency_key, body)
    resp = JSONResponse(body)
    set_common_headers(resp, etag=updated.etag)
    return resp


@router.delete(
    "/{dataset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить датасет",
    dependencies=[Depends(require_scopes("dataset:write"))],
)
async def delete_dataset(
    request: Request,
    dataset_id: UUID = Path(...),
    repo: DatasetRepository = Depends(get_repo),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    try:
        await repo.delete(dataset_id)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Dataset not found", type_uri="urn:problem:dataset:not-found", trace_id=trace_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================ Пример подключения ============================
# В главном модуле:
#   from fastapi import FastAPI
#   from .routers.v1 import datasets
#   app = FastAPI()
#   app.include_router(datasets.router)
