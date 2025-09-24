# datafabric-core/api/http/routers/v1/catalog.py
# Industrial-grade Catalog API (v1) for DataFabric Core
# Features:
# - Datasets CRUD (+ search) with cursor pagination, filtering, sorting
# - ETag/Last-Modified conditional responses (304)
# - Idempotency for create via Idempotency-Key
# - Repository abstraction with in-memory fallback
# - Unified error taxonomy via errors.py (RFC 7807)
# - Strict Pydantic models with examples and constraints

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, ConfigDict, constr, validator

try:
    # Prefer local domain errors if available
    from api.http.errors import (
        install_error_handlers,  # noqa: F401 (hint to integrators)
        bad_request,
        conflict,
        not_found,
        unauthorized,
        forbidden,
        unprocessable,
        too_many_requests,
        service_unavailable,
    )
except Exception:
    # Minimal fallbacks if errors module is not present (should not happen in prod)
    def _http_error(msg, code=status.HTTP_400_BAD_REQUEST):
        raise HTTPException(code, detail=msg)

    def bad_request(msg, **_):  # type: ignore
        return _http_error(msg, status.HTTP_400_BAD_REQUEST)

    def conflict(*_, **__):  # type: ignore
        return _http_error("Conflict", status.HTTP_409_CONFLICT)

    def not_found(*_, **__):  # type: ignore
        return _http_error("Not Found", status.HTTP_404_NOT_FOUND)

    def unauthorized(*_, **__):  # type: ignore
        return _http_error("Unauthorized", status.HTTP_401_UNAUTHORIZED)

    def forbidden(*_, **__):  # type: ignore
        return _http_error("Forbidden", status.HTTP_403_FORBIDDEN)

    def unprocessable(msg, **_):  # type: ignore
        return _http_error(msg, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def too_many_requests():  # type: ignore
        return _http_error("Too Many Requests", status.HTTP_429_TOO_MANY_REQUESTS)

    def service_unavailable(*_, **__):  # type: ignore
        return _http_error("Service Unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

DatasetVisibility = constr(pattern="^(public|internal|private)$")

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _slugify(name: str) -> str:
    # Simple deterministic slug; replace with robust lib if needed
    s = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    while "--" in s:
        s = s.replace("--", "-")
    return s or "dataset"

class DatasetBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: constr(min_length=1, max_length=200)
    description: constr(min_length=0, max_length=10_000) = ""
    tags: List[constr(min_length=1, max_length=64)] = Field(default_factory=list)
    owner: constr(min_length=1, max_length=128)
    visibility: DatasetVisibility = "internal"

    @validator("tags")
    def _norm_tags(cls, v: List[str]) -> List[str]:
        norm = []
        for t in v:
            tt = t.strip().lower()
            if tt:
                norm.append(tt)
        # unique while preserving order
        seen = set()
        out = []
        for t in norm:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out[:100]  # hard cap

class DatasetCreate(DatasetBase):
    id: Optional[constr(min_length=3, max_length=128)] = None  # optional client-supplied id

class DatasetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[constr(min_length=1, max_length=200)] = None
    description: Optional[constr(min_length=0, max_length=10_000)] = None
    tags: Optional[List[constr(min_length=1, max_length=64)]] = None
    visibility: Optional[DatasetVisibility] = None

class DatasetSummary(BaseModel):
    id: str
    name: str
    slug: str
    tags: List[str]
    owner: str
    visibility: str
    created_at: datetime
    updated_at: datetime
    version: int

class DatasetDetail(DatasetSummary):
    description: str
    # Place for extended fields (schema, size stats, lineage refs, etc.)

class SearchQuery(BaseModel):
    q: Optional[constr(min_length=1, max_length=256)] = None
    tags: List[constr(min_length=1, max_length=64)] = Field(default_factory=list)
    owner: Optional[constr(min_length=1, max_length=128)] = None
    visibility: Optional[DatasetVisibility] = None
    sort: constr(pattern="^(updated_at|created_at|name)$") = "updated_at"
    order: constr(pattern="^(asc|desc)$") = "desc"
    limit: int = Field(50, ge=1, le=200)
    cursor: Optional[str] = None

class SearchResponse(BaseModel):
    items: List[DatasetSummary]
    next_cursor: Optional[str] = None

# ------------------------------------------------------------------------------
# Repository abstraction
# ------------------------------------------------------------------------------

class CatalogRepository(Protocol):
    async def create(self, data: DatasetCreate, *, idem_key: Optional[str]) -> DatasetDetail: ...
    async def get(self, dataset_id: str) -> Optional[DatasetDetail]: ...
    async def update(self, dataset_id: str, patch: DatasetUpdate) -> Optional[DatasetDetail]: ...
    async def delete(self, dataset_id: str) -> bool: ...
    async def search(self, query: SearchQuery) -> Tuple[List[DatasetSummary], Optional[str]]: ...
    async def compute_etag(self, dataset_id: str) -> Optional[str]: ...

# ------------------------------------------------------------------------------
# In-memory robust fallback (thread-safe-ish under asyncio)
# ------------------------------------------------------------------------------

class _InMemoryRepo(CatalogRepository):
    def __init__(self):
        self._lock = asyncio.Lock()
        self._data: Dict[str, DatasetDetail] = {}
        self._idempotency: Dict[str, str] = {}  # idem_key -> dataset_id

    async def create(self, data: DatasetCreate, *, idem_key: Optional[str]) -> DatasetDetail:
        async with self._lock:
            if idem_key and idem_key in self._idempotency:
                # Return existing resource for the same idem key
                dsid = self._idempotency[idem_key]
                return self._data[dsid]

            ds_id = data.id or _slugify(data.name)
            if ds_id in self._data:
                raise conflict("Dataset already exists", resource="dataset", id=ds_id)

            now = _utc_now()
            detail = DatasetDetail(
                id=ds_id,
                name=data.name,
                slug=_slugify(data.name),
                description=data.description,
                tags=list(dict.fromkeys([t.lower() for t in data.tags])),
                owner=data.owner,
                visibility=str(data.visibility),
                created_at=now,
                updated_at=now,
                version=1,
            )
            self._data[ds_id] = detail
            if idem_key:
                self._idempotency[idem_key] = ds_id
            return detail

    async def get(self, dataset_id: str) -> Optional[DatasetDetail]:
        async with self._lock:
            return self._data.get(dataset_id)

    async def update(self, dataset_id: str, patch: DatasetUpdate) -> Optional[DatasetDetail]:
        async with self._lock:
            ds = self._data.get(dataset_id)
            if not ds:
                return None
            changed = False
            data = ds.model_dump()
            if patch.name is not None and patch.name != ds.name:
                data["name"] = patch.name
                data["slug"] = _slugify(patch.name)
                changed = True
            if patch.description is not None and patch.description != ds.description:
                data["description"] = patch.description
                changed = True
            if patch.tags is not None:
                tags = list(dict.fromkeys([t.strip().lower() for t in patch.tags if t.strip()]))
                if tags != ds.tags:
                    data["tags"] = tags
                    changed = True
            if patch.visibility is not None and patch.visibility != ds.visibility:
                data["visibility"] = str(patch.visibility)
                changed = True
            if changed:
                data["updated_at"] = _utc_now()
                data["version"] = ds.version + 1
                ds = DatasetDetail(**data)
                self._data[dataset_id] = ds
            return ds

    async def delete(self, dataset_id: str) -> bool:
        async with self._lock:
            return self._data.pop(dataset_id, None) is not None

    async def search(self, query: SearchQuery) -> Tuple[List[DatasetSummary], Optional[str]]:
        async with self._lock:
            items = list(self._data.values())

            # Filter
            if query.q:
                ql = query.q.lower()
                items = [d for d in items if ql in d.name.lower() or ql in d.description.lower()]
            if query.tags:
                tags = set(t.lower() for t in query.tags)
                items = [d for d in items if tags.issubset(set(d.tags))]
            if query.owner:
                items = [d for d in items if d.owner == query.owner]
            if query.visibility:
                items = [d for d in items if d.visibility == query.visibility]

            # Sort
            reverse = query.order == "desc"
            if query.sort == "updated_at":
                items.sort(key=lambda d: d.updated_at, reverse=reverse)
            elif query.sort == "created_at":
                items.sort(key=lambda d: d.created_at, reverse=reverse)
            elif query.sort == "name":
                items.sort(key=lambda d: d.name.lower(), reverse=reverse)

            # Cursor pagination (base64 of index)
            start = 0
            if query.cursor:
                try:
                    start = int(base64.urlsafe_b64decode(query.cursor.encode("utf-8")).decode("utf-8"))
                except Exception:
                    raise bad_request("Invalid cursor", reason="malformed_cursor")
            end = min(start + query.limit, len(items))
            page = items[start:end]
            next_cursor = base64.urlsafe_b64encode(str(end).encode("utf-8")).decode("utf-8") if end < len(items) else None

            # Summaries
            summaries = [DatasetSummary(**d.model_dump(exclude={"description"})) for d in page]
            return summaries, next_cursor

    async def compute_etag(self, dataset_id: str) -> Optional[str]:
        async with self._lock:
            ds = self._data.get(dataset_id)
            if not ds:
                return None
            payload = f"{ds.id}:{ds.version}:{int(ds.updated_at.timestamp())}".encode("utf-8")
            return hashlib.sha256(payload).hexdigest()


# ------------------------------------------------------------------------------
# DI helpers
# ------------------------------------------------------------------------------

async def get_repo(request: Request) -> CatalogRepository:
    repo = getattr(request.app.state, "catalog_repo", None)
    if repo is None:
        # Attach default in-memory repo once
        repo = _InMemoryRepo()
        request.app.state.catalog_repo = repo
    return repo

# ------------------------------------------------------------------------------
# ETag / conditional helpers
# ------------------------------------------------------------------------------

def _etag_for(detail: DatasetDetail) -> str:
    payload = f"{detail.id}:{detail.version}:{int(detail.updated_at.timestamp())}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def _httpdate(dt: datetime) -> str:
    # RFC1123 format
    return dt.astimezone(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@router.get("/datasets", response_model=SearchResponse, summary="Search datasets")
async def search_datasets(
    q: Optional[str] = None,
    tags: Optional[str] = None,  # comma-separated to be CLI friendly
    owner: Optional[str] = None,
    visibility: Optional[str] = None,
    sort: str = "updated_at",
    order: str = "desc",
    limit: int = 50,
    cursor: Optional[str] = None,
    repo: CatalogRepository = Depends(get_repo),
):
    # Validate simple query params into SearchQuery
    tag_list = [t for t in (tags.split(",") if tags else []) if t.strip()]
    try:
        sq = SearchQuery(
            q=q, tags=tag_list, owner=owner, visibility=visibility,
            sort=sort, order=order, limit=limit, cursor=cursor
        )
    except Exception:
        raise unprocessable("Invalid search parameters", errors=["bad_query_params"])
    items, next_cursor = await repo.search(sq)
    return SearchResponse(items=items, next_cursor=next_cursor)

@router.post(
    "/datasets",
    status_code=status.HTTP_201_CREATED,
    response_model=DatasetDetail,
    summary="Create dataset (idempotent with Idempotency-Key)",
)
async def create_dataset(
    payload: DatasetCreate,
    response: Response,
    repo: CatalogRepository = Depends(get_repo),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    if idempotency_key is not None:
        if not idempotency_key or len(idempotency_key) > 256:
            raise bad_request("Invalid Idempotency-Key", reason="invalid_idem_key")
    detail = await repo.create(payload, idem_key=idempotency_key)
    etag = _etag_for(detail)
    response.headers["ETag"] = etag
    response.headers["Last-Modified"] = _httpdate(detail.updated_at)
    return detail

@router.get(
    "/datasets/{dataset_id}",
    response_model=DatasetDetail,
    summary="Get dataset by id with ETag/Last-Modified",
)
async def get_dataset(
    dataset_id: str,
    request: Request,
    response: Response,
    repo: CatalogRepository = Depends(get_repo),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    if_modified_since: Optional[str] = Header(default=None, alias="If-Modified-Since"),
):
    detail = await repo.get(dataset_id)
    if not detail:
        raise not_found(resource="dataset", id_=dataset_id)

    etag = _etag_for(detail)
    last_mod = _httpdate(detail.updated_at)
    # Conditional handling
    if if_none_match and if_none_match.strip('"') == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    if if_modified_since:
        # Simple parse by comparing httpdate strings; robust parse can be added
        if if_modified_since == last_mod:
            return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    response.headers["ETag"] = etag
    response.headers["Last-Modified"] = last_mod
    return detail

@router.patch(
    "/datasets/{dataset_id}",
    response_model=DatasetDetail,
    summary="Patch dataset fields",
)
async def patch_dataset(
    dataset_id: str,
    payload: DatasetUpdate,
    response: Response,
    repo: CatalogRepository = Depends(get_repo),
):
    if payload.model_dump(exclude_none=True) == {}:
        raise bad_request("Empty update payload", reason="empty_patch")
    updated = await repo.update(dataset_id, payload)
    if not updated:
        raise not_found(resource="dataset", id_=dataset_id)
    response.headers["ETag"] = _etag_for(updated)
    response.headers["Last-Modified"] = _httpdate(updated.updated_at)
    return updated

@router.delete(
    "/datasets/{dataset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete dataset",
)
async def delete_dataset(
    dataset_id: str,
    repo: CatalogRepository = Depends(get_repo),
):
    ok = await repo.delete(dataset_id)
    if not ok:
        raise not_found(resource="dataset", id_=dataset_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
