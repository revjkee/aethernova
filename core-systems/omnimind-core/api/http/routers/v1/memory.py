# -*- coding: utf-8 -*-
"""
OmniMind Core — Memory API (v1)
Промышленный роутер FastAPI:
- CRUD: get, delete, patch, batch append
- Идемпотентность по X-Request-ID
- ETag + If-Match для оптимистической блокировки
- Пагинация через непрозрачный page_token (base64url JSON)
- Фильтры: agent_id, types, tags, время, текстовый и векторный запрос
- Интеграция: rate limiting, аутентификация (JWT/API key заглушка), прометей-метрики
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, root_validator, validator
from prometheus_client import Counter, Histogram

# --- Интеграции с сервером (rate_limit/auth). Мягкое связывание на случай изоляции модулей. ---
try:
    # ожидаем размещение server.py на два уровня выше
    from ...server import rate_limit, auth_dependency, Principal  # type: ignore
except Exception:  # pragma: no cover
    # Фолбэк для автономного тестирования роутера
    from typing import NamedTuple

    class Principal(NamedTuple):
        sub: Optional[str] = None
        roles: Tuple[str, ...] = tuple()
        api_key_hash: Optional[str] = None

    async def auth_dependency() -> Principal:  # type: ignore
        return Principal()

    async def rate_limit():  # type: ignore
        return None

# --- Логгер и метрики ---
log = logging.getLogger("omnimind.api.memory")

MEM_REQS = Counter(
    "omnimind_memory_requests_total",
    "Total memory API requests",
    ["op", "status"],
)
MEM_LATENCY = Histogram(
    "omnimind_memory_latency_seconds",
    "Latency of memory API operations",
    ["op"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)

# --- Доменные типы ---
MemoryType = Literal["EPISODIC", "SEMANTIC", "LONG_TERM", "VECTOR"]

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _make_etag(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def _b64url_encode(d: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode("utf-8")).decode("ascii").rstrip("=")

def _b64url_decode(s: str) -> Dict[str, Any]:
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode((s + pad).encode("ascii")).decode("utf-8"))

# --- Pydantic схемы ---
class MemoryIn(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=200)
    type: MemoryType = Field(..., description="Тип памяти")
    data: Dict[str, Any] = Field(..., description="Произвольное содержимое")
    relevance: float = Field(0.5, ge=0.0, le=1.0)
    expire_time: Optional[datetime] = Field(None, description="RFC3339 UTC")

    @validator("expire_time")
    def _exp_future(cls, v):
        if v and v.tzinfo is None:
            raise ValueError("expire_time must be timezone-aware (UTC)")
        return v

class MemoryOut(MemoryIn):
    id: str
    create_time: datetime
    update_time: datetime
    tags: List[str] = []
    etag: str

class MemoryPatch(BaseModel):
    relevance: Optional[float] = Field(None, ge=0.0, le=1.0)
    expire_time: Optional[datetime] = None
    add_tags: List[str] = []
    remove_tags: List[str] = []

class Page(BaseModel):
    page_size: int = Field(20, ge=1, le=1000)
    page_token: Optional[str] = None

class MemoryQuery(BaseModel):
    agent_id: Optional[str] = None
    types: Optional[List[MemoryType]] = None
    tags_any: Optional[List[str]] = None
    tags_all: Optional[List[str]] = None
    text: Optional[str] = Field(None, description="Текстовый запрос (семантика определяется реализацией)")
    vector: Optional[List[float]] = Field(None, description="Вектор для поиска близости")
    top_k: Optional[int] = Field(10, ge=1, le=1000)
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    page: Page = Field(default_factory=Page)
    with_scores: bool = False

    @root_validator
    def _validate_search_mode(cls, values):
        text, vector = values.get("text"), values.get("vector")
        if text and vector:
            raise ValueError("Use either text or vector, not both")
        return values

class BatchAppendRequest(BaseModel):
    items: List[MemoryIn]
    # Идемпотентность всей пачки
    request_id: Optional[str] = None

class BatchAppendResponse(BaseModel):
    ids: List[str]
    etags: List[str]
    count: int

# --- Абстракция репозитория ---
class MemoryRepository:
    """
    Абстракция слоя хранения. Реализация должна быть потокобезопасной/корутинной.
    """
    async def get(self, id_: str) -> Optional[MemoryOut]:
        raise NotImplementedError

    async def delete(self, id_: str) -> bool:
        raise NotImplementedError

    async def upsert(self, item: MemoryIn, id_: Optional[str], request_id: Optional[str]) -> MemoryOut:
        raise NotImplementedError

    async def patch(self, id_: str, patch: MemoryPatch) -> Optional[MemoryOut]:
        raise NotImplementedError

    async def list(
        self,
        page_size: int,
        cursor: Optional[Dict[str, Any]],
        filters: Dict[str, Any],
    ) -> Tuple[List[MemoryOut], Optional[Dict[str, Any]]]:
        raise NotImplementedError

    async def search_text(
        self,
        query: MemoryQuery,
    ) -> Tuple[List[Tuple[MemoryOut, float]], Optional[Dict[str, Any]]]:
        raise NotImplementedError

    async def search_vector(
        self,
        query: MemoryQuery,
    ) -> Tuple[List[Tuple[MemoryOut, float]], Optional[Dict[str, Any]]]:
        raise NotImplementedError

# --- Простая in-memory реализация (дефолт для dev/test; прод — заменяется) ---
@dataclass
class _Stored:
    doc: MemoryOut
    request_id: Optional[str] = None

class InMemoryMemoryRepository(MemoryRepository):
    def __init__(self) -> None:
        self._data: Dict[str, _Stored] = {}
        self._by_req: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def get(self, id_: str) -> Optional[MemoryOut]:
        async with self._lock:
            st = self._data.get(id_)
            return st.doc if st else None

    async def delete(self, id_: str) -> bool:
        async with self._lock:
            return self._data.pop(id_, None) is not None

    async def upsert(self, item: MemoryIn, id_: Optional[str], request_id: Optional[str]) -> MemoryOut:
        async with self._lock:
            if request_id and request_id in self._by_req:
                # идемпотентный возврат ранее созданного
                existing_id = self._by_req[request_id]
                return self._data[existing_id].doc

            now = _utcnow()
            if id_ and id_ in self._data:
                prev = self._data[id_].doc
                doc = MemoryOut(
                    id=id_,
                    agent_id=item.agent_id,
                    type=item.type,
                    data=item.data,
                    relevance=item.relevance,
                    expire_time=item.expire_time,
                    tags=prev.tags,
                    create_time=prev.create_time,
                    update_time=now,
                    etag="",
                )
            else:
                new_id = hashlib.sha1(f"{now.timestamp()}:{len(self._data)}".encode()).hexdigest()
                doc = MemoryOut(
                    id=new_id,
                    agent_id=item.agent_id,
                    type=item.type,
                    data=item.data,
                    relevance=item.relevance,
                    expire_time=item.expire_time,
                    tags=[],
                    create_time=now,
                    update_time=now,
                    etag="",
                )

            payload = {
                "id": doc.id,
                "agent_id": doc.agent_id,
                "type": doc.type,
                "data": doc.data,
                "relevance": doc.relevance,
                "expire_time": doc.expire_time.isoformat() if doc.expire_time else None,
                "update_time": doc.update_time.isoformat(),
            }
            doc.etag = _make_etag(payload)

            self._data[doc.id] = _Stored(doc=doc, request_id=request_id)
            if request_id:
                self._by_req[request_id] = doc.id
            return doc

    async def patch(self, id_: str, patch: MemoryPatch) -> Optional[MemoryOut]:
        async with self._lock:
            st = self._data.get(id_)
            if not st:
                return None
            doc = st.doc
            changed = False
            if patch.relevance is not None and patch.relevance != doc.relevance:
                doc.relevance = patch.relevance
                changed = True
            if patch.expire_time is not None and patch.expire_time != doc.expire_time:
                doc.expire_time = patch.expire_time
                changed = True
            if patch.add_tags:
                new = list(dict.fromkeys(doc.tags + patch.add_tags))
                if new != doc.tags:
                    doc.tags = new
                    changed = True
            if patch.remove_tags:
                new = [t for t in doc.tags if t not in set(patch.remove_tags)]
                if new != doc.tags:
                    doc.tags = new
                    changed = True
            if changed:
                doc.update_time = _utcnow()
                payload = {
                    "id": doc.id,
                    "agent_id": doc.agent_id,
                    "type": doc.type,
                    "data": doc.data,
                    "relevance": doc.relevance,
                    "expire_time": doc.expire_time.isoformat() if doc.expire_time else None,
                    "update_time": doc.update_time.isoformat(),
                }
                doc.etag = _make_etag(payload)
            self._data[id_] = _Stored(doc=doc, request_id=st.request_id)
            return doc

    async def list(
        self,
        page_size: int,
        cursor: Optional[Dict[str, Any]],
        filters: Dict[str, Any],
    ) -> Tuple[List[MemoryOut], Optional[Dict[str, Any]]]:
        async with self._lock:
            items = [s.doc for s in self._data.values()]
            # фильтры
            agent_id = filters.get("agent_id")
            types = set(filters.get("types") or [])
            tags_any = set(filters.get("tags_any") or [])
            tags_all = set(filters.get("tags_all") or [])
            t_from = filters.get("time_from")
            t_to = filters.get("time_to")
            now = _utcnow()

            def _pred(m: MemoryOut) -> bool:
                if m.expire_time and m.expire_time < now:
                    return False
                if agent_id and m.agent_id != agent_id:
                    return False
                if types and m.type not in types:
                    return False
                if tags_any and not (tags_any & set(m.tags)):
                    return False
                if tags_all and not set(tags_all).issubset(set(m.tags)):
                    return False
                if t_from and m.create_time < t_from:
                    return False
                if t_to and m.create_time > t_to:
                    return False
                return True

            filtered = [m for m in items if _pred(m)]
            # порядок: по update_time desc
            filtered.sort(key=lambda m: m.update_time, reverse=True)

            start = int(cursor.get("offset", 0)) if cursor else 0
            page = filtered[start:start + page_size]
            next_cursor = {"offset": start + len(page)} if (start + len(page)) < len(filtered) else None
            return page, next_cursor

    async def search_text(
        self,
        query: MemoryQuery,
    ) -> Tuple[List[Tuple[MemoryOut, float]], Optional[Dict[str, Any]]]:
        # Простейшая заглушка: подстроковый матч в json-данных
        page, cursor = await self.list(query.page.page_size, _cursor(query.page.page_token), _filters_from_query(query))
        text = (query.text or "").lower()
        scored: List[Tuple[MemoryOut, float]] = []
        for m in page:
            blob = json.dumps(m.data, ensure_ascii=False).lower()
            score = 1.0 if text and text in blob else 0.0
            if not text or score > 0:
                scored.append((m, score))
        scored.sort(key=lambda t: (t[1], t[0].update_time), reverse=True)
        return scored, cursor

    async def search_vector(
        self,
        query: MemoryQuery,
    ) -> Tuple[List[Tuple[MemoryOut, float]], Optional[Dict[str, Any]]]:
        # Заглушка: возвращаем без реального ANN. Прод реализует через Faiss/HNSW/PGVector.
        page, cursor = await self.list(query.page.page_size, _cursor(query.page.page_token), _filters_from_query(query))
        return [(m, 0.0) for m in page], cursor

# --- Утилиты для пагинации/фильтров ---
def _cursor(token: Optional[str]) -> Optional[Dict[str, Any]]:
    return _b64url_decode(token) if token else None

def _next_token(cursor: Optional[Dict[str, Any]]) -> Optional[str]:
    return _b64url_encode(cursor) if cursor else None

def _filters_from_query(q: MemoryQuery) -> Dict[str, Any]:
    return {
        "agent_id": q.agent_id,
        "types": q.types,
        "tags_any": q.tags_any,
        "tags_all": q.tags_all,
        "time_from": q.time_from,
        "time_to": q.time_to,
    }

# --- DI репозитория ---
def _get_repo(request: Request) -> MemoryRepository:
    repo = getattr(request.app.state, "memory_repo", None)
    if repo is None:
        # дефолт безопасен для dev/test; замените в server.py:
        # app.state.memory_repo = PgVectorRepository(...)
        repo = InMemoryMemoryRepository()
        request.app.state.memory_repo = repo
    return repo

# --- Роутер ---
memory_router = APIRouter(prefix="/v1/memory", tags=["memory"])

# --- Endpoints ---

@memory_router.get("/{memory_id}", response_model=MemoryOut, dependencies=[Depends(rate_limit)])
async def get_memory(memory_id: str, request: Request, response: Response, principal: Principal = Depends(auth_dependency)):
    op = "get"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        doc = await repo.get(memory_id)
        if not doc:
            MEM_REQS.labels(op, "404").inc()
            raise HTTPException(status_code=404, detail="Not found")
        response.headers["ETag"] = doc.etag
        response.headers["Cache-Control"] = "no-store"
        MEM_REQS.labels(op, "200").inc()
        return doc
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

@memory_router.delete("/{memory_id}", status_code=204, dependencies=[Depends(rate_limit)])
async def delete_memory(memory_id: str, request: Request, principal: Principal = Depends(auth_dependency)):
    op = "delete"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        ok = await repo.delete(memory_id)
        MEM_REQS.labels(op, "204" if ok else "404").inc()
        if not ok:
            raise HTTPException(status_code=404, detail="Not found")
        return Response(status_code=204)
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

@memory_router.patch("/{memory_id}", response_model=MemoryOut, dependencies=[Depends(rate_limit)])
async def patch_memory(
    memory_id: str,
    patch: MemoryPatch,
    request: Request,
    response: Response,
    if_match: Optional[str] = None,
    principal: Principal = Depends(auth_dependency),
):
    op = "patch"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        # Оптимистическая блокировка через If-Match
        current = await repo.get(memory_id)
        if not current:
            MEM_REQS.labels(op, "404").inc()
            raise HTTPException(status_code=404, detail="Not found")
        if if_match and if_match != current.etag:
            MEM_REQS.labels(op, "412").inc()
            raise HTTPException(status_code=412, detail="Precondition Failed (ETag mismatch)")
        updated = await repo.patch(memory_id, patch)
        if not updated:
            MEM_REQS.labels(op, "404").inc()
            raise HTTPException(status_code=404, detail="Not found")
        response.headers["ETag"] = updated.etag
        response.headers["Cache-Control"] = "no-store"
        MEM_REQS.labels(op, "200").inc()
        return updated
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

@memory_router.post("/append", response_model=MemoryOut, status_code=201, dependencies=[Depends(rate_limit)])
async def append_memory(
    payload: MemoryIn,
    request: Request,
    response: Response,
    principal: Principal = Depends(auth_dependency),
    x_request_id: Optional[str] = None,
):
    op = "append"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        req_id = x_request_id or request.headers.get("x-request-id")
        doc = await repo.upsert(payload, id_=None, request_id=req_id)
        response.headers["ETag"] = doc.etag
        response.headers["Cache-Control"] = "no-store"
        MEM_REQS.labels(op, "201").inc()
        return doc
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

@memory_router.post("/batch", response_model=BatchAppendResponse, status_code=201, dependencies=[Depends(rate_limit)])
async def batch_append_memory(
    body: BatchAppendRequest,
    request: Request,
    response: Response,
    principal: Principal = Depends(auth_dependency),
):
    op = "batch"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        ids: List[str] = []
        etags: List[str] = []
        for item in body.items:
            doc = await repo.upsert(item, id_=None, request_id=body.request_id)
            ids.append(doc.id)
            etags.append(doc.etag)
        MEM_REQS.labels(op, "201").inc()
        return BatchAppendResponse(ids=ids, etags=etags, count=len(ids))
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

@memory_router.post("/query", dependencies=[Depends(rate_limit)])
async def query_memory(
    q: MemoryQuery,
    request: Request,
    principal: Principal = Depends(auth_dependency),
):
    op = "query"
    t0 = time.perf_counter()
    try:
        repo = _get_repo(request)
        cursor_in = _cursor(q.page.page_token)
        if q.vector:
            results, cursor_out = await repo.search_vector(q)
        elif q.text:
            results, cursor_out = await repo.search_text(q)
        else:
            # обычный листинг с фильтрами
            docs, cursor_out = await repo.list(q.page.page_size, cursor_in, _filters_from_query(q))
            results = [(d, 0.0) for d in docs]

        next_token = _next_token(cursor_out)
        payload = {
            "results": [
                {"item": r[0].dict(), **({"score": r[1]} if q.with_scores else {})}
                for r in results
            ][: q.top_k or len(results)],
            "next_page_token": next_token,
        }
        MEM_REQS.labels(op, "200").inc()
        return payload
    finally:
        MEM_LATENCY.labels(op).observe(time.perf_counter() - t0)

# Опционально: регистрация роутера выполняется в server.py
# from ops.api.http.routers.v1.memory import memory_router
# app.include_router(memory_router)
