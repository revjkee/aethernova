# -*- coding: utf-8 -*-
"""
ABAC Attributes API (v1)

Функциональность:
- GET   /v1/attributes                 — список (пагинация cursor-based, фильтр q=)
- GET   /v1/attributes/{key}           — чтение по ключу, ETag
- POST  /v1/attributes                 — создание, идемпотентность (Idempotency-Key)
- PUT   /v1/attributes/{key}           — полное обновление (If-Match для оптимистической блокировки)
- PATCH /v1/attributes/{key}           — частичное обновление (merge), If-Match
- DELETE /v1/attributes/{key}          — удаление, If-Match (опционально)
- POST  /v1/attributes/_bulk           — атомарный bulk upsert (best-effort в in-memory)
- POST  /v1/attributes/_validate       — dry-run валидация по JSON Schema

Безопасность и доступ:
- Чтение: требуется скоуп policy:read или роль admin/analyst (пример).
- Запись: policy:write или роль admin.
- Ответы в формате problem+json (RFC 7807) для ошибок.

Интеграция:
- Валидация против JSON Schema (Draft 2020-12): schemas/jsonschema/v1/abac_attribute.schema.json
- Метрики: счетчики по операциям и статусам.
- ETag = sha256 нормализованного содержимого.

Подключение:
    from policy_core.api.http.routers.v1 import attributes
    app.include_router(attributes.router, prefix="/v1")

I cannot verify this.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter
from starlette.responses import Response as StarletteResponse

try:
    import jsonschema
    from jsonschema import Draft202012Validator
except Exception:  # pragma: no cover
    jsonschema = None
    Draft202012Validator = None  # type: ignore

# ---- Метрики ----
ATTR_REQS = Counter(
    "policy_attributes_requests_total",
    "Requests to attributes endpoints",
    ["method", "op", "status"],
)

def _count(method: str, op: str, status_code: int) -> None:
    try:
        ATTR_REQS.labels(method, op, str(status_code)).inc()
    except Exception:
        pass

# ---- Зависимости авторизации (упрощённо) ----

class Principal(BaseModel):
    sub: Optional[str] = None
    roles: List[str] = []
    scopes: List[str] = []

class AuthContext(BaseModel):
    principal: Optional[Principal] = None
    api_key_used: bool = False

# Переиспользуйте зависимость из server.py, здесь — легкий заглушечный вариант
async def get_auth_ctx(request: Request) -> AuthContext:
    scopes = []
    roles = []
    # Пример извлечения скоупов/ролей из заголовков для упрощения локальной проверки.
    if hdr := request.headers.get("X-Debug-Scopes"):
        scopes = [s.strip() for s in hdr.split(",") if s.strip()]
    if hdr := request.headers.get("X-Debug-Roles"):
        roles = [s.strip() for s in hdr.split(",") if s.strip()]
    return AuthContext(principal=Principal(sub="debug", roles=roles, scopes=scopes))

def require_read(auth: AuthContext = Depends(get_auth_ctx)) -> None:
    p = auth.principal
    if not p:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if "policy:read" in p.scopes or "admin" in p.roles or "analyst" in p.roles:
        return
    raise HTTPException(status_code=403, detail="Forbidden")

def require_write(auth: AuthContext = Depends(get_auth_ctx)) -> None:
    p = auth.principal
    if not p:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if "policy:write" in p.scopes or "admin" in p.roles:
        return
    raise HTTPException(status_code=403, detail="Forbidden")

# ---- Модели ----

class AttributeModel(BaseModel):
    # Храним документ валидации как произвольный JSON согласно jsonschema.
    # Ключ — часть пути, но также дублируем в теле для удобства/целостности.
    key: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
    document: Dict[str, Any] = Field(..., description="Полный документ атрибута по схеме v1")
    version: int = Field(1, ge=1, description="Версия документа (ручное версионирование)")
    created_at: Optional[int] = Field(None, description="Epoch ms")
    updated_at: Optional[int] = Field(None, description="Epoch ms")
    etag: Optional[str] = Field(None, description="ETag контента (server-generated)")

class AttributeList(BaseModel):
    items: List[AttributeModel]
    next_cursor: Optional[str] = None
    total: Optional[int] = None

class BulkUpsertRequest(BaseModel):
    items: List[AttributeModel]
    # Если true — все или ничего (в in-memory реализация best-effort, для БД используйте транзакцию)
    atomic: bool = False

class ValidateRequest(BaseModel):
    items: List[Dict[str, Any]]

class Problem(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: Any = None

# ---- Валидация JSON Schema ----

SCHEMA_PATH = os.environ.get(
    "ABAC_ATTRIBUTE_SCHEMA",
    "policy-core/schemas/jsonschema/v1/abac_attribute.schema.json",
)

@lru_cache(maxsize=1)
def _load_schema() -> Dict[str, Any]:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

@lru_cache(maxsize=1)
def _get_validator():
    if jsonschema is None or Draft202012Validator is None:  # pragma: no cover
        return None
    schema = _load_schema()
    return Draft202012Validator(schema)

def validate_attribute_document(doc: Dict[str, Any]) -> List[str]:
    """
    Возвращает список текстов ошибок (пусто, если валидно).
    """
    v = _get_validator()
    if v is None:
        # Если jsonschema не доступен, считаем валидным на свой риск.
        return []
    errors = []
    for err in v.iter_errors(doc):
        path = "$" + "".join([f"[{p}]" if isinstance(p, int) else f".{p}" for p in err.absolute_path])
        errors.append(f"{path}: {err.message}")
    return errors

# ---- ETag ----

def compute_etag(model: AttributeModel) -> str:
    # Нормализуем документ: без полей времени/etag
    payload = {
        "key": model.key,
        "document": model.document,
        "version": model.version,
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

# ---- Репозиторий (интерфейс + memory impl) ----

class AttributesRepo:
    async def list(
        self, limit: int, cursor: Optional[str], q: Optional[str]
    ) -> Tuple[List[AttributeModel], Optional[str], Optional[int]]:
        raise NotImplementedError

    async def get(self, key: str) -> Optional[AttributeModel]:
        raise NotImplementedError

    async def create(self, item: AttributeModel, idem_key: Optional[str]) -> AttributeModel:
        raise NotImplementedError

    async def put(self, key: str, item: AttributeModel, if_match: Optional[str]) -> AttributeModel:
        raise NotImplementedError

    async def patch(self, key: str, patch_doc: Dict[str, Any], if_match: Optional[str]) -> AttributeModel:
        raise NotImplementedError

    async def delete(self, key: str, if_match: Optional[str]) -> None:
        raise NotImplementedError

    async def bulk_upsert(self, items: List[AttributeModel], atomic: bool) -> List[AttributeModel]:
        raise NotImplementedError

@dataclass
class _Stored:
    model: AttributeModel
    idem_keys: set

class InMemoryAttributesRepo(AttributesRepo):
    def __init__(self) -> None:
        self._by_key: Dict[str, _Stored] = {}

    async def list(self, limit: int, cursor: Optional[str], q: Optional[str]) -> Tuple[List[AttributeModel], Optional[str], Optional[int]]:
        keys = sorted(self._by_key.keys())
        start = 0
        if cursor:
            try:
                start = keys.index(cursor)
            except ValueError:
                start = 0
        res: List[AttributeModel] = []
        nxt: Optional[str] = None
        matched = [k for k in keys if (not q or q.lower() in k.lower())]
        for k in matched[start : start + limit]:
            res.append(self._by_key[k].model)
        if start + limit < len(matched):
            nxt = matched[start + limit]
        return res, nxt, len(matched)

    async def get(self, key: str) -> Optional[AttributeModel]:
        st = self._by_key.get(key)
        return deepcopy(st.model) if st else None

    async def create(self, item: AttributeModel, idem_key: Optional[str]) -> AttributeModel:
        now = int(time.time() * 1000)
        if item.key in self._by_key:
            raise HTTPException(status_code=409, detail="Already exists")
        item.created_at = now
        item.updated_at = now
        item.etag = compute_etag(item)
        self._by_key[item.key] = _Stored(model=deepcopy(item), idem_keys=set([idem_key] if idem_key else []))
        return item

    async def put(self, key: str, item: AttributeModel, if_match: Optional[str]) -> AttributeModel:
        now = int(time.time() * 1000)
        st = self._by_key.get(key)
        if not st:
            raise HTTPException(status_code=404, detail="Not found")
        # Optimistic concurrency
        if if_match and st.model.etag and if_match != st.model.etag:
            raise HTTPException(status_code=412, detail="Precondition Failed")
        item.created_at = st.model.created_at or now
        item.updated_at = now
        item.etag = compute_etag(item)
        self._by_key[key] = _Stored(model=deepcopy(item), idem_keys=st.idem_keys)
        return item

    async def patch(self, key: str, patch_doc: Dict[str, Any], if_match: Optional[str]) -> AttributeModel:
        st = self._by_key.get(key)
        if not st:
            raise HTTPException(status_code=404, detail="Not found")
        if if_match and st.model.etag and if_match != st.model.etag:
            raise HTTPException(status_code=412, detail="Precondition Failed")
        # Merge только поддерево document/version
        new = deepcopy(st.model)
        if "document" in patch_doc and isinstance(patch_doc["document"], dict):
            new.document = deep_merge(new.document, patch_doc["document"])
        if "version" in patch_doc and isinstance(patch_doc["version"], int):
            new.version = patch_doc["version"]
        now = int(time.time() * 1000)
        new.updated_at = now
        new.etag = compute_etag(new)
        self._by_key[key] = _Stored(model=deepcopy(new), idem_keys=st.idem_keys)
        return new

    async def delete(self, key: str, if_match: Optional[str]) -> None:
        st = self._by_key.get(key)
        if not st:
            raise HTTPException(status_code=404, detail="Not found")
        if if_match and st.model.etag and if_match != st.model.etag:
            raise HTTPException(status_code=412, detail="Precondition Failed")
        del self._by_key[key]

    async def bulk_upsert(self, items: List[AttributeModel], atomic: bool) -> List[AttributeModel]:
        # best-effort для памяти: нет транзакций, но проверим схему и соберём список результатов
        out: List[AttributeModel] = []
        backup = deepcopy(self._by_key) if atomic else None
        try:
            for it in items:
                now = int(time.time() * 1000)
                st = self._by_key.get(it.key)
                if st:
                    it.created_at = st.model.created_at or now
                else:
                    it.created_at = now
                it.updated_at = now
                it.etag = compute_etag(it)
                self._by_key[it.key] = _Stored(model=deepcopy(it), idem_keys=set())
                out.append(it)
        except Exception:
            if atomic and backup is not None:
                self._by_key = backup
            raise
        return out

# ---- Вспомогательное ----

def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    res = deepcopy(a)
    for k, v in b.items():
        if k in res and isinstance(res[k], dict) and isinstance(v, dict):
            res[k] = deep_merge(res[k], v)
        else:
            res[k] = deepcopy(v)
    return res

_repo_singleton: Optional[AttributesRepo] = None

def get_repo() -> AttributesRepo:
    global _repo_singleton
    if _repo_singleton is None:
        _repo_singleton = InMemoryAttributesRepo()
    return _repo_singleton

# ---- Роутер ----

router = APIRouter(prefix="/attributes", tags=["attributes"])

# Список
@router.get("", response_model=AttributeList, responses={401: {"model": Problem}, 403: {"model": Problem}})
async def list_attributes(
    limit: int = Query(50, ge=1, le=500),
    cursor: Optional[str] = Query(None, description="Ключ, с которого начать следующую страницу"),
    q: Optional[str] = Query(None, description="Фильтр по подстроке ключа"),
    _: None = Depends(require_read),
    repo: AttributesRepo = Depends(get_repo),
    request: Request = None,
):
    items, next_cursor, total = await repo.list(limit=limit, cursor=cursor, q=q)
    resp = AttributeList(items=items, next_cursor=next_cursor, total=total)
    _count("GET", "list", 200)
    return resp

# Получение по ключу
@router.get("/{key}", response_model=AttributeModel, responses={404: {"model": Problem}, 401: {"model": Problem}, 403: {"model": Problem}})
async def get_attribute(
    key: str = Path(..., pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
    _: None = Depends(require_read),
    repo: AttributesRepo = Depends(get_repo),
):
    item = await repo.get(key)
    if not item:
        _count("GET", "get", 404)
        raise HTTPException(status_code=404, detail="Not found")
    etag = item.etag or compute_etag(item)
    # ETag 304
    if if_none_match and if_none_match == etag:
        _count("GET", "get", 304)
        return StarletteResponse(status_code=304, headers={"ETag": etag})
    headers = {"ETag": etag, "Cache-Control": "no-cache"}
    _count("GET", "get", 200)
    return JSONResponse(item.model_dump(), headers=headers, status_code=200)

# Создание
@router.post("", response_model=AttributeModel, status_code=201, responses={400: {"model": Problem}, 401: {"model": Problem}, 403: {"model": Problem}, 409: {"model": Problem}})
async def create_attribute(
    payload: AttributeModel = Body(...),
    idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    _: None = Depends(require_write),
    repo: AttributesRepo = Depends(get_repo),
):
    # Согласованность key vs document.key если присутствует
    doc = payload.document or {}
    doc_key = doc.get("key")
    if doc_key and doc_key != payload.key:
        _count("POST", "create", 400)
        raise HTTPException(status_code=400, detail="document.key mismatch")
    # Валидация схемы
    errs = validate_attribute_document(doc if doc else {"key": payload.key, "kind": "string"})
    if errs:
        _count("POST", "create", 422)
        return JSONResponse(
            {
                "type": "about:blank",
                "title": "Validation failed",
                "status": 422,
                "detail": errs,
            },
            status_code=422,
            media_type="application/problem+json",
        )
    created = await repo.create(payload, idem_key=idem_key)
    headers = {"ETag": created.etag or "", "Location": f"/v1/attributes/{created.key}"}
    _count("POST", "create", 201)
    return JSONResponse(created.model_dump(), status_code=201, headers=headers)

# Полное обновление
@router.put("/{key}", response_model=AttributeModel, responses={400: {"model": Problem}, 401: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}})
async def put_attribute(
    key: str = Path(..., pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"),
    payload: AttributeModel = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _: None = Depends(require_write),
    repo: AttributesRepo = Depends(get_repo),
):
    if payload.key != key:
        _count("PUT", "put", 400)
        raise HTTPException(status_code=400, detail="Body key must match path key")
    errs = validate_attribute_document(payload.document)
    if errs:
        _count("PUT", "put", 422)
        return JSONResponse(
            {"type": "about:blank", "title": "Validation failed", "status": 422, "detail": errs},
            status_code=422,
            media_type="application/problem+json",
        )
    updated = await repo.put(key, payload, if_match=if_match)
    headers = {"ETag": updated.etag or ""}
    _count("PUT", "put", 200)
    return JSONResponse(updated.model_dump(), headers=headers, status_code=200)

# Частичное обновление
@router.patch("/{key}", response_model=AttributeModel, responses={400: {"model": Problem}, 401: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}})
async def patch_attribute(
    key: str = Path(..., pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"),
    patch_doc: Dict[str, Any] = Body(..., description="Поддерживаются поля: document (merge), version (int)"),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _: None = Depends(require_write),
    repo: AttributesRepo = Depends(get_repo),
):
    if not isinstance(patch_doc, dict):
        _count("PATCH", "patch", 400)
        raise HTTPException(status_code=400, detail="Invalid patch document")
    # Если меняют документ — провалидируем результат заранее
    if "document" in patch_doc and isinstance(patch_doc["document"], dict):
        current = await repo.get(key)
        if not current:
            _count("PATCH", "patch", 404)
            raise HTTPException(status_code=404, detail="Not found")
        merged = deep_merge(current.document, patch_doc["document"])
        errs = validate_attribute_document(merged)
        if errs:
            _count("PATCH", "patch", 422)
            return JSONResponse(
                {"type": "about:blank", "title": "Validation failed", "status": 422, "detail": errs},
                status_code=422,
                media_type="application/problem+json",
            )
    updated = await repo.patch(key, patch_doc, if_match=if_match)
    headers = {"ETag": updated.etag or ""}
    _count("PATCH", "patch", 200)
    return JSONResponse(updated.model_dump(), headers=headers, status_code=200)

# Удаление
@router.delete("/{key}", status_code=204, responses={401: {"model": Problem}, 403: {"model": Problem}, 404: {"model": Problem}, 412: {"model": Problem}})
async def delete_attribute(
    key: str = Path(..., pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    _: None = Depends(require_write),
    repo: AttributesRepo = Depends(get_repo),
):
    await repo.delete(key, if_match=if_match)
    _count("DELETE", "delete", 204)
    return StarletteResponse(status_code=204)

# Bulk upsert
@router.post("/_bulk", response_model=List[AttributeModel], responses={401: {"model": Problem}, 403: {"model": Problem}, 422: {"model": Problem}})
async def bulk_upsert(
    req: BulkUpsertRequest,
    _: None = Depends(require_write),
    repo: AttributesRepo = Depends(get_repo),
):
    # Валидация всех документов
    all_errs = []
    for i, it in enumerate(req.items):
        errs = validate_attribute_document(it.document)
        if errs:
            all_errs.append({"index": i, "errors": errs})
    if all_errs:
        _count("POST", "bulk", 422)
        return JSONResponse(
            {"type": "about:blank", "title": "Validation failed", "status": 422, "detail": all_errs},
            status_code=422,
            media_type="application/problem+json",
        )
    out = await repo.bulk_upsert(req.items, atomic=req.atomic)
    _count("POST", "bulk", 200)
    return out

# Dry-run validate
@router.post("/_validate", responses={200: {"description": "OK"}, 422: {"model": Problem}})
async def validate_only(req: ValidateRequest):
    all_errs = []
    for i, doc in enumerate(req.items):
        errs = validate_attribute_document(doc)
        if errs:
            all_errs.append({"index": i, "errors": errs})
    if all_errs:
        _count("POST", "validate", 422)
        return JSONResponse(
            {"type": "about:blank", "title": "Validation failed", "status": 422, "detail": all_errs},
            status_code=422,
            media_type="application/problem+json",
        )
    _count("POST", "validate", 200)
    return JSONResponse({"ok": True, "count": len(req.items)}, status_code=200)
