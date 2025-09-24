# datafabric-core/api/http/routers/v1/policies.py
from __future__ import annotations

import hashlib
import json
import re
import time
import typing as t
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    Header,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, constr, validator

# Зависимости безопасности (см. api/http/middleware/auth.py)
try:
    from ...middleware.auth import require_scopes, Principal
except Exception:  # при статическом анализе/тестах
    def require_scopes(*_args, **_kwargs):  # type: ignore
        async def _dep(*_a, **_kw):  # type: ignore
            return None
        return _dep
    Principal = t.Any  # type: ignore


# ============================ Типы/модели домена ============================

SemVerStr = constr(regex=r"^[0-9]+\.[0-9]+\.[0-9]+$")
NameStr = constr(strip_whitespace=True, min_length=3, max_length=128, regex=r"^[A-Za-z0-9_\-\s]+$")
DescStr = constr(strip_whitespace=True, min_length=10, max_length=2048)
TagStr = constr(strip_whitespace=True, min_length=2, max_length=64)

class PolicyStatus(str):
    active = "active"
    inactive = "inactive"
    deprecated = "deprecated"
    archived = "archived"

class RuleType(str):
    access_control = "access_control"
    data_retention = "data_retention"
    encryption = "encryption"
    masking = "masking"
    validation = "validation"
    custom = "custom"

class RuleEffect(str):
    allow = "allow"
    deny = "deny"
    log = "log"
    alert = "alert"

class RuleBase(BaseModel):
    id: UUID
    type: t.Literal[
        RuleType.access_control,
        RuleType.data_retention,
        RuleType.encryption,
        RuleType.masking,
        RuleType.validation,
        RuleType.custom,
    ]
    parameters: dict = Field(..., description="Специфичные параметры правила")
    effect: t.Literal[
        RuleEffect.allow,
        RuleEffect.deny,
        RuleEffect.log,
        RuleEffect.alert,
    ]
    priority: int | None = Field(50, ge=1, le=100)

class RuleCreate(BaseModel):
    type: RuleBase.__fields__["type"].type_
    parameters: dict = Field(..., min_items=1)
    effect: RuleBase.__fields__["effect"].type_
    priority: int | None = Field(50, ge=1, le=100)

class RuleUpdate(RuleCreate):
    pass

class PolicyBase(BaseModel):
    name: NameStr
    description: DescStr
    status: t.Literal[
        PolicyStatus.active,
        PolicyStatus.inactive,
        PolicyStatus.deprecated,
        PolicyStatus.archived,
    ]
    tags: list[TagStr] = Field(default_factory=list)

    @validator("tags")
    def _uniq_tags(cls, v: list[str]) -> list[str]:
        if len(v) != len(set(v)):
            raise ValueError("tags must be unique")
        return v

class PolicyCreate(PolicyBase):
    version: SemVerStr = Field("1.0.0")
    rules: list[RuleCreate] = Field(default_factory=list)

class PolicyUpdate(PolicyBase):
    version: SemVerStr | None = None
    rules: list[RuleUpdate] | None = None

class Policy(PolicyBase):
    id: UUID
    version: SemVerStr
    rules: list[RuleBase]
    owner: str | None = Field(None, description="Идентификатор владельца")
    createdAt: datetime
    updatedAt: datetime
    etag: str | None = None

class PageMeta(BaseModel):
    page: int = Field(1, ge=1)
    perPage: int = Field(20, ge=1, le=200)
    total: int = Field(..., ge=0)

T = t.TypeVar("T")
class Page(BaseModel, t.Generic[T]):
    items: list[T]
    meta: PageMeta

class ProblemDetails(BaseModel):
    type: str = Field("about:blank")
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None
    traceId: str | None = None
    errors: list[dict] | None = None


# ============================ Репозиторий (контракт) ============================

class PolicyRepository(t.Protocol):
    async def list(
        self,
        *,
        page: int,
        per_page: int,
        sort: str | None,
        q: str | None,
        status: str | None,
        tag: str | None,
    ) -> tuple[list[Policy], int]: ...

    async def get(self, policy_id: UUID) -> Policy | None: ...
    async def create(self, data: PolicyCreate, owner: str | None) -> Policy: ...
    async def replace(self, policy_id: UUID, data: PolicyUpdate, if_match: str | None) -> Policy: ...
    async def patch(self, policy_id: UUID, data: dict, if_match: str | None) -> Policy: ...
    async def delete(self, policy_id: UUID) -> None: ...
    async def get_etag(self, policy_id: UUID) -> str | None: ...


# ============================ Ин‑мемори реализация для dev/test ============================

@dataclass
class _Stored:
    obj: Policy

class InMemoryPolicyRepo(PolicyRepository):
    def __init__(self) -> None:
        self._store: dict[UUID, _Stored] = {}

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _etag(payload: dict) -> str:
        h = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return f'W/"{h[:16]}"'

    def _serialize_for_etag(self, p: Policy) -> dict:
        return p.dict(exclude={"etag"})

    async def list(
        self,
        *,
        page: int,
        per_page: int,
        sort: str | None,
        q: str | None,
        status: str | None,
        tag: str | None,
    ) -> tuple[list[Policy], int]:
        vals = [s.obj for s in self._store.values()]

        if q:
            ql = q.lower()
            vals = [p for p in vals if ql in p.name.lower() or ql in p.description.lower()]
        if status:
            vals = [p for p in vals if p.status == status]
        if tag:
            vals = [p for p in vals if tag in (p.tags or [])]

        if sort:
            reverse = sort.startswith("-")
            key = sort[1:] if reverse else sort
            if key in {"name", "createdAt", "updatedAt", "version"}:
                vals.sort(key=lambda p: getattr(p, key), reverse=reverse)

        total = len(vals)
        start = (page - 1) * per_page
        end = start + per_page
        return vals[start:end], total

    async def get(self, policy_id: UUID) -> Policy | None:
        item = self._store.get(policy_id)
        return item.obj if item else None

    async def create(self, data: PolicyCreate, owner: str | None) -> Policy:
        now = self._now()
        # Сформируем RuleBase с генерацией id там, где необходимо (для создания)
        rules: list[RuleBase] = []
        for r in data.rules or []:
            rules.append(
                RuleBase(
                    id=uuid4(),
                    type=r.type,
                    parameters=r.parameters,
                    effect=r.effect,
                    priority=r.priority or 50,
                )
            )
        obj = Policy(
            id=uuid4(),
            version=data.version,
            name=data.name,
            description=data.description,
            status=data.status,
            tags=data.tags or [],
            rules=rules,
            owner=owner,
            createdAt=now,
            updatedAt=now,
            etag=None,
        )
        obj.etag = self._etag(self._serialize_for_etag(obj))
        self._store[obj.id] = _Stored(obj=obj)
        return obj

    async def replace(self, policy_id: UUID, data: PolicyUpdate, if_match: str | None) -> Policy:
        cur = self._store.get(policy_id)
        if not cur:
            raise KeyError("not-found")
        if if_match and cur.obj.etag and if_match != cur.obj.etag:
            raise PermissionError("precondition-failed")

        rules = cur.obj.rules
        if data.rules is not None:
            # Полная замена набора правил, id правил не меняем если не заданы
            new_rules: list[RuleBase] = []
            for r in data.rules:
                new_rules.append(
                    RuleBase(
                        id=uuid4(),
                        type=r.type,
                        parameters=r.parameters,
                        effect=r.effect,
                        priority=r.priority or 50,
                    )
                )
            rules = new_rules

        updated = Policy(
            id=cur.obj.id,
            version=data.version or cur.obj.version,
            name=data.name,
            description=data.description,
            status=data.status,
            tags=data.tags or [],
            rules=rules,
            owner=cur.obj.owner,
            createdAt=cur.obj.createdAt,
            updatedAt=self._now(),
            etag=None,
        )
        updated.etag = self._etag(self._serialize_for_etag(updated))
        self._store[policy_id] = _Stored(obj=updated)
        return updated

    async def patch(self, policy_id: UUID, data: dict, if_match: str | None) -> Policy:
        cur = self._store.get(policy_id)
        if not cur:
            raise KeyError("not-found")
        if if_match and cur.obj.etag and if_match != cur.obj.etag:
            raise PermissionError("precondition-failed")

        payload = cur.obj.dict()
        payload.update({k: v for k, v in data.items() if v is not None and k != "rules"})
        payload["updatedAt"] = self._now()

        # Патч правил не поддерживаем в merge‑patch (для простоты) — ожидаем replace/отдельный router /rules
        updated = Policy(**payload)
        updated.etag = self._etag(self._serialize_for_etag(updated))
        self._store[policy_id] = _Stored(obj=updated)
        return updated

    async def delete(self, policy_id: UUID) -> None:
        if policy_id not in self._store:
            raise KeyError("not-found")
        del self._store[policy_id]

    async def get_etag(self, policy_id: UUID) -> str | None:
        cur = self._store.get(policy_id)
        return cur.obj.etag if cur else None


# ============================ Идемпотентность (простая TTL‑карта) ============================

class IdempotencyCache:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._data: dict[str, tuple[float, dict]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> dict | None:
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
        for k, (ts, _) in list(self._data.items()):
            if now - ts > self._ttl:
                self._data.pop(k, None)

_idem_cache = IdempotencyCache(ttl_seconds=600)


# ============================ Утилиты ответов ============================

def problem(
    *,
    status_code: int,
    title: str,
    detail: str | None = None,
    trace_id: str | None = None,
    type_uri: str = "about:blank",
    errors: list[dict] | None = None,
) -> JSONResponse:
    body = {"type": type_uri, "title": title, "status": status_code}
    if detail:
        body["detail"] = detail
    if trace_id:
        body["traceId"] = trace_id
    if errors:
        body["errors"] = errors
    return JSONResponse(body, status_code=status_code)

def set_common_headers(resp: Response, *, etag: str | None = None, vary_extra: str | None = None) -> None:
    if etag:
        resp.headers["ETag"] = etag
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    if vary_extra:
        cur = resp.headers.get("Vary")
        parts = {*(cur.split(",") if cur else []), vary_extra, "Accept"}
        resp.headers["Vary"] = ", ".join(sorted([p.strip() for p in parts if p.strip()]))


# ============================ DI: репозиторий ============================

def get_repo() -> PolicyRepository:
    # В продакшене внедряется реальный репозиторий (PostgreSQL/SQLAlchemy и т.д.)
    return InMemoryPolicyRepo()


# ============================ Router ============================

router = APIRouter(prefix="/policies", tags=["policies"])


# ---------------------------- LIST ----------------------------

@router.get(
    "",
    response_model=Page[Policy],
    summary="Список политик",
    dependencies=[Depends(require_scopes("policy:read"))],
)
async def list_policies(
    request: Request,
    page: int = Query(1, ge=1),
    perPage: int = Query(20, ge=1, le=200),
    sort: str | None = Query(None, description="name|createdAt|updatedAt|version; префикс '-' — убывание"),
    status_filter: str | None = Query(None, alias="status"),
    q: str | None = Query(None, description="Поиск по имени/описанию"),
    tag: str | None = Query(None, description="Фильтр по тегу"),
    repo: PolicyRepository = Depends(get_repo),
):
    items, total = await repo.list(page=page, per_page=perPage, sort=sort, q=q, status=status_filter, tag=tag)
    payload = {
        "items": [json.loads(Policy.parse_obj(p).json()) for p in items],
        "meta": {"page": page, "perPage": perPage, "total": total},
    }
    resp = JSONResponse(payload)
    set_common_headers(resp, vary_extra="Accept")
    return resp


# ---------------------------- CREATE ----------------------------

@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=Policy,
    summary="Создать политику",
    dependencies=[Depends(require_scopes("policy:write"))],
)
async def create_policy(
    request: Request,
    body: PolicyCreate,
    repo: PolicyRepository = Depends(get_repo),
    principal: Principal = Depends(require_scopes("policy:write")),  # возвращает Principal
    idempotency_key: str | None = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    if idempotency_key:
        cached = _idem_cache.get(idempotency_key)
        if cached:
            resp = JSONResponse(cached, status_code=status.HTTP_201_CREATED)
            set_common_headers(resp, etag=cached.get("etag"))
            return resp
    try:
        owner_id = getattr(principal, "subject", None) if principal else None
        created = await repo.create(body, owner=owner_id)
    except Exception as e:
        return problem(status_code=500, title="Create failed", detail=str(e), trace_id=trace_id, type_uri="urn:problem:policy:create")

    payload = json.loads(Policy.parse_obj(created).json())
    if idempotency_key:
        _idem_cache.set(idempotency_key, payload)

    resp = JSONResponse(payload, status_code=status.HTTP_201_CREATED)
    set_common_headers(resp, etag=created.etag)
    resp.headers["Location"] = f"{request.url}/{created.id}"
    return resp


# ---------------------------- GET ----------------------------

@router.get(
    "/{policy_id}",
    response_model=Policy,
    summary="Получить политику",
    dependencies=[Depends(require_scopes("policy:read"))],
)
async def get_policy(
    request: Request,
    policy_id: UUID = Path(...),
    repo: PolicyRepository = Depends(get_repo),
):
    obj = await repo.get(policy_id)
    if not obj:
        return problem(status_code=404, title="Not Found", detail="Policy not found", type_uri="urn:problem:policy:not-found",
                       trace_id=request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id"))
    resp = JSONResponse(json.loads(Policy.parse_obj(obj).json()))
    set_common_headers(resp, etag=obj.etag)
    return resp


# ---------------------------- REPLACE ----------------------------

@router.put(
    "/{policy_id}",
    response_model=Policy,
    summary="Полная замена политики",
    dependencies=[Depends(require_scopes("policy:write"))],
)
async def replace_policy(
    request: Request,
    policy_id: UUID = Path(...),
    body: PolicyUpdate = ...,
    repo: PolicyRepository = Depends(get_repo),
    if_match: str | None = Header(None, alias="If-Match"),
    idempotency_key: str | None = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    try:
        updated = await repo.replace(policy_id, body, if_match=if_match)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Policy not found", type_uri="urn:problem:policy:not-found", trace_id=trace_id)
    except PermissionError:
        return problem(status_code=412, title="Precondition Failed", detail="ETag mismatch", type_uri="urn:problem:policy:precondition", trace_id=trace_id)
    except Exception as e:
        return problem(status_code=500, title="Replace failed", detail=str(e), type_uri="urn:problem:policy:replace", trace_id=trace_id)

    payload = json.loads(Policy.parse_obj(updated).json())
    if idempotency_key:
        _idem_cache.set(idempotency_key, payload)
    resp = JSONResponse(payload)
    set_common_headers(resp, etag=updated.etag)
    return resp


# ---------------------------- PATCH ----------------------------

@router.patch(
    "/{policy_id}",
    response_model=Policy,
    summary="Частичное обновление политики (JSON Merge Patch)",
    dependencies=[Depends(require_scopes("policy:write"))],
)
async def patch_policy(
    request: Request,
    policy_id: UUID = Path(...),
    patch: dict = ...,  # merge-patch, валидация ниже
    repo: PolicyRepository = Depends(get_repo),
    if_match: str | None = Header(None, alias="If-Match"),
    idempotency_key: str | None = Header(None, convert_underscores=False, alias="Idempotency-Key"),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")

    # Минимальная валидация patch-полей
    allowed_keys = {"name", "description", "status", "tags", "version"}
    unknown = set(patch.keys()) - allowed_keys
    if unknown:
        return problem(status_code=400, title="Bad Request", detail=f"Unknown fields in patch: {', '.join(sorted(unknown))}",
                       type_uri="urn:problem:policy:patch:unknown-fields", trace_id=trace_id)
    if "version" in patch and patch["version"] is not None:
        if not re.match(r"^[0-9]+\.[0-9]+\.[0-9]+$", str(patch["version"])):
            return problem(status_code=400, title="Bad Request", detail="version must be SemVer (x.y.z)",
                           type_uri="urn:problem:policy:patch:bad-semver", trace_id=trace_id)

    try:
        updated = await repo.patch(policy_id, patch, if_match=if_match)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Policy not found", type_uri="urn:problem:policy:not-found", trace_id=trace_id)
    except PermissionError:
        return problem(status_code=412, title="Precondition Failed", detail="ETag mismatch", type_uri="urn:problem:policy:precondition", trace_id=trace_id)
    except Exception as e:
        return problem(status_code=500, title="Patch failed", detail=str(e), type_uri="urn:problem:policy:patch", trace_id=trace_id)

    payload = json.loads(Policy.parse_obj(updated).json())
    if idempotency_key:
        _idem_cache.set(idempotency_key, payload)
    resp = JSONResponse(payload)
    set_common_headers(resp, etag=updated.etag)
    return resp


# ---------------------------- DELETE ----------------------------

@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить политику",
    dependencies=[Depends(require_scopes("policy:write"))],
)
async def delete_policy(
    request: Request,
    policy_id: UUID = Path(...),
    repo: PolicyRepository = Depends(get_repo),
):
    trace_id = request.headers.get("X-Trace-Id") or request.headers.get("X-Request-Id")
    try:
        await repo.delete(policy_id)
    except KeyError:
        return problem(status_code=404, title="Not Found", detail="Policy not found", type_uri="urn:problem:policy:not-found", trace_id=trace_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================ Пример подключения ============================
# В главном модуле FastAPI:
#   from fastapi import FastAPI
#   from .routers.v1 import policies
#   app = FastAPI()
#   app.include_router(policies.router)
#
# Отдельные endpoints для /policies/{policyId}/rules можно вынести в routers/v1/rules.py
# (или добавить сюда), чтобы соответствовать спецификации OpenAPI.
