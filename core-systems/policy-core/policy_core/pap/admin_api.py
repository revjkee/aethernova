# -*- coding: utf-8 -*-
"""
policy-core / policy_core / pap / admin_api.py

Промышленный асинхронный PAP Admin API:
- FastAPI APIRouter с префиксом /v1/pap
- CRUD политик, публикация, валидация, импорт/экспорт
- Идемпотентность (Idempotency-Key), ETag/If-Match конкурентность
- Роли: policy.viewer, policy.editor, policy.admin
- Структурированный аудит-лог
- In-memory репозиторий по умолчанию (заменяемый на БД)

Зависимости: fastapi, pydantic
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple, Union

from fastapi import (
    APIRouter,
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
from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# ЛОГИРОВАНИЕ И АУДИТ
# ---------------------------------------------------------------------------

logger = logging.getLogger("policy_core.pap.admin_api")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)


def audit(event: str, *, principal: "UserPrincipal", **kwargs: Any) -> None:
    payload = {
        "ts": dt.datetime.utcnow().isoformat() + "Z",
        "event": event,
        "actor": principal.sub,
        "roles": principal.roles,
        "attrs": kwargs,
    }
    logger.info(json.dumps(payload, ensure_ascii=False))


# ---------------------------------------------------------------------------
# МОДЕЛИ ДОМЕНА
# ---------------------------------------------------------------------------

RuleEffect = Literal["allow", "deny"]
PolicyStatus = Literal["draft", "published", "retired"]


class Rule(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    action: str = Field(..., min_length=1, max_length=256)
    resource: str = Field(..., min_length=1, max_length=512)
    subject: Optional[Dict[str, Any]] = Field(
        default=None, description="Атрибуты субъекта (ABAC)"
    )
    condition: Optional[Dict[str, Any]] = Field(
        default=None, description="Условие применения"
    )
    effect: RuleEffect = Field(default="allow")

    @field_validator("action", "resource")
    @classmethod
    def no_whitespace(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Пустая строка недопустима")
        return v.strip()


class PolicyBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    rules: List[Rule] = Field(default_factory=list)
    priority: int = Field(default=100, ge=0, le=1_000_000)
    tags: List[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def norm_tags(cls, tags: List[str]) -> List[str]:
        seen = set()
        normed = []
        for t in tags:
            t2 = re.sub(r"\s+", "-", t.strip().lower())
            if t2 and t2 not in seen:
                seen.add(t2)
                normed.append(t2)
        return normed

    @model_validator(mode="after")
    def check_rules(self):
        if len(self.rules) == 0:
            raise ValueError("Политика должна содержать хотя бы одно правило")
        return self


class PolicyIn(PolicyBase):
    status: PolicyStatus = Field(default="draft")


class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    rules: Optional[List[Rule]] = None
    priority: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    tags: Optional[List[str]] = None
    status: Optional[PolicyStatus] = None

    @field_validator("tags")
    @classmethod
    def norm_tags(cls, tags: Optional[List[str]]) -> Optional[List[str]]:
        if tags is None:
            return tags
        seen = set()
        normed = []
        for t in tags:
            t2 = re.sub(r"\s+", "-", t.strip().lower())
            if t2 and t2 not in seen:
                seen.add(t2)
                normed.append(t2)
        return normed


class PolicyOut(PolicyBase):
    id: uuid.UUID
    version: int
    checksum: str
    status: PolicyStatus
    created_at: dt.datetime
    updated_at: dt.datetime
    created_by: str
    updated_by: str
    etag: str


class ValidationIssue(BaseModel):
    path: str
    message: str
    severity: Literal["error", "warning"] = "error"


class ValidationResult(BaseModel):
    valid: bool
    issues: List[ValidationIssue] = Field(default_factory=list)


class ImportConflictStrategy(BaseModel):
    strategy: Literal["skip", "overwrite", "abort"] = "abort"


class ImportItemResult(BaseModel):
    name: str
    id: Optional[uuid.UUID] = None
    status: Literal["created", "updated", "skipped", "error"]
    message: Optional[str] = None


class ImportResult(BaseModel):
    dry_run: bool
    summary: Dict[str, int]
    items: List[ImportItemResult]


class Bundle(BaseModel):
    items: List[PolicyIn]
    generated_at: Optional[dt.datetime] = Field(default_factory=dt.datetime.utcnow)
    signature: Optional[str] = Field(
        default=None, description="Опциональная подпись бандла"
    )


# ---------------------------------------------------------------------------
# ПОЛЬЗОВАТЕЛЬ И БЕЗОПАСНОСТЬ
# ---------------------------------------------------------------------------

@dataclass
class UserPrincipal:
    sub: str
    roles: List[str]

    def has(self, role: str) -> bool:
        return role in self.roles or "policy.admin" in self.roles


async def get_principal(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> UserPrincipal:
    # Пример простейшей аутентификации для демонстрации:
    # "Bearer admin" -> admin, роль policy.admin
    # "Bearer editor" -> editor, роль policy.editor
    # иначе -> viewer
    sub = "anonymous"
    roles = ["policy.viewer"]
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip().lower()
        if token == "admin":
            sub, roles = "admin", ["policy.admin"]
        elif token == "editor":
            sub, roles = "editor", ["policy.editor"]
        else:
            sub, roles = token, ["policy.viewer"]
    return UserPrincipal(sub=sub, roles=roles)


def require_role(required: str):
    async def _dep(user: UserPrincipal = Depends(get_principal)) -> UserPrincipal:
        if not user.has(required):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _dep


# ---------------------------------------------------------------------------
# РЕПОЗИТОРИЙ И СЕРВИС
# ---------------------------------------------------------------------------

class PolicyRepository(Protocol):
    async def total(
        self,
        *,
        q: Optional[str],
        status: Optional[PolicyStatus],
        tag: Optional[str],
    ) -> int: ...

    async def list(
        self,
        *,
        q: Optional[str],
        status: Optional[PolicyStatus],
        tag: Optional[str],
        sort: str,
        limit: int,
        offset: int,
    ) -> List[Dict[str, Any]]: ...

    async def get(self, policy_id: uuid.UUID) -> Optional[Dict[str, Any]]: ...
    async def get_by_name(self, name: str) -> Optional[Dict[str, Any]]: ...
    async def create(self, data: Dict[str, Any]) -> Dict[str, Any]: ...
    async def update(self, policy_id: uuid.UUID, data: Dict[str, Any]) -> Dict[str, Any]: ...
    async def delete(self, policy_id: uuid.UUID) -> None: ...
    async def upsert(self, by_name: str, data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]: ...
    async def store_idempotency(self, key: str, result_id: uuid.UUID) -> None: ...
    async def get_idempotency(self, key: str) -> Optional[uuid.UUID]: ...


class InMemoryPolicyRepository:
    def __init__(self) -> None:
        self._items: Dict[uuid.UUID, Dict[str, Any]] = {}
        self._idemp: Dict[str, uuid.UUID] = {}
        self._lock = asyncio.Lock()

    async def total(self, *, q, status, tag) -> int:
        return len(await self.list(q=q, status=status, tag=tag, sort="created_at:desc", limit=10**9, offset=0))

    async def list(self, *, q, status, tag, sort, limit, offset) -> List[Dict[str, Any]]:
        items = list(self._items.values())
        if q:
            s = q.lower()
            items = [x for x in items if s in x["name"].lower() or (x.get("description") or "").lower().find(s) >= 0]
        if status:
            items = [x for x in items if x["status"] == status]
        if tag:
            items = [x for x in items if tag in x.get("tags", [])]
        # sort: field:direction
        try:
            field, direction = sort.split(":")
        except Exception:
            field, direction = "created_at", "desc"
        reverse = direction.lower() == "desc"
        items.sort(key=lambda x: x.get(field), reverse=reverse)
        return items[offset : offset + limit]

    async def get(self, policy_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        return self._items.get(policy_id)

    async def get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for it in self._items.values():
            if it["name"] == name:
                return it
        return None

    async def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        async with self._lock:
            self._items[data["id"]] = data
        return data

    async def update(self, policy_id: uuid.UUID, data: Dict[str, Any]) -> Dict[str, Any]:
        async with self._lock:
            if policy_id not in self._items:
                raise KeyError("not found")
            self._items[policy_id] = data
            return data

    async def delete(self, policy_id: uuid.UUID) -> None:
        async with self._lock:
            self._items.pop(policy_id, None)

    async def upsert(self, by_name: str, data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        async with self._lock:
            existing = await self.get_by_name(by_name)
            if existing:
                data["id"] = existing["id"]
                self._items[data["id"]] = data
                return "updated", data
            else:
                self._items[data["id"]] = data
                return "created", data

    async def store_idempotency(self, key: str, result_id: uuid.UUID) -> None:
        async with self._lock:
            self._idemp[key] = result_id

    async def get_idempotency(self, key: str) -> Optional[uuid.UUID]:
        return self._idemp.get(key)


class PolicyService:
    def __init__(self, repo: PolicyRepository) -> None:
        self.repo = repo

    # ------------ helpers ------------
    @staticmethod
    def _checksum(payload: Dict[str, Any]) -> str:
        m = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
        return m.hexdigest()

    @staticmethod
    def _etag(policy: Dict[str, Any]) -> str:
        raw = f'{policy["id"]}:{policy["version"]}:{policy["checksum"]}'
        return f'W/"{hashlib.sha256(raw.encode()).hexdigest()}"'

    def _to_out(self, it: Dict[str, Any]) -> PolicyOut:
        model = PolicyOut(
            id=it["id"],
            name=it["name"],
            description=it.get("description"),
            rules=[Rule(**r) for r in it.get("rules", [])],
            priority=it.get("priority", 100),
            tags=it.get("tags", []),
            version=it["version"],
            checksum=it["checksum"],
            status=it["status"],
            created_at=it["created_at"],
            updated_at=it["updated_at"],
            created_by=it["created_by"],
            updated_by=it["updated_by"],
            etag=self._etag(it),
        )
        return model

    async def list(
        self,
        *,
        q: Optional[str],
        status: Optional[PolicyStatus],
        tag: Optional[str],
        sort: str,
        limit: int,
        offset: int,
    ) -> Tuple[List[PolicyOut], int]:
        total = await self.repo.total(q=q, status=status, tag=tag)
        items = await self.repo.list(q=q, status=status, tag=tag, sort=sort, limit=limit, offset=offset)
        return [self._to_out(x) for x in items], total

    async def get(self, policy_id: uuid.UUID) -> PolicyOut:
        it = await self.repo.get(policy_id)
        if not it:
            raise HTTPException(status_code=404, detail="Policy not found")
        return self._to_out(it)

    async def create(
        self,
        data: PolicyIn,
        principal: UserPrincipal,
        *,
        idempotency_key: Optional[str],
    ) -> PolicyOut:
        if await self.repo.get_by_name(data.name):
            raise HTTPException(status_code=409, detail="Policy with this name already exists")

        if idempotency_key:
            existing = await self.repo.get_idempotency(idempotency_key)
            if existing:
                return await self.get(existing)

        now = dt.datetime.utcnow()
        payload = data.model_dump()
        checksum = self._checksum(payload)
        it = {
            "id": uuid.uuid4(),
            "name": data.name,
            "description": data.description,
            "rules": [r.model_dump() for r in data.rules],
            "priority": data.priority,
            "tags": data.tags,
            "version": 1,
            "checksum": checksum,
            "status": data.status,
            "created_at": now,
            "updated_at": now,
            "created_by": principal.sub,
            "updated_by": principal.sub,
        }
        it = await self.repo.create(it)
        if idempotency_key:
            await self.repo.store_idempotency(idempotency_key, it["id"])
        return self._to_out(it)

    async def _update_common(
        self,
        *,
        policy_id: uuid.UUID,
        principal: UserPrincipal,
        if_match: Optional[str],
        updater: callable,
    ) -> PolicyOut:
        it = await self.repo.get(policy_id)
        if not it:
            raise HTTPException(status_code=404, detail="Policy not found")

        current_etag = self._etag(it)
        if if_match and if_match != current_etag:
            raise HTTPException(status_code=412, detail="Precondition Failed: ETag mismatch")

        # применяем изменения
        updater(it)

        payload = {
            "name": it["name"],
            "description": it.get("description"),
            "rules": it.get("rules", []),
            "priority": it.get("priority"),
            "tags": it.get("tags", []),
            "status": it["status"],
        }
        it["checksum"] = self._checksum(payload)
        it["version"] += 1
        it["updated_at"] = dt.datetime.utcnow()
        it["updated_by"] = principal.sub

        it = await self.repo.update(policy_id, it)
        return self._to_out(it)

    async def put(
        self,
        policy_id: uuid.UUID,
        data: PolicyIn,
        principal: UserPrincipal,
        *,
        if_match: Optional[str],
    ) -> PolicyOut:
        def updater(it: Dict[str, Any]) -> None:
            it["name"] = data.name
            it["description"] = data.description
            it["rules"] = [r.model_dump() for r in data.rules]
            it["priority"] = data.priority
            it["tags"] = data.tags
            it["status"] = data.status

        return await self._update_common(policy_id=policy_id, principal=principal, if_match=if_match, updater=updater)

    async def patch(
        self,
        policy_id: uuid.UUID,
        data: PolicyUpdate,
        principal: UserPrincipal,
        *,
        if_match: Optional[str],
    ) -> PolicyOut:
        def updater(it: Dict[str, Any]) -> None:
            if data.name is not None:
                it["name"] = data.name
            if data.description is not None:
                it["description"] = data.description
            if data.rules is not None:
                it["rules"] = [r.model_dump() for r in data.rules]
            if data.priority is not None:
                it["priority"] = data.priority
            if data.tags is not None:
                it["tags"] = data.tags
            if data.status is not None:
                it["status"] = data.status

        return await self._update_common(policy_id=policy_id, principal=principal, if_match=if_match, updater=updater)

    async def delete(self, policy_id: uuid.UUID, *, hard: bool, principal: UserPrincipal) -> None:
        it = await self.repo.get(policy_id)
        if not it:
            return
        if hard:
            await self.repo.delete(policy_id)
        else:
            # мягкое удаление: переводим в retired
            if it["status"] != "retired":
                it["status"] = "retired"
                it["version"] += 1
                it["updated_at"] = dt.datetime.utcnow()
                it["updated_by"] = principal.sub
                await self.repo.update(policy_id, it)

    async def publish(self, policy_id: uuid.UUID, *, principal: UserPrincipal) -> PolicyOut:
        def updater(it: Dict[str, Any]) -> None:
            if it["status"] == "retired":
                raise HTTPException(status_code=409, detail="Cannot publish retired policy")
            it["status"] = "published"

        return await self._update_common(policy_id=policy_id, principal=principal, if_match=None, updater=updater)

    async def validate(self, data: PolicyIn) -> ValidationResult:
        issues: List[ValidationIssue] = []
        # Примеры базовых проверок
        seen = set()
        for idx, rule in enumerate(data.rules):
            key = (rule.action, rule.resource, rule.effect)
            if key in seen:
                issues.append(
                    ValidationIssue(
                        path=f"rules[{idx}]",
                        message="Дубликат по action+resource+effect",
                        severity="warning",
                    )
                )
            else:
                seen.add(key)
            if rule.effect not in ("allow", "deny"):
                issues.append(
                    ValidationIssue(path=f"rules[{idx}].effect", message="Недопустимый effect", severity="error")
                )

        return ValidationResult(valid=not any(i.severity == "error" for i in issues), issues=issues)

    async def import_bundle(
        self,
        bundle: Bundle,
        *,
        strategy: Literal["skip", "overwrite", "abort"],
        dry_run: bool,
        principal: UserPrincipal,
        idempotency_key: Optional[str],
    ) -> ImportResult:
        if idempotency_key:
            existing = await self.repo.get_idempotency(idempotency_key)
            if existing:
                # идемпотентность для всего бандла: возвращаем "ничего не делаем"
                return ImportResult(dry_run=True, summary={"created": 0, "updated": 0, "skipped": 0, "error": 0}, items=[])

        items: List[ImportItemResult] = []
        counts = {"created": 0, "updated": 0, "skipped": 0, "error": 0}

        for p in bundle.items:
            valid = await self.validate(p)
            if not valid.valid and strategy == "abort":
                items.append(ImportItemResult(name=p.name, status="error", message="Validation failed"))
                counts["error"] += 1
                continue

            now = dt.datetime.utcnow()
            payload = p.model_dump()
            checksum = self._checksum(payload)
            candidate = {
                "id": uuid.uuid4(),
                "name": p.name,
                "description": p.description,
                "rules": [r.model_dump() for r in p.rules],
                "priority": p.priority,
                "tags": p.tags,
                "version": 1,
                "checksum": checksum,
                "status": p.status,
                "created_at": now,
                "updated_at": now,
                "created_by": principal.sub,
                "updated_by": principal.sub,
            }

            if dry_run:
                # только считаем
                exists = await self.repo.get_by_name(p.name)
                if exists:
                    if strategy == "skip":
                        items.append(ImportItemResult(name=p.name, id=exists["id"], status="skipped"))
                        counts["skipped"] += 1
                    else:
                        items.append(ImportItemResult(name=p.name, id=exists["id"], status="updated"))
                        counts["updated"] += 1
                else:
                    items.append(ImportItemResult(name=p.name, status="created"))
                    counts["created"] += 1
                continue

            exists = await self.repo.get_by_name(p.name)
            if exists and strategy == "skip":
                items.append(ImportItemResult(name=p.name, id=exists["id"], status="skipped"))
                counts["skipped"] += 1
            elif exists and strategy in ("overwrite", "abort"):
                candidate["id"] = exists["id"]
                await self.repo.update(candidate["id"], candidate)
                items.append(ImportItemResult(name=p.name, id=candidate["id"], status="updated"))
                counts["updated"] += 1
            else:
                created = await self.repo.create(candidate)
                items.append(ImportItemResult(name=p.name, id=created["id"], status="created"))
                counts["created"] += 1

        if idempotency_key and not dry_run:
            # Сохраняем маркер идемпотентности бандла (условно id последнего измененного)
            last_id = next((i.id for i in reversed(items) if i.id is not None), uuid.uuid4())
            await self.repo.store_idempotency(idempotency_key, last_id)  # типовой маркер

        return ImportResult(dry_run=dry_run, summary=counts, items=items)

    async def export_bundle(
        self,
        *,
        q: Optional[str],
        status: Optional[PolicyStatus],
        tag: Optional[str],
    ) -> Bundle:
        items, _ = await self.list(q=q, status=status, tag=tag, sort="created_at:desc", limit=10**6, offset=0)
        # Преобразуем в PolicyIn для чистого экспорта
        export_items = [
            PolicyIn(
                name=p.name,
                description=p.description,
                rules=p.rules,
                priority=p.priority,
                tags=p.tags,
                status=p.status,
            )
            for p in items
        ]
        return Bundle(items=export_items)


# ---------------------------------------------------------------------------
# DI: получаем сервис; подмените на свой репозиторий/сервис при интеграции
# ---------------------------------------------------------------------------

_repo_singleton: Optional[PolicyRepository] = None
_service_singleton: Optional[PolicyService] = None


async def get_service() -> PolicyService:
    global _repo_singleton, _service_singleton
    if _service_singleton is None:
        # В проде замените на реализацию под вашу БД
        _repo_singleton = InMemoryPolicyRepository()
        _service_singleton = PolicyService(_repo_singleton)
    return _service_singleton


# ---------------------------------------------------------------------------
# FASTAPI ROUTER
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/pap", tags=["PAP Admin API"])


# --------- LIST
@router.get(
    "/policies",
    response_model=List[PolicyOut],
    summary="Список политик с фильтрами и пагинацией",
)
async def list_policies(
    response: Response,
    q: Optional[str] = Query(default=None, description="Поиск по name/description"),
    status_filter: Optional[PolicyStatus] = Query(default=None, alias="status"),
    tag: Optional[str] = Query(default=None),
    sort: str = Query(default="created_at:desc", pattern=r"^[a-zA-Z_]+:(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.viewer")),
):
    items, total = await svc.list(q=q, status=status_filter, tag=tag, sort=sort, limit=limit, offset=offset)
    response.headers["X-Total-Count"] = str(total)
    audit("policy.list", principal=principal, total=total, q=q, status=status_filter, tag=tag, sort=sort)
    return items


# --------- GET
@router.get(
    "/policies/{policy_id}",
    response_model=PolicyOut,
    summary="Получить политику",
)
async def get_policy(
    request: Request,
    response: Response,
    policy_id: uuid.UUID = Path(...),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.viewer")),
):
    out = await svc.get(policy_id)
    etag = out.etag
    inm = request.headers.get("If-None-Match")
    if inm and inm == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    response.headers["ETag"] = etag
    audit("policy.get", principal=principal, policy_id=str(policy_id))
    return out


# --------- CREATE
@router.post(
    "/policies",
    status_code=201,
    response_model=PolicyOut,
    summary="Создать политику (идемпотентно)",
)
async def create_policy(
    data: PolicyIn = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.editor")),
):
    result = await svc.create(data, principal, idempotency_key=idempotency_key)
    audit("policy.create", principal=principal, policy_id=str(result.id), name=result.name)
    return result


# --------- PUT
@router.put(
    "/policies/{policy_id}",
    response_model=PolicyOut,
    summary="Полная замена политики",
)
async def put_policy(
    policy_id: uuid.UUID = Path(...),
    data: PolicyIn = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.editor")),
):
    result = await svc.put(policy_id, data, principal, if_match=if_match)
    audit("policy.put", principal=principal, policy_id=str(policy_id), name=result.name)
    return result


# --------- PATCH
@router.patch(
    "/policies/{policy_id}",
    response_model=PolicyOut,
    summary="Частичное обновление политики",
)
async def patch_policy(
    policy_id: uuid.UUID = Path(...),
    data: PolicyUpdate = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.editor")),
):
    result = await svc.patch(policy_id, data, principal, if_match=if_match)
    audit("policy.patch", principal=principal, policy_id=str(policy_id))
    return result


# --------- DELETE
@router.delete(
    "/policies/{policy_id}",
    status_code=204,
    summary="Удаление политики (мягкое по умолчанию)",
)
async def delete_policy(
    policy_id: uuid.UUID = Path(...),
    hard: bool = Query(default=False, description="true для полного удаления"),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.editor")),
):
    if hard and not principal.has("policy.admin"):
        raise HTTPException(status_code=403, detail="Hard delete requires policy.admin")
    await svc.delete(policy_id, hard=hard, principal=principal)
    audit("policy.delete", principal=principal, policy_id=str(policy_id), hard=hard)
    return Response(status_code=204)


# --------- PUBLISH
@router.post(
    "/policies/{policy_id}/publish",
    response_model=PolicyOut,
    summary="Публикация политики",
)
async def publish_policy(
    policy_id: uuid.UUID = Path(...),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.editor")),
):
    result = await svc.publish(policy_id, principal=principal)
    audit("policy.publish", principal=principal, policy_id=str(policy_id))
    return result


# --------- VALIDATE
@router.post(
    "/policies/validate",
    response_model=ValidationResult,
    summary="Валидация политики без сохранения",
)
async def validate_policy(
    data: PolicyIn = Body(...),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.viewer")),
):
    res = await svc.validate(data)
    audit("policy.validate", principal=principal, valid=res.valid, issues=len(res.issues))
    return res


# --------- IMPORT
class ImportRequest(BaseModel):
    bundle: Bundle
    strategy: Literal["skip", "overwrite", "abort"] = "abort"
    dry_run: bool = False


@router.post(
    "/policies/import",
    response_model=ImportResult,
    summary="Импорт бандла политик (идемпотентно)",
)
async def import_policies(
    req: ImportRequest = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.admin")),
):
    res = await svc.import_bundle(
        req.bundle,
        strategy=req.strategy,
        dry_run=req.dry_run,
        principal=principal,
        idempotency_key=idempotency_key,
    )
    audit("policy.import", principal=principal, dry_run=req.dry_run, summary=res.summary)
    return res


# --------- EXPORT
@router.get(
    "/policies/export",
    response_model=Bundle,
    summary="Экспорт политик (фильтры по желанию)",
)
async def export_policies(
    q: Optional[str] = Query(default=None),
    status_filter: Optional[PolicyStatus] = Query(default=None, alias="status"),
    tag: Optional[str] = Query(default=None),
    svc: PolicyService = Depends(get_service),
    principal: UserPrincipal = Depends(require_role("policy.viewer")),
):
    bundle = await svc.export_bundle(q=q, status=status_filter, tag=tag)
    audit("policy.export", principal=principal, count=len(bundle.items))
    return bundle
