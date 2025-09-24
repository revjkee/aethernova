# cybersecurity-core/api/http/routers/v1/policies.py
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, TypedDict
from uuid import UUID, uuid4

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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict

# ==========================
# Константы и утилиты
# ==========================

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9\.-]+)?$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_etag(payload: Dict[str, Any]) -> str:
    """
    Строгий ETag на основе стабильного дампа JSON без пробелов.
    Рекомендуется включать поля updated_at / revision для детерминированности.
    """
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f'W/"{sha256_hex(canonical)}"'  # слабый ETag уместен для JSON


def problem_detail(
    *,
    title: str,
    status_code: int,
    detail: Optional[str] = None,
    type_uri: str = "about:blank",
    instance: Optional[str] = None,
    extras: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """
    RFC7807 problem+json.
    """
    body: Dict[str, Any] = {
        "type": type_uri,
        "title": title,
        "status": status_code,
    }
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    if extras:
        body.update(extras)
    return JSONResponse(status_code=status_code, content=body, media_type="application/problem+json")


# ==========================
# Модели API
# ==========================

PolicyType = Literal["rbac", "ids", "edr", "ti", "blocklist"]
PolicyStatus = Literal["draft", "active", "deprecated"]

class PolicyRule(BaseModel):
    """
    Универсальное правило политики.
    Для сложных DSL допустимо хранение normalized condition/action.
    """
    model_config = ConfigDict(extra="forbid")

    id: Optional[UUID] = Field(default=None, description="Идентификатор правила")
    description: Optional[str] = Field(default=None, max_length=2000)
    condition: Dict[str, Any] = Field(default_factory=dict, description="Условие с операторами DSL")
    actions: List[Dict[str, Any]] = Field(default_factory=list, description="Список действий")

class PolicyBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., pattern=r"^[a-z][a-z0-9_\-]{1,63}$", description="Системное имя политики")
    title: Optional[str] = Field(default=None, max_length=256, description="Читаемый заголовок")
    type: PolicyType = Field(..., description="Тип политики")
    version: str = Field(..., description="Семвер версии политики")
    status: PolicyStatus = Field(default="draft", description="Статус политики")
    description: Optional[str] = Field(default=None, max_length=4000)
    tags: List[str] = Field(default_factory=list, description="Теги политики")
    scope: Optional[Dict[str, Any]] = Field(default=None, description="Ограничение применимости (org, tenant, env)")

class PolicyCreate(PolicyBase):
    rules: List[PolicyRule] = Field(default_factory=list, description="Правила политики")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class PolicyUpdate(BaseModel):
    """
    Частичное обновление.
    """
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4000)
    status: Optional[PolicyStatus] = None
    version: Optional[str] = Field(default=None, description="Семвер")
    tags: Optional[List[str]] = None
    scope: Optional[Dict[str, Any]] = None
    rules: Optional[List[PolicyRule]] = None
    metadata: Optional[Dict[str, Any]] = None

class PolicyOut(PolicyBase):
    id: UUID
    created_at: datetime
    updated_at: datetime
    revision: int = Field(..., ge=0, description="Версия записи для optimistic locking")
    etag: str = Field(..., description="ETag для If-Match/If-None-Match")

class Pagination(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)
    next_cursor: Optional[str] = None
    prev_cursor: Optional[str] = None

class PolicyList(BaseModel):
    items: List[PolicyOut]
    page: Pagination

class EvaluateRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict, description="Проверяемый объект")
    mode: Literal["dry_run", "enforce"] = "dry_run"
    context: Dict[str, Any] = Field(default_factory=dict, description="Контекст (subject, env)")
    policy_id: Optional[UUID] = Field(default=None, description="Если не указан, используется embedded_policy")
    embedded_policy: Optional[PolicyCreate] = Field(default=None, description="Одноразовая inline-политика")

class EvaluateResponse(BaseModel):
    decision: Literal["allow", "deny"]
    matched_rules: List[UUID] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)

class ExportFormat(BaseModel):
    format: Literal["json", "yaml"] = "json"
    pretty: bool = True

# ==========================
# Абстракции сервисного слоя
# ==========================

class PolicyRecord(TypedDict, total=False):
    id: UUID
    name: str
    title: Optional[str]
    type: PolicyType
    version: str
    status: PolicyStatus
    description: Optional[str]
    tags: List[str]
    scope: Optional[Dict[str, Any]]
    rules: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    revision: int


class PolicyService(Protocol):
    """
    Протокол сервисного слоя. Реализация работает с AsyncSession, аудит-логами и кешем.
    """
    async def list_policies(
        self,
        *,
        limit: int,
        cursor: Optional[str],
        type_: Optional[PolicyType],
        status_: Optional[PolicyStatus],
        q: Optional[str],
        tags: Optional[List[str]],
        tenant_id: Optional[str],
    ) -> Tuple[List[PolicyRecord], Pagination]:
        ...

    async def create_policy(
        self, *, data: PolicyCreate, idempotency_key: Optional[str], subject: str
    ) -> PolicyRecord:
        ...

    async def get_policy(self, *, policy_id: UUID) -> PolicyRecord:
        ...

    async def update_policy_put(
        self, *, policy_id: UUID, data: PolicyCreate, expected_revision: Optional[int]
    ) -> PolicyRecord:
        ...

    async def update_policy_patch(
        self, *, policy_id: UUID, data: PolicyUpdate, expected_revision: Optional[int]
    ) -> PolicyRecord:
        ...

    async def delete_policy(self, *, policy_id: UUID, subject: str) -> None:
        ...

    async def set_status(self, *, policy_id: UUID, status_: PolicyStatus, subject: str) -> PolicyRecord:
        ...

    async def evaluate(
        self, *, request: EvaluateRequest
    ) -> EvaluateResponse:
        ...

    async def export(
        self, *, policy_id: UUID, fmt: Literal["json", "yaml"], pretty: bool
    ) -> Tuple[str, str]:  # (media_type, content)
        ...


# ==========================
# Зависимости (интеграция безопасности)
# ==========================

async def require_scopes(
    request: Request,
    scopes: Iterable[str],
) -> None:
    """
    Заглушка для проверки скоупов OAuth2 / RBAC.
    В проде подключите вашу реализацию, которая бросает HTTPException(403) при нарушении.
    """
    granted = set(getattr(request.state, "scopes", []) or [])
    needed = set(scopes)
    if not needed.issubset(granted):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scopes")


async def get_subject(request: Request) -> str:
    """
    Возвращает идентификатор субъекта (пользователь/сервис).
    В проде свяжите с JWT / mTLS идентичностью.
    """
    sub = getattr(request.state, "subject", None)
    return sub or "anonymous"


def get_policy_service() -> PolicyService:
    """
    Фабрика сервисного слоя. В реальном приложении предоставьте через DI-контейнер.
    """
    raise NotImplementedError("Bind PolicyService implementation via dependency override")


# ==========================
# Инициализация роутера
# ==========================

router = APIRouter(prefix="/v1/policies", tags=["Policies"])

# ==========================
# Эндпоинты
# ==========================

@router.get(
    "",
    response_model=PolicyList,
    status_code=status.HTTP_200_OK,
    summary="Список политик",
)
async def list_policies(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Размер страницы"),
    cursor: Optional[str] = Query(None, description="Курсор страницы"),
    type_: Optional[PolicyType] = Query(None, alias="type"),
    status_: Optional[PolicyStatus] = Query(None, alias="status"),
    q: Optional[str] = Query(None, min_length=1, max_length=256, description="Поисковая строка"),
    tags: Optional[List[str]] = Query(None, description="Фильтр по тегам"),
    tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    _=Depends(lambda req=request: require_scopes(req, ["policies:read"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyList:
    try:
        items_raw, page = await service.list_policies(
            limit=limit, cursor=cursor, type_=type_, status_=status_, q=q, tags=tags, tenant_id=tenant_id
        )
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to list policies",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )

    items: List[PolicyOut] = []
    for rec in items_raw:
        etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
        items.append(
            PolicyOut(
                id=rec["id"],
                name=rec["name"],
                title=rec.get("title"),
                type=rec["type"],
                version=rec["version"],
                status=rec["status"],
                description=rec.get("description"),
                tags=rec.get("tags", []),
                scope=rec.get("scope"),
                created_at=rec["created_at"],
                updated_at=rec["updated_at"],
                revision=rec["revision"],
                etag=etag,
            )
        )
    return PolicyList(items=items, page=page)


@router.post(
    "",
    response_model=PolicyOut,
    status_code=status.HTTP_201_CREATED,
    summary="Создать политику (идемпотентно)",
)
async def create_policy(
    request: Request,
    data: PolicyCreate = Body(...),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    subject: str = Depends(get_subject),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    if not SEMVER_RE.match(data.version):
        raise HTTPException(status_code=400, detail="Invalid semantic version")
    try:
        rec = await service.create_policy(data=data, idempotency_key=idempotency_key, subject=subject)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to create policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag,
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyOut,
    status_code=status.HTTP_200_OK,
    summary="Получить политику",
)
async def get_policy(
    request: Request,
    response: Response,
    policy_id: UUID = Path(...),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    _=Depends(lambda req=request: require_scopes(req, ["policies:read"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    try:
        rec = await service.get_policy(policy_id=policy_id)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to fetch policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    if if_none_match and if_none_match == etag:
        # 304 без тела
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    response.headers["ETag"] = etag
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag,
    )


@router.put(
    "/{policy_id}",
    response_model=PolicyOut,
    summary="Полное обновление политики (optimistic locking)",
)
async def update_policy_put(
    request: Request,
    policy_id: UUID = Path(...),
    data: PolicyCreate = Body(...),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    if not SEMVER_RE.match(data.version):
        raise HTTPException(status_code=400, detail="Invalid semantic version")

    expected_revision: Optional[int] = None
    if if_match:
        # Допускаем W/"<hash>-rev:<n>"
        try:
            if if_match.startswith('W/"') and if_match.endswith('"') and "-rev:" in if_match:
                expected_revision = int(if_match.split("-rev:")[-1].rstrip('"'))
        except Exception:
            expected_revision = None

    try:
        rec = await service.update_policy_put(policy_id=policy_id, data=data, expected_revision=expected_revision)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to update policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag + f"-rev:{rec['revision']}",
    )


@router.patch(
    "/{policy_id}",
    response_model=PolicyOut,
    summary="Частичное обновление политики (optimistic locking)",
)
async def update_policy_patch(
    request: Request,
    policy_id: UUID = Path(...),
    data: PolicyUpdate = Body(...),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    expected_revision: Optional[int] = None
    if if_match:
        try:
            if if_match.startswith('W/"') and if_match.endswith('"') and "-rev:" in if_match:
                expected_revision = int(if_match.split("-rev:")[-1].rstrip('"'))
        except Exception:
            expected_revision = None

    if data.version and not SEMVER_RE.match(data.version):
        raise HTTPException(status_code=400, detail="Invalid semantic version")

    try:
        rec = await service.update_policy_patch(policy_id=policy_id, data=data, expected_revision=expected_revision)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to patch policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag + f"-rev:{rec['revision']}",
    )


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить политику",
)
async def delete_policy(
    request: Request,
    policy_id: UUID = Path(...),
    subject: str = Depends(get_subject),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> Response:
    try:
        await service.delete_policy(policy_id=policy_id, subject=subject)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to delete policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{policy_id}/publish",
    response_model=PolicyOut,
    summary="Опубликовать политику (active)",
)
async def publish_policy(
    request: Request,
    policy_id: UUID = Path(...),
    subject: str = Depends(get_subject),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    try:
        rec = await service.set_status(policy_id=policy_id, status_="active", subject=subject)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to publish policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag,
    )


@router.post(
    "/{policy_id}/deprecate",
    response_model=PolicyOut,
    summary="Депрецировать политику (deprecated)",
)
async def deprecate_policy(
    request: Request,
    policy_id: UUID = Path(...),
    subject: str = Depends(get_subject),
    _=Depends(lambda req=request: require_scopes(req, ["policies:write"])),
    service: PolicyService = Depends(get_policy_service),
) -> PolicyOut:
    try:
        rec = await service.set_status(policy_id=policy_id, status_="deprecated", subject=subject)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to deprecate policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    etag = compute_etag({"id": str(rec["id"]), "rev": rec["revision"], "updated_at": rec["updated_at"].isoformat()})
    return PolicyOut(
        id=rec["id"],
        name=rec["name"],
        title=rec.get("title"),
        type=rec["type"],
        version=rec["version"],
        status=rec["status"],
        description=rec.get("description"),
        tags=rec.get("tags", []),
        scope=rec.get("scope"),
        created_at=rec["created_at"],
        updated_at=rec["updated_at"],
        revision=rec["revision"],
        etag=etag,
    )


@router.post(
    "/{policy_id}/evaluate",
    response_model=EvaluateResponse,
    summary="Оценка политики (dry_run/enforce)",
)
async def evaluate_policy(
    request: Request,
    policy_id: UUID = Path(...),
    body: EvaluateRequest = Body(...),
    _=Depends(lambda req=request: require_scopes(req, ["policies:evaluate"])),
    service: PolicyService = Depends(get_policy_service),
) -> EvaluateResponse:
    # Принудительно зафиксируем policy_id для сервисного слоя
    body.policy_id = policy_id
    try:
        result = await service.evaluate(request=body)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to evaluate policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    return result


@router.post(
    "/{policy_id}/export",
    summary="Экспорт политики (json/yaml)",
    responses={
        200: {
            "content": {
                "application/json": {},
                "application/yaml": {},
            },
            "description": "Экспортированный документ",
        }
    },
)
async def export_policy(
    request: Request,
    policy_id: UUID = Path(...),
    opts: ExportFormat = Body(default=ExportFormat()),
    _=Depends(lambda req=request: require_scopes(req, ["policies:read"])),
    service: PolicyService = Depends(get_policy_service),
):
    try:
        media_type, content = await service.export(policy_id=policy_id, fmt=opts.format, pretty=opts.pretty)
    except HTTPException:
        raise
    except Exception as exc:
        return problem_detail(
            title="Failed to export policy",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    return Response(content=content, media_type=media_type)
