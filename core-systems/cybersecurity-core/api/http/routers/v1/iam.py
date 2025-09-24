# cybersecurity-core/api/http/routers/v1/iam.py
from __future__ import annotations

import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Protocol, Iterable

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Header,
    Request,
    Response,
    status,
    Query,
)
from pydantic import BaseModel, Field, EmailStr, constr
from enum import Enum


# -----------------------------------------------------------------------------
# Логгер
# -----------------------------------------------------------------------------
logger = logging.getLogger("iam.v1")
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# Типы и модели
# -----------------------------------------------------------------------------
class PrincipalType(str, Enum):
    user = "user"
    service = "service"


class Principal(BaseModel):
    id: str = Field(..., description="Уникальный идентификатор субъекта")
    subject: str = Field(..., description="Уникальный логин/идентификатор субъекта")
    type: PrincipalType = Field(..., description="Тип субъекта (пользователь/сервис)")
    org_id: Optional[str] = Field(None, description="Организация")
    roles: List[str] = Field(default_factory=list, description="Роли")
    permissions: List[str] = Field(default_factory=list, description="Разрешения")


# ---- Auth / Tokens
class LoginRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=1)
    password: constr(min_length=1)
    scope: Optional[List[str]] = Field(default=None, description="Желаемые scope, опционально")
    audience: Optional[str] = Field(default=None, description="Аудитория токена")


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Срок жизни access токена в секундах")


class RefreshRequest(BaseModel):
    refresh_token: constr(min_length=10)


class LogoutRequest(BaseModel):
    refresh_token: constr(min_length=10)


# ---- Users / Me
class UserOut(BaseModel):
    id: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: bool = True
    roles: List[str] = []
    permissions: List[str] = []


# ---- Roles / Permissions
class RoleIn(BaseModel):
    name: constr(strip_whitespace=True, min_length=2, max_length=64)
    permissions: List[constr(strip_whitespace=True, min_length=2)] = Field(default_factory=list)
    description: Optional[str] = None


class RoleUpdate(BaseModel):
    name: Optional[constr(strip_whitespace=True, min_length=2, max_length=64)] = None
    permissions: Optional[List[constr(strip_whitespace=True, min_length=2)]] = None
    description: Optional[str] = None


class RoleOut(BaseModel):
    id: str
    name: str
    permissions: List[str]
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AssignRoleIn(BaseModel):
    role_id: str


# ---- API Keys
class CreateApiKeyIn(BaseModel):
    name: constr(strip_whitespace=True, min_length=2, max_length=100)
    scope: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = Field(None, description="UTC")
    note: Optional[str] = None


class ApiKeyCreatedOut(BaseModel):
    id: str
    name: str
    prefix: str
    secret: str = Field(..., description="Показывается только при создании")
    scope: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    scope: List[str]
    created_at: datetime
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked: bool = False


# ---- Service Accounts
class ServiceAccountIn(BaseModel):
    name: constr(strip_whitespace=True, min_length=2, max_length=100)
    description: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class ServiceAccountCreatedOut(BaseModel):
    id: str
    name: str
    client_id: str
    client_secret: str = Field(..., description="Показывается только при создании/ротации")
    roles: List[str]
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    active: bool = True


class ServiceAccountOut(BaseModel):
    id: str
    name: str
    client_id: str
    roles: List[str]
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    active: bool = True


# ---- Audit
class AuditEventOut(BaseModel):
    id: str
    ts: datetime
    principal_id: Optional[str] = None
    action: str
    resource: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int


class PageOut(BaseModel):
    items: List[Any]
    meta: PageMeta


# -----------------------------------------------------------------------------
# Протоколы (интерфейсы) сервисов и репозиториев для DI
# -----------------------------------------------------------------------------
class TokenService(Protocol):
    async def issue_pair(self, user_id: str, scope: Optional[List[str]], audience: Optional[str]) -> Tuple[str, str, int]:
        ...

    async def refresh(self, refresh_token: str) -> Tuple[str, str, int]:
        ...

    async def revoke(self, refresh_token: str) -> None:
        ...

    async def verify(self, token: str) -> Dict[str, Any]:
        ...


class UserRepo(Protocol):
    async def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        ...

    async def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        ...

    async def get_permissions(self, user_id: str) -> List[str]:
        ...

    async def list_roles(self, user_id: str) -> List[str]:
        ...

    async def assign_role(self, user_id: str, role_id: str) -> None:
        ...


class RoleRepo(Protocol):
    async def create(self, name: str, permissions: List[str], description: Optional[str]) -> Dict[str, Any]:
        ...

    async def update(self, role_id: str, name: Optional[str], permissions: Optional[List[str]], description: Optional[str]) -> Dict[str, Any]:
        ...

    async def delete(self, role_id: str) -> None:
        ...

    async def get(self, role_id: str) -> Optional[Dict[str, Any]]:
        ...

    async def list(self, page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        ...


class ApiKeyService(Protocol):
    async def create(self, owner_id: str, name: str, scope: List[str], expires_at: Optional[datetime], idempotency_key: Optional[str]) -> Dict[str, Any]:
        ...

    async def list(self, owner_id: str, page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        ...

    async def revoke(self, owner_id: str, api_key_id: str) -> None:
        ...

    async def resolve_owner_from_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        ...

    async def get_secret_by_prefix(self, prefix: str) -> Optional[str]:
        ...


class ServiceAccountRepo(Protocol):
    async def create(self, name: str, roles: List[str], description: Optional[str], expires_at: Optional[datetime]) -> Dict[str, Any]:
        ...

    async def rotate_secret(self, sa_id: str) -> Dict[str, Any]:
        ...

    async def get(self, sa_id: str) -> Optional[Dict[str, Any]]:
        ...


class AuditService(Protocol):
    async def write(self, event: Dict[str, Any]) -> None:
        ...

    async def query(self, filters: Dict[str, Any], page: int, page_size: int) -> Tuple[List[Dict[str, Any]], int]:
        ...


# -----------------------------------------------------------------------------
# DI-заглушки (должны быть переопределены в приложении)
# -----------------------------------------------------------------------------
def _not_configured(name: str):
    raise RuntimeError(f"{name} dependency is not configured. Override it via FastAPI dependency_overrides or container.")


async def get_token_service() -> TokenService:
    _not_configured("TokenService")


async def get_user_repo() -> UserRepo:
    _not_configured("UserRepo")


async def get_role_repo() -> RoleRepo:
    _not_configured("RoleRepo")


async def get_apikey_service() -> ApiKeyService:
    _not_configured("ApiKeyService")


async def get_sa_repo() -> ServiceAccountRepo:
    _not_configured("ServiceAccountRepo")


async def get_audit_service() -> AuditService:
    _not_configured("AuditService")


# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def require(condition: bool, status_code: int, message: str):
    if not condition:
        raise HTTPException(status_code=status_code, detail=message)


def digest_hmac_sha256(secret: str, payload: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def build_signing_payload(method: str, path_qs: str, body: str, timestamp: str) -> str:
    # Совместимо с клиентом: METHOD \n PATH?QS \n BODY \n TIMESTAMP
    return f"{method.upper()}\n{path_qs}\n{body}\n{timestamp}"


def get_request_id(x_request_id: Optional[str]) -> str:
    return x_request_id or str(uuid.uuid4())


# -----------------------------------------------------------------------------
# Безопасность: Current principal + проверка HMAC (опционально)
# -----------------------------------------------------------------------------
async def current_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_org_id: Optional[str] = Header(default=None, alias="x-org-id"),
    token_svc: TokenService = Depends(get_token_service),
    apikey_svc: ApiKeyService = Depends(get_apikey_service),
    user_repo: UserRepo = Depends(get_user_repo),
) -> Principal:
    # Bearer приоритетнее API Key
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = await token_svc.verify(token)
        except Exception as ex:
            logger.warning("Token verify failed: %s", ex)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        sub = str(claims.get("sub") or "")
        sub_type = str(claims.get("type") or "user")
        require(bool(sub), status.HTTP_401_UNAUTHORIZED, "Invalid token subject")
        # Извлекаем роли/пермишены из claims или из БД
        permissions = list(claims.get("permissions") or [])
        roles = list(claims.get("roles") or [])
        if not permissions:
            try:
                permissions = await user_repo.get_permissions(sub)
            except Exception:
                permissions = []
        if not roles:
            try:
                roles = await user_repo.list_roles(sub)
            except Exception:
                roles = []
        return Principal(
            id=sub,
            subject=sub,
            type=PrincipalType.service if sub_type == "service" else PrincipalType.user,
            org_id=x_org_id,
            roles=roles,
            permissions=permissions,
        )

    # X-API-Key
    if x_api_key:
        owner = await apikey_svc.resolve_owner_from_key(x_api_key)
        require(owner is not None, status.HTTP_401_UNAUTHORIZED, "Invalid API key")
        return Principal(
            id=str(owner["id"]),
            subject=str(owner.get("subject") or owner["id"]),
            type=PrincipalType.service if owner.get("type") == "service" else PrincipalType.user,
            org_id=x_org_id or owner.get("org_id"),
            roles=list(owner.get("roles") or []),
            permissions=list(owner.get("permissions") or []),
        )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


def permission_required(permission: str):
    async def _guard(principal: Principal = Depends(current_principal)):
        if permission not in set(principal.permissions):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return principal

    return _guard


async def optional_hmac_verify(
    request: Request,
    x_signature: Optional[str] = Header(default=None, alias="x-signature"),
    x_timestamp: Optional[str] = Header(default=None, alias="x-timestamp"),
    x_signature_alg: Optional[str] = Header(default=None, alias="x-signature-alg"),
    x_key_prefix: Optional[str] = Header(default=None, alias="x-key-prefix"),
    apikey_svc: ApiKeyService = Depends(get_apikey_service),
) -> None:
    if not x_signature:
        return  # подписи нет — пропускаем
    require(x_timestamp is not None, status.HTTP_400_BAD_REQUEST, "Missing x-timestamp")
    require(x_signature_alg in (None, "HMAC-SHA256", "hmac-sha256"), status.HTTP_400_BAD_REQUEST, "Unsupported signature alg")
    # Ищем секрет по префиксу
    require(x_key_prefix is not None, status.HTTP_400_BAD_REQUEST, "Missing x-key-prefix")
    secret = await apikey_svc.get_secret_by_prefix(x_key_prefix)
    require(secret is not None, status.HTTP_401_UNAUTHORIZED, "Unknown key prefix")

    body = (await request.body()).decode("utf-8") if request.method != "GET" else ""
    path_qs = request.url.path
    if request.url.query:
        path_qs += f"?{request.url.query}"
    payload = build_signing_payload(request.method, path_qs, body, x_timestamp)
    calc = digest_hmac_sha256(secret, payload)
    if not hmac.compare_digest(calc, x_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")


# -----------------------------------------------------------------------------
# Роутер
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/v1/iam", tags=["IAM"])


# ---- Auth endpoints ----------------------------------------------------------
@router.post("/login", response_model=TokenPair, status_code=status.HTTP_200_OK)
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
    user_repo: UserRepo = Depends(get_user_repo),
    token_svc: TokenService = Depends(get_token_service),
    audit: AuditService = Depends(get_audit_service),
):
    req_id = get_request_id(x_request_id)
    user = await user_repo.authenticate(data.username, data.password)
    if not user:
        await audit.write(
            {
                "ts": now_utc().isoformat(),
                "action": "auth.login.failed",
                "resource": "iam/login",
                "principal_id": None,
                "request_id": req_id,
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "metadata": {"username": data.username},
            }
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access, refresh, exp = await token_svc.issue_pair(str(user["id"]), data.scope, data.audience)

    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "auth.login.success",
            "resource": "iam/login",
            "principal_id": str(user["id"]),
            "request_id": req_id,
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    response.headers["x-request-id"] = req_id
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=exp)


@router.post("/token/refresh", response_model=TokenPair)
async def refresh_token(
    data: RefreshRequest,
    request: Request,
    response: Response,
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
    token_svc: TokenService = Depends(get_token_service),
    audit: AuditService = Depends(get_audit_service),
):
    req_id = get_request_id(x_request_id)
    try:
        access, refresh, exp = await token_svc.refresh(data.refresh_token)
    except Exception as ex:
        await audit.write(
            {
                "ts": now_utc().isoformat(),
                "action": "auth.refresh.failed",
                "resource": "iam/token/refresh",
                "principal_id": None,
                "request_id": req_id,
                "metadata": {"error": str(ex)[:200]},
            }
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "auth.refresh.success",
            "resource": "iam/token/refresh",
            "principal_id": None,
            "request_id": req_id,
        }
    )
    response.headers["x-request-id"] = req_id
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=exp)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    data: LogoutRequest,
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
    token_svc: TokenService = Depends(get_token_service),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
):
    req_id = get_request_id(x_request_id)
    await token_svc.revoke(data.refresh_token)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "auth.logout",
            "resource": "iam/logout",
            "principal_id": principal.id,
            "request_id": req_id,
        }
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- Me / Permissions --------------------------------------------------------
@router.get("/me", response_model=UserOut)
async def get_me(
    principal: Principal = Depends(current_principal),
    user_repo: UserRepo = Depends(get_user_repo),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
    response: Response = None,
):
    if response is not None:
        response.headers["x-request-id"] = get_request_id(x_request_id)
    user = await user_repo.get_by_id(principal.id)
    # Формируем ответ из principal и профиля
    return UserOut(
        id=principal.id,
        email=(user or {}).get("email"),
        full_name=(user or {}).get("full_name"),
        is_active=(user or {}).get("is_active", True),
        roles=principal.roles,
        permissions=principal.permissions,
    )


@router.get("/permissions", response_model=List[str])
async def get_permissions(
    principal: Principal = Depends(current_principal),
    response: Response = None,
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    if response is not None:
        response.headers["x-request-id"] = get_request_id(x_request_id)
    return principal.permissions


# ---- Roles CRUD --------------------------------------------------------------
@router.post(
    "/roles",
    response_model=RoleOut,
    dependencies=[Depends(permission_required("iam.roles.write")), Depends(optional_hmac_verify)],
)
async def create_role(
    data: RoleIn,
    role_repo: RoleRepo = Depends(get_role_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    request: Request = None,
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    role = await role_repo.create(data.name, data.permissions, data.description)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "role.create",
            "resource": f"iam/roles/{role['id']}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
            "metadata": {"name": data.name, "permissions": data.permissions},
        }
    )
    return RoleOut(
        id=str(role["id"]),
        name=role["name"],
        permissions=list(role.get("permissions") or []),
        description=role.get("description"),
        created_at=role.get("created_at", now_utc()),
        updated_at=role.get("updated_at", now_utc()),
    )


@router.patch(
    "/roles/{role_id}",
    response_model=RoleOut,
    dependencies=[Depends(permission_required("iam.roles.write")), Depends(optional_hmac_verify)],
)
async def update_role(
    role_id: str,
    data: RoleUpdate,
    role_repo: RoleRepo = Depends(get_role_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    role = await role_repo.update(role_id, data.name, data.permissions, data.description)
    require(role is not None, status.HTTP_404_NOT_FOUND, "Role not found")
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "role.update",
            "resource": f"iam/roles/{role_id}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
        }
    )
    return RoleOut(
        id=str(role["id"]),
        name=role["name"],
        permissions=list(role.get("permissions") or []),
        description=role.get("description"),
        created_at=role.get("created_at", now_utc()),
        updated_at=role.get("updated_at", now_utc()),
    )


@router.delete(
    "/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(permission_required("iam.roles.write")), Depends(optional_hmac_verify)],
)
async def delete_role(
    role_id: str,
    role_repo: RoleRepo = Depends(get_role_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    await role_repo.delete(role_id)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "role.delete",
            "resource": f"iam/roles/{role_id}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
        }
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/roles",
    response_model=PageOut,
    dependencies=[Depends(permission_required("iam.roles.read"))],
)
async def list_roles(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    role_repo: RoleRepo = Depends(get_role_repo),
):
    items, total = await role_repo.list(page=page, page_size=page_size)
    roles = [
        RoleOut(
            id=str(r["id"]),
            name=r["name"],
            permissions=list(r.get("permissions") or []),
            description=r.get("description"),
            created_at=r.get("created_at", now_utc()),
            updated_at=r.get("updated_at", now_utc()),
        ).dict()
        for r in items
    ]
    return PageOut(items=roles, meta=PageMeta(page=page, page_size=page_size, total=total))


# ---- Assign role to user -----------------------------------------------------
@router.post(
    "/users/{user_id}/roles:assign",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(permission_required("iam.roles.assign")), Depends(optional_hmac_verify)],
)
async def assign_role_to_user(
    user_id: str,
    data: AssignRoleIn,
    user_repo: UserRepo = Depends(get_user_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    await user_repo.assign_role(user_id, data.role_id)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "user.role.assign",
            "resource": f"iam/users/{user_id}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
            "metadata": {"role_id": data.role_id},
        }
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- API Keys endpoints ------------------------------------------------------
@router.post(
    "/api-keys",
    response_model=ApiKeyCreatedOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(permission_required("iam.apikeys.write")), Depends(optional_hmac_verify)],
)
async def create_api_key(
    data: CreateApiKeyIn,
    request: Request,
    principal: Principal = Depends(current_principal),
    apikey_svc: ApiKeyService = Depends(get_apikey_service),
    audit: AuditService = Depends(get_audit_service),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    created = await apikey_svc.create(
        owner_id=principal.id,
        name=data.name,
        scope=data.scope,
        expires_at=data.expires_at,
        idempotency_key=idempotency_key,
    )
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "apikey.create",
            "resource": f"iam/api-keys/{created['id']}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
            "metadata": {"name": data.name, "scope": data.scope},
        }
    )
    return ApiKeyCreatedOut(
        id=str(created["id"]),
        name=created["name"],
        prefix=created["prefix"],
        secret=created["secret"],  # только в этом ответе
        scope=list(created.get("scope") or []),
        created_at=created.get("created_at", now_utc()),
        expires_at=created.get("expires_at"),
    )


@router.get(
    "/api-keys",
    response_model=PageOut,
    dependencies=[Depends(permission_required("iam.apikeys.read"))],
)
async def list_api_keys(
    principal: Principal = Depends(current_principal),
    apikey_svc: ApiKeyService = Depends(get_apikey_service),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    items, total = await apikey_svc.list(principal.id, page=page, page_size=page_size)
    keys = [
        ApiKeyOut(
            id=str(k["id"]),
            name=k["name"],
            prefix=k["prefix"],
            scope=list(k.get("scope") or []),
            created_at=k.get("created_at", now_utc()),
            last_used_at=k.get("last_used_at"),
            expires_at=k.get("expires_at"),
            revoked=bool(k.get("revoked", False)),
        ).dict()
        for k in items
    ]
    return PageOut(items=keys, meta=PageMeta(page=page, page_size=page_size, total=total))


@router.delete(
    "/api-keys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(permission_required("iam.apikeys.write")), Depends(optional_hmac_verify)],
)
async def revoke_api_key(
    api_key_id: str,
    principal: Principal = Depends(current_principal),
    apikey_svc: ApiKeyService = Depends(get_apikey_service),
    audit: AuditService = Depends(get_audit_service),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    await apikey_svc.revoke(principal.id, api_key_id)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "apikey.revoke",
            "resource": f"iam/api-keys/{api_key_id}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
        }
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- Service Accounts endpoints ---------------------------------------------
@router.post(
    "/service-accounts",
    response_model=ServiceAccountCreatedOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(permission_required("iam.service_accounts.write")), Depends(optional_hmac_verify)],
)
async def create_service_account(
    data: ServiceAccountIn,
    sa_repo: ServiceAccountRepo = Depends(get_sa_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    sa = await sa_repo.create(data.name, data.roles, data.description, data.expires_at)
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "sa.create",
            "resource": f"iam/service-accounts/{sa['id']}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
            "metadata": {"roles": data.roles},
        }
    )
    return ServiceAccountCreatedOut(
        id=str(sa["id"]),
        name=sa["name"],
        client_id=sa["client_id"],
        client_secret=sa["client_secret"],  # показывается только при создании
        roles=list(sa.get("roles") or []),
        permissions=list(sa.get("permissions") or []),
        created_at=sa.get("created_at", now_utc()),
        expires_at=sa.get("expires_at"),
        active=bool(sa.get("active", True)),
    )


@router.post(
    "/service-accounts/{sa_id}:rotate-secret",
    response_model=ServiceAccountCreatedOut,
    dependencies=[Depends(permission_required("iam.service_accounts.write")), Depends(optional_hmac_verify)],
)
async def rotate_sa_secret(
    sa_id: str,
    sa_repo: ServiceAccountRepo = Depends(get_sa_repo),
    audit: AuditService = Depends(get_audit_service),
    principal: Principal = Depends(current_principal),
    x_request_id: Optional[str] = Header(default=None, alias="x-request-id"),
):
    sa = await sa_repo.rotate_secret(sa_id)
    require(sa is not None, status.HTTP_404_NOT_FOUND, "Service account not found")
    await audit.write(
        {
            "ts": now_utc().isoformat(),
            "action": "sa.rotate_secret",
            "resource": f"iam/service-accounts/{sa_id}",
            "principal_id": principal.id,
            "request_id": get_request_id(x_request_id),
        }
    )
    return ServiceAccountCreatedOut(
        id=str(sa["id"]),
        name=sa["name"],
        client_id=sa["client_id"],
        client_secret=sa["client_secret"],  # только при ротации
        roles=list(sa.get("roles") or []),
        permissions=list(sa.get("permissions") or []),
        created_at=sa.get("created_at", now_utc()),
        expires_at=sa.get("expires_at"),
        active=bool(sa.get("active", True)),
    )


# ---- Audit logs --------------------------------------------------------------
@router.get(
    "/audit-logs",
    response_model=PageOut,
    dependencies=[Depends(permission_required("iam.audit.read"))],
)
async def query_audit_logs(
    audit: AuditService = Depends(get_audit_service),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    principal_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None, description="Начало интервала"),
    until: Optional[datetime] = Query(None, description="Конец интервала"),
):
    filters: Dict[str, Any] = {}
    if principal_id:
        filters["principal_id"] = principal_id
    if action:
        filters["action"] = action
    if resource:
        filters["resource"] = resource
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until
    items, total = await audit.query(filters=filters, page=page, page_size=page_size)
    out = [
        AuditEventOut(
            id=str(i.get("id") or uuid.UUID(int=0)),
            ts=i.get("ts") or now_utc(),
            principal_id=i.get("principal_id"),
            action=i.get("action") or "",
            resource=i.get("resource") or "",
            ip=i.get("ip"),
            user_agent=i.get("user_agent"),
            request_id=i.get("request_id"),
            metadata=i.get("metadata") or {},
        ).dict()
        for i in items
    ]
    return PageOut(items=out, meta=PageMeta(page=page, page_size=page_size, total=total))
