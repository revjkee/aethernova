# ledger-core/api/http/routers/v1/admin.py
from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, Iterable, List, Optional, Protocol, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict, field_validator

logger = logging.getLogger("ledger_core.api.admin")

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    responses={404: {"description": "Not Found"}},
)

# -----------------------------------------------------------------------------
# Контракты зависимостей (DI) — реализуются в слое сервисов и внедряются сверху
# -----------------------------------------------------------------------------

class KeyRotationService(Protocol):
    def rotate(self, *, kid_hint: Optional[str], dry_run: bool) -> Dict[str, Any]: ...

class CacheService(Protocol):
    def invalidate(self, *, prefix: str, namespace: Optional[str]) -> int: ...

class JobsService(Protocol):
    def trigger(self, *, job_id: str, args: Dict[str, Any] | None) -> Dict[str, Any]: ...
    def list_jobs(self) -> List[Dict[str, Any]]: ...

class AuditService(Protocol):
    def query(
        self,
        *,
        limit: int,
        cursor: Optional[str],
        actor_id: Optional[str],
        action: Optional[str],
        resource_type: Optional[str],
        resource_id: Optional[str],
        time_from: Optional[datetime],
        time_to: Optional[datetime],
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]: ...

class FeatureFlagsService(Protocol):
    def list_flags(self) -> Dict[str, bool]: ...
    def set_flag(self, *, name: str, enabled: bool) -> Dict[str, bool]: ...

class SessionsService(Protocol):
    def revoke(self, *, session_id: str) -> bool: ...

# -----------------------------------------------------------------------------
# Модели запросов/ответов
# -----------------------------------------------------------------------------

class PageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(50, ge=1, le=1000)
    cursor: Optional[str] = Field(None, description="Прозрачный курсор, выданный сервером")

class PageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    next_cursor: Optional[str] = None
    total: Optional[int] = Field(None, description="Опционально, если известно")

class InfoResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app: str = "ledger-core"
    env: str = Field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    version: str = Field(default_factory=lambda: os.getenv("APP_VERSION", "0.0.0"))
    git_sha: str = Field(default_factory=lambda: os.getenv("GIT_SHA", "unknown"))
    started_at: datetime
    uptime_seconds: int
    region: Optional[str] = Field(default_factory=lambda: os.getenv("REGION", None))
    node: str = Field(default_factory=lambda: os.uname().nodename if hasattr(os, "uname") else "unknown")
    features: Dict[str, bool] = Field(default_factory=dict)

class RotateKeysRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kid_hint: Optional[str] = Field(None, description="Желаемая активная метка ключа")
    dry_run: bool = False

class RotateKeysResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_kid: Optional[str] = None
    new_kid: Optional[str] = None
    rotated_at: datetime
    details: Dict[str, Any] = Field(default_factory=dict)

class CacheInvalidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prefix: str = Field(..., min_length=1, max_length=256)
    namespace: Optional[str] = Field(None, max_length=128)

class JobTriggerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(..., min_length=1)
    args: Optional[Dict[str, Any]] = None

class JobTriggerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    enqueued: bool
    execution_id: Optional[str] = None
    eta: Optional[datetime] = None
    queue: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class AuditQueryRequest(PageRequest):
    actor_id: Optional[str] = None
    action: Optional[str] = Field(None, pattern=r"^[A-Z_]+$")
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None

    @field_validator("time_to")
    @classmethod
    def _validate_range(cls, v, info):
        # Валидация по месту: если есть оба значения, to>=from
        # Само сравнение выполним в обработчике, чтобы знать оба
        return v

class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="allow")
    audit_id: str
    resource_type: str
    resource_id: str
    action: str
    actor_id: str
    occurred_at: datetime
    attributes: Dict[str, Any] = Field(default_factory=dict)

class AuditQueryResponse(PageResponse):
    items: List[AuditEntry] = Field(default_factory=list)

class FlagItem(BaseModel):
    name: str
    enabled: bool

class FlagsListResponse(BaseModel):
    flags: List[FlagItem]

class FlagSetRequest(BaseModel):
    enabled: bool

class SessionRevokeResponse(BaseModel):
    revoked: bool

# -----------------------------------------------------------------------------
# Аутентификация/авторизация и инфраструктурные зависимости
# -----------------------------------------------------------------------------

class AdminPrincipal(BaseModel):
    sub: str
    scope: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None

    def require_admin(self) -> None:
        if "admin" not in self.scope:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_scope")

# В проде замените на реальную валидацию JWT (JWKS/KMS/HSM и пр.)
def get_admin_principal(authorization: Annotated[str | None, Header(alias="Authorization")] = None) -> AdminPrincipal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_bearer")
    token = authorization.split(" ", 1)[1].strip()
    # TODO: заменить парсинг/валидацию на полноценную реализацию.
    # Допускаем псевдо‑токен "dev-admin" для локальной разработки.
    if token == "dev-admin":
        return AdminPrincipal(sub="dev", scope=["admin"])
    # Для безоп. шаблона:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")

AdminDep = Annotated[AdminPrincipal, Depends(get_admin_principal)]

# Идемпотентность: принимаем ключ и прокидываем вниз
IdemKey = Annotated[str | None, Header(alias="X-Idempotency-Key", default=None)]

# Request‑ID: если не пришёл — сгенерируем
RequestId = Annotated[str | None, Header(alias="X-Request-Id", default=None)]

# -----------------------------------------------------------------------------
# Плагины зависимостей (здесь — заглушки). В приложении переопределите Depends.
# -----------------------------------------------------------------------------

def get_key_rotation_service() -> KeyRotationService:
    class _InMem(KeyRotationService):
        _active = "v1"
        def rotate(self, *, kid_hint: Optional[str], dry_run: bool) -> Dict[str, Any]:
            new = kid_hint or f"v{int(self._active.strip('v')) + 1}"
            details = {"dry_run": dry_run, "previous": self._active, "candidate": new}
            if not dry_run:
                self._active = new
            return {"old_kid": details["previous"], "new_kid": new, "details": details}
    return _InMem()

def get_cache_service() -> CacheService:
    class _InMem(CacheService):
        def invalidate(self, *, prefix: str, namespace: Optional[str]) -> int:
            # В проде — вызов Redis/Memcached. Возвращаем "число затронутых ключей"
            return 0
    return _InMem()

def get_jobs_service() -> JobsService:
    class _InMem(JobsService):
        def trigger(self, *, job_id: str, args: Dict[str, Any] | None) -> Dict[str, Any]:
            return {"job_id": job_id, "enqueued": True, "execution_id": str(uuid.uuid4()), "queue": "default"}
        def list_jobs(self) -> List[Dict[str, Any]]:
            return [{"id": "fx-refresh"}, {"id": "clean-tmp"}, {"id": "reindex-audit"}]
    return _InMem()

def get_audit_service() -> AuditService:
    class _InMem(AuditService):
        def query(self, **kwargs) -> Tuple[List[Dict[str, Any]], Optional[str]]:
            items = []
            now = datetime.now(timezone.utc)
            for i in range(3):
                items.append({
                    "audit_id": str(uuid.uuid4()),
                    "resource_type": "ledger.Transaction",
                    "resource_id": f"tx-{i}",
                    "action": "READ",
                    "actor_id": "dev",
                    "occurred_at": now,
                    "attributes": {"env": "dev"},
                })
            return items, None
    return _InMem()

def get_flags_service() -> FeatureFlagsService:
    class _InMem(FeatureFlagsService):
        _flags: Dict[str, bool] = {"bulk_import": True, "async_exports": True, "double_entry_strict": True}
        def list_flags(self) -> Dict[str, bool]: return dict(self._flags)
        def set_flag(self, *, name: str, enabled: bool) -> Dict[str, bool]:
            self._flags[name] = enabled
            return dict(self._flags)
    return _InMem()

def get_sessions_service() -> SessionsService:
    class _InMem(SessionsService):
        def revoke(self, *, session_id: str) -> bool: return True
    return _InMem()

KeyRotationDep = Annotated[KeyRotationService, Depends(get_key_rotation_service)]
CacheDep = Annotated[CacheService, Depends(get_cache_service)]
JobsDep = Annotated[JobsService, Depends(get_jobs_service)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]
FlagsDep = Annotated[FeatureFlagsService, Depends(get_flags_service)]
SessionsDep = Annotated[SessionsService, Depends(get_sessions_service)]

# -----------------------------------------------------------------------------
# Вспомогательные утилиты
# -----------------------------------------------------------------------------

START_TS = time.time()

def _ensure_request_id(resp: Response, incoming: Optional[str]) -> str:
    rid = incoming or str(uuid.uuid4())
    resp.headers["X-Request-Id"] = rid
    return rid

def _set_cache_control_no_store(resp: Response) -> None:
    resp.headers["Cache-Control"] = "no-store"

def _idempotency_guard(idem_key: Optional[str]) -> None:
    # Здесь может быть lookup в Redis. Сейчас — только валидация формата/длины.
    if idem_key is not None and (len(idem_key) < 8 or len(idem_key) > 128):
        raise HTTPException(status_code=400, detail="invalid idempotency key")

# -----------------------------------------------------------------------------
# Эндпоинты
# -----------------------------------------------------------------------------

@router.get("/info", response_model=InfoResponse, status_code=200)
def get_info(
    response: Response,
    principal: AdminDep,
    flags: FlagsDep,
    request_id: RequestId = None,
):
    principal.require_admin()
    _set_cache_control_no_store(response)
    rid = _ensure_request_id(response, request_id)
    uptime = int(time.time() - START_TS)
    body = InfoResponse(
        started_at=datetime.fromtimestamp(START_TS, tz=timezone.utc),
        uptime_seconds=uptime,
        features=flags.list_flags(),
    )
    logger.debug("admin.info", extra={"request_id": rid, "uptime": uptime})
    return body

@router.post(
    "/keys/rotate",
    response_model=RotateKeysResponse,
    status_code=status.HTTP_200_OK,
)
def rotate_keys(
    payload: RotateKeysRequest,
    response: Response,
    principal: AdminDep,
    svc: KeyRotationDep,
    idem_key: IdemKey = None,
    request_id: RequestId = None,
):
    principal.require_admin()
    _idempotency_guard(idem_key)
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)

    try:
        result = svc.rotate(kid_hint=payload.kid_hint, dry_run=payload.dry_run)
        return RotateKeysResponse(
            old_kid=result.get("old_kid"),
            new_kid=result.get("new_kid"),
            rotated_at=datetime.now(timezone.utc),
            details=result.get("details") or {},
        )
    except Exception as e:
        logger.exception("key_rotation_failed")
        raise HTTPException(status_code=500, detail="key_rotation_failed") from e

@router.post(
    "/cache/invalidate",
    status_code=status.HTTP_200_OK,
)
def cache_invalidate(
    payload: CacheInvalidateRequest,
    response: Response,
    principal: AdminDep,
    svc: CacheDep,
    idem_key: IdemKey = None,
    request_id: RequestId = None,
):
    principal.require_admin()
    _idempotency_guard(idem_key)
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)

    affected = svc.invalidate(prefix=payload.prefix, namespace=payload.namespace)
    return {"affected": affected}

@router.get("/jobs", status_code=200)
def list_jobs(
    response: Response,
    principal: AdminDep,
    svc: JobsDep,
    request_id: RequestId = None,
):
    principal.require_admin()
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)
    return {"items": svc.list_jobs()}

@router.post("/jobs/trigger", response_model=JobTriggerResponse, status_code=202)
def trigger_job(
    payload: JobTriggerRequest,
    response: Response,
    principal: AdminDep,
    svc: JobsDep,
    idem_key: IdemKey = None,
    request_id: RequestId = None,
):
    principal.require_admin()
    _idempotency_guard(idem_key)
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)

    if not payload.job_id:
        raise HTTPException(status_code=400, detail="job_id_required")
    res = svc.trigger(job_id=payload.job_id, args=payload.args)
    return JobTriggerResponse(
        job_id=res.get("job_id", payload.job_id),
        enqueued=bool(res.get("enqueued", True)),
        execution_id=res.get("execution_id"),
        eta=res.get("eta"),
        queue=res.get("queue"),
        details={k: v for k, v in res.items() if k not in {"job_id", "enqueued", "execution_id", "eta", "queue"}},
    )

@router.post("/audit/query", response_model=AuditQueryResponse, status_code=200)
def audit_query(
    payload: AuditQueryRequest,
    response: Response,
    principal: AdminDep,
    svc: AuditDep,
    request_id: RequestId = None,
):
    principal.require_admin()
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)

    if payload.time_from and payload.time_to and payload.time_to < payload.time_from:
        raise HTTPException(status_code=400, detail="invalid_time_range")

    items, next_cursor = svc.query(
        limit=payload.limit,
        cursor=payload.cursor,
        actor_id=payload.actor_id,
        action=payload.action,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        time_from=payload.time_from,
        time_to=payload.time_to,
    )
    # Нормализация к контракту
    entries = [AuditEntry(**it) for it in items]
    return AuditQueryResponse(items=entries, next_cursor=next_cursor)

@router.get("/flags", response_model=FlagsListResponse, status_code=200)
def flags_list(
    response: Response,
    principal: AdminDep,
    svc: FlagsDep,
    request_id: RequestId = None,
):
    principal.require_admin()
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)
    flags = svc.list_flags()
    return FlagsListResponse(flags=[FlagItem(name=k, enabled=v) for k, v in sorted(flags.items())])

@router.patch("/flags/{flag}", response_model=FlagsListResponse, status_code=200)
def flags_set(
    flag: str,
    body: FlagSetRequest,
    response: Response,
    principal: AdminDep,
    svc: FlagsDep,
    idem_key: IdemKey = None,
    request_id: RequestId = None,
):
    principal.require_admin()
    _idempotency_guard(idem_key)
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)
    flags = svc.set_flag(name=flag, enabled=body.enabled)
    return FlagsListResponse(flags=[FlagItem(name=k, enabled=v) for k, v in sorted(flags.items())])

@router.delete("/sessions/{session_id}", response_model=SessionRevokeResponse, status_code=200)
def revoke_session(
    session_id: str,
    response: Response,
    principal: AdminDep,
    svc: SessionsDep,
    idem_key: IdemKey = None,
    request_id: RequestId = None,
):
    principal.require_admin()
    _idempotency_guard(idem_key)
    _set_cache_control_no_store(response)
    _ensure_request_id(response, request_id)
    ok = svc.revoke(session_id=session_id)
    if not ok:
        # 200 с revoked=false, чтобы не раскрывать существование сессии
        return SessionRevokeResponse(revoked=False)
    return SessionRevokeResponse(revoked=True)

# -----------------------------------------------------------------------------
# Глобальные обработчики ошибок для единого формата (опционально)
# -----------------------------------------------------------------------------

@router.exception_handler(HTTPException)
async def _http_exc_handler(request: Request, exc: HTTPException):
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    body = {
        "error": {
            "code": exc.status_code,
            "message": exc.detail,
        }
    }
    resp = JSONResponse(status_code=exc.status_code, content=body)
    resp.headers["X-Request-Id"] = rid
    resp.headers["Cache-Control"] = "no-store"
    return resp

@router.exception_handler(Exception)
async def _unhandled_exc_handler(request: Request, exc: Exception):
    logger.exception("unhandled_admin_error")
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    body = {
        "error": {
            "code": 500,
            "message": "internal_error",
        }
    }
    resp = JSONResponse(status_code=500, content=body)
    resp.headers["X-Request-Id"] = rid
    resp.headers["Cache-Control"] = "no-store"
    return resp
