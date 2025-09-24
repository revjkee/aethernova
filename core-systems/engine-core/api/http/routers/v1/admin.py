# -*- coding: utf-8 -*-
"""
Admin Router (v1)
Промышленный админ-роутер FastAPI с:
- Асинхронным стилем (совместим с async SQLAlchemy — в этом файле имитируется абстракцией AsyncDB)
- RBAC/Scopes (RequireRole/RequireScope), проверка JWT-заглушкой
- Идемпотентность на основе заголовка X-Idempotency-Key
- Корреляция запросов X-Request-ID (создание при отсутствии)
- Пагинация, сортировка, фильтрация для списков
- Стандартизованный формат ошибок и ответов
- Аудит-логирование админских действий
- Минимальный rate-limit dependency (токен-бакет in-memory, опционально)
- Безопасные заголовки в ответах

Заметки:
1) Все внешние интеграции (БД, кэши, очереди) абстрагированы внутри файла для изоляции.
2) Для боевого окружения замените заглушки на реальные реализации (JWT verify, AsyncDB, AuditSink).
3) Стиль схем — Pydantic v1 (BaseModel/Field) для максимальной совместимости.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------

logger = logging.getLogger("engine_core.admin_router")
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Безопасные константы/заголовки
# ---------------------------------------------------------------------------

X_REQ_ID = "X-Request-ID"
X_IDEMPOTENCY_KEY = "X-Idempotency-Key"
X_RATE_LIMIT = "X-RateLimit-Limit"
X_RATE_REMAIN = "X-RateLimit-Remaining"
X_RATE_RESET = "X-RateLimit-Reset"


# ---------------------------------------------------------------------------
# Заглушка JWT/Пользователь/RBAC
# ---------------------------------------------------------------------------

class User(BaseModel):
    id: uuid.UUID
    email: str
    is_active: bool = True
    roles: List[str] = Field(default_factory=list)  # например: ["admin", "staff"]
    scopes: List[str] = Field(default_factory=list)  # например: ["admin:read", "admin:write"]


async def verify_jwt_and_get_user(authorization: Optional[str]) -> User:
    """
    Заглушка проверки JWT. В проде заменить на реальную верификацию (kid/issuer/aud/exp).
    Для демонстрации: если заголовок отсутствует — 401.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Bearer token")
    # Декод токена -> payload -> поиск пользователя
    # Здесь — всегда админ для примера:
    return User(
        id=uuid.uuid4(),
        email="admin@example.org",
        roles=["admin"],
        scopes=["admin:read", "admin:write"],
    )


class RequireRole:
    def __init__(self, *roles: str):
        self.roles = set(roles)

    async def __call__(self, user: User = Depends(lambda authorization=Header(None, alias="Authorization"): verify_jwt_and_get_user(authorization))):
        if not set(user.roles).intersection(self.roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user


class RequireScope:
    def __init__(self, *scopes: str):
        self.scopes = set(scopes)

    async def __call__(self, user: User = Depends(lambda authorization=Header(None, alias="Authorization"): verify_jwt_and_get_user(authorization))):
        if not set(user.scopes).issuperset(self.scopes):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing required scope")
        return user


# ---------------------------------------------------------------------------
# Идемпотентность (in-memory, TTL)
# ---------------------------------------------------------------------------

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl = ttl_seconds
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._order = deque()  # для GC

    def _gc(self):
        now = time.time()
        while self._order:
            key, ts = self._order[0]
            if now - ts > self.ttl:
                self._order.popleft()
                self._store.pop(key, None)
            else:
                break

    def get_or_set(self, key: str, value_factory) -> Dict[str, Any]:
        self._gc()
        if key in self._store:
            return self._store[key][1]
        value = value_factory()
        ts = time.time()
        self._store[key] = (ts, value)
        self._order.append((key, ts))
        return value


IDEMPOTENCY = IdempotencyStore(ttl_seconds=900)


async def idempotency_guard(idempotency_key: Optional[str] = Header(None, alias=X_IDEMPOTENCY_KEY)) -> Optional[Dict[str, Any]]:
    if not idempotency_key:
        return None
    # Вернем ранее вычисленный результат, если ключ был использован
    container = IDEMPOTENCY.get_or_set(idempotency_key, value_factory=lambda: {})
    return container


# ---------------------------------------------------------------------------
# In-memory Rate Limit (на роут/ключ)
# ---------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate: int, per_seconds: int):
        self.capacity = rate
        self.tokens = rate
        self.per_seconds = per_seconds
        self.updated_at = time.time()

    def consume(self, amount: int = 1) -> Tuple[bool, int, int]:
        now = time.time()
        # пополняем
        delta = now - self.updated_at
        refill = int(delta / self.per_seconds * self.capacity)
        if refill > 0:
            self.tokens = min(self.capacity, self.tokens + refill)
            self.updated_at = now
        if self.tokens >= amount:
            self.tokens -= amount
            reset_in = self.per_seconds - int((now - self.updated_at))
            return True, self.tokens, max(0, reset_in)
        reset_in = self.per_seconds - int((now - self.updated_at))
        return False, self.tokens, max(0, reset_in)


RATE_BUCKETS: Dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(rate=30, per_seconds=60))


async def rate_limit_dependency(request: Request, response: Response):
    # Ключ — путь + крашер по пользователю (IP или user_id). Здесь — по пути.
    key = f"{request.url.path}"
    ok, remaining, reset = RATE_BUCKETS[key].consume(1)
    response.headers[X_RATE_LIMIT] = str(RATE_BUCKETS[key].capacity)
    response.headers[X_RATE_REMAIN] = str(max(0, remaining))
    response.headers[X_RATE_RESET] = str(reset)
    if not ok:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


# ---------------------------------------------------------------------------
# Стандартизованный ответ/ошибки
# ---------------------------------------------------------------------------

class ErrorItem(BaseModel):
    code: str
    message: str
    field: Optional[str] = None


class ApiError(BaseModel):
    request_id: str
    errors: List[ErrorItem]


class ApiMeta(BaseModel):
    request_id: str
    timestamp: datetime
    next_page: Optional[str] = None


class ApiResponse(BaseModel):
    meta: ApiMeta
    data: Any


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def make_response(data: Any, request_id: str, next_page: Optional[str] = None) -> ApiResponse:
    return ApiResponse(
        meta=ApiMeta(request_id=request_id, timestamp=now_utc(), next_page=next_page),
        data=data,
    )


def make_error(request_id: str, code: str, message: str, field: Optional[str] = None) -> JSONResponse:
    payload = ApiError(request_id=request_id, errors=[ErrorItem(code=code, message=message, field=field)]).dict()
    return JSONResponse(status_code=400, content=payload)


# ---------------------------------------------------------------------------
# Абстракции БД/Аудита/Кэша (заглушки)
# ---------------------------------------------------------------------------

class AsyncDB:
    """Простейшая имитация асинхронной БД."""
    def __init__(self):
        self.users: Dict[uuid.UUID, Dict[str, Any]] = {}
        self.audit: List[Dict[str, Any]] = []

    async def list_users(self, q: Optional[str], role: Optional[str], is_active: Optional[bool],
                         sort: Literal["created_at", "email"] = "created_at",
                         order: Literal["asc", "desc"] = "desc",
                         limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        users = list(self.users.values())
        if q:
            users = [u for u in users if q.lower() in u["email"].lower()]
        if role:
            users = [u for u in users if role in u["roles"]]
        if is_active is not None:
            users = [u for u in users if u["is_active"] == is_active]
        reverse = order == "desc"
        users.sort(key=lambda u: u.get(sort, ""), reverse=reverse)
        total = len(users)
        return users[offset: offset + limit], total

    async def set_user_active(self, user_id: uuid.UUID, is_active: bool) -> bool:
        if user_id not in self.users:
            return False
        self.users[user_id]["is_active"] = is_active
        return True

    async def promote_admin(self, user_id: uuid.UUID) -> bool:
        if user_id not in self.users:
            return False
        roles = set(self.users[user_id]["roles"])
        roles.add("admin")
        self.users[user_id]["roles"] = list(roles)
        return True

    async def demote_admin(self, user_id: uuid.UUID) -> bool:
        if user_id not in self.users:
            return False
        roles = set(self.users[user_id]["roles"])
        if "admin" in roles:
            roles.remove("admin")
        self.users[user_id]["roles"] = list(roles)
        return True

    async def write_audit(self, record: Dict[str, Any]):
        self.audit.append(record)

    async def list_audit(self, action: Optional[str], actor: Optional[str], since: Optional[datetime],
                         limit: int, offset: int) -> Tuple[List[Dict[str, Any]], int]:
        items = self.audit
        if action:
            items = [a for a in items if a.get("action") == action]
        if actor:
            items = [a for a in items if a.get("actor_email") == actor]
        if since:
            items = [a for a in items if a.get("ts") and a["ts"] >= since]
        total = len(items)
        items.sort(key=lambda a: a.get("ts", now_utc()), reverse=True)
        return items[offset: offset + limit], total


DB = AsyncDB()


class AuditSink:
    @staticmethod
    async def emit(action: str, actor: User, request_id: str, details: Dict[str, Any]):
        await DB.write_audit({
            "id": str(uuid.uuid4()),
            "ts": now_utc(),
            "action": action,
            "actor_id": str(actor.id),
            "actor_email": actor.email,
            "request_id": request_id,
            "details": details,
        })


# Предзаполнение пользователей (демо)
async def _seed_users():
    if DB.users:
        return
    for i in range(1, 6):
        uid = uuid.uuid4()
        DB.users[uid] = {
            "id": str(uid),
            "email": f"user{i}@example.org",
            "is_active": True,
            "roles": ["staff"] if i % 2 == 0 else [],
            "created_at": f"2025-08-0{i}T10:00:00Z",
        }

asyncio.get_event_loop().run_until_complete(_seed_users())


# ---------------------------------------------------------------------------
# Схемы
# ---------------------------------------------------------------------------

class HealthStatus(BaseModel):
    status: Literal["ok", "degraded", "fail"]
    uptime_seconds: float
    version: str = "v1"
    time: datetime


class AdminUserOut(BaseModel):
    id: str
    email: str
    is_active: bool
    roles: List[str]
    created_at: str


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class UsersPage(BaseModel):
    meta: PageMeta
    items: List[AdminUserOut]


class LockAction(BaseModel):
    reason: Optional[str] = Field(None, max_length=256)


class FeatureFlagSet(BaseModel):
    key: str = Field(..., regex=r"^[a-z0-9_.-]{1,64}$")
    enabled: bool
    note: Optional[str] = Field(None, max_length=256)


class JobRunRequest(BaseModel):
    name: str = Field(..., regex=r"^[a-z0-9_.:-]{1,64}$")
    args: Dict[str, Any] = Field(default_factory=dict)

    @validator("args")
    def _size_guard(cls, v):
        # Ограничим размер полезной нагрузки (защита от злоупотреблений)
        if len(str(v)) > 4096:
            raise ValueError("args too large")
        return v


class JobRunResult(BaseModel):
    accepted: bool
    job_id: str
    eta_seconds: int


class CachePurgeRequest(BaseModel):
    scope: Literal["all", "auth", "catalog", "feature_flags"] = "all"


class AuditLogItem(BaseModel):
    id: str
    ts: datetime
    action: str
    actor_email: str
    request_id: str
    details: Dict[str, Any]


class AuditPage(BaseModel):
    meta: PageMeta
    items: List[AuditLogItem]


class OkResponse(BaseModel):
    ok: bool = True


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/http/routers/v1/admin", tags=["admin"])


# Общий препроцессинг: корреляция и безопасные заголовки
async def _prepare_response_headers(request: Request, response: Response) -> str:
    req_id = request.headers.get(X_REQ_ID) or str(uuid.uuid4())
    response.headers[X_REQ_ID] = req_id
    # Набор безопасных заголовков
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return req_id


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireRole("admin"))],
    summary="Проверка здоровья админ‑сервиса",
)
async def health(request: Request, response: Response):
    request_id = await _prepare_response_headers(request, response)
    uptime = time.process_time()  # демонстрационная метрика
    data = HealthStatus(status="ok", uptime_seconds=uptime, time=now_utc())
    return make_response(data=data.dict(), request_id=request_id)


@router.get(
    "/users",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:read"))],
    summary="Список пользователей (пагинация/фильтры/сортировка)",
)
async def list_users(
    request: Request,
    response: Response,
    q: Optional[str] = Query(None, max_length=128, description="Поиск по email"),
    role: Optional[str] = Query(None, max_length=32),
    is_active: Optional[bool] = Query(None),
    sort: Literal["created_at", "email"] = Query("created_at"),
    order: Literal["asc", "desc"] = Query("desc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _user: User = Depends(RequireScope("admin:read")),
):
    request_id = await _prepare_response_headers(request, response)
    items, total = await DB.list_users(q=q, role=role, is_active=is_active, sort=sort, order=order, limit=limit, offset=offset)

    page = UsersPage(
        meta=PageMeta(total=total, limit=limit, offset=offset),
        items=[AdminUserOut(**u) for u in items],
    )
    next_page = None
    if offset + limit < total:
        next_page = f"/api/http/routers/v1/admin/users?limit={limit}&offset={offset+limit}"

    return make_response(data=page.dict(), request_id=request_id, next_page=next_page)


@router.post(
    "/users/{user_id}/lock",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Блокировка пользователя",
)
async def lock_user(
    user_id: uuid.UUID,
    request: Request,
    response: Response,
    payload: LockAction,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)

    # Идемпотентность: если результат уже вычислялся, вернем его
    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "lock_user"})
        return make_response(idem["result"], request_id=request_id)

    ok = await DB.set_user_active(user_id, is_active=False)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    await AuditSink.emit("user.lock", actor=actor, request_id=request_id, details={"user_id": str(user_id), "reason": payload.reason})

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.post(
    "/users/{user_id}/unlock",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Разблокировка пользователя",
)
async def unlock_user(
    user_id: uuid.UUID,
    request: Request,
    response: Response,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)

    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "unlock_user"})
        return make_response(idem["result"], request_id=request_id)

    ok = await DB.set_user_active(user_id, is_active=True)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    await AuditSink.emit("user.unlock", actor=actor, request_id=request_id, details={"user_id": str(user_id)})

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.post(
    "/admins/{user_id}",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Повышение пользователя до администратора",
)
async def promote_admin(
    user_id: uuid.UUID,
    request: Request,
    response: Response,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)

    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "promote_admin"})
        return make_response(idem["result"], request_id=request_id)

    ok = await DB.promote_admin(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    await AuditSink.emit("admin.promote", actor=actor, request_id=request_id, details={"user_id": str(user_id)})

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.delete(
    "/admins/{user_id}",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Снятие прав администратора",
)
async def demote_admin(
    user_id: uuid.UUID,
    request: Request,
    response: Response,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)

    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "demote_admin"})
        return make_response(idem["result"], request_id=request_id)

    ok = await DB.demote_admin(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")

    await AuditSink.emit("admin.demote", actor=actor, request_id=request_id, details={"user_id": str(user_id)})

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.get(
    "/audit-logs",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:read"))],
    summary="Просмотр аудито‑логов",
)
async def list_audit_logs(
    request: Request,
    response: Response,
    action: Optional[str] = Query(None, max_length=64),
    actor: Optional[str] = Query(None, max_length=128),
    since: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    request_id = await _prepare_response_headers(request, response)
    items, total = await DB.list_audit(action=action, actor=actor, since=since, limit=limit, offset=offset)
    page = AuditPage(
        meta=PageMeta(total=total, limit=limit, offset=offset),
        items=[AuditLogItem(**x) for x in items],
    )
    next_page = None
    if offset + limit < total:
        next_page = f"/api/http/routers/v1/admin/audit-logs?limit={limit}&offset={offset+limit}"
    return make_response(data=page.dict(), request_id=request_id, next_page=next_page)


@router.post(
    "/cache/purge",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Очистка кэша по области",
)
async def cache_purge(
    request: Request,
    response: Response,
    payload: CachePurgeRequest,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
    background: BackgroundTasks = None,
):
    request_id = await _prepare_response_headers(request, response)

    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "cache_purge"})
        return make_response(idem["result"], request_id=request_id)

    async def _purge():
        logger.info("Cache purge started", extra={"scope": payload.scope, "request_id": request_id})
        await asyncio.sleep(0.05)  # имитируем время очистки
        logger.info("Cache purge completed", extra={"scope": payload.scope, "request_id": request_id})

    if background:
        background.add_task(asyncio.create_task, _purge())
    else:
        await _purge()

    await AuditSink.emit("cache.purge", actor=actor, request_id=request_id, details={"scope": payload.scope})

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.post(
    "/feature-flags/set",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Установка фичефлага",
)
async def set_feature_flag(
    request: Request,
    response: Response,
    payload: FeatureFlagSet,
    idem: Optional[Dict[str, Any]] = Depends(idempotency_guard),
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)
    if idem is not None and "result" in idem:
        logger.info("Idempotent replay", extra={"request_id": request_id, "endpoint": "set_feature_flag"})
        return make_response(idem["result"], request_id=request_id)

    # В реальности — запись в фиче‑флаг‑хранилище.
    logger.info("Feature flag set", extra={"key": payload.key, "enabled": payload.enabled, "request_id": request_id})
    await AuditSink.emit("feature.flag.set", actor=actor, request_id=request_id, details=payload.dict())

    data = OkResponse().dict()
    if idem is not None:
        idem["result"] = data
    return make_response(data=data, request_id=request_id)


@router.post(
    "/jobs/run",
    response_model=ApiResponse,
    dependencies=[Depends(rate_limit_dependency), Depends(RequireScope("admin:write"))],
    summary="Запуск фоновой административной задачи",
)
async def run_job(
    request: Request,
    response: Response,
    payload: JobRunRequest,
    actor: User = Depends(RequireScope("admin:write")),
):
    request_id = await _prepare_response_headers(request, response)

    job_id = str(uuid.uuid4())

    async def _run():
        logger.info("Job started", extra={"name": payload.name, "job_id": job_id, "request_id": request_id})
        await asyncio.sleep(0.1)  # имитация длительной работы
        logger.info("Job finished", extra={"name": payload.name, "job_id": job_id, "request_id": request_id})

    # Планирование без блокировки запроса
    asyncio.create_task(_run())
    await AuditSink.emit("job.run", actor=actor, request_id=request_id, details={"job_id": job_id, "name": payload.name})

    result = JobRunResult(accepted=True, job_id=job_id, eta_seconds=1)
    return make_response(data=result.dict(), request_id=request_id)


# ---------------------------------------------------------------------------
# Глобальный обработчик ошибок (локально для роутера)
# ---------------------------------------------------------------------------

@router.middleware("http")
async def admin_router_middleware(request: Request, call_next):
    # Проставим X-Request-ID при входе и поймаем неожиданные ошибки
    req_id = request.headers.get(X_REQ_ID) or str(uuid.uuid4())
    try:
        response: Response = await call_next(request)
        # Если downstream не поставил — поставим здесь
        if X_REQ_ID not in response.headers:
            response.headers[X_REQ_ID] = req_id
        return response
    except HTTPException as he:
        logger.warning("HTTPException", extra={"request_id": req_id, "path": str(request.url), "detail": he.detail})
        return JSONResponse(
            status_code=he.status_code,
            content=ApiError(request_id=req_id, errors=[ErrorItem(code="http_error", message=str(he.detail))]).dict(),
        )
    except Exception as e:
        logger.exception("Unhandled exception", extra={"request_id": req_id, "path": str(request.url)})
        return JSONResponse(
            status_code=500,
            content=ApiError(request_id=req_id, errors=[ErrorItem(code="internal_error", message="Internal Server Error")]).dict(),
        )
