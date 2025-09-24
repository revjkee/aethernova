# File: veilmind-core/api/http/routers/v1/dp.py
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

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
from starlette.concurrency import run_in_threadpool

# Pydantic v1/v2 компат
try:  # Pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, field_validator
    PydModelConfigKw = {"model_config": ConfigDict(extra="forbid", frozen=False)}
    def field_validator_v2(*args, **kwargs):  # shim
        return field_validator(*args, **kwargs)
except Exception:  # Pydantic v1
    from pydantic import BaseModel, Field, validator as field_validator
    PydModelConfigKw = {"extra": "forbid"}
    def field_validator_v2(*args, **kwargs):  # shim to v1
        return field_validator(*args, **kwargs)

# Опциональные метрики (не критично в рантайме)
try:
    from prometheus_client import Counter, Histogram
except Exception:  # если недоступно — заглушки
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_: Any, **__: Any) -> None: ...
        def observe(self, *_: Any, **__: Any) -> None: ...
    Counter = Histogram = lambda *_, **__: _Noop()  # type: ignore

# -----------------------------------------------------------------------------
# Константы и настройки
# -----------------------------------------------------------------------------

ROUTER_PREFIX = "/v1/dp"
HMAC_ENV_KEY = os.getenv("DP_API_HMAC_KEY", "")
ALLOWED_IDEMPOTENCY_TTL_SEC = int(os.getenv("DP_API_IDEMPOTENCY_TTL_SEC", "86400"))
DEFAULT_RATE_LIMIT_RPS = float(os.getenv("DP_API_RATE_LIMIT_RPS", "50"))  # per-tenant
MAX_REQUEST_BODY_BYTES = int(os.getenv("DP_API_MAX_BODY", "1048576"))  # 1 MiB

# -----------------------------------------------------------------------------
# Метрики
# -----------------------------------------------------------------------------
API_REQS = Counter(
    "dp_api_requests_total",
    "Count of DP API requests",
    ["endpoint", "method", "status", "tenant"],
)
API_LATENCY = Histogram(
    "dp_api_request_latency_seconds",
    "Latency of DP API requests",
    ["endpoint", "method", "tenant"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def make_hmac(payload: Dict[str, Any]) -> str:
    if not HMAC_ENV_KEY:
        return ""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(HMAC_ENV_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return mac

def redact(s: Optional[str], max_len: int = 256) -> Optional[str]:
    if s is None:
        return None
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s

SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-.:]{1,127}$")

# -----------------------------------------------------------------------------
# Аутентификация и авторизация
# -----------------------------------------------------------------------------

@dataclass
class Actor:
    subject: str
    tenant_id: Optional[str]
    scopes: List[str]
    mTLS: bool = False

class AuthError(HTTPException):
    def __init__(self, detail: str, code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(status_code=code, detail=detail, headers={"WWW-Authenticate": "Bearer"})

async def get_current_actor(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    tenant: Optional[str] = Header(None, alias="X-Tenant-ID"),
    client_cert: Optional[str] = Header(None, alias="X-Client-Cert"),
) -> Actor:
    """
    Простая заглушка авторизации:
    - Bearer <token>, где токен не пустой — допуск.
    - mTLS допускается при наличии X-Client-Cert.
    В проде замените на интеграцию с вашим провайдером (OIDC/JWT/mTLS).
    """
    if client_cert:
        # Минимальная проверка длины
        if len(client_cert) < 20:
            raise AuthError("Invalid client certificate header")
        return Actor(subject="mtls-client", tenant_id=tenant, scopes=["dp:read", "dp:write"], mTLS=True)

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise AuthError("Empty token")
        # Здесь возможно декодирование JWT и проверка scope/tenant
        return Actor(subject="bearer-user", tenant_id=tenant, scopes=["dp:read", "dp:write"])

    raise AuthError("Missing or invalid credentials")

# -----------------------------------------------------------------------------
# Идемпотентность и лимитирование
# -----------------------------------------------------------------------------

class IdempotencyStore:
    """
    Ин-мемори хранилище идемпотентности для примера.
    В прод — используйте Redis/PostgreSQL с уникальным ключом и TTL.
    """
    def __init__(self) -> None:
        self._items: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        data = self._items.get(key)
        if not data:
            return None
        exp, payload = data
        if now > exp:
            self._items.pop(key, None)
            return None
        return payload

    def set(self, key: str, response_payload: Dict[str, Any], ttl_sec: int) -> None:
        exp = time.time() + max(1, ttl_sec)
        self._items[key] = (exp, response_payload)

class TokenBucket:
    def __init__(self, rps: float, burst: Optional[float] = None) -> None:
        self.rate = float(max(0.1, rps))
        self.capacity = float(burst if burst and burst > 0 else self.rate * 2)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

class RateLimiter:
    def __init__(self, default_rps: float) -> None:
        self.default_rps = default_rps
        self.buckets: Dict[str, TokenBucket] = {}

    def check(self, key: str) -> bool:
        b = self.buckets.get(key)
        if not b:
            b = self.buckets[key] = TokenBucket(self.default_rps)
        return b.allow()

IDEMP_STORE = IdempotencyStore()
RATE_LIMITER = RateLimiter(DEFAULT_RATE_LIMIT_RPS)

# -----------------------------------------------------------------------------
# Схемы запросов/ответов
# -----------------------------------------------------------------------------

WindowName = Literal["daily", "monthly"]
RunMode = Literal["estimate", "charge"]

class MechanismUse(BaseModel):
    mechanism: str = Field(..., description="Имя механизма (конфиг)")
    repeats: int = Field(1, ge=1, le=10_000, description="Сколько раз применяется внутри шага")

class PipelineUse(BaseModel):
    pipeline: str = Field(..., description="Имя пайплайна")
    window: WindowName = Field(..., description="Окно начисления (например, daily|monthly)")
    dry_run: bool = Field(False, description="True — только оценка без списания")
    tenant: Optional[str] = Field(None, description="Перекрыть X-Tenant-ID")
    steps: Optional[List[MechanismUse]] = Field(None, description="Переопределить шаги конфигурации пайплайна")

    @field_validator_v2("pipeline")
    def _name_ok(cls, v: str) -> str:
        if not SAFE_NAME_RE.match(v):
            raise ValueError("pipeline: invalid name")
        return v

class EstimateRequest(BaseModel, **PydModelConfigKw):
    mode: RunMode = Field("estimate")
    use: PipelineUse

class ChargeRequest(BaseModel, **PydModelConfigKw):
    mode: RunMode = Field("charge")
    use: PipelineUse
    idempotency_key: Optional[str] = Field(None, description="Ключ идемпотентности (Idempotency-Key)")

class BudgetWindow(BaseModel):
    name: WindowName
    epsilon_limit: float
    delta_limit: float
    epsilon_used: float
    delta_used: float
    epsilon_remaining: float
    delta_remaining: float
    updated_at: datetime

class BudgetState(BaseModel):
    tenant: str
    windows: List[BudgetWindow]

class EstimateResponse(BaseModel):
    tenant: str
    pipeline: str
    window: WindowName
    epsilon_total_max: float
    delta_total_max: float
    allowed: bool
    dry_run: bool
    details: Dict[str, Any]
    event_id: str
    links: Dict[str, str]

class ChargeResponse(BaseModel):
    tenant: str
    pipeline: str
    window: WindowName
    epsilon_charged: float
    delta_charged: float
    balance: Dict[str, float]
    idempotent: bool
    event_id: str
    links: Dict[str, str]

class ErrorResponse(BaseModel):
    code: str
    message: str
    hint: Optional[str] = None

# -----------------------------------------------------------------------------
# Сервисный слой (абстракция)
# -----------------------------------------------------------------------------

class DPAccountantService(ABC):
    @abstractmethod
    async def list_pipelines(self) -> List[str]: ...
    @abstractmethod
    async def get_budget(self, tenant: str) -> BudgetState: ...
    @abstractmethod
    async def estimate(self, use: PipelineUse, actor: Actor) -> Tuple[float, float, Dict[str, Any]]: ...
    @abstractmethod
    async def charge(self, use: PipelineUse, actor: Actor) -> Tuple[float, float, Dict[str, Any]]: ...
    @abstractmethod
    async def get_audit(self, event_id: str, actor: Actor) -> Optional[Dict[str, Any]]: ...

class InMemoryDPAccountantService(DPAccountantService):
    """
    Демонстрационная реализация:
    - хранит бюджеты в памяти
    - эмулирует стоимость: сумма repeats * 0.05 ε и 1e-8 δ
    В проде заменить на вашу систему учета (PostgreSQL/Redis + RDP/PLD).
    """
    def __init__(self) -> None:
        self._pipelines = {"public_metrics_daily", "model_training_main"}
        self._budgets: Dict[str, Dict[WindowName, Dict[str, float]]] = {}
        self._audit: Dict[str, Dict[str, Any]] = {}

    def _ensure_tenant(self, tenant: str) -> None:
        if tenant not in self._budgets:
            self._budgets[tenant] = {
                "daily":  {"limit_e": 1.0, "limit_d": 1e-8, "used_e": 0.0, "used_d": 0.0},
                "monthly":{"limit_e": 4.0, "limit_d": 1e-6, "used_e": 0.0, "used_d": 0.0},
            }

    async def list_pipelines(self) -> List[str]:
        return sorted(self._pipelines)

    async def get_budget(self, tenant: str) -> BudgetState:
        self._ensure_tenant(tenant)
        win = self._budgets[tenant]
        windows = []
        for name in ("daily", "monthly"):
            w = win[name]  # type: ignore[index]
            windows.append(BudgetWindow(
                name=name,  # type: ignore[arg-type]
                epsilon_limit=w["limit_e"],
                delta_limit=w["limit_d"],
                epsilon_used=w["used_e"],
                delta_used=w["used_d"],
                epsilon_remaining=max(0.0, w["limit_e"] - w["used_e"]),
                delta_remaining=max(0.0, w["limit_d"] - w["used_d"]),
                updated_at=utc_now(),
            ))
        return BudgetState(tenant=tenant, windows=windows)

    def _estimate_cost(self, use: PipelineUse) -> Tuple[float, float, Dict[str, Any]]:
        steps = use.steps or [MechanismUse(mechanism="default", repeats=1)]
        eps = sum(max(1, s.repeats) * 0.05 for s in steps)
        delt = sum(max(1, s.repeats) * 1e-8 for s in steps)
        return float(eps), float(delt), {"steps": [s.dict() for s in steps]}

    async def estimate(self, use: PipelineUse, actor: Actor) -> Tuple[float, float, Dict[str, Any]]:
        return self._estimate_cost(use)

    async def charge(self, use: PipelineUse, actor: Actor) -> Tuple[float, float, Dict[str, Any]]:
        tenant = use.tenant or actor.tenant_id or "default"
        self._ensure_tenant(tenant)
        eps, delt, details = self._estimate_cost(use)
        w = self._budgets[tenant][use.window]  # type: ignore[index]
        if w["used_e"] + eps > w["limit_e"] or w["used_d"] + delt > w["limit_d"]:
            raise HTTPException(status_code=409, detail="Budget exceeded")
        w["used_e"] += eps
        w["used_d"] += delt
        return eps, delt, details

    async def get_audit(self, event_id: str, actor: Actor) -> Optional[Dict[str, Any]]:
        return self._audit.get(event_id)

SERVICE: DPAccountantService = InMemoryDPAccountantService()

def get_service() -> DPAccountantService:
    return SERVICE

# -----------------------------------------------------------------------------
# Роутер
# -----------------------------------------------------------------------------

router = APIRouter(prefix=ROUTER_PREFIX, tags=["dp"])

# ----------------------- Мидлвары уровня роутера -----------------------------

@router.middleware("http")
async def _body_limit(request: Request, call_next):
    # Ограничение размера тела запроса
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=ErrorResponse(code="payload_too_large", message="Request entity too large").dict(),
        )
    start = time.perf_counter()
    try:
        resp: Response = await call_next(request)
        return resp
    finally:
        elapsed = time.perf_counter() - start
        path = request.url.path.replace(ROUTER_PREFIX, "").strip("/") or "root"
        tenant = request.headers.get("X-Tenant-ID", "") or "none"
        try:
            API_LATENCY.labels(endpoint=path, method=request.method, tenant=tenant).observe(elapsed)
        except Exception:
            pass

# ----------------------------- Эндпоинты -------------------------------------

@router.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "time": utc_now().isoformat()}

@router.get("/pipelines")
async def list_pipelines(
    actor: Actor = Depends(get_current_actor),
    svc: DPAccountantService = Depends(get_service),
):
    items = await svc.list_pipelines()
    payload = {"items": items, "count": len(items)}
    mac = make_hmac(payload)
    resp = JSONResponse(content=payload)
    if mac:
        resp.headers["X-Integrity"] = mac
    API_REQS.labels(endpoint="pipelines", method="GET", status="200", tenant=str(actor.tenant_id or "none")).inc()
    return resp

@router.get("/tenants/{tenant}/budget", response_model=BudgetState, responses={
    404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}
})
async def get_budget(
    tenant: str,
    actor: Actor = Depends(get_current_actor),
    svc: DPAccountantService = Depends(get_service),
):
    if not SAFE_NAME_RE.match(tenant):
        raise HTTPException(status_code=400, detail="Invalid tenant id")
    # Авторизация: только свой тенант, если не указаны расширенные права
    if actor.tenant_id and tenant != actor.tenant_id and "dp:admin" not in actor.scopes:
        raise HTTPException(status_code=403, detail="Forbidden for tenant")
    state = await svc.get_budget(tenant)
    payload = json.loads(state.json() if hasattr(state, "json") else json.dumps(state))  # robust
    mac = make_hmac(payload)
    resp = JSONResponse(content=payload)
    if mac:
        resp.headers["X-Integrity"] = mac
    API_REQS.labels(endpoint="budget", method="GET", status="200", tenant=tenant).inc()
    return resp

@router.post("/estimate", response_model=EstimateResponse, responses={
    400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}
})
async def estimate_budget(
    req: EstimateRequest,
    actor: Actor = Depends(get_current_actor),
    svc: DPAccountantService = Depends(get_service),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    tenant = req.use.tenant or actor.tenant_id or "default"
    # Rate limit per-tenant
    if not RATE_LIMITER.check(tenant):
        API_REQS.labels(endpoint="estimate", method="POST", status="429", tenant=tenant).inc()
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if idempotency_key and not SAFE_NAME_RE.match(idempotency_key):
        raise HTTPException(status_code=400, detail="Invalid Idempotency-Key")

    eps, delt, details = await svc.estimate(req.use, actor)
    allowed = True  # Оценка не изменяет состояние
    eid = f"dp::{tenant}::{req.use.pipeline}::estimate::{uuid.uuid4()}"
    payload = EstimateResponse(
        tenant=tenant,
        pipeline=req.use.pipeline,
        window=req.use.window,
        epsilon_total_max=eps,
        delta_total_max=delt,
        allowed=allowed,
        dry_run=True,
        details=details,
        event_id=eid,
        links={
            "self": f"{ROUTER_PREFIX}/estimate",
            "budget": f"{ROUTER_PREFIX}/tenants/{tenant}/budget",
        },
    ).dict()
    mac = make_hmac(payload)
    resp = JSONResponse(content=payload, status_code=200)
    if mac:
        resp.headers["X-Integrity"] = mac
    API_REQS.labels(endpoint="estimate", method="POST", status="200", tenant=tenant).inc()
    return resp

@router.post("/charge", response_model=ChargeResponse, responses={
    400: {"model": ErrorResponse}, 401: {"model": ErrorResponse},
    403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}, 429: {"model": ErrorResponse}
})
async def charge_budget(
    req: ChargeRequest,
    actor: Actor = Depends(get_current_actor),
    svc: DPAccountantService = Depends(get_service),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    tenant = req.use.tenant or actor.tenant_id or "default"

    # Rate limit per-tenant
    if not RATE_LIMITER.check(tenant):
        API_REQS.labels(endpoint="charge", method="POST", status="429", tenant=tenant).inc()
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Идемпотентность: при одинаковом ключе возвращаем первый результат
    idem_key = req.idempotency_key or idempotency_key
    if idem_key:
        if not SAFE_NAME_RE.match(idem_key):
            raise HTTPException(status_code=400, detail="Invalid Idempotency-Key")
        cached = IDEMP_STORE.get(f"{tenant}:{idem_key}")
        if cached:
            API_REQS.labels(endpoint="charge", method="POST", status="200", tenant=tenant).inc()
            resp = JSONResponse(content=cached, status_code=200)
            mac = make_hmac(cached)
            if mac:
                resp.headers["X-Integrity"] = mac
            resp.headers["X-Idempotent-Replay"] = "true"
            return resp

    try:
        eps, delt, details = await svc.charge(req.use, actor)
    except HTTPException as e:
        API_REQS.labels(endpoint="charge", method="POST", status=str(e.status_code), tenant=tenant).inc()
        raise

    eid = f"dp::{tenant}::{req.use.pipeline}::charge::{uuid.uuid4()}"
    # Баланс после списания
    state = await svc.get_budget(tenant)
    win = next((w for w in state.windows if w.name == req.use.window), None)
    balance = {
        "epsilon_remaining": getattr(win, "epsilon_remaining", 0.0),
        "delta_remaining": getattr(win, "delta_remaining", 0.0),
    }

    payload = ChargeResponse(
        tenant=tenant,
        pipeline=req.use.pipeline,
        window=req.use.window,
        epsilon_charged=eps,
        delta_charged=delt,
        balance=balance,
        idempotent=bool(idem_key),
        event_id=eid,
        links={
            "self": f"{ROUTER_PREFIX}/charge",
            "budget": f"{ROUTER_PREFIX}/tenants/{tenant}/budget",
            "audit": f"{ROUTER_PREFIX}/audit/{eid}",
        },
    ).dict()

    # Сохраняем идемпотентный ответ
    if idem_key:
        IDEMP_STORE.set(f"{tenant}:{idem_key}", payload, ALLOWED_IDEMPOTENCY_TTL_SEC)

    mac = make_hmac(payload)
    resp = JSONResponse(content=payload, status_code=200)
    if mac:
        resp.headers["X-Integrity"] = mac
    API_REQS.labels(endpoint="charge", method="POST", status="200", tenant=tenant).inc()
    return resp

@router.get("/audit/{event_id}", responses={
    200: {"content": {"application/json": {} }},
    404: {"model": ErrorResponse}
})
async def get_audit(
    event_id: str,
    actor: Actor = Depends(get_current_actor),
    svc: DPAccountantService = Depends(get_service),
):
    if not event_id or len(event_id) < 8:
        raise HTTPException(status_code=400, detail="Invalid event_id")
    data = await svc.get_audit(event_id, actor)
    if not data:
        raise HTTPException(status_code=404, detail="Not found")
    mac = make_hmac(data)
    resp = JSONResponse(content=data, status_code=200)
    if mac:
        resp.headers["X-Integrity"] = mac
    API_REQS.labels(endpoint="audit", method="GET", status="200", tenant=str(actor.tenant_id or "none")).inc()
    return resp

# -----------------------------------------------------------------------------
# Глобальный обработчик ошибок (форматированный вывод)
# -----------------------------------------------------------------------------

@router.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    path = request.url.path.replace(ROUTER_PREFIX, "").strip("/") or "root"
    tenant = request.headers.get("X-Tenant-ID", "") or "none"
    API_REQS.labels(endpoint=path, method=request.method, status=str(exc.status_code), tenant=tenant).inc()
    content = ErrorResponse(
        code=_map_status_to_code(exc.status_code),
        message=redact(str(exc.detail)),
        hint=None,
    ).dict()
    return JSONResponse(status_code=exc.status_code, content=content)

def _map_status_to_code(sc: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        413: "payload_too_large",
        415: "unsupported_media_type",
        422: "unprocessable_entity",
        429: "rate_limited",
        500: "internal_error",
    }.get(sc, "error")

# -----------------------------------------------------------------------------
# Пример интеграции в приложение:
#
# from fastapi import FastAPI
# from veilmind_core.api.http.routers.v1.dp import router as dp_router
# app = FastAPI()
# app.include_router(dp_router)
#
# Для продакшн-режима замените InMemoryDPAccountantService на вашу реализацию и
# внедрите её через Depends(get_service).
# -----------------------------------------------------------------------------
