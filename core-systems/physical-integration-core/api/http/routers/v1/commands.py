# physical-integration-core/api/http/routers/v1/commands.py
from __future__ import annotations

import uuid
import time
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Response,
    status,
)
from pydantic import BaseModel, Field, conlist, constr

logger = logging.getLogger("physical_integration_core.api.commands")

router = APIRouter(prefix="/api/v1/commands", tags=["Commands"])

# --------------------------------------------------------------------------------------
# Security / Principal
# --------------------------------------------------------------------------------------

class Principal(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)

async def get_current_principal(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Principal:
    """
    ПРИМЕЧАНИЕ: Заглушка для примера.
    В проде замените на полноценную валидацию JWT/API-Key, проверку сроков/ролей/скоупов.
    """
    if not authorization and not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Демонстрационные безопасные дефолты:
    # В реальном коде извлечь tenant_id и subject из токена.
    return Principal(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        roles=["operator"],
        scopes=["commands:execute", "ota:assign"],
    )

# --------------------------------------------------------------------------------------
# Idempotency (интерфейс + безопасная in-memory реализация)
# --------------------------------------------------------------------------------------

@runtime_checkable
class IdempotencyRepository(Protocol):
    async def get(self, tenant_id: uuid.UUID, key: str) -> Optional[Dict[str, Any]]: ...
    async def put(self, tenant_id: uuid.UUID, key: str, payload: Dict[str, Any], ttl_seconds: int = 3600) -> None: ...

class InMemoryIdempotencyRepository(IdempotencyRepository):
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def _k(self, tenant_id: uuid.UUID, key: str) -> str:
        return f"{tenant_id}:{key}"

    async def get(self, tenant_id: uuid.UUID, key: str) -> Optional[Dict[str, Any]]:
        rec = self._store.get(self._k(tenant_id, key))
        if not rec:
            return None
        if rec.get("_exp") and rec["_exp"] < time.time():
            self._store.pop(self._k(tenant_id, key), None)
            return None
        return rec.get("payload")

    async def put(self, tenant_id: uuid.UUID, key: str, payload: Dict[str, Any], ttl_seconds: int = 3600) -> None:
        self._store[self._k(tenant_id, key)] = {"payload": payload, "_exp": time.time() + ttl_seconds}

# --------------------------------------------------------------------------------------
# Safety Evaluator (интерфейс + безопасная заглушка)
# --------------------------------------------------------------------------------------

class SafetySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SafetyViolation(BaseModel):
    code: constr(strip_whitespace=True, min_length=1)
    severity: SafetySeverity
    message: str
    subsystem: Optional[str] = None

class SafetyVerdict(BaseModel):
    allow: bool
    safe_mode: bool = False
    action: str
    deny: List[SafetyViolation] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_version: Optional[str] = None
    change_id: Optional[str] = None

class SafetyEvaluationInput(BaseModel):
    action: str
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = Field(default_factory=dict)
    maintenance: Optional[Dict[str, Any]] = None

@runtime_checkable
class SafetyEvaluator(Protocol):
    async def evaluate(self, device_id: uuid.UUID, payload: SafetyEvaluationInput) -> SafetyVerdict: ...

class AllowAllSafetyEvaluator(SafetyEvaluator):
    async def evaluate(self, device_id: uuid.UUID, payload: SafetyEvaluationInput) -> SafetyVerdict:
        return SafetyVerdict(allow=True, action=payload.action)

# --------------------------------------------------------------------------------------
# Command Dispatcher (интерфейс + заглушка)
# --------------------------------------------------------------------------------------

class DispatchResult(BaseModel):
    command_id: uuid.UUID
    scheduled_at: datetime

@runtime_checkable
class CommandDispatcher(Protocol):
    async def dispatch(self, *, tenant_id: uuid.UUID, device_id: uuid.UUID, command: str, params: Dict[str, Any]) -> DispatchResult: ...

class NoopDispatcher(CommandDispatcher):
    async def dispatch(self, *, tenant_id: uuid.UUID, device_id: uuid.UUID, command: str, params: Dict[str, Any]) -> DispatchResult:
        return DispatchResult(command_id=uuid.uuid4(), scheduled_at=datetime.now(timezone.utc))

# --------------------------------------------------------------------------------------
# Audit Logger (интерфейс + безопасная реализация в лог)
# --------------------------------------------------------------------------------------

@runtime_checkable
class AuditLogger(Protocol):
    async def log(self, event: str, data: Dict[str, Any]) -> None: ...

class StdAuditLogger(AuditLogger):
    async def log(self, event: str, data: Dict[str, Any]) -> None:
        logger.info("AUDIT %s %s", event, data)

# --------------------------------------------------------------------------------------
# Rate Limiter (очень простой per-tenant in-memory токенбакет)
# --------------------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = burst
        self.timestamp = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

class InMemoryRateLimiter:
    def __init__(self, rate_per_sec: float = 20.0, burst: int = 40) -> None:
        self.rate = rate_per_sec
        self.burst = burst
        self.buckets: Dict[uuid.UUID, TokenBucket] = {}

    def check(self, tenant_id: uuid.UUID) -> bool:
        b = self.buckets.get(tenant_id)
        if b is None:
            b = TokenBucket(self.rate, self.burst)
            self.buckets[tenant_id] = b
        return b.allow()

rate_limiter = InMemoryRateLimiter()

# --------------------------------------------------------------------------------------
# API Schemas
# --------------------------------------------------------------------------------------

class CommandType(str, Enum):
    START = "START"
    RESUME = "RESUME"
    RUN = "RUN"
    SHUTDOWN = "SHUTDOWN"
    MAINTENANCE = "MAINTENANCE"
    OTA_ASSIGN = "OTA_ASSIGN"
    OTA_CANCEL = "OTA_CANCEL"

class Approver(BaseModel):
    id: constr(min_length=1)
    name: Optional[str] = None
    signature_b64: Optional[str] = None

class MaintenanceBlock(BaseModel):
    requested: bool = False
    approvers: conlist(Approver, min_items=0, max_items=16) = Field(default_factory=list)
    approved_until: Optional[datetime] = None
    scope: Dict[str, str] = Field(default_factory=dict)

class CommandTarget(BaseModel):
    device_id: uuid.UUID

class CommandParams(BaseModel):
    # Параметры команд (расширяемые)
    # Для OTA_ASSIGN допустимы image_id / channel / constraints
    image_id: Optional[uuid.UUID] = None
    channel: Optional[str] = None
    constraints: Dict[str, Any] = Field(default_factory=dict)

class CommandRequest(BaseModel):
    command: CommandType
    targets: conlist(CommandTarget, min_items=1, max_items=1000)
    params: CommandParams = Field(default_factory=CommandParams)
    maintenance: Optional[MaintenanceBlock] = None

class DeviceCommandResult(BaseModel):
    device_id: uuid.UUID
    accepted: bool
    reason: Optional[str] = None
    verdict: Optional[SafetyVerdict] = None
    command_id: Optional[uuid.UUID] = None
    scheduled_at: Optional[datetime] = None

class CommandResponse(BaseModel):
    request_id: uuid.UUID
    correlation_id: str
    accepted_count: int
    results: List[DeviceCommandResult]

class ErrorModel(BaseModel):
    detail: str

# --------------------------------------------------------------------------------------
# Dependencies wiring (в реальном приложении замените на ваши провайдеры/контейнер)
# --------------------------------------------------------------------------------------

_idemp_repo: IdempotencyRepository = InMemoryIdempotencyRepository()
_safety: SafetyEvaluator = AllowAllSafetyEvaluator()
_dispatcher: CommandDispatcher = NoopDispatcher()
_audit: AuditLogger = StdAuditLogger()

def get_idempotency_repo() -> IdempotencyRepository:
    return _idemp_repo

def get_safety() -> SafetyEvaluator:
    return _safety

def get_dispatcher() -> CommandDispatcher:
    return _dispatcher

def get_audit() -> AuditLogger:
    return _audit

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _normalize_idempotency_key(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    v = raw.strip()
    if not v:
        return None
    if len(v) > 128:
        raise HTTPException(status_code=400, detail="Idempotency-Key too long")
    return v

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@router.post(
    "/execute",
    response_model=CommandResponse,
    responses={
        400: {"model": ErrorModel},
        401: {"model": ErrorModel},
        403: {"model": ErrorModel},
        409: {"model": ErrorModel},
        429: {"model": ErrorModel},
        500: {"model": ErrorModel},
    },
    summary="Execute device command(s) with safety evaluation and idempotency",
)
async def execute_commands(
    request: CommandRequest,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    idempotency_repo: IdempotencyRepository = Depends(get_idempotency_repo),
    safety: SafetyEvaluator = Depends(get_safety),
    dispatcher: CommandDispatcher = Depends(get_dispatcher),
    audit: AuditLogger = Depends(get_audit),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    idem_key_header: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Correlation
    correlation_id = x_request_id or str(uuid.uuid4())
    response.headers["X-Request-ID"] = correlation_id

    # Rate limit per tenant
    if not rate_limiter.check(principal.tenant_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # RBAC
    if request.command in {CommandType.OTA_ASSIGN, CommandType.OTA_CANCEL} and "ota:assign" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Forbidden")
    if request.command not in {CommandType.OTA_ASSIGN, CommandType.OTA_CANCEL} and "commands:execute" not in principal.scopes:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Idempotency
    idem_key = _normalize_idempotency_key(idem_key_header)
    if idem_key:
        cached = await idempotency_repo.get(principal.tenant_id, idem_key)
        if cached:
            # Возвращаем ранее зафиксированный ответ
            response.headers["Idempotent-Replay"] = "true"
            return cached

    req_id = uuid.uuid4()
    results: List[DeviceCommandResult] = []

    # Safety action mapping
    action_str = request.command.value

    # Выполняем безопасную оценку + диспатч на каждую цель
    for t in request.targets:
        try:
            # Safety Evaluation Input (минимальный набор — расширьте при интеграции)
            s_input = SafetyEvaluationInput(
                action=action_str,
                time=_now_utc(),
                context={
                    "tenant_id": str(principal.tenant_id),
                    "principal_id": str(principal.id),
                    "correlation_id": correlation_id,
                },
                maintenance=(
                    request.maintenance.dict() if request.maintenance else None
                ),
            )
            verdict = await safety.evaluate(t.device_id, s_input)

            if not verdict.allow and request.command != CommandType.SHUTDOWN:
                results.append(
                    DeviceCommandResult(
                        device_id=t.device_id,
                        accepted=False,
                        reason="Safety policy denied",
                        verdict=verdict,
                    )
                )
                continue

            # Команды, требующие параметров: базовая валидация
            if request.command == CommandType.OTA_ASSIGN:
                if not (request.params.image_id or request.params.channel):
                    results.append(
                        DeviceCommandResult(
                            device_id=t.device_id,
                            accepted=False,
                            reason="OTA_ASSIGN requires image_id or channel",
                            verdict=verdict,
                        )
                    )
                    continue

            # Dispatch
            dispatch_res = await dispatcher.dispatch(
                tenant_id=principal.tenant_id,
                device_id=t.device_id,
                command=request.command.value,
                params=request.params.dict(),
            )

            results.append(
                DeviceCommandResult(
                    device_id=t.device_id,
                    accepted=True,
                    verdict=verdict,
                    command_id=dispatch_res.command_id,
                    scheduled_at=dispatch_res.scheduled_at,
                )
            )

            # Audit per device
            await audit.log(
                event="command.dispatch",
                data={
                    "tenant_id": str(principal.tenant_id),
                    "principal_id": str(principal.id),
                    "device_id": str(t.device_id),
                    "command": request.command.value,
                    "accepted": True,
                    "correlation_id": correlation_id,
                    "scheduled_at": dispatch_res.scheduled_at.isoformat(),
                },
            )

        except HTTPException:
            raise
        except Exception as ex:  # noqa: BLE001
            logger.exception("Dispatch failed for device %s", t.device_id)
            results.append(
                DeviceCommandResult(
                    device_id=t.device_id,
                    accepted=False,
                    reason=f"Internal error: {ex}",
                )
            )
            await audit.log(
                event="command.error",
                data={
                    "tenant_id": str(principal.tenant_id),
                    "principal_id": str(principal.id),
                    "device_id": str(t.device_id),
                    "command": request.command.value,
                    "accepted": False,
                    "correlation_id": correlation_id,
                    "error": str(ex),
                },
            )

    payload = CommandResponse(
        request_id=req_id,
        correlation_id=correlation_id,
        accepted_count=sum(1 for r in results if r.accepted),
        results=results,
    ).dict()

    # Persist idempotent result if key provided
    if idem_key:
        await idempotency_repo.put(principal.tenant_id, idem_key, payload, ttl_seconds=3600)
        response.headers["Idempotent-Replay"] = "false"

    return payload


@router.post(
    "/maintenance/approve",
    response_model=CommandResponse,
    responses={400: {"model": ErrorModel}, 401: {"model": ErrorModel}, 403: {"model": ErrorModel}},
    summary="Approve maintenance mode (two-person rule) and apply to devices",
)
async def maintenance_approve(
    request: CommandRequest,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    idempotency_repo: IdempotencyRepository = Depends(get_idempotency_repo),
    safety: SafetyEvaluator = Depends(get_safety),
    dispatcher: CommandDispatcher = Depends(get_dispatcher),
    audit: AuditLogger = Depends(get_audit),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    idem_key_header: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Ограничим именно на MAINTENANCE
    if request.command != CommandType.MAINTENANCE:
        raise HTTPException(status_code=400, detail="maintenance/approve supports MAINTENANCE command only")

    # Простая проверка двух лиц
    if not request.maintenance or not request.maintenance.requested or len(request.maintenance.approvers) < 2:
        raise HTTPException(status_code=400, detail="Two approvers required for maintenance")

    return await execute_commands(
        request=request,
        response=response,
        principal=principal,
        idempotency_repo=idempotency_repo,
        safety=safety,
        dispatcher=dispatcher,
        audit=audit,
        x_request_id=x_request_id,
        idem_key_header=idem_key_header,
    )
