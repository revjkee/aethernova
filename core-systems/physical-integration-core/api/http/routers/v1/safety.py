# -*- coding: utf-8 -*-
"""
physical-integration-core/api/http/routers/v1/safety.py

Промышленный роутер управления безопасностью:
- Эндпоинты: health, alarms (list/ack), E-Stop (activate/reset), safety zones (get/set),
  LOTO permits (issue/revoke/list).
- RBAC/Scopes: через зависимости из middleware.auth.
- Идемпотентность: заголовок Idempotency-Key для изменяющих операций.
- Rate limit (token bucket) для критических команд.
- Асинхронная публикация событий в шину (Kafka/MQTT/др.) через абстракцию EventBus.
- Аудит и метрики (prometheus_client — опционально).
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, BackgroundTasks, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, constr

# ---- Импорты зависимостей авторизации (с безопасными заглушками) ----
try:
    from api.http.middleware.auth import (
        require_scopes,
        require_roles,
        require_predicate,
        current_auth,
        AuthContext,
    )
except Exception:  # pragma: no cover
    # Минимальные заглушки на случай отсутствия модуля в рантайме тестов
    class AuthContext(BaseModel):  # type: ignore
        subject: str = "anonymous"
        roles: set[str] = set()
        scopes: set[str] = set()
        tenant: Optional[str] = None

    def current_auth(_: Request = None) -> AuthContext:  # type: ignore
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    def require_scopes(_: List[str], all_: bool = True):  # type: ignore
        def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
            return ctx
        return _dep

    def require_roles(_: List[str], all_: bool = False):  # type: ignore
        def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
            return ctx
        return _dep

    def require_predicate(*args, **kwargs):  # type: ignore
        return Depends(lambda: None)

# ---- Метрики (опционально) ----
try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **kw): pass
        def labels(self, *a, **kw): return self
        def observe(self, *a, **kw): return None
        def inc(self, *a, **kw): return None
    Counter = Histogram = _Noop  # type: ignore

logger = logging.getLogger("safety")
logger.setLevel(logging.INFO)

SAFETY_OP_LATENCY = Histogram(
    "safety_operation_latency_seconds",
    "Latency of safety operations",
    ["op", "outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)
SAFETY_OP_TOTAL = Counter(
    "safety_operation_total",
    "Count of safety operations",
    ["op", "outcome"],
)

# =============================================================================
# Вспомогательные абстракции: EventBus, Idempotency, Rate Limiter
# =============================================================================

class EventBus:
    """Абстрактная шина событий. Реализуйте publish() в продакшене."""
    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        logger.info("EVENT PUBLISH %s %s", topic, payload)

_default_event_bus = EventBus()


class IdempotencyStore:
    """In-memory идемпотентность с TTL (для single-instance или как локальный кэш)."""
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._data: Dict[str, tuple[float, Dict[str, Any]]] = {}
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, value_factory) -> Dict[str, Any]:
        now = time.time()
        async with self._lock:
            # cleanup
            expired = [k for k, (ts, _) in self._data.items() if now - ts > self._ttl]
            for k in expired:
                self._data.pop(k, None)
            # get or create
            if key in self._data:
                return self._data[key][1]
            value = await value_factory()
            self._data[key] = (now, value)
            return value

_idem_store = IdempotencyStore(ttl_seconds=900)


class TokenBucket:
    """Простой токен-бакет на субъект (anti-abuse для опасных команд)."""
    def __init__(self, rate_per_min: int, burst: int) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst
        self._state: Dict[str, tuple[float, float]] = {}  # subject -> (tokens, last_ts)
        self._lock = asyncio.Lock()

    async def allow(self, subject: str) -> bool:
        now = time.time()
        async with self._lock:
            tokens, last = self._state.get(subject, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._state[subject] = (tokens, now)
                return False
            self._state[subject] = (tokens - 1.0, now)
            return True

# Для E-Stop по умолчанию: не чаще 6 команд/мин с буфером 3
_estop_bucket = TokenBucket(rate_per_min=6, burst=3)

# =============================================================================
# Модели данных
# =============================================================================

class HealthOut(BaseModel):
    status: str = "ok"
    ts: float = Field(default_factory=lambda: time.time())

class AlarmItem(BaseModel):
    id: constr(strip_whitespace=True, min_length=1)
    key: constr(strip_whitespace=True, min_length=1)  # логический ключ/тег
    severity: int = Field(ge=100, le=1000)
    message: str
    active: bool = True
    raised_at: float
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    annotations: Dict[str, Any] = Field(default_factory=dict)

class AlarmAckIn(BaseModel):
    alarm_id: str = Field(..., min_length=1)
    comment: Optional[str] = Field(default=None, max_length=1024)

class OpResult(BaseModel):
    request_id: str
    status: str
    detail: Optional[str] = None
    at: float = Field(default_factory=lambda: time.time())

class EStopAction(str, Enum):
    ACTIVATE = "activate"
    RESET = "reset"

class EStopIn(BaseModel):
    action: EStopAction
    reason: str = Field(..., min_length=3, max_length=256)
    asset_id: constr(regex=r"^[A-Za-z0-9._:-]{1,64}$") = "GLOBAL"
    dry_run: bool = False

class ZoneState(str, Enum):
    SAFE = "safe"          # безопасное состояние
    ARMED = "armed"        # зона "взведена"
    DISARMED = "disarmed"  # снята
    FAULT = "fault"        # неисправность

class ZoneSetIn(BaseModel):
    zone_id: constr(regex=r"^[A-Za-z0-9._:-]{1,64}$")
    state: ZoneState
    reason: Optional[str] = Field(default=None, max_length=256)

class ZoneItem(BaseModel):
    zone_id: str
    state: ZoneState
    updated_at: float
    updated_by: str
    annotations: Dict[str, Any] = Field(default_factory=dict)

class PermitIssueIn(BaseModel):
    asset_id: constr(regex=r"^[A-Za-z0-9._:-]{1,64}$")
    reason: str = Field(..., min_length=3, max_length=256)
    valid_for_seconds: int = Field(default=4 * 3600, ge=60, le=7 * 24 * 3600)
    tags: List[constr(regex=r"^[A-Za-z0-9._:-]{1,64}$")] = Field(default_factory=list)

class PermitItem(BaseModel):
    permit_id: str
    asset_id: str
    issued_at: float
    issued_by: str
    expires_at: float
    reason: str
    tags: List[str] = Field(default_factory=list)
    revoked: bool = False
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None

class PermitRevokeIn(BaseModel):
    permit_id: str
    reason: Optional[str] = Field(default=None, max_length=256)

# =============================================================================
# In-memory состояние (в проде — вынести в БД/Redis)
# =============================================================================

class _State:
    def __init__(self) -> None:
        self.alarms: Dict[str, AlarmItem] = {}
        self.zones: Dict[str, ZoneItem] = {}
        self.permits: Dict[str, PermitItem] = {}
        self.lock = asyncio.Lock()

STATE = _State()

# =============================================================================
# Роутер
# =============================================================================

router = APIRouter(prefix="/v1/safety", tags=["safety"])

# ---- Утилиты ----

def _new_request_id() -> str:
    return str(uuid.uuid4())

async def _publish_event(bus: EventBus, topic: str, payload: Dict[str, Any]) -> None:
    try:
        await bus.publish(topic, payload)
    except Exception:  # pragma: no cover
        logger.exception("Event publish failed")

def _roles_any(*roles: str):
    return require_predicate(lambda ctx: bool(set(roles) & ctx.roles), error_detail="Forbidden: role required")

# =============================================================================
# Endpoints
# =============================================================================

@router.get("/health", response_model=HealthOut, dependencies=[Depends(require_scopes(["safety.read"], all_=False))])
async def health() -> HealthOut:
    return HealthOut()

@router.get(
    "/alarms",
    response_model=List[AlarmItem],
    dependencies=[Depends(require_scopes(["safety.read"], all_=False))]
)
async def list_alarms() -> List[AlarmItem]:
    async with STATE.lock:
        return list(STATE.alarms.values())

@router.post(
    "/alarms/ack",
    response_model=OpResult,
    dependencies=[Depends(require_scopes(["safety.write", "svc.write"], all_=False))]
)
async def ack_alarm(
    payload: AlarmAckIn,
    background: BackgroundTasks,
    auth: AuthContext = Depends(current_auth),
    event_bus: EventBus = _default_event_bus,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    op_name = "alarm_ack"
    start = time.perf_counter()

    async def _do() -> Dict[str, Any]:
        async with STATE.lock:
            alarm = STATE.alarms.get(payload.alarm_id)
            if not alarm or not alarm.active:
                # Разрешаем повторный ACK или ACK неактивной тревоги с "ok"
                res = OpResult(request_id=_new_request_id(), status="ok", detail="No active alarm / already acked")
            else:
                alarm.acknowledged = True
                alarm.acknowledged_by = auth.subject
                alarm.acknowledged_at = time.time()
                STATE.alarms[alarm.id] = alarm
                res = OpResult(request_id=_new_request_id(), status="ok", detail="Acknowledged")

        background.add_task(
            _publish_event,
            event_bus,
            "safety.alarms.ack",
            {
                "alarm_id": payload.alarm_id,
                "by": auth.subject,
                "comment": payload.comment,
                "ts": time.time(),
            },
        )
        return res.model_dict() if hasattr(res, "model_dict") else res.dict()

    key = f"{op_name}:{auth.subject}:{payload.alarm_id}:{idempotency_key or 'no-key'}"
    result = await _idem_store.get_or_set(key, _do)
    SAFETY_OP_TOTAL.labels(op=op_name, outcome="ok").inc()
    SAFETY_OP_LATENCY.labels(op=op_name, outcome="ok").observe(time.perf_counter() - start)
    return result

@router.post(
    "/estop",
    response_model=OpResult,
    dependencies=[
        Depends(require_scopes(["safety.control"], all_=False)),
        _roles_any("safety-operator", "safety-supervisor"),
    ],
)
async def estop(
    req: EStopIn,
    background: BackgroundTasks,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    event_bus: EventBus = _default_event_bus,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    op_name = f"estop_{req.action.value}"
    start = time.perf_counter()

    # Anti-abuse для критической команды
    allowed = await _estop_bucket.allow(auth.subject)
    if not allowed:
        SAFETY_OP_TOTAL.labels(op=op_name, outcome="rate_limited").inc()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many safety commands")

    async def _do() -> Dict[str, Any]:
        request_id = _new_request_id()
        detail = "DRY-RUN" if req.dry_run else "OK"
        # В продакшене здесь вызов драйвера/шлюза реального E-Stop
        event = {
            "request_id": request_id,
            "action": req.action.value,
            "asset_id": req.asset_id,
            "reason": req.reason,
            "by": auth.subject,
            "ip": request.client.host if request.client else None,
            "ts": time.time(),
            "dry_run": req.dry_run,
        }
        background.add_task(_publish_event, event_bus, "safety.estop", event)
        return OpResult(request_id=request_id, status="ok", detail=detail).dict()

    key = f"{op_name}:{auth.subject}:{req.asset_id}:{idempotency_key or 'no-key'}"
    try:
        result = await _idem_store.get_or_set(key, _do)
        SAFETY_OP_TOTAL.labels(op=op_name, outcome="ok").inc()
        SAFETY_OP_LATENCY.labels(op=op_name, outcome="ok").observe(time.perf_counter() - start)
        return result
    except Exception as e:  # pragma: no cover
        SAFETY_OP_TOTAL.labels(op=op_name, outcome="error").inc()
        SAFETY_OP_LATENCY.labels(op=op_name, outcome="error").observe(time.perf_counter() - start)
        logger.exception("E-Stop operation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get(
    "/zones",
    response_model=List[ZoneItem],
    dependencies=[Depends(require_scopes(["safety.read"], all_=False))],
)
async def get_zones() -> List[ZoneItem]:
    async with STATE.lock:
        return list(STATE.zones.values())

@router.put(
    "/zone/state",
    response_model=OpResult,
    dependencies=[
        Depends(require_scopes(["safety.write", "safety.control"], all_=False)),
        _roles_any("safety-engineer", "safety-supervisor"),
    ],
)
async def set_zone_state(
    req: ZoneSetIn,
    background: BackgroundTasks,
    auth: AuthContext = Depends(current_auth),
    event_bus: EventBus = _default_event_bus,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    op_name = "zone_state"
    start = time.perf_counter()

    async def _do() -> Dict[str, Any]:
        now = time.time()
        async with STATE.lock:
            STATE.zones[req.zone_id] = ZoneItem(
                zone_id=req.zone_id,
                state=req.state,
                updated_at=now,
                updated_by=auth.subject,
                annotations={"reason": req.reason} if req.reason else {},
            )
        event = {
            "zone_id": req.zone_id,
            "state": req.state.value,
            "by": auth.subject,
            "reason": req.reason,
            "ts": now,
        }
        await _publish_event(event_bus, "safety.zone.state", event)
        return OpResult(request_id=_new_request_id(), status="ok", detail=f"{req.zone_id} -> {req.state}").dict()

    key = f"{op_name}:{auth.subject}:{req.zone_id}:{req.state.value}:{idempotency_key or 'no-key'}"
    result = await _idem_store.get_or_set(key, _do)
    SAFETY_OP_TOTAL.labels(op=op_name, outcome="ok").inc()
    SAFETY_OP_LATENCY.labels(op=op_name, outcome="ok").observe(time.perf_counter() - start)
    return result

@router.post(
    "/permit/issue",
    response_model=PermitItem,
    dependencies=[
        Depends(require_scopes(["safety.write"], all_=False)),
        _roles_any("safety-supervisor"),
    ],
)
async def issue_permit(
    req: PermitIssueIn,
    background: BackgroundTasks,
    auth: AuthContext = Depends(current_auth),
    event_bus: EventBus = _default_event_bus,
):
    now = time.time()
    pid = str(uuid.uuid7() if hasattr(uuid, "uuid7") else uuid.uuid4())  # py<3.11 fallback
    item = PermitItem(
        permit_id=pid,
        asset_id=req.asset_id,
        issued_at=now,
        issued_by=auth.subject,
        expires_at=now + req.valid_for_seconds,
        reason=req.reason,
        tags=req.tags,
    )
    async with STATE.lock:
        STATE.permits[pid] = item

    background.add_task(
        _publish_event,
        event_bus,
        "safety.permit.issued",
        {
            "permit_id": pid,
            "asset_id": req.asset_id,
            "by": auth.subject,
            "reason": req.reason,
            "tags": req.tags,
            "ts": now,
        },
    )
    return item

@router.post(
    "/permit/revoke",
    response_model=PermitItem,
    dependencies=[
        Depends(require_scopes(["safety.write"], all_=False)),
        _roles_any("safety-supervisor"),
    ],
)
async def revoke_permit(
    req: PermitRevokeIn,
    background: BackgroundTasks,
    auth: AuthContext = Depends(current_auth),
    event_bus: EventBus = _default_event_bus,
):
    async with STATE.lock:
        item = STATE.permits.get(req.permit_id)
        if not item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Permit not found")
        if item.revoked:
            return item
        item.revoked = True
        item.revoked_at = time.time()
        item.revoked_by = auth.subject
        STATE.permits[item.permit_id] = item

    background.add_task(
        _publish_event,
        event_bus,
        "safety.permit.revoked",
        {
            "permit_id": item.permit_id,
            "asset_id": item.asset_id,
            "by": auth.subject,
            "reason": req.reason,
            "ts": item.revoked_at,
        },
    )
    return item

@router.get(
    "/permits",
    response_model=List[PermitItem],
    dependencies=[Depends(require_scopes(["safety.read"], all_=False))],
)
async def list_permits() -> List[PermitItem]:
    async with STATE.lock:
        return list(STATE.permits.values())
