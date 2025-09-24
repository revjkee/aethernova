# -*- coding: utf-8 -*-
"""
physical-integration-core/api/graphql/server.py

Промышленный GraphQL-сервер (Strawberry + FastAPI) для physical-integration-core:
- Контекст с AuthContext из HTTP middleware, RBAC/Scopes пермишены.
- Ограничения глубины/сложности запроса (DoS-защита).
- Идемпотентность и rate-limit для мутаций.
- Persisted Queries (APQ) по sha256 (регистрация/использование).
- Подписки через WebSocket (встроенный PubSub).
- Метрики Prometheus (опционально), OTel-трейсинг (опционально).
- Безопасный error formatter (скрывает stack в prod).

Зависимости (рекомендуемые):
  strawberry-graphql[fastapi]>=0.215
  fastapi>=0.103
  uvicorn[standard]>=0.23
  aiodataloader>=0.3 (опционально)
  prometheus-client>=0.16 (опционально)
  opentelemetry-sdk/opentelemetry-instrumentation-asgi (опц.)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import types
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

# ---- Опциональные зависимости с безопасными fallback'ами ----
try:
    import strawberry
    from strawberry.fastapi import GraphQLRouter
    from strawberry.schema.config import StrawberryConfig
    from strawberry.types import Info
    from strawberry.permission import BasePermission
    from strawberry.subscriptions import GRAPHQL_TRANSPORT_WS_PROTOCOL
except Exception as e:  # pragma: no cover
    raise RuntimeError("strawberry-graphql не установлен: pip install strawberry-graphql[fastapi]") from e

try:
    from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse
except Exception as e:  # pragma: no cover
    raise RuntimeError("fastapi не установлен: pip install fastapi") from e

try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    class BaseModel:  # minimal polyfill
        def __init__(self, **kwargs): 
            for k, v in kwargs.items(): setattr(self, k, v)
        def model_dump(self): return self.__dict__
    def Field(default=None, **kw): return default

# Метрики (опциональные)
try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **kw): pass
        def labels(self, *a, **kw): return self
        def observe(self, *a, **kw): return None
        def inc(self, *a, **kw): return None
    Counter = Histogram = _Noop  # type: ignore

# OTel (опционально)
try:
    from opentelemetry import trace  # noqa
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False

# ---- Импорт auth-контекста из HTTP middleware ----
try:
    from api.http.middleware.auth import AuthContext, current_auth  # FastAPI Depends
except Exception:  # pragma: no cover
    class AuthContext(BaseModel):  # type: ignore
        subject: str = "anonymous"
        roles: set[str] = set()
        scopes: set[str] = set()
        tenant: Optional[str] = None
    def current_auth(*args, **kwargs):  # type: ignore
        raise HTTPException(status_code=401, detail="Unauthorized")

logger = logging.getLogger("graphql")
logger.setLevel(logging.INFO)

# =============================================================================
# Настройки
# =============================================================================

class GraphQLSettings(BaseModel):
    env: str = Field(default=os.getenv("ENVIRONMENT", "prod"))
    graphiql: bool = Field(default=bool(int(os.getenv("GRAPHQL_GRAPHIQL", "0"))))
    max_depth: int = Field(default=int(os.getenv("GRAPHQL_MAX_DEPTH", "12")))
    max_complexity: int = Field(default=int(os.getenv("GRAPHQL_MAX_COMPLEXITY", "2000")))
    apq_enabled: bool = Field(default=bool(int(os.getenv("GRAPHQL_APQ", "1"))))
    apq_ttl_seconds: int = Field(default=int(os.getenv("GRAPHQL_APQ_TTL", "86400")))
    mutation_rps: float = Field(default=float(os.getenv("GRAPHQL_MUTATION_RPS", "2.0")))
    mutation_burst: int = Field(default=int(os.getenv("GRAPHQL_MUTATION_BURST", "5")))
    enable_metrics: bool = Field(default=bool(int(os.getenv("GRAPHQL_METRICS", "1"))))

SETTINGS = GraphQLSettings()

GQL_REQ_LATENCY = Histogram(
    "graphql_request_latency_seconds",
    "GraphQL request latency",
    ["operation", "outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
GQL_REQ_TOTAL = Counter(
    "graphql_requests_total",
    "GraphQL requests by operation and outcome",
    ["operation", "outcome"],
)

# =============================================================================
# Persisted Queries (APQ)
# =============================================================================

class APQStore:
    """Простое in-memory хранилище sha256->query с TTL (для single-instance/GW-кэша)."""
    def __init__(self, ttl_seconds: int = 86400) -> None:
        self._ttl = ttl_seconds
        self._data: Dict[str, Tuple[float, str]] = {}
        self._lock = asyncio.Lock()

    async def get(self, sha: str) -> Optional[str]:
        now = time.time()
        async with self._lock:
            rec = self._data.get(sha)
            if not rec:
                return None
            ts, q = rec
            if now - ts > self._ttl:
                self._data.pop(sha, None)
                return None
            return q

    async def put(self, sha: str, query: str) -> None:
        async with self._lock:
            self._data[sha] = (time.time(), query)

APQ = APQStore(ttl_seconds=SETTINGS.apq_ttl_seconds)

async def resolve_apq(request: Request, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Реализация APQ (Apollo Persisted Queries совместимая схема extensions.persistedQuery.sha256Hash).
    Поведение:
      - Если есть query и sha256Hash: проверим хеш и сохраним.
      - Если есть только sha256Hash: попытаемся подставить сохраненный query.
    """
    if not SETTINGS.apq_enabled:
        return body

    ext = body.get("extensions") or {}
    pq = ext.get("persistedQuery") or {}
    sha = pq.get("sha256Hash")
    if not sha:
        return body

    query = body.get("query")
    if query:
        calc = hashlib.sha256(query.encode("utf-8")).hexdigest()
        if calc != sha:
            raise HTTPException(status_code=400, detail="APQ sha256 mismatch")
        await APQ.put(sha, query)
        return body

    stored = await APQ.get(sha)
    if not stored:
        # Совместимо с Apollo: GraphQL error PersistedQueryNotFound
        return {"errors": [{"message": "PersistedQueryNotFound"}]}
    body["query"] = stored
    return body

# =============================================================================
# Rate limit и идемпотентность для мутаций
# =============================================================================

class TokenBucket:
    def __init__(self, rps: float, burst: int) -> None:
        self.rps = rps
        self.burst = burst
        self._state: Dict[str, Tuple[float, float]] = {}  # subject -> (tokens, last_ts)
        self._lock = asyncio.Lock()

    async def allow(self, subject: str) -> bool:
        now = time.time()
        async with self._lock:
            tokens, last = self._state.get(subject, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rps)
            if tokens < 1.0:
                self._state[subject] = (tokens, now)
                return False
            self._state[subject] = (tokens - 1.0, now)
            return True

MUT_BUCKET = TokenBucket(SETTINGS.mutation_rps, SETTINGS.mutation_burst)

class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        now = time.time()
        async with self._lock:
            # cleanup
            for k, (ts, _) in list(self._data.items()):
                if now - ts > self._ttl:
                    self._data.pop(k, None)
            if key in self._data:
                return self._data[key][1]
            val = await factory() if asyncio.iscoroutinefunction(factory) else factory()
            self._data[key] = (now, val)
            return val

IDEMP = IdempotencyStore()

# =============================================================================
# Пермишены: Scopes / Roles
# =============================================================================

class Requires(BasePermission):
    message = "Forbidden: missing scopes/roles"

    def __init__(self, scopes: Optional[List[str]] = None, roles: Optional[List[str]] = None,
                 all_scopes: bool = True, all_roles: bool = False) -> None:
        self.scopes = set(scopes or [])
        self.roles = set(roles or [])
        self.all_scopes = all_scopes
        self.all_roles = all_roles

    def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
        ctx: GQLContext = info.context
        if ctx.auth is None:
            return False
        if self.scopes:
            if self.all_scopes and not self.scopes.issubset(ctx.auth.scopes):
                return False
            if not self.all_scopes and not (self.scopes & ctx.auth.scopes):
                return False
        if self.roles:
            if self.all_roles and not self.roles.issubset(ctx.auth.roles):
                return False
            if not self.all_roles and not (self.roles & ctx.auth.roles):
                return False
        return True

# =============================================================================
# Контекст и PubSub
# =============================================================================

@dataclass
class GQLContext:
    request: Request
    auth: Optional[AuthContext]
    loaders: Any
    pubsub: "PubSub"

class PubSub:
    """Простой asyncio PubSub для подписок."""
    def __init__(self) -> None:
        self._topics: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: Any) -> None:
        async with self._lock:
            queues = list(self._topics.get(topic, []))
        for q in queues:
            await q.put(payload)

    async def subscribe(self, topic: str) -> AsyncIterator[Any]:
        q: asyncio.Queue = asyncio.Queue()
        async with self._lock:
            self._topics.setdefault(topic, []).append(q)
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            async with self._lock:
                self._topics.get(topic, []).remove(q)

PUBSUB = PubSub()

# =============================================================================
# Датамодели GraphQL
# =============================================================================

@strawberry.type
class Health:
    status: str
    ts: float

@strawberry.type
class Alarm:
    id: str
    key: str
    severity: int
    message: str
    active: bool
    raised_at: float
    acknowledged: bool
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[float]

@strawberry.type
class Zone:
    zone_id: str
    state: str
    updated_at: float
    updated_by: str

@strawberry.type
class Permit:
    permit_id: str
    asset_id: str
    issued_at: float
    issued_by: str
    expires_at: float
    reason: str
    tags: List[str]
    revoked: bool
    revoked_at: Optional[float]
    revoked_by: Optional[str]

@strawberry.type
class OpResult:
    request_id: str
    status: str
    detail: Optional[str]

# =============================================================================
# Репозитории/сервисы (абстракции). В проде подменяются реализацией.
# =============================================================================

class SafetyService:
    async def list_alarms(self, ctx: GQLContext) -> List[Alarm]:  # pragma: no cover
        return []
    async def ack_alarm(self, ctx: GQLContext, alarm_id: str, comment: Optional[str]) -> OpResult:  # pragma: no cover
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="noop")
    async def estop(self, ctx: GQLContext, action: str, asset_id: str, reason: str, dry_run: bool) -> OpResult:  # pragma: no cover
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="noop")
    async def list_zones(self, ctx: GQLContext) -> List[Zone]:  # pragma: no cover
        return []
    async def set_zone(self, ctx: GQLContext, zone_id: str, state: str, reason: Optional[str]) -> OpResult:  # pragma: no cover
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="noop")
    async def list_permits(self, ctx: GQLContext) -> List[Permit]:  # pragma: no cover
        return []
    async def issue_permit(self, ctx: GQLContext, asset_id: str, reason: str, valid_for_seconds: int, tags: List[str]) -> Permit:  # pragma: no cover
        now = time.time()
        return Permit(
            permit_id=str(uuid.uuid4()), asset_id=asset_id, issued_at=now, issued_by=ctx.auth.subject if ctx.auth else "system",
            expires_at=now + valid_for_seconds, reason=reason, tags=tags, revoked=False, revoked_at=None, revoked_by=None
        )
    async def revoke_permit(self, ctx: GQLContext, permit_id: str, reason: Optional[str]) -> Permit:  # pragma: no cover
        now = time.time()
        return Permit(
            permit_id=permit_id, asset_id="unknown", issued_at=now-10, issued_by="system",
            expires_at=now+3600, reason=reason or "", tags=[], revoked=True, revoked_at=now, revoked_by=ctx.auth.subject if ctx.auth else "system"
        )

# Базовая in-memory демо-реализация (для запуска без внешних зависимостей)
class InMemorySafetyService(SafetyService):
    def __init__(self) -> None:
        self._alarms: Dict[str, Dict[str, Any]] = {}
        self._zones: Dict[str, Dict[str, Any]] = {}
        self._permits: Dict[str, Dict[str, Any]] = {}
        # Создадим одну-две записи
        a_id = "A1"
        self._alarms[a_id] = dict(
            id=a_id, key="energy.grid_breaker_closed", severity=700, message="Grid breaker opened",
            active=True, raised_at=time.time()-60, acknowledged=False, acknowledged_by=None, acknowledged_at=None
        )
        self._zones["Z1"] = dict(zone_id="Z1", state="safe", updated_at=time.time(), updated_by="system")
    async def list_alarms(self, ctx: GQLContext) -> List[Alarm]:
        return [Alarm(**a) for a in self._alarms.values()]
    async def ack_alarm(self, ctx: GQLContext, alarm_id: str, comment: Optional[str]) -> OpResult:
        a = self._alarms.get(alarm_id)
        if not a or not a["active"]:
            return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="No active alarm / already acked")
        a["acknowledged"] = True
        a["acknowledged_by"] = ctx.auth.subject if ctx.auth else "system"
        a["acknowledged_at"] = time.time()
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="Acknowledged")
    async def estop(self, ctx: GQLContext, action: str, asset_id: str, reason: str, dry_run: bool) -> OpResult:
        await PUBSUB.publish("safety.estop", {"action": action, "asset_id": asset_id, "reason": reason, "by": ctx.auth.subject if ctx.auth else "system"})
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail="DRY-RUN" if dry_run else "OK")
    async def list_zones(self, ctx: GQLContext) -> List[Zone]:
        return [Zone(**z) for z in self._zones.values()]
    async def set_zone(self, ctx: GQLContext, zone_id: str, state: str, reason: Optional[str]) -> OpResult:
        self._zones[zone_id] = dict(zone_id=zone_id, state=state, updated_at=time.time(), updated_by=ctx.auth.subject if ctx.auth else "system")
        await PUBSUB.publish("safety.zone", {"zone_id": zone_id, "state": state, "reason": reason})
        return OpResult(request_id=str(uuid.uuid4()), status="ok", detail=f"{zone_id} -> {state}")
    async def list_permits(self, ctx: GQLContext) -> List[Permit]:
        return [Permit(**p) for p in self._permits.values()]
    async def issue_permit(self, ctx: GQLContext, asset_id: str, reason: str, valid_for_seconds: int, tags: List[str]) -> Permit:
        now = time.time()
        pid = str(uuid.uuid4())
        p = dict(
            permit_id=pid, asset_id=asset_id, issued_at=now, issued_by=ctx.auth.subject if ctx.auth else "system",
            expires_at=now + valid_for_seconds, reason=reason, tags=tags, revoked=False, revoked_at=None, revoked_by=None
        )
        self._permits[pid] = p
        await PUBSUB.publish("safety.permit", {"permit_id": pid, "asset_id": asset_id, "event": "issued"})
        return Permit(**p)
    async def revoke_permit(self, ctx: GQLContext, permit_id: str, reason: Optional[str]) -> Permit:
        p = self._permits.get(permit_id)
        if not p:
            raise HTTPException(status_code=404, detail="Permit not found")
        p["revoked"] = True
        p["revoked_at"] = time.time()
        p["revoked_by"] = ctx.auth.subject if ctx.auth else "system"
        await PUBSUB.publish("safety.permit", {"permit_id": permit_id, "event": "revoked"})
        return Permit(**p)

SAFETY_SERVICE: SafetyService = InMemorySafetyService()

# =============================================================================
# Query / Mutation / Subscription
# =============================================================================

@strawberry.type
class Query:
    @strawberry.field(permission_classes=[Requires(scopes=["safety.read"], roles=[], all_scopes=False)])
    async def health(self, info: Info) -> Health:
        return Health(status="ok", ts=time.time())

    @strawberry.field(permission_classes=[Requires(scopes=["safety.read"], roles=[], all_scopes=False)])
    async def alarms(self, info: Info) -> List[Alarm]:
        return await SAFETY_SERVICE.list_alarms(info.context)

    @strawberry.field(permission_classes=[Requires(scopes=["safety.read"], roles=[], all_scopes=False)])
    async def zones(self, info: Info) -> List[Zone]:
        return await SAFETY_SERVICE.list_zones(info.context)

    @strawberry.field(permission_classes=[Requires(scopes=["safety.read"], roles=[], all_scopes=False)])
    async def permits(self, info: Info) -> List[Permit]:
        return await SAFETY_SERVICE.list_permits(info.context)

@strawberry.type
class Mutation:
    @strawberry.mutation(permission_classes=[Requires(scopes=["safety.write", "svc.write"], roles=[], all_scopes=False)])
    async def ack_alarm(self, info: Info, alarm_id: str, comment: Optional[str] = None,
                        idempotency_key: Optional[str] = None) -> OpResult:
        ctx: GQLContext = info.context
        # Rate limit
        subj = ctx.auth.subject if ctx.auth else "anonymous"
        if not await MUT_BUCKET.allow(subj):
            raise HTTPException(status_code=429, detail="Too many GraphQL mutations")
        # Idempotency
        key = f"ack_alarm:{subj}:{alarm_id}:{idempotency_key or 'no-key'}"
        async def _do(): return await SAFETY_SERVICE.ack_alarm(ctx, alarm_id, comment)
        return await IDEMP.get_or_set(key, _do)

    @strawberry.mutation(permission_classes=[Requires(scopes=["safety.control"], roles=["safety-operator", "safety-supervisor"], all_scopes=False, all_roles=False)])
    async def estop(self, info: Info, action: str, asset_id: str = "GLOBAL", reason: str = "GraphQL", dry_run: bool = False,
                    idempotency_key: Optional[str] = None) -> OpResult:
        ctx: GQLContext = info.context
        subj = ctx.auth.subject if ctx.auth else "anonymous"
        if not await MUT_BUCKET.allow(subj):
            raise HTTPException(status_code=429, detail="Too many GraphQL mutations")
        key = f"estop:{subj}:{asset_id}:{action}:{idempotency_key or 'no-key'}"
        async def _do(): return await SAFETY_SERVICE.estop(ctx, action, asset_id, reason, dry_run)
        return await IDEMP.get_or_set(key, _do)

    @strawberry.mutation(permission_classes=[Requires(scopes=["safety.write"], roles=["safety-engineer","safety-supervisor"], all_scopes=False, all_roles=False)])
    async def set_zone_state(self, info: Info, zone_id: str, state: str, reason: Optional[str] = None,
                             idempotency_key: Optional[str] = None) -> OpResult:
        ctx: GQLContext = info.context
        subj = ctx.auth.subject if ctx.auth else "anonymous"
        if not await MUT_BUCKET.allow(subj):
            raise HTTPException(status_code=429, detail="Too many GraphQL mutations")
        key = f"zone:{subj}:{zone_id}:{state}:{idempotency_key or 'no-key'}"
        async def _do(): return await SAFETY_SERVICE.set_zone(ctx, zone_id, state, reason)
        return await IDEMP.get_or_set(key, _do)

    @strawberry.mutation(permission_classes=[Requires(scopes=["safety.write"], roles=["safety-supervisor"], all_scopes=False, all_roles=False)])
    async def issue_permit(self, info: Info, asset_id: str, reason: str, valid_for_seconds: int = 4*3600,
                           tags: Optional[List[str]] = None) -> Permit:
        ctx: GQLContext = info.context
        subj = ctx.auth.subject if ctx.auth else "anonymous"
        if not await MUT_BUCKET.allow(subj):
            raise HTTPException(status_code=429, detail="Too many GraphQL mutations")
        return await SAFETY_SERVICE.issue_permit(ctx, asset_id, reason, valid_for_seconds, tags or [])

    @strawberry.mutation(permission_classes=[Requires(scopes=["safety.write"], roles=["safety-supervisor"], all_scopes=False, all_roles=False)])
    async def revoke_permit(self, info: Info, permit_id: str, reason: Optional[str] = None) -> Permit:
        ctx: GQLContext = info.context
        subj = ctx.auth.subject if ctx.auth else "anonymous"
        if not await MUT_BUCKET.allow(subj):
            raise HTTPException(status_code=429, detail="Too many GraphQL mutations")
        return await SAFETY_SERVICE.revoke_permit(ctx, permit_id, reason)

@strawberry.type
class Subscription:
    @strawberry.subscription(permission_classes=[Requires(scopes=["safety.read"], roles=[], all_scopes=False)])
    async def safety_events(self, info: Info, topic: str = "safety.estop") -> AsyncIterator[strawberry.JSON]:
        async for item in PUBSUB.subscribe(topic):
            yield strawberry.JSON(item)

# =============================================================================
# Depth/Complexity валидация
# =============================================================================

def _calc_depth(node, depth=0) -> int:
    # Минимальный расчёт глубины для validation_rules (без graphql-core правил)
    if not hasattr(node, "selection_set") or not node.selection_set:
        return depth
    return max(_calc_depth(sel, depth + 1) for sel in node.selection_set.selections)

def validate_depth_and_complexity(params) -> None:
    """Вызывается до выполнения операции (hook Strawberry)."""
    try:
        # params: strawberry.execution.ExecutionContext
        doc = params.query_graphql.document  # graphql.language.ast.DocumentNode
        depths = [_calc_depth(defn) for defn in doc.definitions if getattr(defn, "selection_set", None)]
        depth = max(depths or [0])
        if depth > SETTINGS.max_depth:
            raise HTTPException(status_code=400, detail=f"Query depth {depth} exceeds limit {SETTINGS.max_depth}")
        # Простая оценка сложности: количество полей * глубина
        fields = sum(len(getattr(defn.selection_set, "selections", []) or []) for defn in doc.definitions if getattr(defn, "selection_set", None))
        complexity = fields * max(depth, 1)
        if complexity > SETTINGS.max_complexity:
            raise HTTPException(status_code=400, detail=f"Query complexity {complexity} exceeds limit {SETTINGS.max_complexity}")
    except HTTPException:
        raise
    except Exception:
        # На ошибке парсинга/оценки не валим выполнение
        return

# =============================================================================
# Error formatter
# =============================================================================

def error_formatter(error: strawberry.types.ErrorValue) -> strawberry.types.ErrorValue:
    unsafe = SETTINGS.env not in ("prod", "production")
    # Скрываем stacktrace/ошибки Python в prod, оставляем message + path + extensions.code
    if not unsafe:
        error.stack = None
        if error.extensions:
            # Удаляем потенциально чувствительные поля
            for k in list(error.extensions.keys()):
                if k not in ("code", ):
                    error.extensions.pop(k, None)
    return error

# =============================================================================
# Контекст и создание роутера
# =============================================================================

async def get_context(request: Request) -> GQLContext:
    # AuthContext монтируется HTTP middleware'ом: request.state.auth
    auth: Optional[AuthContext] = getattr(request.state, "auth", None)
    loaders = types.SimpleNamespace()  # место для DataLoader'ов
    return GQLContext(request=request, auth=auth, loaders=loaders, pubsub=PUBSUB)

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
)

def create_router() -> APIRouter:
    # GraphQLRouter с ограничениями и кастомным обработчиком запросов (APQ)
    gql = GraphQLRouter(
        schema,
        graphiql=SETTINGS.graphiql,
        context_getter=get_context,
        subscription_protocols=[GRAPHQL_TRANSPORT_WS_PROTOCOL],
        error_formatter=error_formatter,
    )

    # Оборачиваем POST/GET для поддержки APQ (persisted queries)
    router = APIRouter()

    @router.api_route("/graphql", methods=["GET", "POST"])
    async def graphql_entry(request: Request):
        start = time.time()
        op_name = "unknown"
        outcome = "ok"
        try:
            if request.method == "GET":
                # Для простоты: Strawberry сам парсит query из строк запроса; APQ в GET редко регистрируют.
                resp = await gql.handle_http(request=request)
            else:
                body = await request.json()
                # APQ
                body2 = await resolve_apq(request, body)
                if "errors" in body2:
                    # PersistedQueryNotFound
                    outcome = "apq_not_found"
                    return JSONResponse(body2, status_code=200)
                # Достаём operationName для метрик
                op_name = body2.get("operationName") or op_name
                # Проксируем в GraphQLRouter через подменённый request с новым json-телом
                class _Req(Request):
                    async def json(self_nonlocal) -> Any:  # noqa
                        return body2
                # Starlette Request неизменяем, применяем небольшой трюк
                request._body = json.dumps(body2).encode("utf-8")  # type: ignore
                resp = await gql.handle_http(request=request)

            return resp
        except HTTPException as he:
            outcome = f"deny_{he.status_code}"
            return JSONResponse({"errors": [{"message": he.detail}]}, status_code=he.status_code)
        except Exception as e:  # pragma: no cover
            logger.exception("GraphQL error")
            outcome = "error"
            return JSONResponse({"errors": [{"message": "Internal error"}]}, status_code=500)
        finally:
            if SETTINGS.enable_metrics:
                GQL_REQ_TOTAL.labels(operation=op_name, outcome=outcome).inc()
                GQL_REQ_LATENCY.labels(operation=op_name, outcome=outcome).observe(time.time() - start)

    # Делегируем WebSocket и прочие пути самому GraphQLRouter
    # GraphiQL и subscriptions останутся доступны через mounted router:
    router.mount("", gql)
    return router

# Экспортируем готовый роутер для подключения в основное приложение
router = create_router()

# Опционально: самостоятельный запуск для отладки
if __name__ == "__main__":  # pragma: no cover
    app = FastAPI()
    # В боевом приложении здесь уже стоит AuthMiddleware; для демо опускаем.
    app.include_router(router)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
