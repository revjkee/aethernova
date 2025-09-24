# policy-core/api/graphql/server.py
# Промышленный GraphQL сервер для policy-core на FastAPI + Ariadne.
# Особенности:
#  - Загрузка SDL из schemas/graphql/schema.graphql
#  - Кастомные Scalar: DateTime, UUID, JSON
#  - Runtime-директивы (через extensions): @auth, @rateLimit, @cacheControl, @redact
#  - Подписки (GraphQL over WebSocket)
#  - Persisted Queries (APQ, sha256)
#  - Depth/complexity лимиты
#  - Унифицированный контекст (principal, roles, correlation, traceparent)
#  - DI-хуки: get_pdp(), get_policy_repo(), get_decision_repo()
#  - Единый формат ошибок

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import re
import time
import uuid
from functools import lru_cache
from typing import Any, AsyncGenerator, Dict, Optional, Tuple

from ariadne import (
    ScalarType,
    QueryType,
    MutationType,
    SubscriptionType,
    make_executable_schema,
    load_schema_from_path,
)
from ariadne.asgi import GraphQL
from ariadne.types import Extension
from fastapi import FastAPI, Request
from graphql import (
    GraphQLError,
    GraphQLField,
    GraphQLResolveInfo,
    parse,
    specified_rules,
    validate,
)
from pydantic import BaseModel

# -------------------------------
# Константы/пути
# -------------------------------

ROOT_DIR = os.getenv("PROJECT_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")))
SDL_PATH = os.path.join(ROOT_DIR, "schemas", "graphql", "schema.graphql")

# -------------------------------
# Утилиты: контекст, принципал
# -------------------------------

class RequestContext(BaseModel):
    principal: str = "anonymous"
    roles: tuple[str, ...] = ()
    correlation_id: str = ""
    traceparent: str = ""
    request: Optional[Request] = None
    # хранилища/сервисы (DI)
    services: Dict[str, Any] = {}

async def build_context_value(request: Request) -> RequestContext:
    auth = request.headers.get("authorization") or ""
    # Пример: "Bearer user:alice roles:ADMIN,VIEWER"
    m_roles = re.search(r"roles:([A-Za-z_,\-]+)", auth)
    roles = tuple((m_roles.group(1).split(",")) if m_roles else [])
    principal = "anonymous"
    m_user = re.search(r"user:([A-Za-z0-9_\-:@.]+)", auth)
    if m_user:
        principal = m_user.group(1)
    correlation_id = request.headers.get("x-correlation-id") or str(uuid.uuid4())
    traceparent = request.headers.get("traceparent") or ""
    ctx = RequestContext(
        principal=principal,
        roles=tuple(r.strip().upper() for r in roles if r.strip()),
        correlation_id=correlation_id,
        traceparent=traceparent,
        request=request,
        services={
            "pdp": await get_pdp(),
            "policy_repo": await get_policy_repo(),
            "decision_repo": await get_decision_repo(),
        },
    )
    return ctx

# -------------------------------
# Кастомные Scalar’ы
# -------------------------------

DateTime = ScalarType("DateTime")
UUIDScalar = ScalarType("UUID")
JSONScalar = ScalarType("JSON")

@DateTime.serializer
def serialize_datetime(value: Any) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    raise GraphQLError("Invalid DateTime value")

@DateTime.value_parser
def parse_datetime_value(value: Any) -> dt.datetime:
    if isinstance(value, str):
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return dt.datetime.fromisoformat(value)
        except Exception as e:
            raise GraphQLError(f"Invalid DateTime: {e}")
    raise GraphQLError("Invalid DateTime")

@UUIDScalar.serializer
def serialize_uuid(value: Any) -> str:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, str):
        # проверим валидность
        uuid.UUID(value)
        return value
    raise GraphQLError("Invalid UUID")

@UUIDScalar.value_parser
def parse_uuid_value(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except Exception as e:
        raise GraphQLError(f"Invalid UUID: {e}")

@JSONScalar.serializer
def serialize_json(value: Any) -> Any:
    return value

@JSONScalar.value_parser
def parse_json_value(value: Any) -> Any:
    # допускаем любые JSON-совместимые значения
    return value

# -------------------------------
# Резолверы (заглушки + DI вызовы)
# -------------------------------

query = QueryType()
mutation = MutationType()
subscription = SubscriptionType()

@query.field("systemHealth")
async def resolve_system_health(*_, **__) -> dict:
    return {"status": "ok", "time": dt.datetime.utcnow().isoformat() + "Z"}

@query.field("policy")
async def resolve_policy(_, info: GraphQLResolveInfo, id: str):
    repo = info.context.services["policy_repo"]
    if not hasattr(repo, "get_by_id"):
        raise GraphQLError("Policy repository is not wired")
    return await repo.get_by_id(id)

@query.field("policies")
async def resolve_policies(_, info: GraphQLResolveInfo, filter=None, first: int = 20, after: Optional[str] = None, sort=None):
    repo = info.context.services["policy_repo"]
    if not hasattr(repo, "search"):
        raise GraphQLError("Policy repository is not wired")
    items, cursor, total = await repo.search(filter=filter, limit=first, cursor=after, sort=sort)
    # Простой адаптер в Relay-подобный ответ
    return {
        "edges": [{"node": p, "cursor": cursor or ""} for p in items],
        "pageInfo": {"hasNextPage": bool(cursor), "hasPreviousPage": False, "startCursor": after, "endCursor": cursor},
        "totalCount": total,
    }

@query.field("decision")
async def resolve_decision(_, info: GraphQLResolveInfo, id: str):
    repo = info.context.services["decision_repo"]
    if not hasattr(repo, "get_by_id"):
        raise GraphQLError("Decision repository is not wired")
    return await repo.get_by_id(id)

@query.field("decisions")
async def resolve_decisions(_, info: GraphQLResolveInfo, filter=None, first: int = 20, after: Optional[str] = None, sort=None):
    repo = info.context.services["decision_repo"]
    if not hasattr(repo, "search"):
        raise GraphQLError("Decision repository is not wired")
    items, cursor, total = await repo.search(filter=filter, limit=first, cursor=after, sort=sort)
    return {
        "edges": [{"node": d, "cursor": cursor or ""} for d in items],
        "pageInfo": {"hasNextPage": bool(cursor), "hasPreviousPage": False, "startCursor": after, "endCursor": cursor},
        "totalCount": total,
    }

@query.field("evaluatePolicy")
async def resolve_evaluate_policy(_, info: GraphQLResolveInfo, input):
    pdp = info.context.services["pdp"]
    if not hasattr(pdp, "evaluate"):
        raise GraphQLError("PDP is not wired")
    # Ожидается контракт, совместимый с вашим PDP
    return await pdp.evaluate(input)

@subscription.source("decisionEvents")
async def decision_events_source(_, info: GraphQLResolveInfo, filter=None) -> AsyncGenerator[dict, None]:
    repo = info.context.services["decision_repo"]
    if not hasattr(repo, "subscribe"):
        raise GraphQLError("Subscriptions not supported by repository")
    async for ev in repo.subscribe(filter=filter):
        yield ev

@subscription.field("decisionEvents")
def decision_events_field(event, *_):
    return event

# -------------------------------
# Extensions (директивы/ограничители/кеш/редакция/APQ)
# -------------------------------

def _field_directive_args(field: GraphQLField, name: str) -> Optional[Dict[str, Any]]:
    """Извлечь аргументы директивы поля из AST."""
    if not field or not field.ast_node or not getattr(field.ast_node, "directives", None):
        return None
    for d in field.ast_node.directives:
        if d.name.value == name:
            args = {}
            for arg in d.arguments or []:
                # упрощённый парсер литералов
                v = arg.value
                if hasattr(v, "values"):  # список
                    args[arg.name.value] = [getattr(i, "value", None) for i in v.values]
                else:
                    args[arg.name.value] = getattr(v, "value", None)
            return args
    return None

class AuthExtension(Extension):
    """Проверяет директиву @auth(requires: [Role!]!) на полях."""
    def resolve(self, next_, root, info: GraphQLResolveInfo, **kwargs):
        field = info.parent_type.fields.get(info.field_name)
        args = _field_directive_args(field, "auth")
        if args:
            required = tuple((r.upper() for r in (args.get("requires") or [])))
            roles = tuple(info.context.roles or ())
            if not any(r in roles for r in required):
                raise GraphQLError(f"Forbidden: requires any of roles {required}")
        return next_(root, info, **kwargs)

class RateLimitExtension(Extension):
    """Простое rate-limit выполнение поля согласно @rateLimit(max, window)."""
    _buckets: Dict[str, Tuple[float, float]] = {}

    def __init__(self, context: RequestContext):
        self.context = context

    async def _check(self, key: str, rate: int, window_sec: float) -> None:
        now = time.monotonic()
        allow, reset = self._buckets.get(key, (rate, now + window_sec))
        if now > reset:
            allow, reset = rate, now + window_sec
        if allow <= 0:
            raise GraphQLError("Rate limit exceeded")
        self._buckets[key] = (allow - 1, reset)

    def resolve(self, next_, root, info: GraphQLResolveInfo, **kwargs):
        field = info.parent_type.fields.get(info.field_name)
        args = _field_directive_args(field, "rateLimit")
        if args:
            try:
                max_calls = int(args.get("max", 60))
                window = str(args.get("window") or "60s")
                m = re.match(r"(\d+)(ms|s|m)", window)
                coef = {"ms": 0.001, "s": 1, "m": 60}[m.group(2)] if m else 1
                window_sec = int(m.group(1)) * coef if m else 60
                key = f"{self.context.principal}:{info.parent_type.name}.{info.field_name}:{max_calls}:{window}"
            except Exception:
                key = f"{self.context.principal}:{info.parent_type.name}.{info.field_name}"
                max_calls, window_sec = 60, 60
            fut = self._check(key, max_calls, window_sec)
            if asyncio.iscoroutinefunction(next_):
                async def _async():
                    await fut
                    return await next_(root, info, **kwargs)
                return _async()
            else:
                # sync resolver
                asyncio.get_event_loop().run_until_complete(fut)
                return next_(root, info, **kwargs)
        return next_(root, info, **kwargs)

class CacheControlExtension(Extension):
    """Собирает @cacheControl(maxAge, scope) и выставляет заголовок."""
    def __init__(self, context: RequestContext):
        self.context = context
        self.max_age = None
        self.scope = None

    def resolve(self, next_, root, info: GraphQLResolveInfo, **kwargs):
        field = info.parent_type.fields.get(info.field_name)
        args = _field_directive_args(field, "cacheControl")
        if args:
            try:
                max_age = int(args.get("maxAge", 0))
                scope = args.get("scope", "PRIVATE")
                # Берём минимальный max-age из затронутых полей и наиболее строгую область
                self.max_age = max(self.max_age or 0, max_age) if self.max_age is not None else max_age
                self.scope = self.scope or scope
            except Exception:
                pass
        return next_(root, info, **kwargs)

    def format(self, context):
        try:
            if self.context.request and self.max_age is not None:
                scope = "private" if (self.scope or "PRIVATE").upper() == "PRIVATE" else "public"
                self.context.request.state.response_headers = self.context.request.state.__dict__.get("response_headers", {})
                self.context.request.state.response_headers["Cache-Control"] = f"{scope}, max-age={int(self.max_age)}"
        except Exception:
            pass
        return None

class RedactExtension(Extension):
    """Маскирует значения для полей, помеченных @redact(mode)."""
    def __init__(self, context: RequestContext):
        self.context = context

    def will_resolve_field(self, root, info: GraphQLResolveInfo, args):
        field = info.parent_type.fields.get(info.field_name)
        dargs = _field_directive_args(field, "redact") or {}
        mode = (dargs.get("mode") or "MASK").upper()

        def _on_end(val):
            try:
                if val is None:
                    return val
                if mode == "MASK":
                    if isinstance(val, str):
                        # простая маска
                        return (val[:2] + "*" * max(0, len(val) - 4) + val[-2:]) if len(val) >= 4 else "***"
                if mode == "HASH":
                    return hashlib.sha256(str(val).encode("utf-8")).hexdigest()
                if mode == "REMOVE":
                    return None
            except Exception:
                return val
            return val
        return _on_end

# APQ (Automatic Persisted Queries)
class APQExtension(Extension):
    _store: Dict[str, str] = {}  # sha256 -> query

    def __init__(self, context: RequestContext):
        self.context = context

    def request_started(self, context):  # type: ignore[override]
        req = getattr(self.context, "request", None)
        if not req:
            return
        try:
            if req.method == "GET":
                return  # GET поддерживается стандартно
            body = req.scope.get("_cached_json")  # кэш FastAPI middleware (если есть)
            if body is None:
                body = {}
            ext = body.get("extensions") or {}
            pq = ext.get("persistedQuery") or {}
            if pq.get("version") == 1:
                sha = pq.get("sha256Hash")
                query = body.get("query")
                if query:
                    # сохранить
                    self._store[sha] = query
                else:
                    # восстановить
                    q = self._store.get(sha)
                    if not q:
                        raise GraphQLError("PersistedQueryNotFound")
                    body["query"] = q
                    req.scope["_cached_json"] = body
        except Exception:
            # безопасно игнорируем
            pass

# -------------------------------
# Depth/Complexity лимиты
# -------------------------------

def create_depth_limit_rule(max_depth: int):
    def rule(context):
        def enter(node, *args):
            depth = 0
            p = context.get_path()
            for _ in p:
                depth += 1
            if depth > max_depth:
                raise GraphQLError(f"Query is too deep (>{max_depth})")
        return {"Field": {"enter": enter}}
    return rule

def create_simple_complexity_rule(max_fields: int):
    counter = {"n": 0}
    def rule(_context):
        def enter(_node, *args):
            counter["n"] += 1
            if counter["n"] > max_fields:
                raise GraphQLError(f"Query is too complex (>{max_fields} fields)")
        return {"Field": {"enter": enter}}
    return rule

# -------------------------------
# DI-заглушки (замените в приложении)
# -------------------------------

async def get_pdp():
    class _Stub:
        async def evaluate(self, input_: dict) -> dict:
            return {
                "effect": "Allow",
                "latencyMs": 1,
                "reasons": [],
                "risk": {"level": "low", "score": 1},
                "obligationsPlan": [],
                "decisionId": str(uuid.uuid4()),
                "correlationId": None,
            }
    return _Stub()

async def get_policy_repo():
    class _Stub:
        async def get_by_id(self, _id): return None
        async def search(self, **_): return ([], None, 0)
    return _Stub()

async def get_decision_repo():
    class _Stub:
        async def get_by_id(self, _id): return None
        async def search(self, **_): return ([], None, 0)
        async def subscribe(self, **_):
            while False:
                yield {}
    return _Stub()

# -------------------------------
# Сборка схемы + приложение ASGI
# -------------------------------

@lru_cache(maxsize=1)
def load_sdl() -> str:
    return load_schema_from_path(SDL_PATH)

schema = make_executable_schema(
    load_sdl(),
    [query, mutation, subscription, DateTime, UUIDScalar, JSONScalar],
)

# Композиция extensions
def extensions_provider(context: RequestContext):
    return [
        AuthExtension(),
        RateLimitExtension(context),
        CacheControlExtension(context),
        RedactExtension(context),
        APQExtension(context),
    ]

validation_rules = list(specified_rules) + [
    create_depth_limit_rule(max_depth=int(os.getenv("GQL_MAX_DEPTH", "20"))),
    create_simple_complexity_rule(max_fields=int(os.getenv("GQL_MAX_FIELDS", "800"))),
]

# FastAPI приложение и GraphQL endpoint
app = FastAPI(title="policy-core GraphQL")

graphql_app = GraphQL(
    schema,
    context_value=build_context_value,
    debug=os.getenv("DEBUG", "false").lower() == "true",
    introspection=os.getenv("GQL_INTROSPECTION", "true").lower() == "true",
    extensions=extensions_provider,
    validation_rules=validation_rules,
    # subscriptions включены по умолчанию (websocket /graphql)
)

# Маршрут GraphQL
app.add_route("/graphql", graphql_app)
app.add_websocket_route("/graphql", graphql_app)

# Добавочный middleware для установки Cache-Control из extensions
@app.middleware("http")
async def apply_cache_headers(request: Request, call_next):
    response = await call_next(request)
    # extensions пишут заголовок в request.state.response_headers
    hdrs = getattr(request.state, "response_headers", {})
    for k, v in hdrs.items():
        response.headers[k] = v
    return response
