# zero-trust-core/api/graphql/server.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
import strawberry
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwk, jwt
from jose.utils import base64url_decode
from pydantic import BaseModel, BaseSettings, Field, HttpUrl, PositiveInt
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info

# ===== Optional instrumentation / pubsub =====
try:
    from opentelemetry import trace  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore

try:
    from broadcaster import Broadcast  # type: ignore
except Exception:  # pragma: no cover
    Broadcast = None  # type: ignore

# ===== Internal session store (reuse HTTP module types) =====
# Для самодостаточности импортируем хранилище из session API
try:
    from zero_trust_core.api.http.routers.v1.session import (  # type: ignore
        MemorySessionStore,
        RedisSessionStore,
        SessionBinding,
        SessionData,
        SessionSecurity,
        SessionStore,
    )
except Exception:
    # Фолбэк: локальная минимальная копия интерфейса (на случай иной структуры проекта)
    class SessionStore:  # type: ignore
        async def put(self, s: Any) -> None: ...
        async def get(self, sid: str) -> Optional[Any]: ...
        async def delete(self, sid: str) -> None: ...
        async def touch(self, sid: str, now: int, idle_ttl_s: int) -> Optional[Any]: ...
        async def by_subject(self, subject: str, tenant: Optional[str], limit: int = 100) -> List[Any]: ...
        async def revoke_by_subject(self, subject: str, tenant: Optional[str]) -> int: ...
        async def ping(self) -> bool: ...

    @dataclass
    class SessionBinding:  # type: ignore
        ip: Optional[str] = None
        user_agent: Optional[str] = None
        device_id: Optional[str] = None
        strict: bool = True

    @dataclass
    class SessionSecurity:  # type: ignore
        mfa_level: str = "none"
        step_up_expires_at: Optional[int] = None
        risk_score: float = 0.0
        risk_level: str = "UNKNOWN"

    @dataclass
    class SessionData:  # type: ignore
        id: str = ""
        subject: str = ""
        tenant: Optional[str] = None
        created_at: int = 0
        absolute_expires_at: int = 0
        idle_expires_at: int = 0
        refresh_expires_at: Optional[int] = None
        decision: str = "active"
        binding: SessionBinding = SessionBinding()
        security: SessionSecurity = SessionSecurity()
        attributes: Dict[str, Any] = None
        revoked: bool = False
        last_seen_at: Optional[int] = None

    class MemorySessionStore(SessionStore):  # type: ignore
        def __init__(self) -> None:
            self._data: Dict[str, SessionData] = {}
            self._by_subj: Dict[tuple, set] = {}

        async def put(self, s: SessionData) -> None:
            self._data[s.id] = s
            key = (s.subject, s.tenant)
            self._by_subj.setdefault(key, set()).add(s.id)

        async def get(self, sid: str) -> Optional[SessionData]:
            s = self._data.get(sid)
            if not s:
                return None
            now = int(time.time())
            if s.revoked or now >= s.absolute_expires_at or now >= s.idle_expires_at:
                return None
            return s

        async def delete(self, sid: str) -> None:
            s = self._data.pop(sid, None)
            if s:
                key = (s.subject, s.tenant)
                ids = self._by_subj.get(key)
                if ids:
                    ids.discard(sid)
                    if not ids:
                        self._by_subj.pop(key, None)

        async def touch(self, sid: str, now: int, idle_ttl_s: int) -> Optional[SessionData]:
            s = self._data.get(sid)
            if not s:
                return None
            if s.revoked or now >= s.absolute_expires_at:
                return None
            s.idle_expires_at = now + idle_ttl_s
            s.last_seen_at = now
            return s

        async def by_subject(self, subject: str, tenant: Optional[str], limit: int = 100) -> List[SessionData]:
            out: List[SessionData] = []
            for sid in list(self._by_subj.get((subject, tenant), set()))[:limit]:
                s = await self.get(sid)
                if s:
                    out.append(s)
            return out

        async def revoke_by_subject(self, subject: str, tenant: Optional[str]) -> int:
            ids = list(self._by_subj.get((subject, tenant), set()))
            cnt = 0
            for sid in ids:
                s = self._data.get(sid)
                if s and not s.revoked:
                    s.revoked = True
                    cnt += 1
            return cnt

        async def ping(self) -> bool:
            return True

    RedisSessionStore = None  # type: ignore


# =========================
# Settings
# =========================

class GQLSettings(BaseSettings):
    app_name: str = "zt-graphql"
    bind_host: str = "0.0.0.0"
    bind_port: int = 8081
    debug: bool = False

    cors_allow_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"])

    # JWT/JWKS
    jwt_algorithms: List[str] = Field(default_factory=lambda: ["EdDSA", "ES256", "RS256"])
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    jwks_url: Optional[HttpUrl] = None
    jwks_file: Optional[str] = None
    jwks_cache_ttl: int = 300

    # Session defaults
    session_idle_ttl_s: PositiveInt = 1800
    session_abs_ttl_s: PositiveInt = 8 * 3600
    session_refresh_ttl_s: PositiveInt = 8 * 3600

    # Limits
    max_query_depth: int = 12
    max_execution_ms: int = 1500

    # Pub/Sub
    broadcast_url: Optional[str] = None  # e.g., "redis://localhost:6379/0" or "memory://"

    class Config:
        env_prefix = "ZTC_GQL_"
        case_sensitive = False


# =========================
# Auth / JWKS
# =========================

@dataclass
class Principal:
    subject: Optional[str]
    tenant: Optional[str]
    roles: List[str]
    groups: List[str]
    token: Optional[str]

class JWKSCache:
    def __init__(self, settings: GQLSettings) -> None:
        self.settings = settings
        self._jwks: Optional[Dict[str, Any]] = None
        self._exp: float = 0.0

    async def get(self) -> Dict[str, Any]:
        now = time.time()
        if self._jwks and now < self._exp:
            return self._jwks
        if self.settings.jwks_url:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(str(self.settings.jwks_url))
                r.raise_for_status()
                self._jwks = r.json()
        elif self.settings.jwks_file:
            with open(self.settings.jwks_file, "r", encoding="utf-8") as f:
                self._jwks = json.load(f)
        else:
            raise RuntimeError("JWKS source not configured")
        self._exp = now + self.settings.jwks_cache_ttl
        return self._jwks or {}

async def verify_jwt(settings: GQLSettings, jwks: JWKSCache, token: str) -> Dict[str, Any]:
    unverified = jwt.get_unverified_header(token)
    kid = unverified.get("kid")
    keys = (await jwks.get()).get("keys", [])
    key = next((k for k in keys if k.get("kid") == kid), None) if kid else (keys[0] if keys else None)
    if not key:
        raise HTTPException(status_code=401, detail="unknown key id")

    # jose сам выберет алгоритм по заголовку; ограничим допустимыми
    claims = jwt.decode(
        token,
        key,
        algorithms=settings.jwt_algorithms,
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"verify_aud": settings.jwt_audience is not None, "verify_iss": settings.jwt_issuer is not None},
    )
    return claims

async def context_principal(request: Request, settings: GQLSettings, jwks: JWKSCache) -> Principal:
    auth = request.headers.get("Authorization") or ""
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    subject = None
    tenant = None
    roles: List[str] = []
    groups: List[str] = []
    if token:
        claims = await verify_jwt(settings, jwks, token)
        subject = claims.get("sub")
        tenant = claims.get("tenant")
        roles = claims.get("roles") or claims.get("realm_access", {}).get("roles", []) or []
        groups = claims.get("groups", [])
    return Principal(subject=subject, tenant=tenant, roles=list(roles), groups=list(groups), token=token)


# =========================
# Pub/Sub for audit events
# =========================

class AuditBus:
    def __init__(self, url: Optional[str] = None) -> None:
        self.url = url
        self._broadcast = Broadcast(url) if (Broadcast and url) else None  # type: ignore
        self._queue: asyncio.Queue = asyncio.Queue()

    async def start(self) -> None:
        if self._broadcast:
            await self._broadcast.connect()  # type: ignore

    async def stop(self) -> None:
        if self._broadcast:
            await self._broadcast.disconnect()  # type: ignore

    async def publish(self, event: Dict[str, Any]) -> None:
        data = json.dumps(event)
        if self._broadcast:
            await self._broadcast.publish(channel="audit", message=data)  # type: ignore
        else:
            await self._queue.put(data)

    async def subscribe(self) -> AsyncGenerator[Dict[str, Any], None]:
        if self._broadcast:
            async with self._broadcast.subscribe(channel="audit") as sub:  # type: ignore
                async for m in sub:
                    yield json.loads(m.message)
        else:
            while True:
                data = await self._queue.get()
                yield json.loads(data)


# =========================
# GraphQL types
# =========================

@strawberry.enum
class Decision(str):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MFA_REQUIRED = "MFA_REQUIRED"
    WARN = "WARN"
    QUARANTINE = "QUARANTINE"
    ERROR = "ERROR"

@strawberry.type
class AuthzResult:
    decision: Decision
    reason: Optional[str]
    rules: Optional[List[str]] = None
    latency_ms: int = 0

@strawberry.type
class PrincipalGQL:
    subject: Optional[str]
    tenant: Optional[str]
    roles: List[str]
    groups: List[str]

@strawberry.type
class SessionBindingGQL:
    ip: Optional[str]
    user_agent: Optional[str]
    device_id: Optional[str]
    strict: bool

@strawberry.type
class SessionSecurityGQL:
    mfa_level: str
    step_up_expires_at: Optional[int]
    risk_score: float
    risk_level: str

@strawberry.type
class SessionGQL:
    id: str
    subject: str
    tenant: Optional[str]
    created_at: int
    absolute_expires_at: int
    idle_expires_at: int
    refresh_expires_at: Optional[int]
    decision: str
    binding: SessionBindingGQL
    security: SessionSecurityGQL
    attributes: strawberry.scalars.JSON
    revoked: bool
    last_seen_at: Optional[int]


# =========================
# Helpers
# =========================

def _now() -> int:
    return int(time.time())

def _client_ip(req: Request) -> Optional[str]:
    xf = req.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    return req.client.host if req.client else None

def _ua(req: Request) -> Optional[str]:
    return req.headers.get("User-Agent")

def _to_gql_session(s: SessionData) -> SessionGQL:
    return SessionGQL(
        id=s.id,
        subject=s.subject,
        tenant=s.tenant,
        created_at=s.created_at,
        absolute_expires_at=s.absolute_expires_at,
        idle_expires_at=s.idle_expires_at,
        refresh_expires_at=s.refresh_expires_at,
        decision=s.decision,
        binding=SessionBindingGQL(
            ip=s.binding.ip, user_agent=s.binding.user_agent, device_id=s.binding.device_id, strict=s.binding.strict
        ),
        security=SessionSecurityGQL(
            mfa_level=s.security.mfa_level,
            step_up_expires_at=s.security.step_up_expires_at,
            risk_score=s.security.risk_score,
            risk_level=s.security.risk_level,
        ),
        attributes=s.attributes or {},
        revoked=s.revoked,
        last_seen_at=s.last_seen_at,
    )

def _authz_minimal(roles: List[str], resource_id: str, action: str, explain: bool = False) -> AuthzResult:
    start = time.perf_counter()
    rules: List[str] = []
    decision = Decision.DENY
    reason = "no matching rule"

    if "admin" in roles:
        decision, reason = Decision.ALLOW, "role admin"
        rules.append("role:admin -> *")
    elif "developer" in roles and action.lower() in ("read", "get", "list") and resource_id.startswith("service:"):
        decision, reason = Decision.ALLOW, "developer read on service:*"
        rules.append("role:developer -> read service:*")
    elif "auditor" in roles and action.lower() in ("read", "get", "list") and resource_id.startswith("audit:"):
        decision, reason = Decision.ALLOW, "auditor read on audit:*"
        rules.append("role:auditor -> read audit:*")

    latency = int((time.perf_counter() - start) * 1000)
    return AuthzResult(decision=decision, reason=reason, rules=rules if explain else None, latency_ms=latency)


# =========================
# GraphQL schema
# =========================

@strawberry.type
class Health:
    ok: bool
    app: str
    now: int
    store: str

@strawberry.type
class Query:
    @strawberry.field
    async def health(self, info: Info) -> Health:
        app: FastAPI = info.context["app"]
        store: SessionStore = info.context["store"]
        ok = await store.ping()
        return Health(ok=ok, app=app.state.settings.app_name, now=_now(), store=store.__class__.__name__)

    @strawberry.field
    async def me(self, info: Info) -> PrincipalGQL:
        p: Principal = info.context["principal"]
        return PrincipalGQL(subject=p.subject, tenant=p.tenant, roles=p.roles, groups=p.groups)

    @strawberry.field
    async def session(self, info: Info, id: str) -> Optional[SessionGQL]:
        store: SessionStore = info.context["store"]
        s = await store.get(id)
        return _to_gql_session(s) if s else None

    @strawberry.field
    async def sessions(self, info: Info, subject: str, tenant: Optional[str] = None, limit: int = 100) -> List[SessionGQL]:
        store: SessionStore = info.context["store"]
        xs = await store.by_subject(subject, tenant, limit=limit)
        return [_to_gql_session(s) for s in xs]

    @strawberry.field
    async def authz(
        self,
        info: Info,
        resource_id: str,
        action: str,
        explain: bool = False,
    ) -> AuthzResult:
        p: Principal = info.context["principal"]
        return _authz_minimal(p.roles, resource_id, action, explain)


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def create_session(
        self,
        info: Info,
        subject: str,
        tenant: Optional[str] = None,
        device_id: Optional[str] = None,
        attributes: strawberry.scalars.JSON = None,
        idle_ttl_seconds: int = None,
        absolute_ttl_seconds: int = None,
        refresh_ttl_seconds: int = None,
        strict_binding: bool = True,
    ) -> SessionGQL:
        request: Request = info.context["request"]
        store: SessionStore = info.context["store"]
        settings: GQLSettings = info.context["settings"]
        bus: AuditBus = info.context["audit_bus"]

        now = _now()
        import secrets
        sid = secrets.token_urlsafe(18)
        s = SessionData(
            id=sid,
            subject=subject,
            tenant=tenant,
            created_at=now,
            absolute_expires_at=now + int(absolute_ttl_seconds or settings.session_abs_ttl_s),
            idle_expires_at=now + int(idle_ttl_seconds or settings.session_idle_ttl_s),
            refresh_expires_at=now + int(refresh_ttl_seconds or settings.session_refresh_ttl_s),
            binding=SessionBinding(
                ip=_client_ip(request),
                user_agent=_ua(request),
                device_id=device_id,
                strict=bool(strict_binding),
            ),
            security=SessionSecurity(),
            attributes=dict(attributes or {}),
            revoked=False,
            last_seen_at=now,
        )
        await store.put(s)
        await bus.publish({"cat": "SESSION", "act": "CREATE", "sid": s.id, "sub": s.subject, "ts": now})
        return _to_gql_session(s)

    @strawberry.mutation
    async def bind_session(
        self,
        info: Info,
        id: str,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_id: Optional[str] = None,
        strict: Optional[bool] = None,
    ) -> SessionGQL:
        request: Request = info.context["request"]
        store: SessionStore = info.context["store"]
        bus: AuditBus = info.context["audit_bus"]
        s = await store.get(id)
        if not s:
            raise HTTPException(status_code=404, detail="session not found")
        s.binding.ip = ip or _client_ip(request) or s.binding.ip
        s.binding.user_agent = user_agent or _ua(request) or s.binding.user_agent
        s.binding.device_id = device_id or s.binding.device_id
        if strict is not None:
            s.binding.strict = bool(strict)
        s.last_seen_at = _now()
        # продлим только idle окно в текущих границах
        idle_window = max(60, s.idle_expires_at - _now())
        await store.touch(s.id, _now(), idle_window)
        await store.put(s)
        await bus.publish({"cat": "SESSION", "act": "BIND", "sid": s.id, "ts": _now()})
        return _to_gql_session(s)

    @strawberry.mutation
    async def step_up_session(self, info: Info, id: str, mfa_level: str = "webauthn", ttl_seconds: int = 3600) -> SessionGQL:
        store: SessionStore = info.context["store"]
        bus: AuditBus = info.context["audit_bus"]
        s = await store.get(id)
        if not s:
            raise HTTPException(status_code=404, detail="session not found")
        now = _now()
        s.security.mfa_level = mfa_level
        s.security.step_up_expires_at = now + int(ttl_seconds)
        s.last_seen_at = now
        await store.put(s)
        await bus.publish({"cat": "SESSION", "act": "STEP_UP", "sid": s.id, "ts": now})
        return _to_gql_session(s)

    @strawberry.mutation
    async def refresh_session(
        self,
        info: Info,
        id: str,
        rebind_ip: Optional[str] = None,
        rebind_user_agent: Optional[str] = None,
        rebind_device_id: Optional[str] = None,
    ) -> SessionGQL:
        store: SessionStore = info.context["store"]
        bus: AuditBus = info.context["audit_bus"]
        s = await store.get(id)
        if not s:
            raise HTTPException(status_code=404, detail="session not found")
        now = _now()
        if s.refresh_expires_at and now >= s.refresh_expires_at:
            raise HTTPException(status_code=401, detail="refresh expired")
        import secrets
        new_id = secrets.token_urlsafe(18)
        s_new = SessionData(
            **{**s.__dict__, "id": new_id}  # копируем поля
        )
        if rebind_ip:
            s_new.binding.ip = rebind_ip
        if rebind_user_agent:
            s_new.binding.user_agent = rebind_user_agent
        if rebind_device_id:
            s_new.binding.device_id = rebind_device_id
        s_new.last_seen_at = now
        s_new.idle_expires_at = now + max(60, s.idle_expires_at - now)
        await store.put(s_new)
        await store.delete(s.id)
        await bus.publish({"cat": "SESSION", "act": "REFRESH", "old": s.id, "sid": s_new.id, "ts": now})
        return _to_gql_session(s_new)

    @strawberry.mutation
    async def revoke_session(self, info: Info, id: Optional[str] = None, subject: Optional[str] = None) -> bool:
        store: SessionStore = info.context["store"]
        bus: AuditBus = info.context["audit_bus"]
        if id:
            s = await store.get(id)
            if not s:
                return True
            s.revoked = True
            await store.put(s)
            await bus.publish({"cat": "SESSION", "act": "REVOKE", "sid": s.id, "ts": _now()})
            return True
        if subject:
            n = await store.revoke_by_subject(subject, None)
            await bus.publish({"cat": "SESSION", "act": "REVOKE_SUBJECT", "sub": subject, "count": n, "ts": _now()})
            return True
        raise HTTPException(status_code=400, detail="id or subject required")

    @strawberry.mutation
    async def update_session_attributes(self, info: Info, id: str, attributes: strawberry.scalars.JSON) -> SessionGQL:
        store: SessionStore = info.context["store"]
        s = await store.get(id)
        if not s:
            raise HTTPException(status_code=404, detail="session not found")
        s.attributes = dict(attributes or {})
        s.last_seen_at = _now()
        await store.put(s)
        return _to_gql_session(s)


# =========================
# Subscriptions
# =========================

@strawberry.type
class AuditEvent:
    cat: str
    act: str
    ts: int
    sid: Optional[str] = None
    sub: Optional[str] = None
    old: Optional[str] = None
    count: Optional[int] = None

@strawberry.type
class Subscription:
    @strawberry.subscription
    async def audit_events(self, info: Info, subject: Optional[str] = None) -> AsyncGenerator[AuditEvent, None]:
        bus: AuditBus = info.context["audit_bus"]
        async for ev in bus.subscribe():
            if subject and ev.get("sub") != subject:
                continue
            yield AuditEvent(**{k: v for k, v in ev.items() if k in AuditEvent.__annotations__})


# =========================
# Execution limits (depth / time)
# =========================

from graphql import parse, visit

def calc_depth(query: str) -> int:
    max_depth = 0
    stack = [0]
    def enter(node, *args):
        nonlocal max_depth
        name = node.__class__.__name__
        if name == "Field" or name == "InlineFragment" or name == "FragmentDefinition" or name == "OperationDefinition":
            stack.append(stack[-1] + 1)
            max_depth = max(max_depth, stack[-1])
    def leave(node, *args):
        name = node.__class__.__name__
        if name in {"Field","InlineFragment","FragmentDefinition","OperationDefinition"}:
            stack.pop()
    try:
        ast = parse(query)
        visit(ast, enter=enter, leave=leave)
    except Exception:
        return 0
    return max_depth

class TimeoutCancel(Exception):
    pass

@asynccontextmanager
async def execution_guard(settings: GQLSettings, query: str):
    depth = calc_depth(query)
    if depth > settings.max_query_depth:
        raise HTTPException(status_code=400, detail=f"query depth {depth} exceeds limit {settings.max_query_depth}")
    loop = asyncio.get_event_loop()
    handle = loop.call_later(settings.max_execution_ms / 1000.0, lambda: (_ for _ in ()).throw(TimeoutCancel()))  # type: ignore
    try:
        yield
    finally:
        handle.cancel()


# =========================
# App factory
# =========================

def make_schema() -> strawberry.Schema:
    return strawberry.Schema(
        query=Query,
        mutation=Mutation,
        subscription=Subscription,
    )

def tracer_span(name: str):
    if not trace:
        class _Noop:
            def __enter__(self): return None
            def __exit__(self, *a): return False
        return _Noop()
    return trace.get_tracer("zt-graphql").start_as_current_span(name)  # type: ignore

def create_app() -> FastAPI:
    settings = GQLSettings()
    logger = logging.getLogger("zt.gql")
    logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')

    app = FastAPI(title="Zero Trust GraphQL", version="1.0")
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        max_age=600,
    )

    # Stores
    store: SessionStore
    if RedisSessionStore and os.getenv("REDIS_URL"):
        try:
            from redis import asyncio as aioredis  # type: ignore
            client = aioredis.from_url(os.environ["REDIS_URL"], encoding="utf-8", decode_responses=False)
            store = RedisSessionStore(client)  # type: ignore
        except Exception as e:  # pragma: no cover
            logger.warning("redis unavailable, use memory: %s", e)
            store = MemorySessionStore()
    else:
        store = MemorySessionStore()
    app.state.session_store = store

    # JWKS cache
    jwks_cache = JWKSCache(settings)
    app.state.jwks_cache = jwks_cache

    # Audit bus
    bus = AuditBus(settings.broadcast_url or "memory://")
    app.state.audit_bus = bus

    @app.on_event("startup")
    async def _startup():
        await bus.start()
        logger.info("GraphQL ready on /graphql (debug=%s)", settings.debug)

    @app.on_event("shutdown")
    async def _shutdown():
        await bus.stop()

    schema = make_schema()

    async def get_context_fn(request: Request) -> Dict[str, Any]:
        with tracer_span("context"):
            principal = await context_principal(request, settings, jwks_cache)
            return {
                "request": request,
                "app": app,
                "settings": settings,
                "store": app.state.session_store,
                "principal": principal,
                "audit_bus": app.state.audit_bus,
            }

    async def process_result(request: Request, result):
        return result

    graphql_app = GraphQLRouter(
        schema,
        context_getter=get_context_fn,
        graphiql=settings.debug,
        process_result=process_result,
    )

    # Wrap route to enforce depth/timeout
    @graphql_app.router.middleware("http")
    async def _guard(request: Request, call_next):
        if request.method == "POST" and request.url.path.endswith("/graphql"):
            try:
                body = await request.json()
            except Exception:
                body = {}
            query = (body.get("query") or "").strip()
            try:
                async with execution_guard(settings, query):
                    return await call_next(request)
            except TimeoutCancel:
                return Response(status_code=408, content=json.dumps({"errors":[{"message":"execution timeout"}]}), media_type="application/json")
            except HTTPException as he:
                return Response(status_code=he.status_code, content=json.dumps({"errors":[{"message":he.detail}]}), media_type="application/json")
        return await call_next(request)

    app.include_router(graphql_app, prefix="/graphql")

    @app.get("/health")
    async def health():
        ok = await store.ping()
        return {"ok": ok, "app": settings.app_name, "now": _now(), "store": store.__class__.__name__}

    return app


# Entrypoint
if __name__ == "__main__":
    import uvicorn
    app = create_app()
    s: GQLSettings = app.state.settings
    uvicorn.run("zero_trust_core.api.graphql.server:create_app", factory=True,
                host=s.bind_host, port=s.bind_port, reload=False)
