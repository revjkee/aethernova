# File: veilmind-core/api/graphql/server.py
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import typing as t
from dataclasses import dataclass
from datetime import datetime, timezone

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, HTMLResponse, Response
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

# Optional OpenTelemetry middleware
try:
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
    _HAS_OTEL = True
except Exception:
    _HAS_OTEL = False

# Prometheus metrics (optional, but recommended)
try:
    from prometheus_client import Counter, Histogram, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
    _REG = CollectorRegistry()
    GQL_REQS = Counter("gql_requests_total", "GraphQL requests", ["op", "tenant", "status"], registry=_REG)
    GQL_ERRS = Counter("gql_errors_total", "GraphQL errors", ["op", "tenant", "type"], registry=_REG)
    GQL_LAT = Histogram(
        "gql_request_latency_seconds",
        "GraphQL latency seconds",
        ["op", "tenant"],
        registry=_REG,
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

# GraphQL/Strawberry
import strawberry
from strawberry.types import Info
from strawberry.dataloader import DataLoader
from graphql import GraphQLSchema, parse, DocumentNode  # for depth/complexity checks

# Reuse auth/service contracts from HTTP layer (if present)
try:
    from veilmind_core.api.http.routers.v1.dp import (
        DPAccountantService,
        InMemoryDPAccountantService,
        Actor,
        make_hmac as _make_hmac,
    )
except Exception:
    # Minimal fallbacks if HTTP layer is not installed
    @dataclass
    class Actor:
        subject: str
        tenant_id: t.Optional[str]
        scopes: t.List[str]
        mTLS: bool = False

    class DPAccountantService:  # type: ignore[override]
        async def list_pipelines(self) -> t.List[str]: ...
        async def get_budget(self, tenant: str) -> t.Any: ...
        async def estimate(self, use: t.Any, actor: Actor) -> t.Tuple[float, float, t.Dict[str, t.Any]]: ...
        async def charge(self, use: t.Any, actor: Actor) -> t.Tuple[float, float, t.Dict[str, t.Any]]: ...
        async def get_audit(self, event_id: str, actor: Actor) -> t.Optional[t.Dict[str, t.Any]]: ...

    class InMemoryDPAccountantService(DPAccountantService):
        async def list_pipelines(self) -> t.List[str]:
            return ["public_metrics_daily"]
        async def get_budget(self, tenant: str) -> t.Any:
            return {"tenant": tenant, "windows": []}
        async def estimate(self, use: t.Any, actor: Actor) -> t.Tuple[float, float, t.Dict[str, t.Any]]:
            return 0.1, 1e-8, {"mock": True}
        async def charge(self, use: t.Any, actor: Actor) -> t.Tuple[float, float, t.Dict[str, t.Any]]:
            return 0.1, 1e-8, {"mock": True}
        async def get_audit(self, event_id: str, actor: Actor) -> t.Optional[t.Dict[str, t.Any]]:
            return None

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ------------------------------------------------------------------------------
# Configuration via environment
# ------------------------------------------------------------------------------
DEBUG = os.getenv("GQL_DEBUG", "false").lower() in ("1", "true", "yes")
GRAPHQL_PATH = os.getenv("GQL_PATH", "/graphql")
GRAPHIQL_ENABLED = os.getenv("GQL_GRAPHIQL", "false").lower() in ("1", "true")
CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("GQL_CORS_ORIGINS", "").split(",") if o.strip()]
HMAC_KEY = os.getenv("GQL_HMAC_KEY", "")  # for response integrity header
MAX_QUERY_BYTES = int(os.getenv("GQL_MAX_QUERY_BYTES", "200000"))  # ~200 KB
REQ_TIMEOUT_SEC = float(os.getenv("GQL_REQ_TIMEOUT_SEC", "5.0"))
MAX_DEPTH = int(os.getenv("GQL_MAX_DEPTH", "10"))
MAX_COMPLEXITY = int(os.getenv("GQL_MAX_COMPLEXITY", "2000"))

# Rate limiting
DEFAULT_RPS = float(os.getenv("GQL_TENANT_RPS", "50"))
BURST_MULTIPLIER = float(os.getenv("GQL_BURST_MULTIPLIER", "2"))

# APQ (Automatic Persisted Queries)
APQ_ENABLED = os.getenv("GQL_APQ_ENABLED", "true").lower() in ("1", "true")
APQ_TTL_SEC = int(os.getenv("GQL_APQ_TTL_SEC", "86400"))
APQ_ALLOW_REGISTER = os.getenv("GQL_APQ_ALLOW_REGISTER", "true").lower() in ("1", "true")
REDIS_URL = os.getenv("REDIS_URL", "")

# ------------------------------------------------------------------------------
# Utilities: HMAC, token bucket, APQ storage
# ------------------------------------------------------------------------------

def make_hmac(payload: t.Dict[str, t.Any]) -> str:
    key = HMAC_KEY or ""
    if not key:
        # fallback to HTTP layer's HMAC if configured there
        try:
            return _make_hmac(payload)  # type: ignore
        except Exception:
            return ""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()

class TokenBucket:
    def __init__(self, rps: float, burst: float) -> None:
        self.rate = max(0.1, rps)
        self.capacity = max(self.rate, burst)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        dt = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + dt * self.rate)
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

class RateLimiter:
    def __init__(self, default_rps: float, burst_mul: float) -> None:
        self.default_rps = default_rps
        self.burst_mul = burst_mul
        self.buckets: dict[str, TokenBucket] = {}

    def check(self, key: str) -> bool:
        b = self.buckets.get(key)
        if not b:
            b = self.buckets[key] = TokenBucket(self.default_rps, self.default_rps * self.burst_mul)
        return b.allow()

RATE_LIMITER = RateLimiter(DEFAULT_RPS, BURST_MULTIPLIER)

# APQ storage
class APQStore:
    async def get(self, key: str) -> t.Optional[str]: ...
    async def set(self, key: str, query: str, ttl_sec: int) -> None: ...

class LRUAPQ(APQStore):
    def __init__(self, size: int = 5000) -> None:
        self.size = size
        self._d: dict[str, tuple[float, str]] = {}  # key -> (exp, query)

    async def get(self, key: str) -> t.Optional[str]:
        data = self._d.get(key)
        if not data:
            return None
        exp, q = data
        if time.time() > exp:
            self._d.pop(key, None)
            return None
        return q

    async def set(self, key: str, query: str, ttl_sec: int) -> None:
        if len(self._d) >= self.size:
            # naive eviction of first item
            self._d.pop(next(iter(self._d)), None)
        self._d[key] = (time.time() + max(1, ttl_sec), query)

_APQ: APQStore

# Optional Redis backend
try:
    import aioredis  # type: ignore
    _HAS_REDIS = bool(REDIS_URL)
except Exception:
    _HAS_REDIS = False

class RedisAPQ(APQStore):
    def __init__(self, url: str) -> None:
        self._url = url
        self._pool = None

    async def _conn(self):
        if self._pool is None:
            self._pool = await aioredis.from_url(self._url, encoding="utf-8", decode_responses=True)
        return self._pool

    async def get(self, key: str) -> t.Optional[str]:
        r = await self._conn()
        val = await r.get(f"apq:{key}")
        return val

    async def set(self, key: str, query: str, ttl_sec: int) -> None:
        r = await self._conn()
        await r.set(f"apq:{key}", query, ex=ttl_sec)

_APQ = RedisAPQ(REDIS_URL) if _HAS_REDIS else LRUAPQ()

# ------------------------------------------------------------------------------
# GraphQL schema (Strawberry)
# ------------------------------------------------------------------------------

# Simple loaders to batch by tenant (example)
async def _load_budget_batch(keys: list[tuple[str, str]], svc: DPAccountantService):
    # keys: [(tenant, window)]
    results: dict[tuple[str, str], t.Any] = {}
    for tenant, window in keys:
        state = await svc.get_budget(tenant)
        results[(tenant, window)] = state
    return [results.get(k) for k in keys]

# Domain types (mapped loosely to HTTP models)
@strawberry.type
class BudgetWindow:
    name: str
    epsilon_limit: float
    delta_limit: float
    epsilon_used: float
    delta_used: float
    epsilon_remaining: float
    delta_remaining: float
    updated_at: str

@strawberry.type
class BudgetState:
    tenant: str
    windows: t.List[BudgetWindow]

@strawberry.type
class EstimateResult:
    tenant: str
    pipeline: str
    window: str
    epsilon_total_max: float
    delta_total_max: float
    dry_run: bool
    event_id: str

@strawberry.type
class ChargeResult:
    tenant: str
    pipeline: str
    window: str
    epsilon_charged: float
    delta_charged: float
    event_id: str

@strawberry.type
class Query:
    @strawberry.field
    async def health(self) -> dict[str, str]:
        return {"status": "ok", "time": _now_utc_iso()}

    @strawberry.field
    async def pipelines(self, info: Info) -> list[str]:
        svc: DPAccountantService = info.context["svc"]
        return await svc.list_pipelines()

    @strawberry.field
    async def budget(self, info: Info, tenant: str) -> BudgetState:
        svc: DPAccountantService = info.context["svc"]
        state = await svc.get_budget(tenant)
        # If state is Pydantic, convert robustly
        if hasattr(state, "dict"):
            state = state.dict()
        windows = [
            BudgetWindow(
                name=w["name"],
                epsilon_limit=w["epsilon_limit"],
                delta_limit=w["delta_limit"],
                epsilon_used=w["epsilon_used"],
                delta_used=w["delta_used"],
                epsilon_remaining=w["epsilon_remaining"],
                delta_remaining=w["delta_remaining"],
                updated_at=str(w.get("updated_at") or _now_utc_iso()),
            )
            for w in state["windows"]
        ]
        return BudgetState(tenant=state["tenant"], windows=windows)

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def estimate(
        self,
        info: Info,
        tenant: t.Optional[str],
        pipeline: str,
        window: str = "daily",
        repeats: int = 1,
    ) -> EstimateResult:
        actor: Actor = info.context["actor"]
        svc: DPAccountantService = info.context["svc"]
        use = _Use(pipeline=pipeline, window=window, dry_run=True, tenant=tenant or actor.tenant_id, steps=[_MechanismUse("default", repeats)])
        eps, delt, _ = await svc.estimate(use, actor)
        return EstimateResult(
            tenant=(tenant or actor.tenant_id or "default"),
            pipeline=pipeline,
            window=window,
            epsilon_total_max=eps,
            delta_total_max=delt,
            dry_run=True,
            event_id=f"gql::{pipeline}::estimate::{hashlib.sha1(os.urandom(8)).hexdigest()}",
        )

    @strawberry.mutation
    async def charge(
        self,
        info: Info,
        tenant: t.Optional[str],
        pipeline: str,
        window: str = "daily",
        repeats: int = 1,
        idempotency_key: t.Optional[str] = None,
    ) -> ChargeResult:
        actor: Actor = info.context["actor"]
        svc: DPAccountantService = info.context["svc"]
        use = _Use(pipeline=pipeline, window=window, dry_run=False, tenant=tenant or actor.tenant_id, steps=[_MechanismUse("default", repeats)])
        eps, delt, _ = await svc.charge(use, actor)
        return ChargeResult(
            tenant=(tenant or actor.tenant_id or "default"),
            pipeline=pipeline,
            window=window,
            epsilon_charged=eps,
            delta_charged=delt,
            event_id=f"gql::{pipeline}::charge::{hashlib.sha1(os.urandom(8)).hexdigest()}",
        )

Schema = strawberry.Schema(query=Query, mutation=Mutation)
_GQL_CORE_SCHEMA: GraphQLSchema = Schema._schema  # access underlying graphql-core schema

# Light DTOs mirroring HTTP shapes (to avoid importing pydantic here)
@dataclass
class _MechanismUse:
    mechanism: str
    repeats: int = 1

@dataclass
class _Use:
    pipeline: str
    window: str
    dry_run: bool
    tenant: t.Optional[str]
    steps: list[_MechanismUse]

# ------------------------------------------------------------------------------
# Validation: depth & naive complexity
# ------------------------------------------------------------------------------

def _calc_depth(doc: DocumentNode) -> int:
    # Rough depth calculator
    max_d = 0
    def _walk(sel_set, d):
        nonlocal max_d
        if not sel_set:
            return
        max_d = max(max_d, d)
        for s in sel_set.selections:
            ss = getattr(s, "selection_set", None)
            if ss:
                _walk(ss, d + 1)
    for defn in doc.definitions:
        ss = getattr(defn, "selection_set", None)
        if ss:
            _walk(ss, 1)
    return max_d

def _calc_complexity(doc: DocumentNode) -> int:
    # Naive: count field nodes; multiply by argument hints (first/limit, default cap)
    mult_keys = {"first", "limit", "take", "pageSize"}
    total = 0
    def _walk(sel_set):
        nonlocal total
        for s in sel_set.selections:
            total += 1
            args = {a.name.value: getattr(a.value, "value", None) for a in getattr(s, "arguments", [])}
            for k in mult_keys:
                v = args.get(k)
                if isinstance(v, int):
                    total += min(v, 1000)  # conservative cap
            ss = getattr(s, "selection_set", None)
            if ss:
                _walk(ss)
    for defn in doc.definitions:
        ss = getattr(defn, "selection_set", None)
        if ss:
            _walk(ss)
    return total

# ------------------------------------------------------------------------------
# Request helpers: actor/context, APQ negotiation, limits
# ------------------------------------------------------------------------------

def _actor_from_headers(req: Request) -> Actor:
    auth = req.headers.get("authorization") or ""
    tenant = req.headers.get("x-tenant-id")
    client_cert = req.headers.get("x-client-cert")
    if client_cert and len(client_cert) > 20:
        return Actor(subject="mtls-client", tenant_id=tenant, scopes=["dp:read", "dp:write"], mTLS=True)
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if token:
            return Actor(subject="bearer-user", tenant_id=tenant, scopes=["dp:read", "dp:write"])
    # Anonymous → forbidden at resolvers’ discretion (we still create an Actor)
    return Actor(subject="anonymous", tenant_id=tenant, scopes=[])

async def _get_graphql_params(req: Request) -> tuple[str, dict, t.Optional[str]]:
    if req.method == "GET":
        query = req.query_params.get("query")
        op = req.query_params.get("operationName")
        variables = req.query_params.get("variables")
        vars_dict = json.loads(variables) if variables else {}
        return query or "", vars_dict, op
    # POST
    raw = await req.body()
    if len(raw) > MAX_QUERY_BYTES:
        raise ValueError("payload_too_large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValueError("invalid_json")
    return data.get("query", ""), data.get("variables", {}) or {}, data.get("operationName")

async def _resolve_apq(query: str, data: dict) -> str:
    if not APQ_ENABLED:
        return query
    ext = data.get("extensions") if isinstance(data, dict) else None
    if not ext or "persistedQuery" not in ext:
        return query
    pq = ext["persistedQuery"] or {}
    sha = pq.get("sha256Hash")
    version = pq.get("version")
    if version != 1 or not isinstance(sha, str) or len(sha) != 64:
        raise ValueError("bad_persisted_query_ext")
    if query:
        # registration flow: verify hash and store
        calc = hashlib.sha256(query.encode("utf-8")).hexdigest()
        if calc != sha:
            raise ValueError("apq_hash_mismatch")
        if APQ_ALLOW_REGISTER:
            await _APQ.set(sha, query, APQ_TTL_SEC)
        return query
    # lookup flow
    stored = await _APQ.get(sha)
    if stored:
        return stored
    # unknown
    raise KeyError("PersistedQueryNotFound")

# ------------------------------------------------------------------------------
# GraphQL execution endpoint
# ------------------------------------------------------------------------------

async def graphql_endpoint(request: Request) -> Response:
    t0 = time.perf_counter()
    tenant = request.headers.get("x-tenant-id") or "none"
    op_name: str = "unknown"
    status_txt = "200"
    try:
        # Rate limit per tenant
        if not RATE_LIMITER.check(tenant):
            status_txt = "429"
            if _HAS_PROM:
                GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": "Rate limit exceeded"}]}, status_code=429)

        # Parse payload
        raw = await request.body()
        if request.method == "POST" and len(raw) > MAX_QUERY_BYTES:
            status_txt = "413"
            if _HAS_PROM:
                GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": "Request entity too large"}]}, status_code=413)
        data = {}
        query, variables, op = "", {}, None
        try:
            if request.method == "GET":
                query, variables, op = await _get_graphql_params(request)
            else:
                data = json.loads(raw.decode("utf-8")) if raw else {}
                query = (data.get("query") or "")
                variables = (data.get("variables") or {}) if isinstance(data.get("variables"), dict) else {}
                op = data.get("operationName")
        except ValueError as ve:
            status_txt = "400"
            if _HAS_PROM:
                GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": str(ve)}]}, status_code=400)

        # APQ negotiation
        if APQ_ENABLED:
            try:
                query = await _resolve_apq(query, data if data else {})
            except KeyError:
                status_txt = "200"
                # Apollo client expects specific error
                err = {"errors": [{"message": "PersistedQueryNotFound", "extensions": {"code": "PERSISTED_QUERY_NOT_FOUND"}}]}
                if _HAS_PROM:
                    GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
                return JSONResponse(err, status_code=200)
            except ValueError as e:
                status_txt = "400"
                if _HAS_PROM:
                    GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
                return JSONResponse({"errors": [{"message": str(e)}]}, status_code=400)

        if not query:
            status_txt = "400"
            if _HAS_PROM:
                GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": "Empty query"}]}, status_code=400)

        # Depth/complexity checks
        doc = parse(query)
        depth = _calc_depth(doc)
        if depth > MAX_DEPTH:
            status_txt = "400"
            if _HAS_PROM:
                GQL_ERRS.labels(op=op or "unknown", tenant=tenant, type="depth").inc()
                GQL_REQS.labels(op=op or "unknown", tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": f"Query depth {depth} exceeds limit {MAX_DEPTH}"}]}, status_code=400)
        complexity = _calc_complexity(doc)
        if complexity > MAX_COMPLEXITY:
            status_txt = "400"
            if _HAS_PROM:
                GQL_ERRS.labels(op=op or "unknown", tenant=tenant, type="complexity").inc()
                GQL_REQS.labels(op=op or "unknown", tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": f"Query complexity {complexity} exceeds limit {MAX_COMPLEXITY}"}]}, status_code=400)

        op_name = op or "anonymous"

        # Build context
        actor = _actor_from_headers(request)
        svc: DPAccountantService = request.app.state.dp_service  # type: ignore[attr-defined]
        loaders = {"budget_loader": DataLoader(lambda ks: _load_budget_batch(ks, svc))}

        async def _execute():
            result = await Schema.execute(
                query,
                variable_values=variables,
                context_value={"actor": actor, "svc": svc, "loaders": loaders, "request": request},
                operation_name=op,
            )
            out: dict[str, t.Any] = {}
            if result.errors:
                errs = []
                for e in result.errors:
                    msg = str(e)
                    # Mask internal details unless DEBUG
                    if not DEBUG and "Internal" in msg:
                        msg = "Internal error"
                    errs.append({"message": msg})
                out["errors"] = errs
            if result.data is not None:
                out["data"] = result.data
            return out

        try:
            out = await asyncio.wait_for(_execute(), timeout=REQ_TIMEOUT_SEC)
        except asyncio.TimeoutError:
            status_txt = "504"
            if _HAS_PROM:
                GQL_ERRS.labels(op=op_name, tenant=tenant, type="timeout").inc()
                GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            return JSONResponse({"errors": [{"message": "Execution timeout"}]}, status_code=504)

        # HMAC integrity header
        mac = make_hmac(out) if isinstance(out, dict) and "data" in out else ""
        resp = JSONResponse(out, status_code=200)
        if mac:
            resp.headers["X-Integrity"] = mac

        status_txt = "200"
        return resp

    finally:
        if _HAS_PROM:
            GQL_REQS.labels(op=op_name, tenant=tenant, status=status_txt).inc()
            GQL_LAT.labels(op=op_name, tenant=tenant).observe(max(0.0, time.perf_counter() - t0))

# Simple /metrics endpoint
async def metrics_endpoint(_: Request) -> Response:
    if not _HAS_PROM:
        return PlainTextResponse("prometheus_client not installed", status_code=501)
    return Response(generate_latest(_REG), media_type=CONTENT_TYPE_LATEST)

# Optional GraphiQL page (disabled by default)
_GRAPHIQL_HTML = """<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Veilmind GraphiQL</title>
    <meta name="robots" content="noindex" />
    <style>html, body, #root { height:100%; margin:0; } </style>
    <link rel="stylesheet" href="https://unpkg.com/graphiql/graphiql.min.css"/>
  </head>
  <body>
    <div id="root"></div>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/graphiql/graphiql.min.js"></script>
    <script>
      const fetcher = GraphiQL.createFetcher({ url: window.location.origin + "%(path)s" });
      ReactDOM.render(React.createElement(GraphiQL, { fetcher }), document.getElementById('root'));
    </script>
  </body>
</html>"""

async def graphiql_endpoint(_: Request) -> Response:
    if not GRAPHIQL_ENABLED:
        return PlainTextResponse("GraphiQL disabled", status_code=404)
    return HTMLResponse(_GRAPHIQL_HTML % {"path": GRAPHQL_PATH})

# ------------------------------------------------------------------------------
# ASGI application factory
# ------------------------------------------------------------------------------

def create_app(service: t.Optional[DPAccountantService] = None) -> Starlette:
    routes = [
        Route(GRAPHQL_PATH, graphql_endpoint, methods=["GET", "POST"]),
        Route("/metrics", metrics_endpoint, methods=["GET"]),
    ]
    if GRAPHIQL_ENABLED:
        routes.append(Route("/graphiql", graphiql_endpoint, methods=["GET"]))

    middlewares = [
        {"middleware_class": GZipMiddleware, "minimum_size": 1024},
    ]
    if CORS_ALLOW_ORIGINS:
        middlewares.append({
            "middleware_class": CORSMiddleware,
            "allow_origins": CORS_ALLOW_ORIGINS,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Authorization", "X-Tenant-ID", "X-Client-Cert", "Idempotency-Key", "Content-Type"],
            "max_age": 600,
        })
    if _HAS_OTEL:
        middlewares.append({"middleware_class": OpenTelemetryMiddleware})

    app = Starlette(routes=routes, debug=DEBUG, middleware=middlewares)  # type: ignore[arg-type]
    app.state.dp_service = service or InMemoryDPAccountantService()  # type: ignore[attr-defined]
    return app

# Uvicorn entrypoint
if __name__ == "__main__":
    import uvicorn  # type: ignore
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
