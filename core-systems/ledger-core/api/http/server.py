"""
Ledger Core — Production-grade HTTP server (FastAPI/ASGI)
Requirements (typical):
  fastapi>=0.115, uvicorn[standard]>=0.30, pydantic>=2
  structlog>=24, prometheus-client>=0.20
  redis>=5, httpx>=0.27, python-jose[cryptography]>=3.3
  SQLAlchemy[asyncio]>=2, asyncpg>=0.29
  aiokafka>=0.10 (optional)
  opentelemetry-sdk>=1.27, opentelemetry-exporter-otlp>=1.27 (optional)

Env hints:
  LEDGER_CONFIG_PATH=/etc/ledger/ledger.yaml
  DATABASE_URL=postgresql+asyncpg://...
  REDIS_URL=redis://... or rediss://...
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import signal
import sys
import time
import typing as t
from functools import lru_cache
from hashlib import sha256
from ipaddress import ip_address

import yaml
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from jose import jwt
from jose.utils import base64url_decode
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Optional imports guarded
try:
    import structlog
except Exception:  # pragma: no cover
    structlog = None

try:
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
except Exception:  # pragma: no cover
    create_async_engine = None
    async_sessionmaker = None
    AsyncSession = None

try:
    from redis.asyncio import Redis, ConnectionError as RedisConnectionError
except Exception:  # pragma: no cover
    Redis = None
    RedisConnectionError = Exception

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

try:
    from aiokafka import AIOKafkaProducer
except Exception:  # pragma: no cover
    AIOKafkaProducer = None

# OpenTelemetry (optional)
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHTTPExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except Exception:  # pragma: no cover
    trace = None
    OTLPHTTPExporter = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None


# =========================
# Metrics
# =========================
REQ_COUNTER = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)
REQ_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
READY_GAUGE = Gauge("ledger_ready", "Readiness 1/0")


# =========================
# Context / Logging
# =========================
_request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)

def _setup_logging(json_logs: bool = True, level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    if structlog:
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.stdlib.add_log_level,
                structlog.contextvars.merge_contextvars,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.UnicodeDecoder(),
                (structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer()),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=structlog.threadlocal.wrap_dict(dict),
            logger_factory=structlog.stdlib.LoggerFactory(),
        )
        logging.basicConfig(stream=sys.stdout, level=lvl)
    else:
        logging.basicConfig(
            stream=sys.stdout,
            level=lvl,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

log = structlog.get_logger("ledger") if structlog else logging.getLogger("ledger")


# =========================
# Config models (subset aligned with ledger.yaml/prod.yaml)
# =========================
class TLSConfig(BaseModel):
    enabled: bool = True
    minVersion: str | None = "TLS1.2"

class CORSConfig(BaseModel):
    enabled: bool = True
    allowedOrigins: list[str] = Field(default_factory=list)
    allowedMethods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    allowedHeaders: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-ID"])
    allowCredentials: bool = True
    maxAge: int = 600

class AuthOIDC(BaseModel):
    issuer: str
    audience: str
    jwksURL: str
    cacheTTL: int = 600  # seconds

class AuthConfig(BaseModel):
    mode: str = "oidc"  # oidc|disabled
    oidc: AuthOIDC | None = None
    jwt_allowedAlgs: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    leeway: int = 30

class ObservabilityConfig(BaseModel):
    logging_level: str = "INFO"
    json_logs: bool = True
    tracing_enabled: bool = True
    otlp_endpoint: str | None = None
    sampling_ratio: float = 0.15

class ServerHTTPConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    readTimeout: float = 15.0
    writeTimeout: float = 15.0
    idleTimeout: float = 60.0
    cors: CORSConfig = CORSConfig()

class HealthChecksConfig(BaseModel):
    checks_db: bool = True
    checks_cache: bool = True
    checks_queue: bool = True
    dependenciesTimeout: float = 3.0

class SecurityConfig(BaseModel):
    tls: TLSConfig = TLSConfig()
    auth: AuthConfig = AuthConfig()

class RateLimitRule(BaseModel):
    path: str
    rps: int
    burst: int

class RateLimitConfig(BaseModel):
    enabled: bool = True
    global_rps: int = 500
    global_burst: int = 200
    rules: list[RateLimitRule] = Field(default_factory=list)
    prefix: str = "ratelimit:"

class RedisConfig(BaseModel):
    url: str | None = None

class DatabaseConfig(BaseModel):
    dsn: str | None = None  # Expect async URL: postgresql+asyncpg://...

class KafkaConfig(BaseModel):
    brokers: list[str] = Field(default_factory=list)
    client_id: str = "ledger-core-http"

class AppConfig(BaseModel):
    environment: str = os.getenv("ENVIRONMENT", "dev")
    service_name: str = "ledger-core"
    version: str = os.getenv("LEDGER_BUILD_VERSION", "0.0.0")
    server: ServerHTTPConfig = ServerHTTPConfig()
    observability: ObservabilityConfig = ObservabilityConfig()
    security: SecurityConfig = SecurityConfig()
    health: HealthChecksConfig = HealthChecksConfig()
    ratelimit: RateLimitConfig = RateLimitConfig()
    redis: RedisConfig = RedisConfig()
    database: DatabaseConfig = DatabaseConfig()
    kafka: KafkaConfig = KafkaConfig()

def load_config() -> AppConfig:
    path = os.getenv("LEDGER_CONFIG_PATH", "/etc/ledger/ledger.yaml")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}
    # Map subset from ledger.yaml/prod.yaml into AppConfig
    # Gracefully handle missing nodes
    def g(*keys, default=None):
        node = raw
        for k in keys:
            node = node.get(k, {})
        return node if node else (default if default is not None else {})
    server_raw = g("server", "http")
    cors_raw = server_raw.get("cors", {})
    observ_raw = g("observability")
    security_raw = g("security")
    auth_raw = security_raw.get("auth", {})
    oidc_raw = auth_raw.get("oidc", {})
    health_raw = g("observability", "health")
    redis_url = g("cache", "redis").get("url") or os.getenv("REDIS_URL")
    db_dsn = g("database", "primary").get("secretRef") or os.getenv("DATABASE_URL")
    kafka_brokers = g("queue", "kafka").get("brokers", [])
    # Build config
    cfg = AppConfig(
        environment=raw.get("metadata", {}).get("environment") or os.getenv("ENVIRONMENT", "dev"),
        service_name=raw.get("metadata", {}).get("service", "ledger-core"),
        version=os.getenv("LEDGER_BUILD_VERSION", "0.0.0"),
        server=ServerHTTPConfig(
            host=server_raw.get("host", "0.0.0.0"),
            port=int(server_raw.get("port", 8080)),
            cors=CORSConfig(
                enabled=cors_raw.get("enabled", True),
                allowedOrigins=cors_raw.get("allowedOrigins", []),
                allowedMethods=cors_raw.get("allowedMethods", ["GET","POST","PUT","PATCH","DELETE"]),
                allowedHeaders=cors_raw.get("allowedHeaders", ["Authorization","Content-Type","X-Request-ID"]),
                allowCredentials=cors_raw.get("allowCredentials", True),
                maxAge=int(cors_raw.get("maxAge", 600)),
            ),
        ),
        observability=ObservabilityConfig(
            logging_level=observ_raw.get("logging", {}).get("level", "INFO"),
            json_logs=observ_raw.get("logging", {}).get("json", True),
            tracing_enabled=observ_raw.get("tracing", {}).get("enabled", True),
            otlp_endpoint=observ_raw.get("tracing", {}).get("otlp", {}).get("endpoint"),
            sampling_ratio=float(observ_raw.get("tracing", {}).get("sampling", {}).get("ratio", 0.15)),
        ),
        security=SecurityConfig(
            tls=TLSConfig(enabled=g("security", "tls").get("enabled", True)),
            auth=AuthConfig(
                mode=auth_raw.get("mode", "oidc"),
                oidc=(AuthOIDC(
                    issuer=oidc_raw.get("issuer", ""),
                    audience=oidc_raw.get("audience", "ledger-core"),
                    jwksURL=oidc_raw.get("jwksURL", ""),
                    cacheTTL=int(oidc_raw.get("cacheTTL", 600)),
                ) if oidc_raw else None),
                jwt_allowedAlgs=auth_raw.get("allowedAlgs", ["RS256", "ES256"]),
                leeway=int(auth_raw.get("leeway", 30)),
            ),
        ),
        health=HealthChecksConfig(
            checks_db=health_raw.get("db", True),
            checks_cache=health_raw.get("cache", True),
            checks_queue=health_raw.get("queue", True),
            dependenciesTimeout=float(health_raw.get("dependenciesTimeout", 3.0)),
        ),
        ratelimit=RateLimitConfig(
            enabled=True,
            global_rps=raw.get("ratelimit", {}).get("global", {}).get("rps", 500),
            global_burst=raw.get("ratelimit", {}).get("global", {}).get("burst", 200),
            rules=[
                RateLimitRule(path=r.get("path"), rps=r.get("rps"), burst=r.get("burst"))
                for r in raw.get("ratelimit", {}).get("endpoints", []) or []
            ],
        ),
        redis=RedisConfig(url=redis_url),
        database=DatabaseConfig(dsn=db_dsn),
        kafka=KafkaConfig(brokers=kafka_brokers, client_id="ledger-core-http"),
    )
    return cfg


# =========================
# Middlewares
# =========================
class RequestIDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, header_name: str = "X-Request-ID"):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.header_name) or sha256(os.urandom(16)).hexdigest()[:16]
        _request_id_ctx.set(rid)
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        finally:
            dur = time.perf_counter() - start
            REQ_COUNTER.labels(request.method, request.url.path, getattr(response, "status_code", 500)).inc()
            REQ_LATENCY.labels(request.method, request.url.path).observe(dur)
        response.headers[self.header_name] = rid
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return response

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = _request_id_ctx.get()
        peer = request.client.host if request.client else "-"
        ua = request.headers.get("user-agent", "-")
        path = request.url.path
        method = request.method
        try:
            response: Response = await call_next(request)
            code = response.status_code
            log.info("http.access", event="request", request_id=rid, method=method, path=path, status=code, ua=ua, peer=peer)
            return response
        except Exception as e:
            log.exception("http.error", request_id=rid, method=method, path=path, error=str(e))
            return JSONResponse({"error": "internal_error", "request_id": rid}, status_code=500)

# Rate limiter (Redis token bucket)
class RateLimiter:
    def __init__(self, redis: Redis | None, cfg: RateLimitConfig):
        self.redis = redis
        self.cfg = cfg

    def _rule_for(self, path: str) -> tuple[int, int]:
        for r in self.cfg.rules:
            if path.startswith(r.path):
                return r.rps, r.burst
        return self.cfg.global_rps, self.cfg.global_burst

    async def allow(self, key: str, path: str) -> bool:
        if not self.redis or not self.cfg.enabled:
            return True
        rps, burst = self._rule_for(path)
        # Token bucket with 1s windows
        bucket = f"{self.cfg.prefix}{key}:{path}"
        pipe = self.redis.pipeline()
        pipe.incr(bucket, 1)
        pipe.expire(bucket, 1)
        count, _ = await pipe.execute()
        return int(count) <= max(1, burst) if rps >= burst else int(count) <= burst

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, limiter: RateLimiter):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
        try:
            # Validate IP string quickly; ignore errors
            ip_address(client_ip)
        except Exception:
            client_ip = "unknown"
        allowed = await self.limiter.allow(client_ip, request.url.path)
        if not allowed:
            return JSONResponse(
                {"error": "rate_limited", "message": "Too Many Requests", "request_id": _request_id_ctx.get()},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        return await call_next(request)


# =========================
# Auth (OIDC/JWT with JWKS)
# =========================
class JWKSCache:
    def __init__(self, jwks_url: str, ttl: int = 600):
        self.jwks_url = jwks_url
        self.ttl = ttl
        self._cached_at = 0.0
        self._jwks = None

    async def get(self) -> dict:
        now = time.time()
        if self._jwks and (now - self._cached_at) < self.ttl:
            return self._jwks
        if not httpx:
            raise HTTPException(status_code=500, detail="httpx not available for JWKS fetch")
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(self.jwks_url)
            r.raise_for_status()
            self._jwks = r.json()
            self._cached_at = now
            return self._jwks

def pick_key(jwks: dict, kid: str) -> dict | None:
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    return None

def auth_dependency_factory(cfg: AppConfig):
    if cfg.security.auth.mode == "disabled" or not cfg.security.auth.oidc:
        async def _noop_dep(_: Request):
            return {"sub": "anonymous"}
        return _noop_dep

    jwks_cache = JWKSCache(cfg.security.auth.oidc.jwksURL, cfg.security.auth.oidc.cacheTTL)
    audience = cfg.security.auth.oidc.audience
    leeway = cfg.security.auth.leeway
    allowed_algs = set(cfg.security.auth.jwt_allowedAlgs)

    async def _verify(request: Request):
        authz = request.headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_bearer")
        token = authz.split(" ", 1)[1].strip()
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        alg = headers.get("alg")
        if alg not in allowed_algs:
            raise HTTPException(status_code=401, detail="alg_not_allowed")
        jwks = await jwks_cache.get()
        jwk = pick_key(jwks, kid) if kid else None
        if not jwk:
            raise HTTPException(status_code=401, detail="kid_not_found")
        try:
            claims = jwt.decode(
                token, jwk, algorithms=[alg],
                audience=audience,
                options={"leeway": leeway, "verify_aud": True}
            )
            # Minimal claims hardening
            if "sub" not in claims:
                raise HTTPException(status_code=401, detail="bad_claims")
            request.state.user = {"sub": claims["sub"], "claims": claims}
            return claims
        except Exception as e:  # pragma: no cover
            raise HTTPException(status_code=401, detail=f"invalid_token: {e!s}")
    return _verify


# =========================
# App factory and resources
# =========================
class Resources:
    def __init__(self):
        self.db_engine = None
        self.db_session_maker = None
        self.redis: Redis | None = None
        self.kafka: AIOKafkaProducer | None = None
        self.otel_sp: BatchSpanProcessor | None = None

RES = Resources()

async def init_db(cfg: AppConfig):
    if not cfg.database.dsn or not create_async_engine:
        return
    RES.db_engine = create_async_engine(cfg.database.dsn, pool_pre_ping=True)
    RES.db_session_maker = async_sessionmaker(RES.db_engine, expire_on_commit=False)

async def init_redis(cfg: AppConfig):
    if not cfg.redis.url or not Redis:
        return
    RES.redis = Redis.from_url(cfg.redis.url, encoding="utf-8", decode_responses=True)
    # Warmup ping
    try:
        await RES.redis.ping()
    except Exception as e:
        log.warning("redis.ping_failed", error=str(e))

async def init_kafka(cfg: AppConfig):
    if not cfg.kafka.brokers or not AIOKafkaProducer:
        return
    RES.kafka = AIOKafkaProducer(bootstrap_servers=cfg.kafka.brokers, client_id=cfg.kafka.client_id)
    try:
        await RES.kafka.start()
    except Exception as e:
        log.warning("kafka.start_failed", error=str(e))

def init_tracing(cfg: AppConfig):
    if not cfg.observability.tracing_enabled or not trace or not TracerProvider or not OTLPHTTPExporter:
        return
    resource = Resource.create({
        "service.name": cfg.service_name,
        "service.version": cfg.version,
        "deployment.environment": cfg.environment,
    })
    provider = TracerProvider(resource=resource)
    exporter = OTLPHTTPExporter(endpoint=cfg.observability.otlp_endpoint) if cfg.observability.otlp_endpoint else OTLPHTTPExporter()
    sp = BatchSpanProcessor(exporter)
    provider.add_span_processor(sp)
    trace.set_tracer_provider(provider)
    RES.otel_sp = sp

def create_app(cfg: AppConfig) -> FastAPI:
    _setup_logging(json_logs=cfg.observability.json_logs, level=cfg.observability.logging_level)
    init_tracing(cfg)

    app = FastAPI(
        title="Ledger Core HTTP API",
        version=cfg.version,
        docs_url=None, redoc_url=None, openapi_url="/openapi.json" if cfg.environment != "prod" else None,
    )

    # Middlewares
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    if cfg.server.cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.server.cors.allowedOrigins or ["https://*.example.com"],
            allow_credentials=cfg.server.cors.allowCredentials,
            allow_methods=cfg.server.cors.allowedMethods,
            allow_headers=cfg.server.cors.allowedHeaders,
            max_age=cfg.server.cors.maxAge,
        )

    # Rate limiter
    limiter = RateLimiter(RES.redis, cfg.ratelimit)
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    # Lifespan
    @app.on_event("startup")
    async def _startup():
        log.info("startup.begin", env=cfg.environment, version=cfg.version)
        await init_db(cfg)
        await init_redis(cfg)
        await init_kafka(cfg)
        READY_GAUGE.set(1)
        log.info("startup.ready")

    @app.on_event("shutdown")
    async def _shutdown():
        READY_GAUGE.set(0)
        if RES.kafka:
            try:
                await RES.kafka.stop()
            except Exception:
                pass
        if RES.redis:
            try:
                await RES.redis.close()
            except Exception:
                pass
        if RES.db_engine:
            try:
                await RES.db_engine.dispose()
            except Exception:
                pass
        log.info("shutdown.complete")

    # Routes
    auth_dep = auth_dependency_factory(cfg)

    @app.get("/health/live", include_in_schema=False)
    async def live():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    async def ready():
        # Probe dependencies with timeout
        ok = True
        details = {}

        async def probe_db():
            if not RES.db_engine or not cfg.health.checks_db:
                return True, "skipped"
            try:
                async with RES.db_engine.connect() as conn:
                    await conn.execute("SELECT 1")
                return True, "ok"
            except Exception as e:
                return False, f"db_error:{e!s}"

        async def probe_redis():
            if not RES.redis or not cfg.health.checks_cache:
                return True, "skipped"
            try:
                await RES.redis.ping()
                return True, "ok"
            except Exception as e:
                return False, f"redis_error:{e!s}"

        async def probe_kafka():
            if not RES.kafka or not cfg.health.checks_queue:
                return True, "skipped"
            try:
                md = await RES.kafka.client.cluster.metadata()
                return (True, "ok") if md.brokers() else (False, "no_brokers")
            except Exception as e:
                return False, f"kafka_error:{e!s}"

        async def with_timeout(coro, name):
            try:
                return await asyncio.wait_for(coro, timeout=cfg.health.dependenciesTimeout)
            except asyncio.TimeoutError:
                return False, "timeout"

        db_ok, db_msg = await with_timeout(probe_db(), "db")
        rd_ok, rd_msg = await with_timeout(probe_redis(), "redis")
        kf_ok, kf_msg = await with_timeout(probe_kafka(), "kafka")

        details.update(db=db_msg, redis=rd_msg, kafka=kf_msg)
        ok = db_ok and rd_ok and kf_ok
        return JSONResponse({"status": "ok" if ok else "degraded", "details": details}, status_code=200 if ok else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # === Minimal Tx API (placeholder; business logic implemented in service layer) ===

    class EntryIn(BaseModel):
        account_id: str
        side: t.Literal["DEBIT", "CREDIT"]
        currency: str
        amount: str
        memo: str | None = None
        attributes: dict[str, t.Any] = Field(default_factory=dict)
        subledger: str | None = None

    class CreateTxIn(BaseModel):
        journal: str
        description: str | None = None
        reference: str | None = None
        entries: list[EntryIn]
        idempotency_key: str | None = None
        post_immediately: bool | None = False

    class TxOut(BaseModel):
        id: str
        status: str
        journal: str
        description: str | None
        reference: str | None
        labels: dict[str, t.Any] = {}
        attributes: dict[str, t.Any] = {}
        created_at: str
        posted_at: str | None = None
        etag: str

    tx_router = APIRouter(prefix="/v1/transactions", tags=["transactions"])

    async def _idempotency_check(idem: str | None) -> bool:
        if not idem or not RES.redis:
            return True
        key = f"idem:{idem}"
        # NX set for 5 minutes
        return await RES.redis.set(key, "1", nx=True, ex=300)

    @tx_router.post("", response_model=TxOut, dependencies=[Depends(auth_dep)])
    async def create_tx(inp: CreateTxIn, request: Request, background: BackgroundTasks):
        # Idem gate
        if not await _idempotency_check(inp.idempotency_key):
            raise HTTPException(status_code=409, detail="duplicate_request")

        # Here you would call domain service (not included)
        # Return stub with deterministic values to make endpoint operational
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        fake_id = sha256(f"{now_iso}:{inp.journal}:{inp.reference or ''}".encode()).hexdigest()[:32]
        etag = sha256(f"{fake_id}:{now_iso}".encode()).hexdigest()[:16]
        status_str = "PENDING" if not inp.post_immediately else "POSTED"

        # Optionally enqueue outbox event via Kafka
        if RES.kafka:
            try:
                payload = json.dumps({"event": "TransactionCreated", "id": fake_id, "journal": inp.journal}).encode()
                await RES.kafka.send_and_wait("ledger.tx.incoming.v1", payload)
            except Exception as e:
                log.warning("kafka.send_failed", error=str(e))

        return TxOut(
            id=fake_id,
            status=status_str,
            journal=inp.journal,
            description=inp.description,
            reference=inp.reference,
            labels={},
            attributes={},
            created_at=now_iso,
            posted_at=now_iso if inp.post_immediately else None,
            etag=etag,
        )

    @tx_router.get("/{tx_id}", dependencies=[Depends(auth_dep)], response_model=TxOut)
    async def get_tx(tx_id: str):
        # Placeholder fetch; production should query DB. We return a deterministic mock.
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        etag = sha256(f"{tx_id}:etag".encode()).hexdigest()[:16]
        return TxOut(
            id=tx_id, status="POSTED", journal="default", description=None, reference=None,
            created_at=now_iso, posted_at=now_iso, etag=etag
        )

    app.include_router(tx_router)

    return app


# =========================
# Entrypoint
# =========================
def _main():
    cfg = load_config()
    app = create_app(cfg)

    # Uvicorn launch if executed directly
    if os.getenv("LEDGER_UVICORN", "1") == "1":
        try:
            import uvicorn  # type: ignore
        except Exception as e:  # pragma: no cover
            print(f"Uvicorn missing: {e}", file=sys.stderr)
            sys.exit(1)

        uvicorn.run(
            app,
            host=cfg.server.host,
            port=cfg.server.port,
            proxy_headers=True,
            forwarded_allow_ips="*",
            log_level=cfg.observability.logging_level.lower(),
            # timeouts are controlled by ingress/proxy; uvicorn has limited knobs
        )
    else:
        # For ASGI servers (gunicorn -k uvicorn.workers.UvicornWorker)
        return app

if __name__ == "__main__":
    _main()
