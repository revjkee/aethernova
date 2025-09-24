# cybersecurity-core/api/http/server.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import uuid
from contextvars import ContextVar
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple, Callable

from fastapi import (
    FastAPI,
    Request,
    Response,
    Header,
    HTTPException,
    Depends,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, BaseSettings, Field, validator

# --- Optional dependencies with safe fallbacks --------------------------------

# structlog for JSON logs
try:
    import structlog  # type: ignore
except Exception:  # pragma: no cover
    structlog = None  # type: ignore

# Prometheus instrumentation
try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore
    _HAS_PROM = True
except Exception:  # pragma: no cover
    from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
    from prometheus_client import Counter, Histogram  # type: ignore
    _HAS_PROM = False

# Redis for rate limiting
try:
    import aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

# JWT
try:
    import jwt  # type: ignore
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

# OpenTelemetry (optional)
try:
    from opentelemetry import trace  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# --- Request-scoped context ----------------------------------------------------

REQUEST_ID_CTX: ContextVar[str] = ContextVar("request_id", default="-")
CLIENT_IP_CTX: ContextVar[str] = ContextVar("client_ip", default="-")
ROUTE_CTX: ContextVar[str] = ContextVar("route", default="-")

# --- Settings ------------------------------------------------------------------

class Settings(BaseSettings):
    APP_NAME: str = Field(default="cybersecurity-core")
    APP_ENV: str = Field(default="prod")  # prod|staging|dev|test
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8080)
    LOG_LEVEL: str = Field(default="INFO")
    LOG_JSON: bool = Field(default=True)

    # Security & CORS
    CORS_ALLOW_ORIGINS: List[str] = Field(default_factory=lambda: [])
    CORS_ALLOW_CREDENTIALS: bool = Field(default=False)
    CORS_ALLOW_METHODS: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    CORS_ALLOW_HEADERS: List[str] = Field(default_factory=lambda: ["*"])
    ENABLE_SECURITY_HEADERS: bool = Field(default=True)
    CONTENT_SECURITY_POLICY: str = Field(
        default="default-src 'none'; frame-ancestors 'none'; base-uri 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'"
    )
    HSTS_MAX_AGE: int = Field(default=31536000)
    HSTS_INCLUDE_SUBDOMAINS: bool = Field(default=True)
    HSTS_PRELOAD: bool = Field(default=False)
    RESPONSE_CACHE_CONTROL: str = Field(default="no-store")
    MAX_REQUEST_BYTES: int = Field(default=2 * 1024 * 1024)  # 2 MiB

    # Auth
    API_KEYS: List[str] = Field(default_factory=list)  # Comma-separated via env
    API_KEY_HEADER: str = Field(default="X-API-Key")
    JWT_ALGORITHMS: List[str] = Field(default_factory=lambda: ["RS256", "HS256"])
    JWT_PUBLIC_KEY: Optional[str] = None  # PEM or raw secret for HS256
    JWT_AUDIENCE: Optional[str] = None
    JWT_ISSUER: Optional[str] = None
    AUTH_REQUIRED: bool = Field(default=False)  # global enforcement flag

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = Field(default=True)
    RATE_LIMIT_RPS: float = Field(default=10.0)       # tokens per second
    RATE_LIMIT_BURST: int = Field(default=20)         # bucket capacity
    RATE_LIMIT_KEY_FUNC: str = Field(default="api_key_or_ip")  # api_key|ip|api_key_or_ip

    # Redis
    REDIS_URL: Optional[str] = None

    # Observability
    PROMETHEUS_ENABLED: bool = Field(default=True)
    OTLP_ENDPOINT: Optional[str] = None  # e.g., http://otel-collector:4318/v1/traces
    OTLP_SERVICE_NAME: str = Field(default="cybersecurity-core-http")
    OTLP_SAMPLER_RATIO: float = Field(default=1.0)

    # Uvicorn
    UVICORN_ACCESS_LOG: bool = Field(default=False)
    UVICORN_WORKERS: int = Field(default=1)
    UVICORN_TIMEOUT_KEEP_ALIVE: int = Field(default=5)
    UVICORN_LOG_LEVEL: str = Field(default="info")
    UVICORN_PROXY_HEADERS: bool = Field(default=True)

    class Config:
        env_file = os.environ.get("ENV_FILE", ".env")
        case_sensitive = True

    @validator("API_KEYS", pre=True)
    def _split_api_keys(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, list):
            return [s.strip() for s in v if s and str(s).strip()]
        return [s.strip() for s in str(v).split(",") if s and s.strip()]

@lru_cache()
def get_settings() -> Settings:
    return Settings()  # type: ignore

# --- Logging -------------------------------------------------------------------

def _init_logging(cfg: Settings) -> None:
    level = getattr(logging, cfg.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=level, stream=sys.stdout)

    if structlog and cfg.LOG_JSON:
        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", key="ts"),
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            cache_logger_on_first_use=True,
        )

def _log() -> Any:
    cfg = get_settings()
    if structlog and cfg.LOG_JSON:
        logger = structlog.get_logger()
        return logger.bind(
            app=cfg.APP_NAME,
            env=cfg.APP_ENV,
            req_id=REQUEST_ID_CTX.get(),
            route=ROUTE_CTX.get(),
            client_ip=CLIENT_IP_CTX.get(),
        )
    # Fallback: std logging with key=value
    return logging.getLogger(cfg.APP_NAME)

# --- Rate Limiter --------------------------------------------------------------

class TokenBucket:
    """Simple async token-bucket."""
    __slots__ = ("capacity", "tokens", "rate", "updated", "lock")

    def __init__(self, capacity: int, rate: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.rate = rate
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def allow(self, cost: float = 1.0) -> bool:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False

class RateLimiter:
    """Rate limiter with optional Redis backend."""
    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
        self._redis = None

    async def start(self) -> None:
        if self.cfg.REDIS_URL and aioredis:
            self._redis = await aioredis.from_url(self.cfg.REDIS_URL, encoding="utf-8", decode_responses=True)

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()

    def _key(self, identifier: str) -> str:
        return f"rl:{self.cfg.APP_NAME}:{identifier}"

    async def allow(self, identifier: str, cost: float = 1.0) -> bool:
        if not self.cfg.RATE_LIMIT_ENABLED:
            return True
        if self._redis:
            # Redis token bucket via Lua-like logic approximated with INCR/EXPIRE
            # Windowed limiter fallback: allow up to BURST per 1s and refill by RPS
            now_sec = int(time.time())
            window = f"{self._key(identifier)}:{now_sec}"
            current = await self._redis.incrbyfloat(window, cost)
            # Set short TTL for window keys
            if current == cost:
                await self._redis.expire(window, 2)
            limit = max(self.cfg.RATE_LIMIT_BURST, int(self.cfg.RATE_LIMIT_RPS))
            return current <= limit
        # In-memory token bucket
        async with self._lock:
            bucket = self._buckets.get(identifier)
            if not bucket:
                bucket = TokenBucket(self.cfg.RATE_LIMIT_BURST, self.cfg.RATE_LIMIT_RPS)
                self._buckets[identifier] = bucket
        return await bucket.allow(cost)

# --- Auth ----------------------------------------------------------------------

class AuthContext(BaseModel):
    subject: Optional[str] = None
    scopes: List[str] = []
    api_key_id: Optional[str] = None
    raw_claims: Dict[str, Any] = {}

def _extract_client_ip(req: Request) -> str:
    # Respect proxy headers if enabled
    cfg = get_settings()
    if cfg.UVICORN_PROXY_HEADERS:
        xff = req.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        xri = req.headers.get("x-real-ip")
        if xri:
            return xri.strip()
    return req.client.host if req.client else "-"

async def api_key_auth(
    request: Request,
    api_key_header: Optional[str] = Header(default=None, alias=None),
) -> Optional[str]:
    cfg = get_settings()
    header_name = cfg.API_KEY_HEADER
    provided = request.headers.get(header_name) or api_key_header
    if not cfg.API_KEYS:
        return None  # auth not configured
    if not provided or provided not in cfg.API_KEYS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return provided

async def jwt_auth(request: Request) -> Optional[AuthContext]:
    cfg = get_settings()
    auth_header = request.headers.get("Authorization", "")
    if not cfg.JWT_PUBLIC_KEY or not auth_header.startswith("Bearer "):
        return None
    if not jwt:
        raise HTTPException(status_code=500, detail="JWT support not installed")
    token = auth_header.split(" ", 1)[1].strip()
    options = {"verify_aud": cfg.JWT_AUDIENCE is not None}
    try:
        claims = jwt.decode(
            token,
            cfg.JWT_PUBLIC_KEY,
            algorithms=cfg.JWT_ALGORITHMS,
            audience=cfg.JWT_AUDIENCE,
            issuer=cfg.JWT_ISSUER,
            options=options,
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")
    sub = claims.get("sub") or claims.get("uid") or claims.get("user_id")
    scopes = claims.get("scope", "")
    scopes_list = scopes.split() if isinstance(scopes, str) else list(scopes or [])
    return AuthContext(subject=sub, scopes=scopes_list, raw_claims=claims)

async def require_auth(ctx: Optional[AuthContext] = Depends(jwt_auth), api_key: Optional[str] = Depends(api_key_auth)) -> AuthContext:
    cfg = get_settings()
    if not cfg.AUTH_REQUIRED and not cfg.API_KEYS and not cfg.JWT_PUBLIC_KEY:
        return AuthContext()
    if api_key:
        return AuthContext(api_key_id="key")
    if ctx:
        return ctx
    raise HTTPException(status_code=401, detail="Authentication required")

# --- FastAPI app ---------------------------------------------------------------

cfg = get_settings()
_init_logging(cfg)
log = _log()

app = FastAPI(
    title=f"{cfg.APP_NAME} HTTP API",
    version="1.0.0",
    docs_url=None if cfg.APP_ENV == "prod" else "/docs",
    redoc_url=None if cfg.APP_ENV == "prod" else "/redoc",
    openapi_url=None if cfg.APP_ENV == "prod" else "/openapi.json",
)

# --- Observability: Prometheus / OTel -----------------------------------------

_registry: Optional[Any] = None
_req_counter = None
_req_hist = None
_instrumentator: Optional[Any] = None

if cfg.PROMETHEUS_ENABLED:
    if _HAS_PROM:
        _instrumentator = Instrumentator(excluded_handlers=["/metrics"])
        _instrumentator.instrument(app)
    else:
        _registry = CollectorRegistry()
        _REQ_COUNTER_NAME = "http_requests_total"
        _REQ_HIST_NAME = "http_request_duration_seconds"
        _req_counter = Counter(
            _REQ_COUNTER_NAME, "Total HTTP requests", ["method", "path", "status"], registry=_registry
        )
        _req_hist = Histogram(
            _REQ_HIST_NAME, "HTTP request duration in seconds", ["method", "path"], registry=_registry
        )

_tracer_provider: Optional[Any] = None
if _HAS_OTEL and cfg.OTLP_ENDPOINT:
    try:
        resource = Resource.create({"service.name": cfg.OTLP_SERVICE_NAME, "service.version": "1.0.0"})
        _tracer_provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=cfg.OTLP_ENDPOINT)
        _tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(_tracer_provider)
        log.info("OpenTelemetry configured", otlp_endpoint=cfg.OTLP_ENDPOINT)
    except Exception as e:  # pragma: no cover
        log.error("OTel init failed", error=str(e))

# --- Redis-backed components ---------------------------------------------------

rate_limiter = RateLimiter(cfg)

# --- Middleware: CORS ----------------------------------------------------------

if cfg.CORS_ALLOW_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.CORS_ALLOW_ORIGINS,
        allow_credentials=cfg.CORS_ALLOW_CREDENTIALS,
        allow_methods=cfg.CORS_ALLOW_METHODS,
        allow_headers=cfg.CORS_ALLOW_HEADERS,
    )

# --- Middleware: request context, timing, security headers, size limit ---------

@app.middleware("http")
async def request_context_mw(request: Request, call_next: Callable) -> Response:
    req_id = request.headers.get("x-request-id") or request.headers.get("x-correlation-id") or str(uuid.uuid4())
    REQUEST_ID_CTX.set(req_id)
    CLIENT_IP_CTX.set(_extract_client_ip(request))
    ROUTE_CTX.set(request.url.path)
    start = time.perf_counter()

    # Body size guard
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > cfg.MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": "Request Entity Too Large", "limit_bytes": cfg.MAX_REQUEST_BYTES, "req_id": req_id},
        )

    # Read body if no content-length to enforce size limit
    async def limited_receive():
        body = await request.receive()
        b = body.get("body", b"")
        if b and len(b) > cfg.MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request Entity Too Large")
        return body

    request._receive = limited_receive  # type: ignore

    # Rate limit key
    identity = "-"
    if cfg.RATE_LIMIT_KEY_FUNC == "api_key":
        identity = request.headers.get(cfg.API_KEY_HEADER, "-")
    elif cfg.RATE_LIMIT_KEY_FUNC == "ip":
        identity = CLIENT_IP_CTX.get()
    else:
        identity = request.headers.get(cfg.API_KEY_HEADER) or CLIENT_IP_CTX.get()

    if cfg.RATE_LIMIT_ENABLED:
        allowed = await rate_limiter.allow(identity or "-")
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "Too Many Requests", "req_id": req_id},
                headers={"Retry-After": "1"},
            )

    try:
        response: Response = await call_next(request)
    except HTTPException as he:
        log.warning("request_error", status=he.status_code, detail=str(he.detail))
        raise
    except Exception as e:
        log.exception("unhandled_exception", error=str(e))
        return JSONResponse(status_code=500, content={"error": "Internal Server Error", "req_id": req_id})

    # Security headers
    if cfg.ENABLE_SECURITY_HEADERS:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault("Content-Security-Policy", cfg.CONTENT_SECURITY_POLICY)
        if request.url.scheme == "https":
            hsts = f"max-age={cfg.HSTS_MAX_AGE}"
            if cfg.HSTS_INCLUDE_SUBDOMAINS:
                hsts += "; includeSubDomains"
            if cfg.HSTS_PRELOAD:
                hsts += "; preload"
            response.headers.setdefault("Strict-Transport-Security", hsts)
        # Cache control
        response.headers.setdefault("Cache-Control", cfg.RESPONSE_CACHE_CONTROL)

    # Correlation headers
    response.headers["X-Request-ID"] = req_id

    # Timing
    elapsed = time.perf_counter() - start
    response.headers["X-Response-Time"] = f"{int(elapsed * 1000)}ms"

    # Metrics (fallback mode)
    if cfg.PROMETHEUS_ENABLED and not _HAS_PROM:
        try:
            if _req_counter:
                _req_counter.labels(method=request.method, path=request.url.path, status=response.status_code).inc()
            if _req_hist:
                _req_hist.labels(method=request.method, path=request.url.path).observe(elapsed)
        except Exception:  # pragma: no cover
            pass

    # Access log
    try:
        _log().info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            ms=int(elapsed * 1000),
        )
    except Exception:  # pragma: no cover
        pass

    return response

# --- Exception handlers --------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    log.info("validation_error", errors=exc.errors())
    return JSONResponse(
        status_code=422,
        content={"error": "ValidationError", "details": exc.errors(), "req_id": REQUEST_ID_CTX.get()},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "req_id": REQUEST_ID_CTX.get()},
        headers=getattr(exc, "headers", None) or {},
    )

# --- Models --------------------------------------------------------------------

class EchoPayload(BaseModel):
    message: str = Field(..., min_length=1, max_length=10_000)
    tags: List[str] = Field(default_factory=list)

class InfoResponse(BaseModel):
    name: str
    env: str
    version: str
    time_utc: float

# --- Routes: Health ------------------------------------------------------------

@app.get("/healthz", response_model=Dict[str, Any], tags=["health"])
async def healthz() -> Dict[str, Any]:
    return {
        "status": "ok",
        "name": cfg.APP_NAME,
        "env": cfg.APP_ENV,
        "req_id": REQUEST_ID_CTX.get(),
    }

@app.get("/livez", response_model=Dict[str, Any], tags=["health"])
async def livez() -> Dict[str, Any]:
    return {"status": "alive", "req_id": REQUEST_ID_CTX.get()}

@app.get("/readyz", response_model=Dict[str, Any], tags=["health"])
async def readyz() -> Dict[str, Any]:
    ready = True
    details: Dict[str, Any] = {}
    if cfg.REDIS_URL:
        details["redis"] = "configured"
        try:
            if rate_limiter._redis:
                pong = await rate_limiter._redis.ping()
                details["redis_ping"] = pong
            else:
                details["redis_ping"] = "not-initialized"
        except Exception as e:
            ready = False
            details["redis_error"] = str(e)
    return {"status": "ready" if ready else "not-ready", "details": details, "req_id": REQUEST_ID_CTX.get()}

# --- Routes: Metrics -----------------------------------------------------------

if cfg.PROMETHEUS_ENABLED:
    if _HAS_PROM:
        @_instrumentator.expose(app, include_in_schema=False)  # type: ignore
        def _exposed_metrics():  # pragma: no cover
            return None
    else:
        @app.get("/metrics")
        async def metrics():
            if not _registry:
                return PlainTextResponse("metrics disabled", status_code=404)
            output = generate_latest(_registry)
            return Response(content=output, media_type="text/plain; version=0.0.4; charset=utf-8")

# --- Routes: API ---------------------------------------------------------------

@app.get("/v1/info", response_model=InfoResponse, tags=["info"])
async def info() -> InfoResponse:
    return InfoResponse(
        name=cfg.APP_NAME,
        env=cfg.APP_ENV,
        version="1.0.0",
        time_utc=time.time(),
    )

@app.post("/v1/echo", tags=["demo"])
async def echo(
    payload: EchoPayload,
    auth: AuthContext = Depends(require_auth),
):
    return {
        "req_id": REQUEST_ID_CTX.get(),
        "subject": auth.subject or auth.api_key_id,
        "message": payload.message,
        "tags": payload.tags,
    }

@app.get("/v1/security/verify_token", tags=["security"])
async def verify_token(ctx: Optional[AuthContext] = Depends(jwt_auth)):
    if not cfg.JWT_PUBLIC_KEY:
        raise HTTPException(status_code=400, detail="JWT is not configured")
    if not ctx:
        raise HTTPException(status_code=401, detail="Invalid or missing JWT")
    return {"subject": ctx.subject, "scopes": ctx.scopes, "claims": ctx.raw_claims}

# --- Lifespan events -----------------------------------------------------------

@app.on_event("startup")
async def on_startup() -> None:
    log.info("startup_begin")
    await rate_limiter.start()
    if cfg.PROMETHEUS_ENABLED and _HAS_PROM and _instrumentator:
        try:
            _instrumentator.expose(app, include_in_schema=False)  # idempotent
        except Exception:  # pragma: no cover
            pass
    log.info("startup_ok")

@app.on_event("shutdown")
async def on_shutdown() -> None:
    log.info("shutdown_begin")
    await rate_limiter.close()
    if _tracer_provider:
        try:
            _tracer_provider.shutdown()  # type: ignore
        except Exception:  # pragma: no cover
            pass
    log.info("shutdown_ok")

# --- Entrypoint ---------------------------------------------------------------

def _uvicorn_kwargs() -> Dict[str, Any]:
    return dict(
        host=cfg.HOST,
        port=cfg.PORT,
        log_level=cfg.UVICORN_LOG_LEVEL,
        access_log=cfg.UVICORN_ACCESS_LOG,
        proxy_headers=cfg.UVICORN_PROXY_HEADERS,
        timeout_keep_alive=cfg.UVICORN_TIMEOUT_KEEP_ALIVE,
        workers=cfg.UVICORN_WORKERS,
    )

def run() -> None:
    import uvicorn  # local import to avoid mandatory dep at import time
    uvicorn.run("server:app", **_uvicorn_kwargs())

if __name__ == "__main__":
    # Graceful shutdown for local run
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, signal.getsignal(sig))
        except Exception:
            pass
    run()
