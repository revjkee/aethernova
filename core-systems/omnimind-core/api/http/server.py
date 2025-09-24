#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OmniMind Core - Production-grade HTTP server (FastAPI)
Features:
- Pydantic Settings (ENV-based config)
- Structured JSON logging with request_id and optional traceparent
- Security headers, CORS, Compression, Timeout
- Global exception handling with unified error schema
- /health, /ready, /metrics (Prometheus), /v1/echo
- Optional OTLP tracing/metrics (OpenTelemetry) via flags
- Rate limiting (in-memory or Redis), simple token-bucket
- JWT auth dependency with roles (optional)
- Graceful shutdown & readiness gates
"""

import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, Optional, Tuple

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, BaseSettings, Field, validator

# Prometheus metrics
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Optional Redis for rate limit
try:
    import redis.asyncio as redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # will fallback to in-memory

# Optional OpenTelemetry (enabled by flags)
_OTEL_AVAILABLE = False
try:  # pragma: no cover
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHTTPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _OTEL_AVAILABLE = True
except Exception:
    pass

APP_START_TIME = time.time()
READINESS_FLAG = {"ready": False}

# ------------------------------
# Config
# ------------------------------
class Settings(BaseSettings):
    app_name: str = Field("omnimind-core", env="APP_NAME")
    env: str = Field("production", env="APP_ENV")
    host: str = Field("0.0.0.0", env="HTTP_HOST")
    port: int = Field(8080, env="HTTP_PORT")
    metrics_port: int = Field(9090, env="METRICS_PORT")
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_json: bool = Field(True, env="LOG_JSON")
    request_timeout_s: int = Field(30, env="HTTP_REQUEST_TIMEOUT_S")

    cors_enabled: bool = Field(True, env="CORS_ENABLED")
    cors_origins: str = Field("*", env="CORS_ORIGINS")
    cors_methods: str = Field("GET,POST,PUT,DELETE,PATCH,OPTIONS", env="CORS_METHODS")
    cors_headers: str = Field("*", env="CORS_HEADERS")

    # Security headers
    security_headers: bool = Field(True, env="SECURITY_HEADERS")

    # Rate limiting
    rate_limit_enabled: bool = Field(True, env="RATE_LIMIT_ENABLED")
    rate_limit_strategy: str = Field("token_bucket", env="RATE_LIMIT_STRATEGY")  # token_bucket|sliding_window
    rate_limit_bucket_rps: int = Field(50, env="RATE_LIMIT_RPS")  # refill per second
    rate_limit_bucket_burst: int = Field(100, env="RATE_LIMIT_BURST")
    rate_limit_key: str = Field("ip", env="RATE_LIMIT_KEY")  # ip|user|api_key
    rate_limit_redis_url: Optional[str] = Field(None, env="RATE_LIMIT_REDIS_URL")

    # JWT (optional)
    jwt_enabled: bool = Field(False, env="JWT_ENABLED")
    jwt_issuer: Optional[str] = Field(None, env="JWT_ISSUER")
    jwt_audience: Optional[str] = Field(None, env="JWT_AUDIENCE")
    jwt_jwks_url: Optional[str] = Field(None, env="JWT_JWKS_URL")  # for real-world use; omitted here

    # OTEL
    otel_enabled: bool = Field(False, env="OTEL_ENABLED")
    otel_endpoint: Optional[str] = Field(None, env="OTLP_ENDPOINT")  # HTTP exporter
    otel_insecure: bool = Field(False, env="OTLP_INSECURE")

    class Config:
        env_file = os.environ.get("ENV_FILE", None)
        case_sensitive = False

    @validator("log_level")
    def _v_level(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARN", "WARNING", "ERROR"}:
            return "INFO"
        return v

    @property
    def cors_origin_list(self):
        return [o.strip() for o in self.cors_origins.split(",")] if self.cors_origins else []

settings = Settings()

# ------------------------------
# Logging
# ------------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        base = {
            "@timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": settings.app_name,
            "env": settings.env,
            "pid": os.getpid(),
        }
        # request/trace context if present
        for key in ("request_id", "trace_id", "span_id", "path", "method", "client_ip"):
            val = getattr(record, key, None)
            if val:
                base[key] = val
        if record.exc_info:
            base["exception"] = "".join(traceback.format_exception(*record.exc_info))[:10000]
        return json.dumps(base, ensure_ascii=False)

def configure_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    level = getattr(logging, settings.log_level if settings.log_level != "WARN" else "WARNING")
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    root.addHandler(handler)

configure_logging()
logger = logging.getLogger("omnimind.http")

# ------------------------------
# Metrics
# ------------------------------
HTTP_REQUESTS = Counter(
    "omnimind_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "omnimind_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
START_TIME = Gauge("omnimind_start_time_seconds", "Application start time (seconds since epoch)")
READINESS = Gauge("omnimind_readiness", "Readiness probe status (1=ready, 0=not ready)")
LIVENESS = Gauge("omnimind_liveness", "Liveness  probe status (1=alive, 0=dead)")
INFLIGHT = Gauge("omnimind_http_inflight_requests", "Inflight HTTP requests")

START_TIME.set(APP_START_TIME)
LIVENESS.set(1)
READINESS.set(0)

# ------------------------------
# Rate Limiter
# ------------------------------
class RateLimiter:
    """
    Token-bucket per key. Redis-backed if configured, otherwise in-memory.
    """

    def __init__(self):
        self.rps = settings.rate_limit_bucket_rps
        self.burst = settings.rate_limit_bucket_burst
        self.strategy = settings.rate_limit_strategy
        self.redis_url = settings.rate_limit_redis_url
        self._mem_buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = asyncio.Lock()
        self._r: Optional["redis.Redis"] = None

    async def setup(self):
        if self.redis_url and redis is not None:
            self._r = redis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

    def _key_for(self, request: Request, user_id: Optional[str], api_key_hash: Optional[str]) -> str:
        if settings.rate_limit_key == "user" and user_id:
            return f"user:{user_id}"
        if settings.rate_limit_key == "api_key" and api_key_hash:
            return f"key:{api_key_hash}"
        # default: ip
        ip = request.client.host if request.client else "0.0.0.0"
        return f"ip:{ip}"

    async def allow(self, key: str) -> bool:
        if not settings.rate_limit_enabled:
            return True
        now = time.monotonic()
        if self._r:
            # Redis Lua for atomic token bucket could be used; here a simple fallback.
            # Note: This simple approach has race windows; for full strictness, use Lua script.
            pipe = self._r.pipeline(True)
            tokens_key = f"rl:{key}:tokens"
            ts_key = f"rl:{key}:ts"

            last_ts = await self._r.get(ts_key)
            last_ts = float(last_ts) if last_ts else now
            delta = max(0.0, now - last_ts)
            refill = delta * self.rps

            # fetch tokens
            tokens = await self._r.get(tokens_key)
            tokens = float(tokens) if tokens else float(self.burst)

            tokens = min(self.burst, tokens + refill)
            allowed = tokens >= 1.0
            tokens = tokens - 1.0 if allowed else tokens

            pipe.set(tokens_key, tokens, ex=60)
            pipe.set(ts_key, now, ex=60)
            await pipe.execute()
            return allowed

        # In-memory
        async with self._lock:
            tokens, last_ts = self._mem_buckets.get(key, (float(self.burst), now))
            delta = max(0.0, now - last_ts)
            refill = delta * self.rps
            tokens = min(self.burst, tokens + refill)
            allowed = tokens >= 1.0
            tokens = tokens - 1.0 if allowed else tokens
            self._mem_buckets[key] = (tokens, now)
            return allowed

rate_limiter = RateLimiter()

# ------------------------------
# Auth (JWT stub)
# ------------------------------
class Principal(BaseModel):
    sub: Optional[str] = None
    roles: Tuple[str, ...] = tuple()
    api_key_hash: Optional[str] = None

async def auth_dependency(authorization: Optional[str] = Header(None)) -> Principal:
    """
    Minimal JWT/API-key extractor. For real validation attach JWKS/issuer checks.
    """
    if not settings.jwt_enabled:
        # Anonymous principal
        return Principal()
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization")
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            # WARNING: stub decode, replace with real JWT validation (PyJWT/jose + JWKS)
            # Here we only parse header.payload.signature structure for demo
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            # Do not base64 decode to avoid dependency; trust external auth in real systems
            # Use hash of token as api_key surrogate
            api_key_hash = str(abs(hash(token)))
            return Principal(sub=None, roles=tuple(), api_key_hash=api_key_hash)
        elif scheme.lower() == "apikey":
            api_key_hash = str(abs(hash(token)))
            return Principal(api_key_hash=api_key_hash)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unsupported Authorization scheme")

# ------------------------------
# FastAPI app
# ------------------------------
app = FastAPI(
    title="OmniMind Core HTTP API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list or ["*"],
        allow_credentials=True,
        allow_methods=[m.strip() for m in settings.cors_methods.split(",")],
        allow_headers=[h.strip() for h in settings.cors_headers.split(",")],
        expose_headers=["X-Request-ID", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"],
        max_age=600,
    )

# Compression
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    start = time.perf_counter()
    INFLIGHT.inc()
    try:
        # Generate/propagate request id
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        # Traceparent passthrough if exists
        traceparent = request.headers.get("traceparent")

        # Timeout guard
        async def _call():
            return await call_next(request)

        try:
            response: Response = await asyncio.wait_for(_call(), timeout=settings.request_timeout_s)
        except asyncio.TimeoutError:
            HTTP_REQUESTS.labels(request.method, request.url.path, str(status.HTTP_504_GATEWAY_TIMEOUT)).inc()
            return JSONResponse(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                content={"code": "timeout", "message": "Request timed out", "request_id": req_id},
            )

        # Add headers
        response.headers["X-Request-ID"] = req_id
        if settings.security_headers:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
            response.headers.setdefault("X-XSS-Protection", "0")
            # Content-Security-Policy is omitted for API JSON

        # Metrics
        dur = time.perf_counter() - start
        HTTP_LATENCY.labels(request.method, request.url.path).observe(dur)
        HTTP_REQUESTS.labels(request.method, request.url.path, str(response.status_code)).inc()

        # Log
        extra = {
            "request_id": req_id,
            "trace_id": traceparent or "",
            "path": request.url.path,
            "method": request.method,
            "client_ip": (request.client.host if request.client else ""),
        }
        logging.getLogger("omnimind.http.access").info("request completed", extra=extra)
        return response
    finally:
        INFLIGHT.dec()

# Global error handler
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    req_id = request.headers.get("x-request-id") or ""
    logging.getLogger("omnimind.http").error("unhandled error", exc_info=exc, extra={
        "request_id": req_id,
        "path": request.url.path,
        "method": request.method,
    })
    HTTP_REQUESTS.labels(request.method, request.url.path, str(status.HTTP_500_INTERNAL_SERVER_ERROR)).inc()
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"code": "internal_error", "message": "Internal Server Error", "request_id": req_id},
    )

# Rate limit dependency
async def rate_limit(request: Request, principal: Principal = Depends(auth_dependency)):
    key = rate_limiter._key_for(request, principal.sub, principal.api_key_hash)
    allowed = await rate_limiter.allow(key)
    if not allowed:
        # Compute reset ~ 1 sec window approximation
        reset_sec = 1
        headers = {
            "RateLimit-Limit": f"{settings.rate_limit_bucket_burst};w=1",
            "RateLimit-Remaining": "0",
            "RateLimit-Reset": str(reset_sec),
            "Retry-After": str(reset_sec),
        }
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests", headers=headers)

# ------------------------------
# Lifespan management
# ------------------------------
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Rate limiter setup
    await rate_limiter.setup()

    # OTEL setup
    if settings.otel_enabled and _OTEL_AVAILABLE and settings.otel_endpoint:
        try:
            resource = Resource.create({"service.name": settings.app_name, "deployment.environment": settings.env})
            provider = TracerProvider(resource=resource)
            exporter = OTLPHTTPSpanExporter(endpoint=settings.otel_endpoint, insecure=settings.otel_insecure)
            processor = BatchSpanProcessor(exporter)
            provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)
            logger.info("OTEL tracing enabled")
        except Exception as e:
            logger.error("Failed to enable OTEL: %s", e)

    # Mark ready after initialization
    READINESS_FLAG["ready"] = True
    READINESS.set(1)
    logger.info("Application is ready")
    try:
        yield
    finally:
        READINESS_FLAG["ready"] = False
        READINESS.set(0)
        logger.info("Shutting down")

app.router.lifespan_context = lifespan

# ------------------------------
# Schemas & Models
# ------------------------------
class EchoRequest(BaseModel):
    message: str
    meta: Optional[Dict[str, Any]] = None

class EchoResponse(BaseModel):
    message: str
    request_id: Optional[str] = None
    time: str

# ------------------------------
# Routes
# ------------------------------
@app.get("/health", response_class=PlainTextResponse, include_in_schema=False)
async def health():
    return "OK"

@app.get("/ready", response_class=PlainTextResponse, include_in_schema=False)
async def ready():
    return "READY" if READINESS_FLAG["ready"] else PlainTextResponse("NOT_READY", status_code=503)

@app.get("/metrics", include_in_schema=False)
async def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

@app.post("/v1/echo", response_model=EchoResponse, dependencies=[Depends(rate_limit)])
async def echo(req: EchoRequest, request: Request, principal: Principal = Depends(auth_dependency)):
    req_id = request.headers.get("x-request-id") or ""
    return EchoResponse(
        message=req.message,
        request_id=req_id,
        time=datetime.now(tz=timezone.utc).isoformat(),
    )

# Example: guarded endpoint requiring role
def require_role(role: str):
    async def _role_dep(principal: Principal = Depends(auth_dependency)):
        if role not in principal.roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return principal
    return _role_dep

@app.get("/v1/agents", dependencies=[Depends(rate_limit)])
async def list_agents(principal: Principal = Depends(auth_dependency)):
    # Placeholder. Integrate with your domain layer/repository.
    return {"agents": [], "count": 0}

# ------------------------------
# Entrypoint
# ------------------------------
def _install_signal_handlers(loop: asyncio.AbstractEventLoop):
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Received termination signal")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)
    return stop_event

def run():
    import uvicorn

    # uvicorn access log is redundant when we have structured access logs
    uvicorn.run(
        "server:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
        # Workers can be scaled externally; use --workers for multi-process
    )

if __name__ == "__main__":
    run()
