# mythos-core/api/http/server.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Callable, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Prometheus metrics (no external web server needed)
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, multiprocess  # type: ignore

# -------------------------
# Settings
# -------------------------

class Settings(BaseSettings):
    service_name: str = "mythos-core"
    service_component: str = "http"
    env: str = os.getenv("NEUROFORGE_PROFILE", "prod")

    bind_host: str = "0.0.0.0"
    bind_port: int = int(os.getenv("MYTHOS_HTTP_PORT", "8080"))

    log_level: str = os.getenv("MYTHOS_LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("MYTHOS_LOG_FORMAT", "json").lower() == "json"

    cors_enabled: bool = os.getenv("MYTHOS_CORS_ENABLED", "false").lower() == "true"
    cors_allow_origins: Tuple[str, ...] = tuple(
        filter(None, os.getenv("MYTHOS_CORS_ALLOW_ORIGINS", "").split(","))
    )
    trusted_hosts: Tuple[str, ...] = tuple(
        filter(None, os.getenv("MYTHOS_TRUSTED_HOSTS", "").split(","))
    )  # e.g. "example.com,.example.com,localhost"

    prometheus_multiproc_dir: Optional[str] = os.getenv("PROMETHEUS_MULTIPROC_DIR")
    metrics_enabled: bool = os.getenv("MYTHOS_METRICS_ENABLED", "true").lower() == "true"

    tracing_enabled: bool = os.getenv("MYTHOS_TRACING_ENABLED", "false").lower() == "true"
    otlp_endpoint: str = os.getenv("OTLP_ENDPOINT", "http://otel-collector:4317")

    # Simple in-memory rate limiter (per-IP)
    rate_limit_enabled: bool = os.getenv("MYTHOS_RATELIMIT_ENABLED", "false").lower() == "true"
    rate_limit_capacity: int = int(os.getenv("MYTHOS_RATELIMIT_CAPACITY", "200"))
    rate_limit_fill_rate: float = float(os.getenv("MYTHOS_RATELIMIT_FILL_RATE", "100"))  # tokens/sec

    # Feature Store endpoint (gRPC/HTTP — заглушка, используйте свой клиент)
    feature_store_endpoint: str = os.getenv("FS_ENDPOINT", "http://feature-store:8081")

    class Config:
        env_prefix = "MYTHOS_"


settings = Settings()

# -------------------------
# Logging (JSON)
# -------------------------

_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "service": settings.service_name,
            "component": settings.service_component,
            "env": settings.env,
            "message": record.getMessage(),
            "request_id": _request_id_ctx.get("-"),
        }
        # Extra fields
        if record.args and isinstance(record.args, dict):
            base.update(record.args)  # type: ignore
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)

def configure_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    lvl = getattr(logging, settings.log_level.upper(), logging.INFO)
    root.setLevel(lvl)

    handler = logging.StreamHandler()
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s %(message)s"))
    root.addHandler(handler)

configure_logging()
log = logging.getLogger("mythos.http")

# -------------------------
# Metrics
# -------------------------

if settings.prometheus_multiproc_dir:
    # Support gunicorn/uvicorn workers
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
else:
    registry = CollectorRegistry()

REQ_COUNTER = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
    registry=registry,
)
REQ_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
    registry=registry,
)

# -------------------------
# Simple token-bucket limiter (per-IP)
# -------------------------

@dataclass
class Bucket:
    tokens: float
    last: float

class RateLimiter:
    def __init__(self, capacity: int, fill_rate: float) -> None:
        self.capacity = capacity
        self.fill_rate = fill_rate
        self._buckets: Dict[str, Bucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.time()
        async with self._lock:
            b = self._buckets.get(key)
            if not b:
                self._buckets[key] = Bucket(tokens=self.capacity - cost, last=now)
                return True
            # refill
            delta = now - b.last
            b.tokens = min(self.capacity, b.tokens + delta * self.fill_rate)
            b.last = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True
            return False

limiter = RateLimiter(settings.rate_limit_capacity, settings.rate_limit_fill_rate)

# -------------------------
# Idempotency cache (in-memory with TTL)
# -------------------------

class IdempotencyCache:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()
        self.ttl = 600.0  # seconds

    async def get_or_set(self, key: str, value_factory: Callable[[], Any]) -> Any:
        now = time.time()
        async with self._lock:
            # Purge expired
            for k, (ts, _) in list(self._store.items()):
                if now - ts > self.ttl:
                    self._store.pop(k, None)
            if key in self._store:
                return self._store[key][1]
            value = value_factory()
            self._store[key] = (now, value)
            return value

idem_cache = IdempotencyCache()

# -------------------------
# Feature Store client (stub interface)
# -------------------------

class FeatureReadQuery(BaseModel):
    user_id: str = Field(..., min_length=1)
    as_of: Optional[int] = Field(None, description="Unix epoch ms")

class FeatureUpsert(BaseModel):
    user_id: str
    event_ts: int
    score: float
    level: int

class FeatureStoreClient:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        # Use httpx or gRPC actual client in real implementation

    async def get_online(self, table: str, key: Dict[str, Any], columns: Tuple[str, ...]) -> Dict[str, Any]:
        # TODO: replace with real call; here is a stub response
        return {"score": 10.5, "level": 1}

    async def upsert(self, table: str, rows: list[Dict[str, Any]]) -> None:
        # TODO: implement actual call
        return None

# -------------------------
# OpenTelemetry (optional)
# -------------------------

def init_tracing(app: FastAPI) -> None:
    if not settings.tracing_enabled:
        return
    try:
        # Lazy import to avoid hard dependency
        from opentelemetry import trace  # type: ignore
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
        from opentelemetry.sdk.resources import Resource  # type: ignore
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore

        resource = Resource.create(
            {
                "service.name": settings.service_name,
                "service.namespace": "mythos",
                "service.version": os.getenv("MYTHOS_VERSION", "0.1.0"),
                "service.instance.id": str(uuid.uuid4()),
                "deployment.environment": settings.env,
            }
        )
        provider = TracerProvider(resource=resource)
        span_exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint, insecure=True)
        processor = BatchSpanProcessor(span_exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        log.info("OpenTelemetry tracing enabled")
    except Exception as e:
        log.warning("Tracing init failed: %s", e)

# -------------------------
# Middleware
# -------------------------

class RequestIDMiddleware:
    def __init__(self, app: FastAPI) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        req_id = None
        for k, v in headers.items():
            if k.decode().lower() == "x-request-id":
                req_id = v.decode()
                break
        if not req_id:
            req_id = str(uuid.uuid4())
        token = _request_id_ctx.set(req_id)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers_list = message.setdefault("headers", [])
                headers_list.append((b"x-request-id", req_id.encode()))
            await send(message)

        try:
            return await self.app(scope, receive, send_wrapper)
        finally:
            _request_id_ctx.reset(token)

class SecurityHeadersMiddleware:
    def __init__(self, app: FastAPI) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"content-security-policy", b"default-src 'none'"),
                    ]
                )
            await send(message)

        return await self.app(scope, receive, send_wrapper)

class MetricsMiddleware:
    def __init__(self, app: FastAPI) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if not settings.metrics_enabled or scope["type"] != "http":
            return await self.app(scope, receive, send)
        method = scope["method"]
        path_template_holder = {"value": scope.get("path", "")}
        start = time.perf_counter()

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                # capture status for counter
                status_code = message["status"]
                path_tmpl = path_template_holder["value"]
                REQ_COUNTER.labels(method=method, path=path_tmpl, status=str(status_code)).inc()
            await send(message)

        async def receive_wrapper():
            return await receive()

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        finally:
            elapsed = time.perf_counter() - start
            path_tmpl = path_template_holder["value"]
            REQ_LATENCY.labels(method=method, path=path_tmpl).observe(elapsed)

# -------------------------
# FastAPI app and lifespan
# -------------------------

app = FastAPI(
    title="Mythos Core HTTP API",
    version=os.getenv("MYTHOS_VERSION", "0.1.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Attach middlewares
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)

if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allow_origins) or ["*"],
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=600,
    )

if settings.trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))

# Global state
app.state.ready = False
app.state.fs_client = FeatureStoreClient(settings.feature_store_endpoint)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_tracing(app)
    log.info("Starting HTTP server", extra={"event": "startup"})
    app.state.ready = True

    # Graceful shutdown handling
    stop_event = asyncio.Event()

    def _signal_handler():
        log.info("Shutdown signal received")
        app.state.ready = False
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows
            signal.signal(sig, lambda *_: _signal_handler())

    try:
        yield
    finally:
        app.state.ready = False
        await asyncio.wait_for(stop_event.wait(), timeout=0.01)
        log.info("HTTP server stopped", extra={"event": "shutdown"})

app.router.lifespan_context = lifespan  # attach lifespan

# -------------------------
# Exception handlers
# -------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    log.warning("Validation error: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "details": exc.errors(),
            "request_id": _request_id_ctx.get("-"),
        },
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    log.warning("HTTP error %s: %s", exc.status_code, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail or "error",
            "request_id": _request_id_ctx.get("-"),
        },
    )

@app.middleware("http")
async def ratelimit_middleware(request: Request, call_next):
    if settings.rate_limit_enabled:
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "0.0.0.0").split(",")[0].strip()
        try:
            # ensure valid IP string
            ip_address(client_ip)
        except Exception:
            client_ip = "0.0.0.0"
        allowed = await limiter.allow(client_ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limited",
                    "request_id": _request_id_ctx.get("-"),
                },
                headers={"Retry-After": "1"},
            )
    response = await call_next(request)
    return response

# -------------------------
# Health and metrics
# -------------------------

@app.get("/healthz", include_in_schema=False)
async def healthz():
    return PlainTextResponse("ok")

@app.get("/readyz", include_in_schema=False)
async def readyz():
    return PlainTextResponse("ready" if app.state.ready else "not-ready", status_code=200 if app.state.ready else 503)

@app.get("/metrics", include_in_schema=False)
async def metrics():
    if not settings.metrics_enabled:
        return PlainTextResponse("metrics disabled", status_code=404)
    data = generate_latest(registry)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

# -------------------------
# API models
# -------------------------

class FeaturesResponse(BaseModel):
    user_id: str
    features: Dict[str, Any]
    source: str = "online"

# -------------------------
# Endpoints
# -------------------------

@app.get("/v1/features", response_model=FeaturesResponse, tags=["features"])
async def get_user_features(user_id: str, as_of: Optional[int] = None, request: Request = None):
    # Template for Feature Store online lookup
    cols = ("score", "level")
    rv = await app.state.fs_client.get_online("user_stats", {"user_id": user_id, "as_of": as_of}, cols)
    return FeaturesResponse(user_id=user_id, features=rv or {}, source="online")

@app.post("/v1/features:upsert", status_code=204, tags=["features"])
async def upsert_features(payload: FeatureUpsert, request: Request):
    # Idempotency-Key support (in-memory cache)
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key:
        result = await idem_cache.get_or_set(idem_key, lambda: {"ok": True})
        # If entry already existed we short-circuit with 208 Already Reported semantics via 200
        if result is not None and result != {"ok": True}:
            return JSONResponse(status_code=200, content=result)

    await app.state.fs_client.upsert("user_stats", [payload.model_dump()])
    return Response(status_code=204)

# Example root
@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse(
        {"service": settings.service_name, "component": settings.service_component, "env": settings.env}
    )

# -------------------------
# Entrypoint
# -------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.http.server:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
        log_level=settings.log_level.lower(),
        access_log=False,  # we log ourselves in JSON
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
