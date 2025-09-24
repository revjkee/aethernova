# datafabric-core/api/http/server.py
# Industrial-grade FastAPI server for DataFabric Core
# Features: robust config, structured logging, request-id, security headers,
# CORS, health/readiness/startup probes, Prometheus metrics (with fallback),
# simple in-memory rate limiting, error handling, API versioning, graceful shutdown,
# optional OpenTelemetry instrumentation when available.

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import typing as t
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRouter
from pydantic import BaseModel, Field, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

# Optional Prometheus
_PROM_AVAILABLE = True
try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        CollectorRegistry,
        CONTENT_TYPE_LATEST,
        generate_latest,
        PlatformCollector,
        ProcessCollector,
        GC_COLLECTOR,
    )
except Exception:
    _PROM_AVAILABLE = False

# Optional OpenTelemetry (auto-instrumentation if installed)
_OTEL_AVAILABLE = True
try:
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
except Exception:
    _OTEL_AVAILABLE = False

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

class ServerSettings(BaseSettings):
    # Core
    app_name: str = "datafabric-core"
    environment: str = Field("production", pattern="^(local|dev|staging|production)$")
    version: str = "1.0.0"
    bind_host: str = "0.0.0.0"
    bind_port: int = 8080

    # CORS
    cors_enabled: bool = True
    cors_allow_origins: list[AnyHttpUrl | str] = Field(
        default_factory=lambda: ["*"]
    )
    cors_allow_credentials: bool = True
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["*"])

    # Security headers
    security_headers_enabled: bool = True

    # Metrics
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"

    # Rate limit (simple in-memory token bucket per IP)
    ratelimit_enabled: bool = True
    ratelimit_requests: int = 120  # tokens per window
    ratelimit_window_sec: int = 60  # refill window
    ratelimit_burst: int = 40       # extra burst
    ratelimit_trust_headers: bool = True  # trust X-Forwarded-For

    # Timeouts
    read_timeout_sec: float = 30.0
    write_timeout_sec: float = 30.0
    request_timeout_sec: float = 60.0

    # OpenTelemetry
    otel_enabled: bool = True
    otel_console_exporter: bool = False

    # Health
    readiness_startup_grace_sec: float = 2.0

    model_config = SettingsConfigDict(env_prefix="DFC_", case_sensitive=False)


@lru_cache(maxsize=1)
def get_settings() -> ServerSettings:
    return ServerSettings()  # reads env with prefix DFC_


# ------------------------------------------------------------------------------
# Logging (structured-ish JSON logs)
# ------------------------------------------------------------------------------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach extras if present
        for key in ("request_id", "path", "method", "status_code", "latency_ms", "client_ip"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        # Exceptions
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(env: str) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO if env != "local" else logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root.handlers = [handler]


# ------------------------------------------------------------------------------
# Middlewares
# ------------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    HEADER_NAME_IN = "X-Request-ID"
    HEADER_NAME_OUT = "X-Request-ID"

    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get(self.HEADER_NAME_IN) or str(uuid.uuid4())
        request.state.request_id = req_id
        response: Response = await call_next(request)
        response.headers[self.HEADER_NAME_OUT] = req_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Hardening headers (safe defaults; adjust per product policy)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';"
        )
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return response


@dataclass
class TokenBucket:
    capacity: int
    refill: int
    window: int
    tokens: int
    updated_at: float


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, settings: ServerSettings):
        super().__init__(app)
        self._settings = settings
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _client_ip(self, request: Request) -> str:
        if self._settings.ratelimit_trust_headers:
            xfwd = request.headers.get("X-Forwarded-For")
            if xfwd:
                ip = xfwd.split(",")[0].strip()
                try:
                    ip_address(ip)
                    return ip
                except Exception:
                    pass
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if not self._settings.ratelimit_enabled:
            return await call_next(request)

        key = self._client_ip(request)
        now = time.time()
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=self._settings.ratelimit_requests + self._settings.ratelimit_burst,
                    refill=self._settings.ratelimit_requests,
                    window=self._settings.ratelimit_window_sec,
                    tokens=self._settings.ratelimit_requests + self._settings.ratelimit_burst,
                    updated_at=now,
                )
                self._buckets[key] = bucket
            # Refill
            elapsed = now - bucket.updated_at
            if elapsed >= bucket.window:
                # number of full windows passed
                nwin = int(elapsed // bucket.window)
                bucket.tokens = min(
                    bucket.tokens + nwin * bucket.refill,
                    bucket.capacity
                )
                bucket.updated_at = now

            if bucket.tokens <= 0:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "rate_limited",
                        "detail": f"Too many requests. Try again later.",
                    },
                )
            bucket.tokens -= 1

        return await call_next(request)


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, timeout_sec: float):
        super().__init__(app)
        self._timeout = timeout_sec

    async def dispatch(self, request: Request, call_next):
        try:
            return await asyncio.wait_for(call_next(request), timeout=self._timeout)
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                content={"error": "timeout", "detail": "Request timed out"},
            )


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger = logging.getLogger("access")
        start = time.perf_counter()
        rid = getattr(request.state, "request_id", None)
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (
            request.client.host if request.client else "unknown"
        )
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as e:
            status_code = 500
            logger.exception("unhandled_exception", extra={"request_id": rid})
            raise e
        finally:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            extra = {
                "request_id": rid,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "latency_ms": elapsed_ms,
                "client_ip": client_ip,
            }
            logger.info("access", extra=extra)


# ------------------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------------------

class Metrics:
    def __init__(self, enabled: bool):
        self.enabled = enabled and _PROM_AVAILABLE
        if self.enabled:
            self.registry = CollectorRegistry(auto_describe=True)
            # Default collectors
            ProcessCollector(registry=self.registry)
            PlatformCollector(registry=self.registry)
            GC_COLLECTOR.registries.add(self.registry)

            self.http_requests = Counter(
                "http_requests_total",
                "Total HTTP requests",
                ["method", "path", "status"],
                registry=self.registry,
            )
            self.http_latency = Histogram(
                "http_request_duration_seconds",
                "HTTP request latency",
                ["method", "path"],
                registry=self.registry,
            )
            self.startup_gauge = Gauge(
                "app_startup_complete",
                "Application startup complete flag (1/0)",
                registry=self.registry,
            )
            self.ready_gauge = Gauge(
                "app_readiness",
                "Application readiness flag (1/0)",
                registry=self.registry,
            )
        else:
            self.registry = None
            self.http_requests = None
            self.http_latency = None
            self.startup_gauge = None
            self.ready_gauge = None

    def render(self) -> tuple[bytes, str]:
        if self.enabled:
            return generate_latest(self.registry), CONTENT_TYPE_LATEST
        # Fallback minimal metrics (text)
        payload = (
            "# Fallback metrics (prometheus not installed)\n"
            "app_startup_complete 1\n"
            "app_readiness 1\n"
        ).encode("utf-8")
        return payload, "text/plain; version=0.0.4; charset=utf-8"


# ------------------------------------------------------------------------------
# Error models & handlers
# ------------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    error: str
    detail: t.Any | None = None


def install_error_handlers(app: FastAPI):
    @app.exception_handler(HTTPException)
    async def http_exc_handler(_: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(error="http_error", detail=exc.detail).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(error="validation_error", detail=exc.errors()).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(_: Request, exc: Exception):
        logging.getLogger(__name__).exception("unhandled_error")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(error="internal_error", detail="Unhandled error").model_dump(),
        )


# ------------------------------------------------------------------------------
# Health / readiness
# ------------------------------------------------------------------------------

class HealthStatus(BaseModel):
    status: str
    details: dict[str, t.Any] = Field(default_factory=dict)


class HealthProbe:
    def __init__(self):
        self._startup_complete = asyncio.Event()
        self._ready = asyncio.Event()

    def set_startup_complete(self):
        self._startup_complete.set()

    def set_ready(self):
        self._ready.set()

    async def wait_startup(self):
        await self._startup_complete.wait()

    async def wait_ready(self):
        await self._ready.wait()


# ------------------------------------------------------------------------------
# Optional OpenTelemetry
# ------------------------------------------------------------------------------

def maybe_install_otel(app: FastAPI, settings: ServerSettings) -> None:
    if not (settings.otel_enabled and _OTEL_AVAILABLE):
        logging.getLogger(__name__).info("otel_disabled_or_unavailable")
        return
    try:
        resource = Resource.create(
            {
                "service.name": settings.app_name,
                "service.version": settings.version,
                "deployment.environment": settings.environment,
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = ConsoleSpanExporter() if settings.otel_console_exporter else None
        if exporter:
            provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        logging.getLogger(__name__).info("otel_initialized")
    except Exception:
        logging.getLogger(__name__).exception("otel_init_failed")


# ------------------------------------------------------------------------------
# Dependencies & routers
# ------------------------------------------------------------------------------

def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")


v1 = APIRouter(prefix="/api/v1")


class EchoIn(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)


class EchoOut(BaseModel):
    request_id: str
    message: str
    echoed_at: float


@v1.post("/echo", response_model=EchoOut, summary="Echo message")
async def echo(
    payload: EchoIn,
    request_id: str = Depends(get_request_id),
):
    return EchoOut(request_id=request_id, message=payload.message, echoed_at=time.time())


# ------------------------------------------------------------------------------
# Lifespan (startup/shutdown hooks)
# ------------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger = logging.getLogger(__name__)
    health: HealthProbe = app.state.health
    metrics: Metrics = app.state.metrics

    # Simulate resource initialization (DB pools, clients, caches, etc.)
    try:
        await asyncio.sleep(settings.readiness_startup_grace_sec)
        health.set_startup_complete()
        if metrics.enabled:
            metrics.startup_gauge.set(1)
        # If your dependencies are ready, set readiness
        health.set_ready()
        if metrics.enabled:
            metrics.ready_gauge.set(1)
        logger.info("startup_complete")
        yield
    except Exception:
        logger.exception("startup_failure")
        raise
    finally:
        # Graceful shutdown
        logger.info("shutdown_begin")
        await asyncio.sleep(0.01)
        logger.info("shutdown_complete")


# ------------------------------------------------------------------------------
# App factory
# ------------------------------------------------------------------------------

def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.environment)

    app = FastAPI(
        title=f"{settings.app_name} HTTP API",
        version=settings.version,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Shared state
    app.state.health = HealthProbe()
    app.state.metrics = Metrics(enabled=settings.metrics_enabled)

    # Middlewares
    app.add_middleware(RequestIDMiddleware)
    if settings.security_headers_enabled:
        app.add_middleware(SecurityHeadersMiddleware)
    if settings.ratelimit_enabled:
        app.add_middleware(RateLimitMiddleware, settings=settings)
    app.add_middleware(RequestTimeoutMiddleware, timeout_sec=settings.request_timeout_sec)
    app.add_middleware(AccessLogMiddleware)

    if settings.cors_enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(o) for o in settings.cors_allow_origins],
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=settings.cors_allow_methods,
            allow_headers=settings.cors_allow_headers,
        )

    # Error handlers
    install_error_handlers(app)

    # Routes
    app.include_router(v1)

    # Root and health
    @app.get("/", include_in_schema=False)
    async def root():
        return {"name": settings.app_name, "version": settings.version, "env": settings.environment}

    @app.get("/health/live", response_model=HealthStatus, include_in_schema=False)
    async def liveness():
        return HealthStatus(status="ok")

    @app.get("/health/ready", response_model=HealthStatus, include_in_schema=False)
    async def readiness(request: Request):
        health: HealthProbe = request.app.state.health
        if not health._ready.is_set():
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=HealthStatus(status="not_ready").model_dump(),
            )
        return HealthStatus(status="ready")

    @app.get("/health/startup", response_model=HealthStatus, include_in_schema=False)
    async def startup_probe(request: Request):
        health: HealthProbe = request.app.state.health
        if not health._startup_complete.is_set():
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=HealthStatus(status="starting").model_dump(),
            )
        return HealthStatus(status="started")

    # Metrics
    settings = get_settings()
    if settings.metrics_enabled:
        metrics_path = settings.metrics_path

        @app.get(metrics_path, include_in_schema=False)
        async def metrics_endpoint(request: Request):
            metrics: Metrics = request.app.state.metrics
            body, content_type = metrics.render()
            return Response(content=body, media_type=content_type)

        # Wrap router to record metrics if Prometheus available
        if app.state.metrics.enabled:
            instrument_routes_with_metrics(app)

    # OpenTelemetry
    maybe_install_otel(app, settings)

    return app


def instrument_routes_with_metrics(app: FastAPI) -> None:
    """Attach lightweight per-request metrics using middleware-free approach."""
    metrics: Metrics = app.state.metrics
    if not metrics.enabled:
        return

    # Use a dispatch function to wrap the ASGI app
    original_app = app.middleware_stack

    class MetricsASGI:
        def __init__(self, inner):
            self.inner = inner

        async def __call__(self, scope: Scope, receive: Receive, send: Send):
            if scope["type"] != "http":
                return await self.inner(scope, receive, send)

            method = scope.get("method", "GET")
            path = scope.get("path", "")

            start = time.perf_counter()
            status_code_container = {"code": 200}

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    status_code_container["code"] = message["status"]
                await send(message)

            try:
                await self.inner(scope, receive, send_wrapper)
            finally:
                elapsed = time.perf_counter() - start
                try:
                    metrics.http_requests.labels(method=method, path=path, status=str(status_code_container["code"])).inc()
                    metrics.http_latency.labels(method=method, path=path).observe(elapsed)
                except Exception:
                    # Never break request on metrics failure
                    pass

    app.middleware_stack = MetricsASGI(original_app)


app = create_app()


# ------------------------------------------------------------------------------
# Uvicorn entry point
# ------------------------------------------------------------------------------

def _install_sigterm_handler():
    loop = asyncio.get_event_loop()

    stop_event = asyncio.Event()

    def _handler():
        loop.create_task(_set())

    async def _set():
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGTERM, _handler)
        loop.add_signal_handler(signal.SIGINT, _handler)
    except NotImplementedError:
        # Windows or restricted env
        pass

    return stop_event


if __name__ == "__main__":
    settings = get_settings()
    try:
        import uvicorn  # type: ignore
    except Exception:
        print("Uvicorn is required to run the server directly: pip install uvicorn[standard]", file=sys.stderr)
        sys.exit(1)

    # Run
    uvicorn.run(
        "api.http.server:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=(settings.environment == "local"),
        proxy_headers=True,
        forwarded_allow_ips="*",
        timeout_keep_alive=int(settings.write_timeout_sec),
        log_config=None,  # we already configured JSON logging
    )
