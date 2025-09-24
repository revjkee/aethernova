# oblivionvault-core/api/http/server.py
"""
Industrial-grade FastAPI server for OblivionVault Core.

Features:
- App factory with Pydantic-based settings (env-driven).
- Structured logging with stdlib logging + request-id context.
- Security headers, CORS, GZip, TrustedHost, body size limiting.
- Per-request timeout middleware.
- Consistent error handling and JSON envelope.
- Health (livez), readiness (readyz), version, echo endpoints.
- Prometheus /metrics (supports multiprocess mode if env set).
- Optional OpenTelemetry tracing/metrics/logs auto-instrumentation.
- Kubernetes-friendly: graceful shutdown, probes, request id (X-Request-ID).
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
import uuid
from dataclasses import dataclass
from ipaddress import ip_address

from fastapi import FastAPI, Request, Response, status, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Scope, Receive, Send

try:
    # Optional: if installed, we instrument automatically
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False

try:
    # Prometheus client
    from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest, multiprocess, Counter, Histogram
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

# ----------------------------
# Settings
# ----------------------------

@dataclass
class Settings:
    app_name: str = os.getenv("APP_NAME", "oblivionvault-core")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    env: str = os.getenv("APP_ENV", "dev")
    host: str = os.getenv("HTTP_HOST", "0.0.0.0")
    port: int = int(os.getenv("HTTP_PORT", "8080"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    allowed_origins: list[str] = tuple(
        filter(None, os.getenv("CORS_ALLOW_ORIGINS", "").split(","))
    ) or ["*"]  # Restrict in prod
    allowed_hosts: list[str] = tuple(
        filter(None, os.getenv("ALLOWED_HOSTS", "").split(","))
    ) or ["*"]  # Restrict in prod
    request_timeout_seconds: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    max_body_bytes: int = int(os.getenv("MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # 5 MiB
    enable_gzip: bool = os.getenv("ENABLE_GZIP", "true").lower() == "true"
    enable_otel: bool = os.getenv("ENABLE_OTEL", "true").lower() == "true"
    enable_metrics: bool = os.getenv("ENABLE_METRICS", "true").lower() == "true"
    prometheus_multiproc_dir: str | None = os.getenv("PROMETHEUS_MULTIPROC_DIR")
    request_id_header: str = os.getenv("REQUEST_ID_HEADER", "X-Request-ID")
    client_ip_header: str = os.getenv("CLIENT_IP_HEADER", "X-Forwarded-For")
    secure_csp: str = os.getenv("SECURE_CSP", "default-src 'none'; frame-ancestors 'none'; base-uri 'none';")
    # Readiness hook toggles
    ready_delay_startup_ms: int = int(os.getenv("READY_DELAY_STARTUP_MS", "0"))

# ----------------------------
# Logging
# ----------------------------

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

def _configure_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    logging.basicConfig(
        level=lvl,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s","request_id":"%(request_id)s"}',
        handlers=handlers,
    )
    # Inject request_id into records
    old_factory = logging.getLogRecordFactory()
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.request_id = _request_id_ctx.get("-")
        return record
    logging.setLogRecordFactory(record_factory)

logger = logging.getLogger("oblivionvault.http")

# ----------------------------
# Prometheus metrics
# ----------------------------

class Metrics:
    def __init__(self, settings: Settings):
        self.enabled = _PROM_AVAILABLE and settings.enable_metrics
        if not self.enabled:
            self.registry = None
            self.http_requests_total = None
            self.http_latency_seconds = None
            return
        if settings.prometheus_multiproc_dir:
            os.environ["PROMETHEUS_MULTIPROC_DIR"] = settings.prometheus_multiproc_dir
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
        else:
            registry = CollectorRegistry()

        self.registry = registry
        self.http_requests_total = Counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "path", "status"],
            registry=registry,
        )
        self.http_latency_seconds = Histogram(
            "http_request_latency_seconds",
            "HTTP request latency in seconds",
            ["method", "path"],
            registry=registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        )

# ----------------------------
# Middleware
# ----------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, header_name: str) -> None:
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.header_name) or str(uuid.uuid4())
        token = _request_id_ctx.set(rid)
        try:
            response: Response = await call_next(request)
        finally:
            _request_id_ctx.reset(token)
        response.headers[self.header_name] = rid
        return response

class ClientIPContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, header_name: str) -> None:
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        client_ip = self._extract_ip(request)
        request.state.client_ip = client_ip
        return await call_next(request)

    def _extract_ip(self, request: Request) -> str:
        xff = request.headers.get(self.header_name, "").split(",")[0].strip()
        try:
            if xff:
                ip_address(xff)
                return xff
        except Exception:
            pass
        client = request.client.host if request.client else ""
        try:
            ip_address(client)
            return client
        except Exception:
            return "0.0.0.0"

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next):
        # Limit only for methods with body
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > self.max_body_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content=error_envelope("request_too_large", f"Body exceeds {self.max_body_bytes} bytes"),
                )
            # Re-create stream for downstream handlers
            async def receive_gen():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive_gen  # type: ignore
        return await call_next(request)

class TimeoutMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, timeout_seconds: float) -> None:
        super().__init__(app)
        self.timeout = timeout_seconds

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout):
                response = await call_next(request)
        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            logger.warning("request timeout exceeded", extra={"duration": duration})
            return JSONResponse(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                content=error_envelope("timeout", f"Request exceeded {self.timeout} seconds"),
            )
        return response

class SecureHeadersMiddleware:
    def __init__(self, app: ASGIApp, csp: str) -> None:
        self.app = app
        self.csp = csp

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers") or [])
                def set_header(name: str, value: str):
                    headers[ name.encode("latin-1") ] = value.encode("latin-1")
                set_header("x-content-type-options", "nosniff")
                set_header("x-frame-options", "DENY")
                set_header("x-xss-protection", "0")
                set_header("content-security-policy", self.csp)
                set_header("referrer-policy", "no-referrer")
                message["headers"] = list(headers.items())
            await send(message)
        await self.app(scope, receive, send_wrapper)

# ----------------------------
# Error envelope and handlers
# ----------------------------

def ok_envelope(data: t.Any) -> dict:
    return {"success": True, "data": data, "error": None}

def error_envelope(code: str, message: str, details: t.Optional[t.Any] = None) -> dict:
    return {"success": False, "data": None, "error": {"code": code, "message": message, "details": details}}

async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=error_envelope("http_error", exc.detail if isinstance(exc.detail, str) else "HTTP error"),
    )

async def validation_exception_handler(request: Request, exc: Exception):
    # Starlette/FastAPI validation errors land differently across versions
    detail = getattr(exc, "errors", lambda: None)()
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_envelope("validation_error", "Request validation failed", detail),
    )

async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_envelope("internal_error", "Internal server error"),
    )

# ----------------------------
# App factory
# ----------------------------

def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    _configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=None if settings.env == "prod" else "/docs",
        redoc_url=None if settings.env == "prod" else "/redoc",
        openapi_url="/openapi.json" if settings.env != "prod" else None,
    )

    # Metrics
    metrics = Metrics(settings)

    # Core middleware
    app.add_middleware(RequestIDMiddleware, header_name=settings.request_id_header)
    app.add_middleware(ClientIPContextMiddleware, header_name=settings.client_ip_header)
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.max_body_bytes)
    app.add_middleware(TimeoutMiddleware, timeout_seconds=settings.request_timeout_seconds)
    if settings.enable_gzip:
        app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(SecureHeadersMiddleware, csp=settings.secure_csp)

    # Exception handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # Optional: OpenTelemetry
    if _OTEL_AVAILABLE and settings.enable_otel:
        _init_otel(settings, app)
        LoggingInstrumentor().instrument(set_logging_format=False)
        logger.info("OpenTelemetry instrumentation enabled")
    else:
        logger.info("OpenTelemetry instrumentation disabled or not installed")

    # Routes
    register_routes(app, settings, metrics)

    # Lifespan events
    @app.on_event("startup")
    async def on_startup():
        if settings.ready_delay_startup_ms > 0:
            await asyncio.sleep(settings.ready_delay_startup_ms / 1000.0)
        logger.info("application startup")

    @app.on_event("shutdown")
    async def on_shutdown():
        logger.info("application shutdown")
        if _OTEL_AVAILABLE and settings.enable_otel:
            _shutdown_otel()

    return app

# ----------------------------
# Routes
# ----------------------------

def register_routes(app: FastAPI, settings: Settings, metrics: Metrics) -> None:
    # Simple request logging and metrics payload
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        path_template = request.scope.get("route").path if request.scope.get("route") else request.url.path
        method = request.method
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start
            extra = {"method": method, "path": path_template, "duration": round(duration, 3)}
            logger.info("request", extra=extra)
            if metrics.enabled:
                try:
                    metrics.http_requests_total.labels(method=method, path=path_template, status=str(status_code)).inc()
                    metrics.http_latency_seconds.labels(method=method, path=path_template).observe(duration)
                except Exception:
                    pass

    @app.get("/livez", response_class=PlainTextResponse, tags=["system"])
    async def livez():
        return "OK"

    @app.get("/healthz", tags=["system"])
    async def healthz():
        # Extend with checks to dependent subsystems
        checks = {
            "status": "ok",
            "time": int(time.time()),
        }
        return ok_envelope(checks)

    @app.get("/readyz", tags=["system"])
    async def readyz():
        # Placeholders for readiness criteria
        # Example: connection pools warm, caches primed, migrations applied
        ready = True
        details = {"ready": ready}
        return ok_envelope(details) if ready else JSONResponse(status_code=503, content=error_envelope("not_ready", "Service warming up"))

    if metrics.enabled:
        @app.get("/metrics")
        async def metrics_handler():
            try:
                output = generate_latest(metrics.registry)
            except Exception:
                # Fallback: empty registry
                output = b""
            return Response(output, media_type=CONTENT_TYPE_LATEST)

    @app.get("/version", tags=["system"])
    async def version():
        build = {
            "name": settings.app_name,
            "version": settings.app_version,
            "env": settings.env,
            "git_sha": os.getenv("GIT_SHA", ""),
        }
        return ok_envelope(build)

    @app.post("/echo", tags=["debug"])
    async def echo(req: Request):
        try:
            payload = await req.json()
        except Exception:
            payload = {"raw": (await req.body()).decode("utf-8", errors="ignore")}
        data = {
            "request_id": _request_id_ctx.get("-"),
            "client_ip": getattr(req.state, "client_ip", ""),
            "payload": payload,
        }
        return ok_envelope(data)

    @app.get("/_system/info", tags=["system"])
    async def system_info():
        info = {
            "python": sys.version,
            "pid": os.getpid(),
            "env": settings.env,
            "tz": time.tzname,
        }
        return ok_envelope(info)

# ----------------------------
# OpenTelemetry helpers
# ----------------------------

def _init_otel(settings: Settings, app: FastAPI) -> None:
    if not _OTEL_AVAILABLE:
        return
    resource = Resource(attributes={SERVICE_NAME: settings.app_name})
    provider = TracerProvider(resource=resource)
    # Example exporter: console. Replace with OTLP exporter in production.
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)

def _shutdown_otel() -> None:
    # Rely on SDK providers to flush on interpreter shutdown; nothing specific here
    pass

# ----------------------------
# Uvicorn entrypoint
# ----------------------------

def run() -> None:
    """
    Launch with: python -m oblivionvault_core.api.http.server
    or: uvicorn oblivionvault_core.api.http.server:create_app --factory --host 0.0.0.0 --port 8080
    """
    import uvicorn
    settings = Settings()
    _configure_logging(settings.log_level)
    logger.info("starting uvicorn", extra={"host": settings.host, "port": settings.port})
    uvicorn.run(
        "oblivionvault_core.api.http.server:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        lifespan="on",
        reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
        # Recommended server-level timeouts for robustness
        timeout_keep_alive=5,
        workers=int(os.getenv("UVICORN_WORKERS", "1")),
    )

if __name__ == "__main__":
    run()
