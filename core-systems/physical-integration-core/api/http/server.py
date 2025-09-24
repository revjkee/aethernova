# physical-integration-core/api/http/server.py
"""
Industrial-grade HTTP server for Physical Integration Core.

Key features:
- FastAPI app with strict settings from environment
- JSON logging with request correlation (X-Request-ID)
- Security headers middleware (HSTS, CSP opt-in, frame deny, referrer policy, etc.)
- Body size limit middleware
- In-memory token-bucket rate limiting (global and per-route)
- Prometheus metrics (/metrics), request counters and latency histograms
- Health and readiness endpoints (/healthz, /readyz)
- RFC 7807 error responses, unified exception handling
- GZip compression, CORS, timeouts-friendly design
- Deterministic version endpoint (build info via env)

Dependencies (python >= 3.9):
  fastapi>=0.111
  uvicorn[standard]>=0.30
  prometheus_client>=0.19

Optional (auto-detected, not required):
  orjson>=3.9  (faster JSON)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Response, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRouter
from pydantic import BaseModel, BaseSettings, Field, validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

# Prometheus
from prometheus_client import Counter, Histogram, Gauge, CONTENT_TYPE_LATEST, generate_latest

# --------- Optional orjson for speed ----------
try:
    import orjson  # type: ignore

    def _dumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY).decode()

except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ======================
# Configuration
# ======================
class Settings(BaseSettings):
    app_name: str = Field(default="physical-integration-core")
    app_version: str = Field(default=os.getenv("APP_VERSION", "1.0.0"))
    environment: str = Field(default=os.getenv("ENVIRONMENT", "prod"))
    debug: bool = Field(default=os.getenv("DEBUG", "false").lower() == "true")

    host: str = Field(default=os.getenv("HTTP_HOST", "0.0.0.0"))
    port: int = Field(default=int(os.getenv("HTTP_PORT", "8080")))
    cors_allow_origins: list[str] = Field(default_factory=lambda: os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if os.getenv("CORS_ALLOW_ORIGINS") else [])
    cors_allow_credentials: bool = Field(default=os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true")
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])

    request_body_limit_mb: int = Field(default=int(os.getenv("REQUEST_BODY_LIMIT_MB", "16")))
    global_rps_limit: int = Field(default=int(os.getenv("GLOBAL_RPS_LIMIT", "500")))
    global_burst: int = Field(default=int(os.getenv("GLOBAL_BURST", "1000")))
    route_rps_limit: int = Field(default=int(os.getenv("ROUTE_RPS_LIMIT", "200")))
    route_burst: int = Field(default=int(os.getenv("ROUTE_BURST", "400")))
    rate_limit_window_seconds: float = Field(default=float(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "1.0")))

    enable_metrics: bool = Field(default=os.getenv("ENABLE_METRICS", "true").lower() == "true")
    csp: str | None = Field(default=os.getenv("CSP", ""))  # e.g., "default-src 'self'"
    hsts_max_age: int = Field(default=int(os.getenv("HSTS_MAX_AGE", "63072000")))  # 2 years

    # Build info
    build_commit: str | None = Field(default=os.getenv("BUILD_COMMIT"))
    build_date: str | None = Field(default=os.getenv("BUILD_DATE"))
    build_ci: str | None = Field(default=os.getenv("BUILD_CI"))

    class Config:
        env_prefix = "PIC_"
        case_sensitive = False


settings = Settings()


# ======================
# Logging
# ======================
_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")
_path_template_ctx: ContextVar[str] = ContextVar("path_template", default="-")

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time_ns() % 1_000_000_000 / 1_000_000):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": _request_id_ctx.get(),
            "path_tmpl": _path_template_ctx.get(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            payload.update(record.extra)  # type: ignore
        return _dumps(payload)


def _setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]


_setup_logging()
log = logging.getLogger("pic.http")


# ======================
# Utilities
# ======================
def get_client_ip(request: Request) -> str:
    # Respect X-Forwarded-For (first IP) if present
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = request.client.host if request.client else "-"
    return client or "-"


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "***"
        else:
            # Trim very long header values to avoid log bloat
            redacted[k] = v if len(v) <= 256 else v[:256] + "...(truncated)"
    return redacted


# ======================
# Rate Limiter (Token Bucket)
# ======================
@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class RateLimiter:
    def __init__(self, rps: int, burst: int, window: float = 1.0) -> None:
        self.capacity = float(burst)
        self.fill_rate = float(rps) / window
        self.window = window
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=self.capacity - 1.0, last_refill=now)
                self._buckets[key] = b
                return True
            # Refill tokens
            elapsed = now - b.last_refill
            if elapsed > 0:
                b.tokens = min(self.capacity, b.tokens + elapsed * self.fill_rate)
                b.last_refill = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            else:
                return False


# ======================
# Prometheus metrics
# ======================
HTTP_REQS = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
READY_GAUGE = Gauge("ready", "Readiness status (1=ready, 0=not ready)")


# ======================
# Middleware
# ======================
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        req_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        _request_id_ctx.set(req_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, hsts_max_age: int, csp: Optional[str]) -> None:
        super().__init__(app)
        self.hsts = f"max-age={hsts_max_age}; includeSubDomains; preload"
        self.csp = csp

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        # Safe headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Strict-Transport-Security", self.hsts)
        if self.csp:
            response.headers.setdefault("Content-Security-Policy", self.csp)
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.max_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content=problem(
                    status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    title="Request body too large",
                    detail=f"Maximum allowed is {self.max_bytes} bytes",
                    type_="about:blank",
                ),
            )

        # If Content-Length is missing or smaller, still enforce by intercepting receive
        async def limited_receive() -> dict:
            message = await request._receive()  # starlette internals
            if message["type"] == "http.request":
                body = message.get("body", b"")
                if body and len(body) > self.max_bytes:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Body too large")
            return message

        # Monkey patch receive for this request only
        original_receive = request._receive
        try:
            request._receive = limited_receive  # type: ignore
            return await call_next(request)
        finally:
            request._receive = original_receive  # type: ignore


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, global_rl: RateLimiter, route_rl: RateLimiter) -> None:
        super().__init__(app)
        self.global_rl = global_rl
        self.route_rl = route_rl

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        ip = get_client_ip(request)
        path = request.scope.get("route").path if request.scope.get("route") else request.url.path
        key_global = f"g:{ip}"
        key_route = f"r:{ip}:{path}"

        ok_global = await self.global_rl.allow(key_global)
        ok_route = await self.route_rl.allow(key_route)
        if not (ok_global and ok_route):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content=problem(
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                    title="Rate limit exceeded",
                    detail="Too many requests, slow down.",
                    type_="about:blank",
                ),
                headers={"Retry-After": "1"},
            )

        return await call_next(request)


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start = time.perf_counter()
        method = request.method
        path = request.url.path

        # Save path template to context for consistent logging
        tmpl = getattr(request.scope.get("route"), "path", path) if request.scope.get("route") else path
        _path_template_ctx.set(tmpl)

        # Redact headers
        hdrs = redact_headers({k.lower(): v for k, v in request.headers.items()})

        try:
            response = await call_next(request)
            elapsed = time.perf_counter() - start
            status_code = response.status_code
            # Metrics
            HTTP_REQS.labels(method=method, path=tmpl, status=str(status_code)).inc()
            HTTP_LATENCY.labels(method=method, path=tmpl).observe(elapsed)
            # Log
            log.info(
                "request",
                extra={
                    "extra": {
                        "method": method,
                        "path": path,
                        "path_tmpl": tmpl,
                        "status": status_code,
                        "duration_ms": round(elapsed * 1000, 3),
                        "client_ip": get_client_ip(request),
                        "ua": request.headers.get("user-agent", "-"),
                        "headers": hdrs if settings.debug else {"user-agent": hdrs.get("user-agent", "-")},
                    }
                },
            )
            return response
        except Exception as exc:
            elapsed = time.perf_counter() - start
            HTTP_REQS.labels(method=method, path=tmpl, status="500").inc()
            HTTP_LATENCY.labels(method=method, path=tmpl).observe(elapsed)
            log.exception("unhandled_error", extra={"extra": {"method": method, "path": path}})
            # Reraise to be caught by exception handlers
            raise


# ======================
# Error handling (RFC7807)
# ======================
def problem(status: int, title: str, detail: str, type_: str = "about:blank", instance: str | None = None, **ext: Any) -> Dict[str, Any]:
    payload = {
        "type": type_,
        "title": title,
        "status": status,
        "detail": detail,
    }
    if instance:
        payload["instance"] = instance
    if ext:
        payload.update(ext)
    return payload


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=problem(
            status=exc.status_code,
            title=exc.detail if isinstance(exc.detail, str) else "HTTP error",
            detail=exc.detail if isinstance(exc.detail, str) else "HTTP error",
        ),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            title="Internal Server Error",
            detail="An unexpected error occurred.",
        ),
    )


# ======================
# Models
# ======================
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


class TelemetryEnvelope(BaseModel):
    twin_name: Optional[str] = Field(None, description="twin/{id}")
    stream: str = Field(..., description="Logical stream name")
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    ts: Optional[float] = Field(None, description="Unix epoch seconds")
    sequence: Optional[str] = Field(None, description="Monotonic counter or ULID")
    partition_key: Optional[str] = None
    schema_uri: Optional[str] = None
    content_type: Optional[str] = "application/json"
    attributes: Dict[str, str] = Field(default_factory=dict)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @validator("sequence")
    def _validate_sequence(cls, v: Optional[str]) -> Optional[str]:
        if v and not (v.isdigit() or ULID_RE.match(v)):
            raise ValueError("sequence must be integer string or ULID")
        return v


class TelemetryIngestRequest(BaseModel):
    envelopes: list[TelemetryEnvelope]


class TelemetryAck(BaseModel):
    status: str
    message: Optional[str] = None


class VersionInfo(BaseModel):
    app: str
    version: str
    environment: str
    build_commit: Optional[str] = None
    build_date: Optional[str] = None
    build_ci: Optional[str] = None


# ======================
# Application factory
# ======================
def build_app() -> FastAPI:
    app = FastAPI(
        title=f"{settings.app_name} HTTP",
        version=settings.app_version,
        docs_url="/docs" if settings.debug else None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    # State
    app.state.ready = False
    READY_GAUGE.set(0)

    # Middlewares
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts_max_age=settings.hsts_max_age,
        csp=(settings.csp or None),
    )
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.request_body_limit_mb * 1024 * 1024,
    )
    app.add_middleware(
        RateLimitMiddleware,
        global_rl=RateLimiter(settings.global_rps_limit, settings.global_burst, settings.rate_limit_window_seconds),
        route_rl=RateLimiter(settings.route_rps_limit, settings.route_burst, settings.rate_limit_window_seconds),
    )
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[o for o in settings.cors_allow_origins if o],
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=settings.cors_allow_methods,
            allow_headers=settings.cors_allow_headers,
        )

    # Exception handlers
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # Routers
    api = APIRouter(prefix="/api/v1", tags=["api"])
    health = APIRouter(tags=["health"])

    @api.post("/ingest/telemetry", response_model=Dict[str, TelemetryAck], summary="Ingest telemetry batch", status_code=202)
    async def ingest_telemetry(req: TelemetryIngestRequest, request: Request) -> Dict[str, TelemetryAck]:
        """
        Idempotent-ish ingest: we accept and ack each envelope.
        Real routing to message bus should be plugged here (e.g., Kafka/AMQP).
        """
        # Example minimal validation and ack
        acks: Dict[str, TelemetryAck] = {}
        for env in req.envelopes:
            # Dedup fingerprint (stateless example)
            fp = f"{env.twin_name}|{env.stream}|{env.event_id}"
            # In production, put to bus with key = partition_key or twin_name
            # e.g., await producers.kafka.send("bus.telemetry.raw", key=..., value=env.dict())
            acks[env.event_id] = TelemetryAck(status="ACCEPTED", message="queued")
        return acks

    @api.get("/version", response_model=VersionInfo, summary="Build and version info")
    async def version() -> VersionInfo:
        return VersionInfo(
            app=settings.app_name,
            version=settings.app_version,
            environment=settings.environment,
            build_commit=settings.build_commit,
            build_date=settings.build_date,
            build_ci=settings.build_ci,
        )

    @health.get("/healthz", summary="Liveness")
    async def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    @health.get("/readyz", summary="Readiness")
    async def readyz() -> Dict[str, str]:
        return {"status": "ready" if app.state.ready else "not-ready"}

    @app.get("/metrics")
    async def metrics() -> Response:
        if not settings.enable_metrics:
            raise HTTPException(status_code=404, detail="metrics disabled")
        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    app.include_router(api)
    app.include_router(health)

    # Lifespan: startup/shutdown
    @app.on_event("startup")
    async def on_startup() -> None:
        log.info("startup_begin", extra={"extra": {"env": settings.environment, "version": settings.app_version}})
        # Initialize connections (placeholders)
        # await producers.init(), await db.connect() ...
        app.state.ready = True
        READY_GAUGE.set(1)
        log.info("startup_complete")

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        log.info("shutdown_begin")
        app.state.ready = False
        READY_GAUGE.set(0)
        # await producers.close(), await db.disconnect() ...
        log.info("shutdown_complete")

    return app


app = build_app()


# ======================
# Uvicorn runner
# ======================
if __name__ == "__main__":
    try:
        import uvicorn  # type: ignore

        uvicorn.run(
            "server:app",
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            access_log=False,  # we do structured logging ourselves
            log_config=None,
        )
    except KeyboardInterrupt:  # pragma: no cover
        pass
