# backend/main.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Iterable, Optional

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, AnyUrl
from pydantic_settings import BaseSettings
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

# --- Optional Sentry ---
try:
    import sentry_sdk  # type: ignore
    from sentry_sdk.integrations.asgi import SentryAsgiMiddleware  # type: ignore
    _SENTRY_AVAILABLE = True
except Exception:
    sentry_sdk = None  # type: ignore
    SentryAsgiMiddleware = None  # type: ignore
    _SENTRY_AVAILABLE = False

# --- Optional OpenTelemetry ---
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False

# --- SQLAlchemy async engine/session ---
try:
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, async_sessionmaker, AsyncSession
    from sqlalchemy import text
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy async components are required. Install: `pip install sqlalchemy[asyncio] asyncpg`"
    ) from e

# --- Prometheus metrics ---
try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
    _PROM_CLIENT_AVAILABLE = True
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "Prometheus client is required. Install: `pip install prometheus-client`"
    ) from e

# --- Prometheus Instrumentator (optional auto-instrumentation) ---
try:
    from prometheus_fastapi_instrumentator import Instrumentator  # type: ignore
    _PROM_INST_AVAILABLE = True
except Exception:
    _PROM_INST_AVAILABLE = False


# =========================
# Settings
# =========================

class Settings(BaseSettings):
    # App
    APP_NAME: str = Field(default="aethernova-backend")
    APP_ENV: str = Field(default="dev")  # dev|staging|prod
    APP_HOST: str = Field(default="0.0.0.0")
    APP_PORT: int = Field(default=8000)
    LOG_LEVEL: str = Field(default="INFO")  # DEBUG|INFO|WARNING|ERROR
    LOG_JSON: bool = Field(default=True)

    # Security / Middleware
    TRUSTED_HOSTS: str = Field(default="*")  # comma-separated or '*'
    HTTPS_REDIRECT: bool = Field(default=False)
    GZIP_MIN_SIZE: int = Field(default=1024)

    # CORS
    CORS_ORIGINS: str = Field(default="*")  # comma-separated or '*'
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: str = Field(default="GET,POST,PUT,PATCH,DELETE,OPTIONS")
    CORS_ALLOW_HEADERS: str = Field(default="*")

    # Database (Postgres recommended)
    DATABASE_URL: Optional[str] = Field(default=None)
    READINESS_CHECK_DB: bool = Field(default=True)

    # Sentry
    SENTRY_DSN: Optional[AnyUrl] = Field(default=None)
    SENTRY_TRACES_SAMPLE_RATE: float = Field(default=0.0)

    # Telemetry
    ENABLE_OTEL: bool = Field(default=False)

    # Prometheus
    ENABLE_PROM_AUTO: bool = Field(default=True)  # use Instrumentator if available
    METRICS_PATH: str = Field(default="/metrics")

    # HTTP client (optional)
    ENABLE_HTTP_CLIENT: bool = Field(default=True)

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


# =========================
# Logging
# =========================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            payload["request_id"] = getattr(record, "request_id")
        if hasattr(record, "path"):
            payload["path"] = getattr(record, "path")
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)  # type: ignore[arg-type]
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if settings.LOG_JSON else logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    logging.getLogger("uvicorn").setLevel(root.level)
    logging.getLogger("uvicorn.error").setLevel(root.level)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


# =========================
# Request ID & Access log middlewares
# =========================

class RequestIDMiddleware:
    def __init__(self, app: ASGIApp, header_name: str = "X-Request-Id"):
        self.app = app
        self.header_name = header_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = None
        for name, value in scope.get("headers", []):
            if name.decode().lower() == self.header_name.lower():
                request_id = value.decode()
                break
        if not request_id:
            request_id = str(uuid.uuid4())

        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        async def send_wrapper(message: dict) -> None:
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((self.header_name.encode(), request_id.encode()))
            await send(message)

        await self.app(scope, receive, send_wrapper)


class AccessLogMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        path = scope.get("path", "")
        client = scope.get("client")
        client_ip = f"{client[0]}:{client[1]}" if client else "-"
        started = time.perf_counter()
        status_code = 0

        async def _send(message: dict) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 0))
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            dur_ms = int((time.perf_counter() - started) * 1000)
            rid = scope.get("state", {}).get("request_id")
            logging.getLogger("http.access").info(
                f'method={method} path="{path}" status={status_code} dur_ms={dur_ms} client="{client_ip}" rid={rid}'
            )


# =========================
# Metrics (manual fallback)
# =========================

registry = CollectorRegistry()
METRICS_APP_UPTIME = Gauge("app_uptime_seconds", "Application uptime in seconds", registry=registry)
METRICS_REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "path", "status"], registry=registry
)
METRICS_REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["method", "path"], registry=registry
)
APP_START_MONOTONIC = time.monotonic()


class MetricsMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        path = scope.get("path", "")
        start = time.monotonic()

        async def send_wrapper(message: dict) -> None:
            if message.get("type") == "http.response.start":
                status = message.get("status", 0)
                try:
                    METRICS_REQUEST_COUNT.labels(method=method, path=path, status=str(status)).inc()
                    METRICS_REQUEST_LATENCY.labels(method=method, path=path).observe(time.monotonic() - start)
                except Exception:
                    pass
            await send(message)

        await self.app(scope, receive, send_wrapper)


# =========================
# Optional HTTP client (backend/src/utils/http_client.py)
# =========================

def _wire_http_client(app: FastAPI) -> None:
    # Ensure backend/src is importable
    base_dir = os.path.dirname(__file__)
    src_dir = os.path.join(base_dir, "src")
    if os.path.isdir(src_dir) and src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    try:
        from utils.http_client import AsyncHTTPClient, build_client_from_env  # type: ignore
    except Exception as e:
        if settings.ENABLE_HTTP_CLIENT:
            logger.warning("HTTP client not available (%s). Skipping.", e)
        return

    app.state.http = build_client_from_env(prefix="HTTP_CLIENT_")  # type: ignore

def _close_http_client(app: FastAPI) -> None:
    http = getattr(app.state, "http", None)
    if http is not None:
        try:
            # AsyncHTTPClient.aclose() is async; schedule closure
            asyncio.create_task(http.aclose())
        except Exception:
            pass


# =========================
# Database
# =========================

engine: Optional[AsyncEngine] = None
SessionFactory: Optional[async_sessionmaker[AsyncSession]] = None


async def create_engine() -> Optional[AsyncEngine]:
    if not settings.DATABASE_URL:
        logging.getLogger(__name__).warning("DATABASE_URL not set; DB features disabled")
        return None
    return create_async_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        future=True,
    )


async def db_ping(conn_engine: AsyncEngine) -> None:
    async with conn_engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
        await conn.commit()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    if SessionFactory is None:
        raise RuntimeError("Database not initialized")
    async with SessionFactory() as session:
        yield session


# =========================
# Lifespan
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[override]
    global engine, SessionFactory

    setup_logging()
    logger.info("Starting application...")

    # Sentry
    if settings.SENTRY_DSN and _SENTRY_AVAILABLE:
        try:
            sentry_sdk.init(dsn=str(settings.SENTRY_DSN), traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE)  # type: ignore
            logger.info("Sentry initialized")
        except Exception as e:
            logger.warning("Sentry init failed: %s", e)

    # HTTP client
    _wire_http_client(app)

    # DB
    engine = await create_engine()
    if engine:
        try:
            await db_ping(engine)
            SessionFactory = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
            logger.info("Database connection OK")
        except Exception as e:
            logger.exception("Database connection failed: %s", e)

    # OpenTelemetry
    if settings.ENABLE_OTEL and _OTEL_AVAILABLE:
        try:
            FastAPIInstrumentor().instrument_app(app)  # type: ignore
            logger.info("OpenTelemetry instrumented")
        except Exception as e:
            logger.warning("OpenTelemetry instrumentation failed: %s", e)

    # Prometheus auto-instrumentation
    prom_instrumentator = None
    if settings.ENABLE_PROM_AUTO and _PROM_INST_AVAILABLE:
        try:
            prom_instrumentator = Instrumentator().instrument(app)  # type: ignore
            logger.info("Prometheus instrumentator attached")
        except Exception as e:
            logger.warning("Prometheus instrumentator failed: %s", e)
    app.state.prom_instrumentator = prom_instrumentator  # may be None

    # Uptime gauge baseline
    METRICS_APP_UPTIME.set(0.0)

    # Graceful shutdown signals (best-effort; not all platforms support)
    stop_event = asyncio.Event()
    def _handle_sig(*_: Any) -> None:
        logger.warning("Shutdown signal received")
        stop_event.set()
    loop = asyncio.get_event_loop()
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass

    try:
        yield
    finally:
        logger.info("Shutting down application...")
        try:
            _close_http_client(app)
        except Exception:
            pass
        if engine:
            try:
                await engine.dispose()
                logger.info("Database engine disposed")
            except Exception:
                pass
        METRICS_APP_UPTIME.set(time.monotonic() - APP_START_MONOTONIC)
        logger.info("Bye.")


# =========================
# App init
# =========================

app = FastAPI(
    title=settings.APP_NAME,
    version=os.getenv("APP_VERSION", "0.1.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Middlewares (order matters)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(AccessLogMiddleware)
# Security/Compression
if settings.TRUSTED_HOSTS != "*":
    allowed_hosts = [h.strip() for h in settings.TRUSTED_HOSTS.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
if settings.HTTPS_REDIRECT:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=settings.GZIP_MIN_SIZE)
# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.CORS_ORIGINS == "*" else [o.strip() for o in settings.CORS_ORIGINS.split(",")],
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=[m.strip() for m in settings.CORS_ALLOW_METHODS.split(",")],
    allow_headers=["*"] if settings.CORS_ALLOW_HEADERS == "*" else [h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",")],
)
# Sentry middleware (optional)
if settings.SENTRY_DSN and _SENTRY_AVAILABLE and SentryAsgiMiddleware is not None:
    app.add_middleware(SentryAsgiMiddleware)


# =========================
# Schemas
# =========================

class HealthResponse(BaseModel):
    status: str
    uptime_seconds: float
    env: str


class ReadyResponse(BaseModel):
    status: str
    db: str


# =========================
# Routes
# =========================

@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Liveness probe: app is running regardless of DB."""
    uptime = time.monotonic() - APP_START_MONOTONIC
    return HealthResponse(status="ok", uptime_seconds=uptime, env=settings.APP_ENV)


@app.get("/ready", response_model=ReadyResponse, tags=["system"])
async def ready() -> Response:
    """Readiness probe: optionally checks DB connectivity."""
    if settings.READINESS_CHECK_DB and engine is not None:
        try:
            await db_ping(engine)
            return JSONResponse(ReadyResponse(status="ready", db="ok").model_dump())
        except Exception as e:
            logging.getLogger(__name__).exception("Readiness DB check failed: %s", e)
            return JSONResponse(status_code=503, content=ReadyResponse(status="not_ready", db="fail").model_dump())
    return JSONResponse(ReadyResponse(status="ready", db="skipped").model_dump())


# /metrics: use Instrumentator if attached, otherwise fallback to manual
if not (settings.ENABLE_PROM_AUTO and _PROM_INST_AVAILABLE):
    @app.get(settings.METRICS_PATH, tags=["system"])
    async def metrics() -> Response:
        METRICS_APP_UPTIME.set(time.monotonic() - APP_START_MONOTONIC)
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
else:
    # if Instrumentator is available, expose via it (in lifespan after app creation)
    try:
        app.state.prom_instrumentator.expose(app, endpoint=settings.METRICS_PATH)  # type: ignore[attr-defined]
    except Exception:
        pass


@app.get("/version", tags=["system"])
async def version() -> dict:
    return {
        "app": settings.APP_NAME,
        "version": os.getenv("APP_VERSION", "0.1.0"),
        "env": settings.APP_ENV,
    }


@app.get("/time", tags=["system"])
async def current_time(request: Request, x_request_id: Optional[str] = Header(default=None)) -> dict:
    return {
        "epoch_utc": int(time.time()),
        "monotonic": time.monotonic(),
        "request_id": x_request_id or request.scope.get("state", {}).get("request_id"),
        "client": request.client.host if request.client else None,
        "path": request.url.path,
    }


@app.get("/db/ping", tags=["db"])
async def db_health(session: AsyncSession = Depends(get_session)) -> dict:
    await session.execute(text("SELECT 1"))
    return {"db": "ok"}


# Global error handlers
@app.exception_handler(Exception)
async def unhandled_exc(request: Request, exc: Exception):
    logging.getLogger(__name__).exception("Unhandled exception occurred")
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


# =========================
# Local dev entrypoint
# =========================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("APP_HOST", settings.APP_HOST),
        port=int(os.getenv("APP_PORT", settings.APP_PORT)),
        reload=os.getenv("APP_RELOAD", "false").lower() in {"1", "true", "yes", "on"},
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level=settings.LOG_LEVEL.lower(),
        server_header=False,
        date_header=True,
    )
