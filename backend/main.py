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
from typing import AsyncGenerator, Optional

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, BaseSettings, Field, AnyUrl
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

# --- Optional Sentry (enabled if SENTRY_DSN provided) ---
try:
    import sentry_sdk  # type: ignore
    from sentry_sdk.integrations.asgi import SentryAsgiMiddleware  # type: ignore
except Exception:
    sentry_sdk = None
    SentryAsgiMiddleware = None  # type: ignore

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
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "Prometheus client is required. Install: `pip install prometheus-client`"
    ) from e


# =========================
# Configuration
# =========================

class Settings(BaseSettings):
    APP_NAME: str = Field(default="aethernova-backend")
    APP_ENV: str = Field(default="dev")  # dev|staging|prod
    APP_HOST: str = Field(default="0.0.0.0")
    APP_PORT: int = Field(default=8000)
    LOG_LEVEL: str = Field(default="INFO")  # DEBUG|INFO|WARNING|ERROR
    LOG_JSON: bool = Field(default=True)

    # Database (Postgres recommended)
    # Example: postgresql+asyncpg://user:pass@localhost:5432/dbname
    DATABASE_URL: Optional[str] = Field(default=None)

    # CORS
    CORS_ORIGINS: str = Field(default="*")  # comma-separated or '*'
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: str = Field(default="GET,POST,PUT,PATCH,DELETE,OPTIONS")
    CORS_ALLOW_HEADERS: str = Field(default="*")

    # Sentry (optional)
    SENTRY_DSN: Optional[AnyUrl] = Field(default=None)
    SENTRY_TRACES_SAMPLE_RATE: float = Field(default=0.0)

    # Readiness: enable DB check for /ready
    READINESS_CHECK_DB: bool = Field(default=True)

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
        # Optional extras
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
    # Clear default handlers to avoid duplicate logs in uvicorn
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if settings.LOG_JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)

    # Reduce noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# =========================
# Request ID middleware
# =========================

class RequestIDMiddleware:
    def __init__(self, app: ASGIApp, header_name: str = "X-Request-ID"):
        self.app = app
        self.header_name = header_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = None
        for name, value in scope.get("headers", []):
            if name.decode().lower() == self.header_name.lower().encode().decode().lower():
                request_id = value.decode()
                break
        if not request_id:
            request_id = str(uuid.uuid4())

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((self.header_name.encode(), request_id.encode()))
            await send(message)

        # Attach request_id to logging
        logging.LoggerAdapter(logging.getLogger("request"), {"request_id": request_id})
        scope["request_id"] = request_id
        await self.app(scope, receive, send_wrapper)


# =========================
# Metrics
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

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status = message["status"]
                METRICS_REQUEST_COUNT.labels(method=method, path=path, status=str(status)).inc()
                METRICS_REQUEST_LATENCY.labels(method=method, path=path).observe(time.monotonic() - start)
            await send(message)

        await self.app(scope, receive, send_wrapper)


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
    logger = logging.getLogger(__name__)
    logger.info("Starting application...")

    # Sentry
    if settings.SENTRY_DSN and sentry_sdk is not None:
        sentry_sdk.init(dsn=str(settings.SENTRY_DSN), traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE)
        logger.info("Sentry initialized")

    # DB
    engine = await create_engine()
    if engine:
        try:
            await db_ping(engine)
            SessionFactory = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
            logger.info("Database connection OK")
        except Exception as e:
            logger.exception("Database connection failed: %s", e)
            # In prod you may choose to raise here; we log and continue for /health vs /ready distinction.

    # Uptime gauge
    METRICS_APP_UPTIME.set(0.0)

    # Graceful shutdown signals
    stop_event = asyncio.Event()

    def _handle_sig(*_):
        logger.warning("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            # On Windows, add_signal_handler may not be available
            pass

    try:
        yield
    finally:
        logger.info("Shutting down application...")
        if engine:
            await engine.dispose()
            logger.info("Database engine disposed")
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

# Middlewares
app.add_middleware(RequestIDMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.CORS_ORIGINS == "*" else [o.strip() for o in settings.CORS_ORIGINS.split(",")],
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=[m.strip() for m in settings.CORS_ALLOW_METHODS.split(",")],
    allow_headers=["*"] if settings.CORS_ALLOW_HEADERS == "*" else [h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",")],
)

if settings.SENTRY_DSN and SentryAsgiMiddleware is not None:
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
async def ready() -> ReadyResponse:
    """Readiness probe: optionally checks DB connectivity."""
    if settings.READINESS_CHECK_DB and engine is not None:
        try:
            await db_ping(engine)
            return ReadyResponse(status="ready", db="ok")
        except Exception as e:
            logging.getLogger(__name__).exception("Readiness DB check failed: %s", e)
            return JSONResponse(status_code=503, content=ReadyResponse(status="not_ready", db="fail").model_dump())
    # If DB check disabled or no engine configured
    return ReadyResponse(status="ready", db="skipped")


@app.get("/metrics", tags=["system"])
async def metrics() -> Response:
    METRICS_APP_UPTIME.set(time.monotonic() - APP_START_MONOTONIC)
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


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
        "request_id": x_request_id or request.scope.get("request_id"),
        "client": request.client.host if request.client else None,
        "path": request.url.path,
    }


# Example dependency usage (kept in-file for self-containment)
@app.get("/db/ping", tags=["db"])
async def db_health(session: AsyncSession = Depends(get_session)) -> dict:
    await session.execute(text("SELECT 1"))
    return {"db": "ok"}


# Global error handlers
@app.exception_handler(Exception)
async def unhandled_exc(request: Request, exc: Exception):
    logger =
