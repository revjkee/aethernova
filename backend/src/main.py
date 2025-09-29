# backend/src/main.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Callable, Iterable, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount
from pydantic import BaseModel, AnyHttpUrl, Field, ValidationError
from pydantic_settings import BaseSettings

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text


# -----------------------------
# Settings
# -----------------------------
class Settings(BaseSettings):
    APP_NAME: str = "NeuroCity Backend"
    APP_ENV: str = Field(default="development", pattern="^(development|staging|production)$")
    APP_VERSION: str = "1.0.0"

    # Security / Network
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    CORS_ORIGINS: str = "http://localhost,http://127.0.0.1"
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    CORS_ALLOW_HEADERS: str = "Authorization,Content-Type,Accept,Accept-Language,Origin,User-Agent,X-Request-ID"

    # Database (async only)
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/postgres"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    DB_ECHO: bool = False

    # Runtime
    REQUEST_ID_HEADER: str = "X-Request-ID"
    READINESS_STARTUP_GRACE_SEC: int = 2

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()


# -----------------------------
# Logging
# -----------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "time": int(time.time() * 1000),
        }
        # Optional extras
        for key in ("request_id", "path", "method", "status_code", "duration_ms"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        return json.dumps(payload, ensure_ascii=False)


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO if settings.APP_ENV != "development" else logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]


setup_logging()
logger = logging.getLogger("app")


# -----------------------------
# Request ID Middleware
# -----------------------------
class RequestIDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, header_name: str = "X-Request-ID"):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = request.headers.get(self.header_name) or str(uuid.uuid4())
        start = time.perf_counter()

        # Attach to state for downstream usage
        request.state.request_id = req_id

        # Proceed
        response = await call_next(request)

        duration_ms = int((time.perf_counter() - start) * 1000)
        response.headers[self.header_name] = req_id

        # Access log
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code}",
            extra={
                "request_id": req_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response


# -----------------------------
# Database (async only)
# -----------------------------
engine: Optional[AsyncEngine] = None
session_factory: Optional[async_sessionmaker[AsyncSession]] = None


async def init_engine() -> None:
    global engine, session_factory

    # Create async engine
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        echo=settings.DB_ECHO,
        pool_pre_ping=True,
        future=True,
    )
    session_factory = async_sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    # Warm-up probe
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))


async def dispose_engine() -> None:
    global engine
    if engine is not None:
        await engine.dispose()
        engine = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if session_factory is None:
        raise RuntimeError("Database is not initialized")
    async with session_factory() as session:
        yield session


# -----------------------------
# Lifespan
# -----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        await init_engine()
        logger.info("Database engine initialized")
    except Exception as exc:
        logger.exception("Failed to initialize database engine")
        # Fail fast in non-dev environments
        if settings.APP_ENV != "development":
            raise
    # Optional grace period for readiness checks in containerized envs
    await asyncio.sleep(max(0, settings.READINESS_STARTUP_GRACE_SEC))

    yield

    # Shutdown
    try:
        await dispose_engine()
        logger.info("Database engine disposed")
    except Exception:
        logger.exception("Failed to dispose database engine")


# -----------------------------
# Routes Registration
# -----------------------------
def register_routes(app: FastAPI) -> None:
    # Placeholder for domain routers, e.g.:
    # from .api.v1.users import router as users_router
    # app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
    pass


# -----------------------------
# Exception Handlers
# -----------------------------
def _problem_json(
    title: str,
    detail: str,
    status_code: int,
    request: Optional[Request] = None,
    extra: Optional[dict] = None,
) -> dict:
    payload = {
        "title": title,
        "detail": detail,
        "status": status_code,
        "type": "about:blank",
    }
    if request is not None:
        payload["instance"] = str(request.url.path)
        payload["request_id"] = getattr(request.state, "request_id", None)
    if extra:
        payload.update(extra)
    return payload


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        logger.warning(f"Validation error: {exc.errors()}")
        payload = _problem_json(
            title="Validation Error",
            detail=f"Request validation failed: {len(exc.errors())} error(s)",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            request=request,
            extra={"errors": exc.errors()},
        )
        return JSONResponse(payload, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    @app.exception_handler(ValidationError)
    async def pydantic_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
        logger.warning(f"Pydantic validation error: {exc}")
        payload = _problem_json(
            title="Data Validation Error",
            detail=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            request=request,
        )
        return JSONResponse(payload, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        payload = _problem_json(
            title="HTTP Error",
            detail=exc.detail,
            status_code=exc.status_code,
            request=request,
        )
        return JSONResponse(payload, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception occurred")
        payload = _problem_json(
            title="Internal Server Error",
            detail="An unexpected error occurred",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request=request,
        )
        return JSONResponse(payload, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -----------------------------
# App Factory
# -----------------------------
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.APP_ENV != "production" else None,
        redoc_url="/redoc" if settings.APP_ENV != "production" else None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Trusted hosts
    allowed_hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    # CORS
    cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
    cors_methods = [m.strip() for m in settings.CORS_ALLOW_METHODS.split(",") if m.strip()]
    cors_headers = [h.strip() for h in settings.CORS_ALLOW_HEADERS.split(",") if h.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=cors_methods,
        allow_headers=cors_headers,
        expose_headers=[settings.REQUEST_ID_HEADER],
    )

    # Compression
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # Request ID
    app.add_middleware(RequestIDMiddleware, header_name=settings.REQUEST_ID_HEADER)

    # Routes
    register_routes(app)

    # Error handlers
    register_exception_handlers(app)

    return app


app = create_app()


# -----------------------------
# Routes
# -----------------------------
class HealthResponse(BaseModel):
    status: str
    uptime_ms: int
    app: str
    version: str


_start_time = time.perf_counter()


@app.get("/", response_class=PlainTextResponse, tags=["system"])
async def root() -> str:
    return "OK"


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    uptime_ms = int((time.perf_counter() - _start_time) * 1000)
    return HealthResponse(
        status="ok",
        uptime_ms=uptime_ms,
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
    )


@app.get("/ready", response_class=PlainTextResponse, tags=["system"])
async def ready() -> str:
    # If engine is up and session_factory exists — we are ready
    if engine is None or session_factory is None:
        # In production, readiness should fail hard to avoid routing traffic
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="not ready")
    return "ready"


# -----------------------------
# Local run (optional)
# -----------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
        log_config=None,  # use our logging
    )
