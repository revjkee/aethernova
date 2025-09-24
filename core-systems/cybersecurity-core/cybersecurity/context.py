from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import re
import socket
import sys
import uuid
from asyncio import AbstractEventLoop
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, AsyncIterator, Iterable, List, Literal, Optional, Sequence, Set, Tuple

# --- Optional third-party imports (graceful degradation) ----------------------
try:
    # Pydantic v2 style settings
    from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore
except Exception:  # pragma: no cover
    # Fallback for environments without pydantic-settings
    from pydantic import BaseSettings  # type: ignore

    SettingsConfigDict = dict  # type: ignore

from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator

try:
    from fastapi import Depends, Header, HTTPException, Request, Response, status
    from fastapi import FastAPI  # only for typing
except Exception:  # pragma: no cover
    # Lightweight stubs for type hints if FastAPI is not present at import time
    Request = Any  # type: ignore
    Response = Any  # type: ignore
    Depends = lambda x: x  # type: ignore
    Header = lambda *args, **kwargs: None  # type: ignore
    HTTPException = Exception  # type: ignore
    status = type("status", (), {"HTTP_400_BAD_REQUEST": 400, "HTTP_403_FORBIDDEN": 403})  # type: ignore
    FastAPI = Any  # type: ignore

try:
    from starlette.middleware.base import BaseHTTPMiddleware
except Exception:  # pragma: no cover
    BaseHTTPMiddleware = object  # type: ignore

# --- SQLAlchemy async (optional but recommended) -----------------------------
try:
    from sqlalchemy.ext.asyncio import (
        AsyncEngine,
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
except Exception:  # pragma: no cover
    AsyncEngine = Any  # type: ignore
    AsyncSession = Any  # type: ignore
    async_sessionmaker = Any  # type: ignore
    create_async_engine = None  # type: ignore

# --- Redis asyncio (optional) ------------------------------------------------
try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore


# =============================================================================
# Settings
# =============================================================================

class Settings(BaseSettings):
    """
    Centralized application settings.
    Load from env/.env. Pydantic v2 compatible.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "cybersecurity-core"
    ENV: Literal["dev", "staging", "prod", "test"] = "dev"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Networking / headers
    TENANT_HEADER: str = "X-Tenant-ID"
    USER_HEADER: str = "X-User-ID"
    ROLES_HEADER: str = "X-Roles"
    REQUEST_ID_HEADER: str = "X-Request-ID"
    CORRELATION_ID_HEADER: str = "X-Correlation-ID"
    TRUST_PROXY: bool = True
    FORWARDED_FOR_HEADER: str = "X-Forwarded-For"

    # DB / Cache (optional)
    DB_ASYNC_URL: Optional[str] = Field(
        default=None,
        description="SQLAlchemy async URL (e.g., postgresql+asyncpg://user:pass@host/db)",
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_PRE_PING: bool = True

    REDIS_URL: Optional[str] = Field(
        default=None,
        description="redis://user:pass@host:6379/0",
    )

    # Telemetry
    OTEL_SERVICE_NAME: Optional[str] = None
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[HttpUrl] = None

    @field_validator("TENANT_HEADER", "USER_HEADER", "ROLES_HEADER", "REQUEST_ID_HEADER", "CORRELATION_ID_HEADER")
    @classmethod
    def _validate_header(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9\-]+", v):
            raise ValueError("Header names must be token chars [A-Za-z0-9-].")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[arg-type]


# =============================================================================
# Request-scoped context
# =============================================================================

Role = Literal["ADMIN", "ANALYST", "RESPONDER", "THREAT_HUNTER", "AUDITOR", "READONLY", "SERVICE"]

@dataclass
class RequestContext:
    request_id: str
    correlation_id: str
    tenant_id: Optional[uuid.UUID]
    user_id: Optional[uuid.UUID]
    roles: Set[Role] = field(default_factory=set)
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: Optional[str] = None

    def as_log_extra(self) -> dict:
        return {
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "roles": sorted(list(self.roles)),
            "ip": self.ip,
            "trace_id": self.trace_id,
        }


_ctx_var: contextvars.ContextVar[Optional[RequestContext]] = contextvars.ContextVar("request_context", default=None)


def get_request_context() -> Optional[RequestContext]:
    return _ctx_var.get()


def set_request_context(ctx: RequestContext) -> None:
    _ctx_var.set(ctx)


def clear_request_context() -> None:
    _ctx_var.set(None)


# =============================================================================
# Logging with contextual enrichment
# =============================================================================

class ContextFilter(logging.Filter):
    """Inject request context into log records."""
    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_request_context()
        record.request_id = getattr(record, "request_id", None)
        record.correlation_id = getattr(record, "correlation_id", None)
        record.tenant_id = getattr(record, "tenant_id", None)
        record.user_id = getattr(record, "user_id", None)
        record.trace_id = getattr(record, "trace_id", None)
        if ctx:
            record.request_id = ctx.request_id
            record.correlation_id = ctx.correlation_id
            record.tenant_id = str(ctx.tenant_id) if ctx.tenant_id else None
            record.user_id = str(ctx.user_id) if ctx.user_id else None
            record.trace_id = ctx.trace_id
        return True


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s "
                "request_id=%(request_id)s correlation_id=%(correlation_id)s "
                "tenant_id=%(tenant_id)s user_id=%(user_id)s trace_id=%(trace_id)s"
        )
        handler.setFormatter(formatter)
        handler.addFilter(ContextFilter())
        root.addHandler(handler)
    root.setLevel(level)

    # Tweak common servers' loggers if present
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "gunicorn.error"):
        try:
            lg = logging.getLogger(name)
            lg.setLevel(level)
            for h in lg.handlers:
                h.addFilter(ContextFilter())
        except Exception:
            pass


# =============================================================================
# Utilities
# =============================================================================

def _gen_id() -> str:
    return str(uuid.uuid4())


def _parse_uuid(value: Optional[str]) -> Optional[uuid.UUID]:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except Exception:
        return None


def _parse_roles(value: Optional[str]) -> Set[Role]:
    """
    Comma/space/semicolon separated roles; case-insensitive; unknown are ignored.
    """
    allowed: Set[str] = {"ADMIN", "ANALYST", "RESPONDER", "THREAT_HUNTER", "AUDITOR", "READONLY", "SERVICE"}
    if not value:
        return set()
    parts = re.split(r"[,\s;]+", value.strip())
    roles: Set[Role] = set()
    for p in parts:
        token = p.strip().upper()
        if token and token in allowed:
            roles.add(token)  # type: ignore[assignment]
    return roles


def _client_ip(request: Request, settings: Settings) -> Optional[str]:
    try:
        if settings.TRUST_PROXY:
            fwd = request.headers.get(settings.FORWARDED_FOR_HEADER)
            if fwd:
                # X-Forwarded-For: client, proxy1, proxy2
                return fwd.split(",")[0].strip()
        # fallback
        return request.client.host if request.client else None  # type: ignore[attr-defined]
    except Exception:
        return None


# =============================================================================
# Middleware for request context & correlation
# =============================================================================

class ContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Optional[Settings] = None) -> None:
        super().__init__(app)
        self.settings = settings or get_settings()

    async def dispatch(self, request: Request, call_next):
        s = self.settings

        req_id = request.headers.get(s.REQUEST_ID_HEADER) or _gen_id()
        corr_id = request.headers.get(s.CORRELATION_ID_HEADER) or req_id

        tenant_id = _parse_uuid(request.headers.get(s.TENANT_HEADER))
        user_id = _parse_uuid(request.headers.get(s.USER_HEADER))
        roles = _parse_roles(request.headers.get(s.ROLES_HEADER))
        ip = _client_ip(request, s)
        ua = request.headers.get("User-Agent")

        ctx = RequestContext(
            request_id=req_id,
            correlation_id=corr_id,
            tenant_id=tenant_id,
            user_id=user_id,
            roles=roles,
            ip=ip,
            user_agent=ua,
            trace_id=None,  # Hook your tracing solution to set this
        )
        token = _ctx_var.set(ctx)
        try:
            response: Response = await call_next(request)
        finally:
            _ctx_var.reset(token)

        # Propagate IDs back
        try:
            response.headers.setdefault(s.REQUEST_ID_HEADER, req_id)
            response.headers.setdefault(s.CORRELATION_ID_HEADER, corr_id)
        except Exception:
            pass
        return response


# =============================================================================
# Resources: DB/Redis and DI helpers
# =============================================================================

class AppResources:
    """
    Application-scoped resources (async). Instantiate once per process.
    """
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.loop: Optional[AbstractEventLoop] = None

        # DB
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker[AsyncSession]] = None  # type: ignore[name-defined]

        # Redis
        self.redis: Optional[Any] = None  # aioredis.Redis

        # Internal state
        self._ready: bool = False
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        async with self._lock:
            if self._ready:
                return
            self.loop = asyncio.get_running_loop()

            # Database
            if self.settings.DB_ASYNC_URL:
                if create_async_engine is None:
                    raise RuntimeError("SQLAlchemy async is not available, but DB_ASYNC_URL is set.")
                self.engine = create_async_engine(
                    self.settings.DB_ASYNC_URL,
                    pool_size=self.settings.DB_POOL_SIZE,
                    max_overflow=self.settings.DB_MAX_OVERFLOW,
                    pool_pre_ping=self.settings.DB_POOL_PRE_PING,
                    future=True,
                )
                self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)  # type: ignore[name-defined]

            # Redis
            if self.settings.REDIS_URL and aioredis:
                self.redis = aioredis.from_url(self.settings.REDIS_URL, decode_responses=True)

            self._ready = True
            logging.getLogger(__name__).info(
                "resources.open",
                extra={"db": bool(self.engine), "redis": bool(self.redis), "env": self.settings.ENV},
            )

    async def close(self) -> None:
        async with self._lock:
            tasks: List[asyncio.Task] = []

            # Redis
            if self.redis is not None:
                try:
                    tasks.append(asyncio.create_task(self.redis.close()))  # type: ignore[attr-defined]
                except Exception:
                    pass
                self.redis = None

            # DB
            if self.engine is not None:
                try:
                    await self.engine.dispose()
                except Exception:
                    pass
                self.engine = None
                self.session_factory = None

            self._ready = False
            logging.getLogger(__name__).info("resources.close")

    async def health(self) -> dict:
        status = {"db": False, "redis": False}
        # DB ping
        if self.engine and self.session_factory:
            try:
                async with self.engine.connect() as conn:  # type: ignore[union-attr]
                    await conn.execute("SELECT 1")  # type: ignore[arg-type]
                status["db"] = True
            except Exception:
                status["db"] = False
        # Redis ping
        if self.redis is not None:
            try:
                pong = await self.redis.ping()
                status["redis"] = bool(pong)
            except Exception:
                status["redis"] = False
        return status


_resources_singleton: Optional[AppResources] = None


def build_resources(settings: Optional[Settings] = None) -> AppResources:
    global _resources_singleton
    if _resources_singleton is None:
        _resources_singleton = AppResources(settings or get_settings())
    return _resources_singleton


async def get_resources() -> AppResources:
    res = build_resources()
    if not res._ready:
        await res.open()
    return res


# --- DB session dependency ----------------------------------------------------

async def get_db_session(resources: AppResources = Depends(get_resources)) -> AsyncIterator[AsyncSession]:
    """
    Usage (FastAPI):
        @app.get("/items")
        async def endpoint(session: AsyncSession = Depends(get_db_session)):
            ...
    """
    if not resources.session_factory:
        raise HTTPException(status_code=500, detail="Database is not configured.")
    session: AsyncSession = resources.session_factory()  # type: ignore[operator]
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


# --- Redis dependency ---------------------------------------------------------

async def get_redis(resources: AppResources = Depends(get_resources)) -> Any:
    if resources.redis is None:
        raise HTTPException(status_code=500, detail="Redis is not configured.")
    return resources.redis


# =============================================================================
# Tenant/User header dependencies and RBAC helpers
# =============================================================================

def tenant_id_from_header(
    s: Settings = Depends(get_settings),
    x_tenant_id: str = Header(..., alias=lambda: get_settings().TENANT_HEADER),  # type: ignore[arg-type]
) -> uuid.UUID:
    """
    Strict tenant extractor: fail 400 if missing/invalid.
    """
    try:
        return uuid.UUID(x_tenant_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid tenant header (UUID expected).")


def require_roles(*required: Role):
    """
    Dependency factory: ensure at least one of required roles is present.
    """
    required_set = set(required)

    async def _checker(request: Request) -> None:
        ctx = get_request_context()
        if not ctx:
            raise HTTPException(status_code=500, detail="Request context is not available.")
        if not (ctx.roles & required_set):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role privileges.")
    return _checker


# =============================================================================
# FastAPI lifespan integration
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # type: ignore[valid-type]
    """
    Example:
        app = FastAPI(lifespan=lifespan)
        app.add_middleware(ContextMiddleware, settings=get_settings())
    """
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)

    resources = build_resources(settings)
    await resources.open()
    try:
        yield
    finally:
        await resources.close()


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "Settings",
    "get_settings",
    "RequestContext",
    "get_request_context",
    "set_request_context",
    "clear_request_context",
    "ContextMiddleware",
    "configure_logging",
    "AppResources",
    "build_resources",
    "get_resources",
    "get_db_session",
    "get_redis",
    "tenant_id_from_header",
    "require_roles",
    "lifespan",
]
