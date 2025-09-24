# neuroforge/core context
# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import atexit
import json
import logging
import os
import signal
import sys
import time
import types
import uuid
from contextlib import asynccontextmanager, AsyncExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Mapping, Optional, Tuple, TypeVar
import contextvars

# ------------------------------ Optional deps ---------------------------------
try:  # HTTP client
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:  # Prometheus
    from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
except Exception:  # pragma: no cover
    CollectorRegistry = Counter = Histogram = generate_latest = CONTENT_TYPE_LATEST = None  # type: ignore

try:  # SQLAlchemy async
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine  # type: ignore
except Exception:  # pragma: no cover
    AsyncEngine = AsyncSession = async_sessionmaker = create_async_engine = None  # type: ignore

try:  # Redis asyncio
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:  # OpenTelemetry
    from opentelemetry import trace  # type: ignore
    from opentelemetry.trace import Tracer  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    Tracer = None  # type: ignore

# ------------------------------ Logging ---------------------------------------

def _setup_logger() -> logging.Logger:
    lvl = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv("LOG_FORMAT", "json").lower()
    logger = logging.getLogger("neuroforge")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if fmt == "json":
            formatter = logging.Formatter(
                fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s","mod":"%(module)s","req":"%(request_id)s"}'
            )
        else:
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(lvl)
    # Add request_id to every record (even if missing)
    class _RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if not hasattr(record, "request_id"):
                record.request_id = current_request_id() or "-"
            return True
    logger.addFilter(_RequestIdFilter())
    return logger

log = _setup_logger()

# ------------------------------ Config ----------------------------------------

@dataclass(frozen=True)
class AppConfig:
    name: str = field(default_factory=lambda: os.getenv("APP_NAME", "neuroforge-core"))
    env: str = field(default_factory=lambda: os.getenv("NF_ENV", "dev"))
    version: str = field(default_factory=lambda: os.getenv("APP_VERSION", "0.0.0"))
    # HTTP client
    http_timeout_s: float = float(os.getenv("HTTP_TIMEOUT_S", "10"))
    http_retries: int = int(os.getenv("HTTP_RETRIES", "3"))
    # Database
    database_url: Optional[str] = os.getenv("DATABASE_URL")
    db_pool_size: int = int(os.getenv("DB_MAX_OPEN", "50"))
    db_pool_acquire_timeout_s: float = float(os.getenv("DB_POOL_TIMEOUT_S", "5"))
    # Redis
    redis_url: Optional[str] = os.getenv("REDIS_URL")
    redis_pool_size: int = int(os.getenv("REDIS_POOL_SIZE", "50"))
    # Metrics
    metrics_enabled: bool = os.getenv("NF_METRICS_ENABLED", "true").lower() == "true"
    # Tracing
    tracing_enabled: bool = os.getenv("OTEL_TRACES_ENABLED", "false").lower() == "true"

    @staticmethod
    def load(path: Optional[str] = None) -> "AppConfig":
        """
        Lightweight loader: takes ENV by default; if JSON/YAML file exists, overlays.
        YAML support requires PyYAML; otherwise JSON is supported natively.
        """
        cfg = AppConfig()  # ENV first
        if not path:
            return cfg
        file = Path(path)
        if not file.exists():
            return cfg
        try:
            data: Dict[str, Any]
            if file.suffix.lower() in {".yaml", ".yml"}:
                try:
                    import yaml  # type: ignore
                    data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
                except Exception:
                    log.warning("YAML not available; skipping config file %s", path)
                    return cfg
            else:
                data = json.loads(file.read_text(encoding="utf-8"))
            # Shallow overlay for known keys
            kwargs = {k: data.get(k, getattr(cfg, k)) for k in vars(cfg).keys()}
            return AppConfig(**kwargs)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("Failed to load config from %s: %s", path, exc)
            return cfg

# ------------------------------ Request context -------------------------------

_request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
_user_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_id", default=None)

def current_request_id() -> Optional[str]:
    return _request_id_var.get()

def current_user_id() -> Optional[str]:
    return _user_id_var.get()

@contextmanager
def bind_request(request_id: Optional[str] = None, user_id: Optional[str] = None):
    """
    Context manager for request-scoped vars. Use in frameworks without DI.
    """
    token_req = _request_id_var.set(request_id or uuid.uuid4().hex)
    token_usr = _user_id_var.set(user_id)
    try:
        yield
    finally:
        _request_id_var.reset(token_req)
        _user_id_var.reset(token_usr)

# ------------------------------ Metrics (optional) ----------------------------

class Metrics:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and CollectorRegistry is not None
        if self.enabled:
            self.registry = CollectorRegistry()
            self.http_requests = Counter(
                "nf_http_requests_total", "Total HTTP requests", ["method", "code", "path"], registry=self.registry
            )
            self.db_ops = Counter("nf_db_ops_total", "DB operations", ["op"], registry=self.registry)
            self.redis_ops = Counter("nf_redis_ops_total", "Redis operations", ["op"], registry=self.registry)
            self.latency = Histogram(
                "nf_request_latency_seconds",
                "Request latency",
                ["path"],
                registry=self.registry,
                buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5),
            )
        else:
            self.registry = None

    def inc_http(self, method: str, code: int, path: str) -> None:
        if self.enabled:
            self.http_requests.labels(method, str(code), path).inc()

    def inc_db(self, op: str) -> None:
        if self.enabled:
            self.db_ops.labels(op).inc()

    def inc_redis(self, op: str) -> None:
        if self.enabled:
            self.redis_ops.labels(op).inc()

    def observe_latency(self, path: str, seconds: float) -> None:
        if self.enabled:
            self.latency.labels(path).observe(seconds)

    def expose_wsgi(self):
        """
        Returns a simple WSGI app for /metrics if needed outside FastAPI.
        """
        if not self.enabled:
            def app(environ, start_response):  # type: ignore
                start_response("204 No Content", [])
                return [b""]
            return app
        def app(environ, start_response):  # type: ignore
            body = generate_latest(self.registry)  # type: ignore
            headers = [("Content-Type", CONTENT_TYPE_LATEST)]  # type: ignore
            start_response("200 OK", headers)
            return [body]
        return app

# ------------------------------ Tracing (optional) ----------------------------

class Tracing:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and trace is not None
        self._tracer = trace.get_tracer("neuroforge") if self.enabled else None

    @property
    def tracer(self):
        return self._tracer

    def start_as_current_span(self, name: str):
        if not self.enabled:
            @contextmanager
            def _noop():
                yield None
            return _noop()
        return self._tracer.start_as_current_span(name)  # type: ignore

# ------------------------------ Database (optional) ---------------------------

class Database:
    def __init__(self, dsn: Optional[str], pool_size: int, acquire_timeout_s: float, metrics: Metrics) -> None:
        self._dsn = dsn
        self._metrics = metrics
        self._engine: Optional[AsyncEngine] = None
        self._session_maker: Optional[async_sessionmaker[AsyncSession]] = None
        self._pool_size = pool_size
        self._acquire_timeout = acquire_timeout_s

    async def start(self) -> None:
        if not self._dsn:
            log.info("Database DSN not configured; DB disabled")
            return
        if create_async_engine is None:
            log.warning("SQLAlchemy not available; DB disabled")
            return
        self._engine = create_async_engine(
            self._dsn,
            pool_size=self._pool_size,
            max_overflow=10,
            pool_timeout=self._acquire_timeout,
            pool_pre_ping=True,
            future=True,
        )
        self._session_maker = async_sessionmaker(self._engine, expire_on_commit=False)
        log.info("Database engine created")

    async def stop(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            log.info("Database engine disposed")
            self._engine = None

    def session(self) -> async_sessionmaker[AsyncSession]:
        if self._session_maker is None:
            raise RuntimeError("Database not initialized or SQLAlchemy missing")
        return self._session_maker

    async def health(self) -> Tuple[bool, str]:
        if self._engine is None:
            return (self._dsn is None, "disabled" if self._dsn is None else "not-initialized")
        try:
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))  # type: ignore[name-defined]
            return True, "ok"
        except Exception as exc:
            return False, f"error: {exc}"

# lazy import for text() without hard dependency at module import
def _sql_text_patch():
    global text
    try:
        from sqlalchemy import text  # type: ignore
    except Exception:
        def text(_: str):  # type: ignore
            raise RuntimeError("SQLAlchemy not installed")
    return text
text = _sql_text_patch()

# ------------------------------ Redis (optional) ------------------------------

class Cache:
    def __init__(self, url: Optional[str], pool_size: int, metrics: Metrics) -> None:
        self._url = url
        self._pool_size = pool_size
        self._metrics = metrics
        self._client: Optional["aioredis.Redis"] = None

    async def start(self) -> None:
        if not self._url:
            log.info("Redis URL not configured; cache disabled")
            return
        if aioredis is None:
            log.warning("redis.asyncio not available; cache disabled")
            return
        self._client = aioredis.from_url(self._url, max_connections=self._pool_size, encoding="utf-8", decode_responses=True)  # type: ignore
        try:
            await self._client.ping()
            log.info("Redis connected")
        except Exception as exc:
            log.error("Redis ping failed: %s", exc)

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.close()
            log.info("Redis closed")
            self._client = None

    @property
    def client(self):
        if self._client is None:
            raise RuntimeError("Redis not initialized or dependency missing")
        return self._client

    async def health(self) -> Tuple[bool, str]:
        if self._client is None:
            return (self._url is None, "disabled" if self._url is None else "not-initialized")
        try:
            pong = await self._client.ping()
            return (bool(pong), "ok" if pong else "no-pong")
        except Exception as exc:
            return False, f"error: {exc}"

# ------------------------------ HTTP client -----------------------------------

class HttpClient:
    def __init__(self, timeout_s: float, retries: int, metrics: Metrics) -> None:
        self._timeout = timeout_s
        self._retries = retries
        self._metrics = metrics
        self._client: Optional["httpx.AsyncClient"] = None

    async def start(self) -> None:
        if httpx is None:
            log.warning("httpx not available; HTTP client will use stdlib per-call (sync)")
            return
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=200)
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            limits=limits,
            follow_redirects=False,
            headers={"User-Agent": "neuroforge-core/http-client"},
            http2=True,
            transport=httpx.AsyncHTTPTransport(retries=self._retries),
        )
        log.info("HTTP client initialized (httpx)")

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            log.info("HTTP client closed")
            self._client = None

    @property
    def client(self):
        return self._client  # may be None if httpx missing

# ------------------------------ AppContext ------------------------------------

T = TypeVar("T")

@dataclass
class AppContext:
    cfg: AppConfig
    metrics: Metrics
    tracing: Tracing
    db: Database
    cache: Cache
    http: HttpClient
    started: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _stack: AsyncExitStack = field(default_factory=AsyncExitStack)

    async def start(self) -> None:
        if self.started:
            return
        async with self._lock:
            if self.started:
                return
            log.info("Starting AppContext env=%s version=%s", self.cfg.env, self.cfg.version)
            await self.db.start()
            await self.cache.start()
            await self.http.start()
            self.started = True
            log.info("AppContext started")

    async def stop(self) -> None:
        if not self.started:
            return
        async with self._lock:
            if not self.started:
                return
            log.info("Stopping AppContext...")
            await self.http.stop()
            await self.cache.stop()
            await self.db.stop()
            self.started = False
            log.info("AppContext stopped")

    async def health(self) -> Dict[str, str]:
        """
        Returns component statuses for /readyz.
        """
        db_ok, db_msg = await self.db.health()
        rd_ok, rd_msg = await self.cache.health()
        components = {
            "db": db_msg,
            "redis": rd_msg,
        }
        # If any required component is not ok → degraded
        return components

# ------------------------------ Singleton / Factory ---------------------------

_APP_CTX: Optional[AppContext] = None

def build_app_context(config_path: Optional[str] = None) -> AppContext:
    global _APP_CTX
    if _APP_CTX is not None:
        return _APP_CTX
    cfg = AppConfig.load(config_path)
    metrics = Metrics(enabled=cfg.metrics_enabled)
    tracing = Tracing(enabled=cfg.tracing_enabled)
    db = Database(cfg.database_url, pool_size=cfg.db_pool_size, acquire_timeout_s=cfg.db_pool_acquire_timeout_s, metrics=metrics)
    cache = Cache(cfg.redis_url, pool_size=cfg.redis_pool_size, metrics=metrics)
    http = HttpClient(timeout_s=cfg.http_timeout_s, retries=cfg.http_retries, metrics=metrics)
    _APP_CTX = AppContext(cfg=cfg, metrics=metrics, tracing=tracing, db=db, cache=cache, http=http)
    _install_signal_handlers()
    atexit.register(_shutdown_atexit)
    return _APP_CTX

def get_app_context() -> AppContext:
    ctx = _APP_CTX or build_app_context()
    return ctx

def _shutdown_atexit():
    ctx = _APP_CTX
    if ctx and ctx.started:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule graceful stop
                loop.create_task(ctx.stop())
            else:
                loop.run_until_complete(ctx.stop())
        except Exception as exc:
            log.warning("atexit shutdown error: %s", exc)

def _install_signal_handlers():
    if os.name != "posix":
        return
    def _handler(signum, frame):
        log.info("Received signal %s, initiating shutdown...", signum)
        ctx = _APP_CTX
        if not ctx:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(ctx.stop())
            else:
                loop.run_until_complete(ctx.stop())
        except Exception as exc:
            log.error("Signal shutdown error: %s", exc)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except Exception:
            pass

# ------------------------------ FastAPI lifespan ------------------------------

@asynccontextmanager
async def fastapi_lifespan(app, config_path: Optional[str] = None) -> AsyncIterator[None]:
    """
    Use in FastAPI(app, lifespan=fastapi_lifespan).
    Exposes app.state.readiness_check for /readyz.
    """
    ctx = build_app_context(config_path)
    await ctx.start()

    def _ready():
        # returns (ok, components)
        # Interpretation: db disabled => ok; enabled but error => degraded
        components = asyncio.run(ctx.health()) if not asyncio.get_event_loop().is_running() else await_health_sync(ctx)  # type: ignore
        ok = True
        for name, msg in components.items():
            if msg not in ("ok", "disabled"):
                ok = False
        return ok, components

    app.state.ctx = ctx
    app.state.readiness_check = _ready
    try:
        yield
    finally:
        await ctx.stop()

def await_health_sync(ctx: AppContext) -> Dict[str, str]:
    """
    In running loop context we cannot call asyncio.run; use loop.create_task + gather synchronously via run_until_complete
    from a new loop only in rare cases. Here we fallback to simple best-effort.
    """
    # Best-effort: return last known or quick probe
    try:
        loop = asyncio.get_event_loop()
        fut = asyncio.ensure_future(ctx.health())
        # Give tiny slice; readiness can still pass with partial info
        return loop.run_until_complete(asyncio.wait_for(fut, timeout=0.5))  # type: ignore
    except Exception:
        return {"db": "unknown", "redis": "unknown"}

# ------------------------------ Helpers for frameworks ------------------------

def request_timer(path: str) -> Callable[[], Callable[[Optional[BaseException]], None]]:
    """
    Usage:
        stop = request_timer("/api/v1/items")()
        ... handle request ...
        stop(None)
    """
    start = time.perf_counter()
    def _finisher(exc: Optional[BaseException]) -> None:
        elapsed = time.perf_counter() - start
        get_app_context().metrics.observe_latency(path, elapsed)
    return lambda: _finisher

def log_with_request(level: int, msg: str, **kwargs: Any) -> None:
    """
    Convenience wrapper that adds request_id automatically.
    """
    extra = kwargs.pop("extra", {})
    extra.update({"request_id": current_request_id() or "-"})
    log.log(level, msg, extra=extra, **kwargs)
