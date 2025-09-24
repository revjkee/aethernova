# cybersecurity-core/cybersecurity/bootstrap.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
import sys
from asyncio import Task
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Awaitable, Callable, Dict, List, Optional

# -----------------------------
# Optional deps (lazy importers)
# -----------------------------
def _try_import(name: str):
    try:
        return __import__(name)
    except Exception:  # noqa: BLE001
        return None

_sqlalchemy = _try_import("sqlalchemy")
_sqlalchemy_async = _try_import("sqlalchemy.ext.asyncio")
_prometheus_client = _try_import("prometheus_client")
_sentry_sdk = _try_import("sentry_sdk")
_ot_trace = None
try:
    _ot_trace = __import__("opentelemetry.trace")
    _ot_resource = __import__("opentelemetry.sdk.resources", fromlist=["Resource"])
    _ot_trace_sdk = __import__("opentelemetry.sdk.trace", fromlist=["TracerProvider"])
    _ot_export = __import__(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter",
        fromlist=["OTLPSpanExporter"],
    )
    _ot_batch = __import__("opentelemetry.sdk.trace.export", fromlist=["BatchSpanProcessor"])
except Exception:  # noqa: BLE001
    _ot_trace = None

# ============================
# Environment & Settings
# ============================
def _env_str(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key, default)
    return v if v not in ("", None) else default

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except Exception:  # noqa: BLE001
        return default

def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

@dataclass(frozen=True)
class Settings:
    app_name: str = "cybersecurity-core"
    env: str = _env_str("APP_ENV", "dev") or "dev"
    log_level: str = _env_str("LOG_LEVEL", "INFO") or "INFO"
    log_json: bool = _env_bool("LOG_JSON", True)
    log_correlation: bool = _env_bool("LOG_CORRELATION", True)

    # Metrics
    metrics_enabled: bool = _env_bool("METRICS_ENABLED", True)
    metrics_port: int = _env_int("METRICS_PORT", 9000)

    # Sentry
    sentry_dsn: Optional[str] = _env_str("SENTRY_DSN", None)
    sentry_traces_sample_rate: float = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.0"))

    # Tracing (OTel)
    tracing_enabled: bool = _env_bool("TRACING_ENABLED", False)
    otlp_endpoint: Optional[str] = _env_str("OTLP_ENDPOINT", None)
    service_version: str = _env_str("SERVICE_VERSION", "0.0.1") or "0.0.1"

    # Database (async SQLAlchemy)
    db_enabled: bool = _env_bool("DB_ENABLED", False)
    database_url: Optional[str] = _env_str("DATABASE_URL", None)
    db_echo: bool = _env_bool("DB_ECHO", False)
    db_pool_size: int = _env_int("DB_POOL_SIZE", 10)
    db_max_overflow: int = _env_int("DB_MAX_OVERFLOW", 20)

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

# ============================
# Logging (JSON formatter)
# ============================
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        # Minimal, fast JSON logs for prod
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
            "pid": record.process,
            "host": socket.gethostname(),
        }
        # Correlation (trace/span) if OpenTelemetry present
        if get_settings().log_correlation and _ot_trace:
            span = _ot_trace.get_current_span()
            if span is not None:
                ctx = span.get_span_context()
                if getattr(ctx, "is_valid", lambda: False)():
                    payload["trace_id"] = f"{ctx.trace_id:032x}"
                    payload["span_id"] = f"{ctx.span_id:016x}"
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def init_logging(level: Optional[str] = None) -> logging.Logger:
    settings = get_settings()
    log_level = (level or settings.log_level).upper()
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    if settings.log_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    logger.addHandler(handler)

    logging.getLogger("uvicorn").setLevel(logger.level)
    logging.getLogger("uvicorn.access").setLevel(logger.level)
    logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)

    logging.getLogger(__name__).info("logging_initialized", extra={"level": log_level})
    return logging.getLogger(__name__)

# ============================
# Sentry (optional)
# ============================
def init_sentry() -> None:
    if not _sentry_sdk:
        logging.getLogger(__name__).info("sentry_skipped_not_installed")
        return
    s = get_settings()
    if not s.sentry_dsn:
        logging.getLogger(__name__).info("sentry_skipped_no_dsn")
        return
    _sentry_sdk.init(
        dsn=s.sentry_dsn,
        traces_sample_rate=s.sentry_traces_sample_rate,
        release=f"{s.app_name}@{s.service_version}",
        environment=s.env,
        send_default_pii=False,
    )
    logging.getLogger(__name__).info("sentry_initialized")

# ============================
# OpenTelemetry Tracing (optional)
# ============================
def init_tracing() -> None:
    if not (get_settings().tracing_enabled and _ot_trace):
        logging.getLogger(__name__).info("tracing_skipped")
        return
    s = get_settings()
    resource = _ot_resource.Resource.create(
        {
            "service.name": s.app_name,
            "service.version": s.service_version,
            "deployment.environment": s.env,
        }
    )
    provider = _ot_trace_sdk.TracerProvider(resource=resource)
    exporter = _ot_export.OTLPSpanExporter(endpoint=s.otlp_endpoint) if s.otlp_endpoint else _ot_export.OTLPSpanExporter()
    span_processor = _ot_batch.BatchSpanProcessor(exporter)
    provider.add_span_processor(span_processor)
    _ot_trace.get_tracer_provider = lambda: provider  # type: ignore
    _ot_trace.set_tracer_provider(provider)
    logging.getLogger(__name__).info("tracing_initialized")

# ============================
# Prometheus Metrics (optional)
# ============================
def start_metrics_server() -> Optional[Callable[[], None]]:
    s = get_settings()
    if not (s.metrics_enabled and _prometheus_client):
        logging.getLogger(__name__).info("metrics_skipped")
        return None
    # Prometheus client provides start_http_server returning None; we wrap with stopper
    _prometheus_client.start_http_server(s.metrics_port)
    logging.getLogger(__name__).info("metrics_server_started", extra={"port": s.metrics_port})

    def _stop() -> None:
        # Standard client has no explicit stop; rely on process shutdown.
        logging.getLogger(__name__).info("metrics_server_stopped")

    return _stop

# ============================
# Database (async SQLAlchemy)
# ============================
AsyncEngine = Any
AsyncSessionMaker = Any

async def init_db() -> tuple[Optional[AsyncEngine], Optional[AsyncSessionMaker]]:
    s = get_settings()
    if not s.db_enabled:
        logging.getLogger(__name__).info("db_skipped_disabled")
        return None, None
    if not (_sqlalchemy_async and _sqlalchemy):
        logging.getLogger(__name__).error("db_error_sqlalchemy_not_installed")
        raise RuntimeError("SQLAlchemy async not installed")

    create_async_engine = _sqlalchemy_async.create_async_engine  # type: ignore[attr-defined]
    async_sessionmaker = _sqlalchemy_async.async_sessionmaker  # type: ignore[attr-defined]

    connect_args: Dict[str, Any] = {}
    engine: AsyncEngine = create_async_engine(
        s.database_url,
        echo=s.db_echo,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        pool_pre_ping=True,
        connect_args=connect_args,
        future=True,
    )
    session_maker: AsyncSessionMaker = async_sessionmaker(bind=engine, expire_on_commit=False)

    # Connection test
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda _: None)  # lightweight sanity check
    except Exception as e:  # noqa: BLE001
        logging.getLogger(__name__).exception("db_connection_failed")
        raise e

    logging.getLogger(__name__).info(
        "db_initialized",
        extra={"url": ("***" if s.database_url and "@" in s.database_url else s.database_url)},
    )
    return engine, session_maker

async def close_db(engine: Optional[AsyncEngine]) -> None:
    if engine is not None:
        await engine.dispose()
        logging.getLogger(__name__).info("db_closed")

# ============================
# Alembic migrations (optional)
# ============================
async def run_migrations(alembic_ini_path: str = "alembic.ini") -> None:
    if not get_settings().db_enabled:
        return
    alembic = _try_import("alembic.config")
    alembic_cmd = _try_import("alembic.command")
    if not (alembic and alembic_cmd):
        logging.getLogger(__name__).warning("alembic_not_installed_skip_migrations")
        return
    cfg = alembic.Config(alembic_ini_path)  # type: ignore[attr-defined]
    alembic_cmd.upgrade(cfg, "head")        # type: ignore[attr-defined]
    logging.getLogger(__name__).info("alembic_migrated")

# ============================
# Boot Context & Orchestration
# ============================
ShutdownHook = Callable[[], Awaitable[None]] | Callable[[], None]

@dataclass
class BootContext:
    settings: Settings
    logger: logging.Logger
    engine: Optional[AsyncEngine] = None
    session_maker: Optional[AsyncSessionMaker] = None
    tasks: List[Task] = field(default_factory=list)
    shutdown_hooks: List[ShutdownHook] = field(default_factory=list)
    started: bool = False

    def add_task(self, task: Task) -> None:
        self.tasks.append(task)

    def add_shutdown_hook(self, hook: ShutdownHook) -> None:
        self.shutdown_hooks.append(hook)

async def _graceful_cancel(tasks: List[Task], timeout: float = 10.0) -> None:
    for t in tasks:
        t.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.wait(tasks, timeout=timeout)

async def bootstrap(run_db_migrations: bool = False) -> BootContext:
    logger = init_logging()
    settings = get_settings()

    init_sentry()
    init_tracing()
    metrics_stop = start_metrics_server()

    engine, session_maker = await init_db()

    if run_db_migrations:
        # Run blocking migration in a thread to keep API responsive
        await asyncio.to_thread(asyncio.run, run_migrations()) if False else await run_migrations()

    ctx = BootContext(settings=settings, logger=logging.getLogger(__name__), engine=engine, session_maker=session_maker)
    if metrics_stop:
        ctx.add_shutdown_hook(metrics_stop)

    # Signal handlers
    def _handle_signal(sig: int, _frame: Any) -> None:
        logging.getLogger(__name__).info("signal_received", extra={"signal": sig})

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            signal.signal(sig, _handle_signal)

    ctx.started = True
    logger.info("bootstrap_completed", extra={"env": settings.env, "app": settings.app_name})
    return ctx

async def shutdown(ctx: BootContext) -> None:
    # Run user hooks (sync or async)
    for hook in ctx.shutdown_hooks:
        if asyncio.iscoroutinefunction(hook):  # type: ignore[arg-type]
            await hook()  # type: ignore[misc]
        else:
            try:
                hook()  # type: ignore[misc]
            except Exception:  # noqa: BLE001
                logging.getLogger(__name__).exception("shutdown_hook_error")

    await _graceful_cancel(ctx.tasks)
    await close_db(ctx.engine)
    logging.getLogger(__name__).info("shutdown_completed")

# ============================
# FastAPI lifespan helper
# ============================
@contextlib.asynccontextmanager
async def fastapi_lifespan(app=None, *, run_db_migrations: bool = False):
    """
    Use in FastAPI app:
        from fastapi import FastAPI
        from cybersecurity.bootstrap import fastapi_lifespan
        app = FastAPI(lifespan=fastapi_lifespan)
    """
    ctx = await bootstrap(run_db_migrations=run_db_migrations)
    try:
        yield ctx
    finally:
        await shutdown(ctx)

# ============================
# Uvicorn logging tune (optional)
# ============================
def tune_uvicorn_access_log() -> None:
    # Compact access logs in JSON or plain format, depending on settings
    logger = logging.getLogger("uvicorn.access")
    if get_settings().log_json:
        for h in list(logger.handlers):
            h.setFormatter(JsonFormatter())
    logging.getLogger(__name__).info("uvicorn_logging_tuned")
