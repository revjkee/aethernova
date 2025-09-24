# File: neuroforge-core/neuroforge/bootstrap.py
# Industrial bootstrap for neuroforge-core:
# - Centralized settings (Pydantic)
# - JSON logging with correlation ids
# - Optional OpenTelemetry (OTLP) tracing + resource attrs
# - Prometheus /metrics (multiprocess-safe)
# - Health/Readiness endpoints (DB/Redis/migrations)
# - FastAPI app factory (middlewares, CORS, gzip, trusted hosts)
# - SQLAlchemy 2.0 session factory (sync engine)
# - Celery app factory (optional)
# - Graceful shutdown and CLI helpers
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Generator, Optional, Tuple

# ----------------------------- Settings --------------------------------------
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict  # pydantic >=2
    from pydantic import Field
except Exception:  # pragma: no cover
    raise RuntimeError("pydantic>=2 and pydantic-settings are required for bootstrap")

class Settings(BaseSettings):
    # App
    APP_NAME: str = "neuroforge-core"
    ENVIRONMENT: str = "development"  # development|staging|production
    LOG_LEVEL: str = "INFO"
    TZ: str = "UTC"

    # HTTP
    HTTP_HOST: str = "0.0.0.0"
    HTTP_PORT: int = 8080
    ALLOWED_HOSTS: str = "*"
    CORS_ORIGINS: str = ""  # comma-separated
    ENABLE_GZIP: bool = True
    ENABLE_METRICS: bool = True
    METRICS_ROUTE: str = "/metrics"

    # Observability
    OTEL_ENABLED: bool = True
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
    OTEL_SERVICE_NAME: Optional[str] = None  # default -> APP_NAME
    PROMETHEUS_MULTIPROC_DIR: Optional[str] = None

    # DB / Cache
    POSTGRES_DSN: str = "postgresql://neuroforge:change_me@localhost:5432/neuroforge"
    REDIS_DSN: Optional[str] = "redis://localhost:6379/1"

    # Celery
    CELERY_ENABLED: bool = True
    CELERY_BROKER_URL: str = "redis://localhost:6379/3"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/4"
    CELERY_TASK_DEFAULT_QUEUE: str = "neuroforge-default"
    CELERY_CONCURRENCY: int = 1

    # Feature flags
    READINESS_CHECK_MIGRATIONS: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

def load_settings() -> Settings:
    s = Settings()  # reads .env if present
    os.environ.setdefault("TZ", s.TZ)
    try:
        import time as _time
        _time.tzset()  # type: ignore[attr-defined]
    except Exception:
        pass
    return s

# ----------------------------- Logging ---------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge extra attrs (from logger.extra or log_record dict)
        for k, v in record.__dict__.items():
            if k in (
                "name","msg","args","levelname","levelno","pathname","filename",
                "module","exc_info","exc_text","stack_info","lineno","funcName",
                "created","msecs","relativeCreated","thread","threadName",
                "processName","process"
            ):
                continue
            base[k] = v
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))

def configure_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    # Suppress noisy loggers defaults
    for noisy in ("uvicorn.access", "asyncio", "aiokafka"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logger

# ----------------------------- OpenTelemetry ---------------------------------
def setup_tracing(settings: Settings) -> None:
    if not settings.OTEL_ENABLED:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        # Optional auto-instrumentation (does nothing if libs missing)
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: F401
            from opentelemetry.instrumentation.requests import RequestsInstrumentor  # noqa: F401
            from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor  # noqa: F401
            from opentelemetry.instrumentation.redis import RedisInstrumentor  # noqa: F401
            # They will be attached inside create_app where app is available.
            globals()["_OTEL_FASTAPI_READY"] = True
        except Exception:
            globals()["_OTEL_FASTAPI_READY"] = False
        endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT
        if not endpoint:
            return
        res = Resource.create(
            {
                "service.name": settings.OTEL_SERVICE_NAME or settings.APP_NAME,
                "service.version": os.getenv("APP_VERSION", "0.0.0"),
                "deployment.environment": settings.ENVIRONMENT,
            }
        )
        provider = TracerProvider(resource=res)
        exporter = OTLPSpanExporter(endpoint=endpoint, timeout=5)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logging.getLogger(__name__).info("otel.tracing.initialized", extra={"endpoint": endpoint})
    except Exception as e:
        logging.getLogger(__name__).warning("otel.tracing.disabled", extra={"reason": str(e)})

# ----------------------------- Database (SQLAlchemy 2.0, sync) ---------------

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
except Exception:  # pragma: no cover
    create_engine = None  # type: ignore

@dataclass
class DB:
    engine: Any
    SessionLocal: Any

def setup_db(dsn: str) -> Optional[DB]:
    if create_engine is None:
        logging.getLogger(__name__).warning("sqlalchemy.not_installed")
        return None
    engine = create_engine(dsn, pool_pre_ping=True, pool_size=10, max_overflow=20, pool_recycle=1800, future=True)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return DB(engine=engine, SessionLocal=SessionLocal)

@contextmanager
def get_db(db: DB) -> Generator[Any, None, None]:
    session = db.SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def check_db_connection(db: DB) -> Tuple[bool, str]:
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as e:
        return False, str(e)

# ----------------------------- Redis (optional) -------------------------------

def check_redis_connection(redis_dsn: Optional[str]) -> Tuple[bool, str]:
    if not redis_dsn:
        return True, "disabled"
    try:
        import redis  # sync client
        r = redis.Redis.from_url(redis_dsn, socket_connect_timeout=2, socket_timeout=2)
        pong = r.ping()
        return (True, "ok") if pong else (False, "no-pong")
    except Exception as e:
        return False, str(e)

# ----------------------------- Prometheus /metrics ----------------------------

def setup_prometheus(settings: Settings) -> None:
    if not settings.ENABLE_METRICS:
        return
    try:
        import prometheus_client as _prom
        if settings.PROMETHEUS_MULTIPROC_DIR:
            os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", settings.PROMETHEUS_MULTIPROC_DIR)
            from prometheus_client import multiprocess  # noqa: F401
        # Default process metrics are enabled on import; nothing else required
        logging.getLogger(__name__).info("prometheus.initialized", extra={"multi": bool(settings.PROMETHEUS_MULTIPROC_DIR)})
    except Exception as e:
        logging.getLogger(__name__).warning("prometheus.disabled", extra={"reason": str(e)})

def prometheus_endpoint():
    try:
        import prometheus_client
        from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest, multiprocess, PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR  # noqa: E501
    except Exception:  # pragma: no cover
        from starlette.responses import PlainTextResponse
        return PlainTextResponse("prometheus not installed", status_code=501)

    from starlette.responses import Response

    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
    else:
        registry = prometheus_client.REGISTRY  # default includes process/platform collectors

    data = generate_latest(registry)
    return Response(content=data, media_type="text/plain; version=0.0.4; charset=utf-8")

# ----------------------------- FastAPI app factory ----------------------------
def create_app(settings: Optional_Settings = None):
    """
    FastAPI/Starlette application factory with health/metrics and middlewares.
    """
    settings = settings or load_settings()
    setup_tracing(settings)
    setup_prometheus(settings)

    # Lazy imports to keep optional deps optional
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.middleware.gzip import GZipMiddleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    from starlette.responses import JSONResponse

    # Our HTTP logging middleware (from project module). Fallback: skip if absent.
    try:
        from neuroforge.api.http.middleware.logging import (
            RequestLoggingMiddleware,
            configure_default_http_logger,
        )
        configure_default_http_logger(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
        use_http_logging = True
    except Exception:
        logging.getLogger(__name__).warning("http.logging.middleware.missing")
        use_http_logging = False

    app = FastAPI(title=settings.APP_NAME, version=os.getenv("APP_VERSION", "0.0.0"))

    # Trust hosts
    hosts = [h.strip() for h in (settings.ALLOWED_HOSTS or "*").split(",") if h.strip()]
    if hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    # CORS
    origins = [o.strip() for o in (settings.CORS_ORIGINS or "").split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["*"],
            allow_credentials=True,
        )

    # GZip
    if settings.ENABLE_GZIP:
        app.add_middleware(GZipMiddleware, minimum_size=1024)

    # Logging
    if use_http_logging:
        app.add_middleware(
            RequestLoggingMiddleware,
            service=settings.APP_NAME,
            environment=settings.ENVIRONMENT,
            success_sample_rate=float(os.getenv("HTTP_LOG_SAMPLE_SUCCESS", "1.0")),
            error_sample_rate=float(os.getenv("HTTP_LOG_SAMPLE_ERROR", "1.0")),
        )

    # Attach DB/session
    app.state.settings = settings
    app.state.db = setup_db(settings.POSTGRES_DSN)

    # Health endpoints
    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"status": "ok", "name": settings.APP_NAME, "env": settings.ENVIRONMENT}

    @app.get("/ready", tags=["ops"])
    def ready():
        db_ok, db_reason = (True, "disabled") if app.state.db is None else check_db_connection(app.state.db)
        redis_ok, redis_reason = check_redis_connection(settings.REDIS_DSN)

        # Optional: check migrations table existence/version
        mig_ok, mig_reason = True, "skipped"
        if settings.READINESS_CHECK_MIGRATIONS and app.state.db is not None:
            try:
                from sqlalchemy import text
                with app.state.db.engine.connect() as conn:
                    # Alembic default table name
                    conn.execute(text("SELECT 1 FROM alembic_version"))
                mig_ok = True
                mig_reason = "ok"
            except Exception as e:
                mig_ok, mig_reason = False, str(e)

        status_code = 200 if (db_ok and redis_ok and mig_ok) else 503
        return JSONResponse(
            {
                "status": "ok" if status_code == 200 else "degraded",
                "checks": {
                    "db": {"ok": db_ok, "reason": db_reason},
                    "redis": {"ok": redis_ok, "reason": redis_reason},
                    "migrations": {"ok": mig_ok, "reason": mig_reason},
                },
            },
            status_code=status_code,
        )

    # Metrics
    if settings.ENABLE_METRICS:
        app.add_api_route(settings.METRICS_ROUTE, prometheus_endpoint, include_in_schema=False, methods=["GET"])

    # OpenTelemetry FastAPI auto-instrumentation (if available)
    if globals().get("_OTEL_FASTAPI_READY", False):
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)
        except Exception as e:
            logging.getLogger(__name__).warning("otel.fastapi.instrumentation_failed", extra={"reason": str(e)})

    # Dependency for DB usage in routes (sync SQLAlchemy)
    def get_db_dep():
        if app.state.db is None:
            return None
        return app.state.db.SessionLocal()

    app.state.db_session = get_db_dep  # used by routers via lambda

    # Graceful shutdown
    @app.on_event("shutdown")
    def _shutdown():
        try:
            if app.state.db is not None:
                app.state.db.engine.dispose()
        except Exception:
            pass

    return app

# ----------------------------- Celery factory (optional) ----------------------
def create_celery(settings: Optional_Settings = None):
    settings = settings or load_settings()
    if not settings.CELERY_ENABLED:
        return None
    try:
        from celery import Celery
    except Exception:
        logging.getLogger(__name__).warning("celery.not_installed")
        return None

    celery = Celery(settings.APP_NAME)
    celery.conf.update(
        broker_url=settings.CELERY_BROKER_URL,
        result_backend=settings.CELERY_RESULT_BACKEND,
        task_default_queue=settings.CELERY_TASK_DEFAULT_QUEUE,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone=settings.TZ,
        enable_utc=True,
        task_routes={
            "neuroforge.worker.*": {"queue": settings.CELERY_TASK_DEFAULT_QUEUE},
        },
    )

    # Attach settings for tasks to use
    celery.conf.NEUROFORGE_SETTINGS = settings

    # Graceful shutdown tuning
    def _install_signals():
        def _term_handler(signum, frame):
            logging.getLogger(__name__).info("celery.worker.term")
        signal.signal(signal.SIGTERM, _term_handler)
    try:
        _install_signals()
    except Exception:
        pass

    return celery

# ----------------------------- CLI helpers ------------------------------------
def _run_uvicorn(app, settings: Settings):
    try:
        import uvicorn
    except Exception:
        raise RuntimeError("uvicorn is required to run API server")
    uvicorn.run(
        app,
        host=settings.HTTP_HOST,
        port=settings.HTTP_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        proxy_headers=True,
        forwarded_allow_ips="*",
        server_header=False,
        date_header=True,
    )

def _cmd_api(args):
    s = load_settings()
    configure_logging(s.LOG_LEVEL)
    app = create_app(s)
    _run_uvicorn(app, s)

def _cmd_check(args):
    s = load_settings()
    configure_logging(s.LOG_LEVEL)
    out: Dict[str, Any] = {"app": s.APP_NAME, "env": s.ENVIRONMENT}

    db = setup_db(s.POSTGRES_DSN)
    db_ok, db_reason = (True, "disabled") if db is None else check_db_connection(db)
    redis_ok, redis_reason = check_redis_connection(s.REDIS_DSN)
    out["db"] = {"ok": db_ok, "reason": db_reason}
    out["redis"] = {"ok": redis_ok, "reason": redis_reason}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    sys.exit(0 if (db_ok and redis_ok) else 1)

def _cmd_print_config(args):
    s = load_settings()
    # Avoid printing secrets fully
    d = s.model_dump()
    for k in list(d.keys()):
        if "PASSWORD" in k or "SECRET" in k or "TOKEN" in k:
            d[k] = "*****"
    print(json.dumps(d, ensure_ascii=False, indent=2))

def main():
    parser = argparse.ArgumentParser(prog="neuroforge-bootstrap", description="Neuroforge Core bootstrap utilities")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_api = sub.add_parser("api", help="Run API server (uvicorn)")
    p_api.set_defaults(func=_cmd_api)

    p_check = sub.add_parser("check", help="Run readiness checks for DB/Redis")
    p_check.set_defaults(func=_cmd_check)

    p_cfg = sub.add_parser("print-config", help="Print effective config")
    p_cfg.set_defaults(func=_cmd_print_config)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
