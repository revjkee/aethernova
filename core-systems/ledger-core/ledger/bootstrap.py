# -*- coding: utf-8 -*-
"""
ledger.bootstrap — промышленный бутстрап ядра Ledger.

Возможности:
- Загрузка конфигурации (Pydantic Settings + .env).
- Логирование: загрузка YAML (ops/configs/logging.yaml) + dictConfig, ENV‑подстановки.
- Чтение версии из ./VERSION и прокидывание в конфиг/логирование.
- БД: SQLAlchemy AsyncEngine (asyncpg), пулы, health‑пробы, ping на старте.
- Миграции: Alembic (по флагу APPLY_MIGRATIONS=true).
- Наблюдаемость: OpenTelemetry (трейсы/метрики/логи) — опционально; Sentry — опционально.
- DI‑контейнер простого вида (dict) с ресурсами (engine, sessionmaker, settings, version и др.).
- Грейсфул: SIGTERM/SIGINT, тайм‑ауты закрытия, отмена фоновых задач.
- Утилиты для интеграции с FastAPI/ASGI (health/metrics/версия).

Зависимости (минимум):
    pydantic>=2, pyyaml, SQLAlchemy>=2.0, asyncpg, alembic, httpx, opentelemetry-sdk (опц.), sentry-sdk (опц.)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import logging.config
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text

# Alembic — опционально, запускаем по флагу
with contextlib.suppress(ImportError):
    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig

# OTel — опционально
with contextlib.suppress(ImportError):
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Sentry — опционально
with contextlib.suppress(ImportError):
    import sentry_sdk


# ============================ Конфигурация ============================

class DatabaseSettings(BaseModel):
    url: str = Field(..., description="postgresql+asyncpg://user:pass@host:5432/db")
    pool_size: int = Field(default=10, ge=1, le=100)
    max_overflow: int = Field(default=10, ge=0, le=100)
    pool_timeout_s: int = Field(default=10, ge=1, le=60)
    connect_timeout_s: int = Field(default=5, ge=1, le=30)
    statement_timeout_ms: int = Field(default=0, ge=0)

class TelemetrySettings(BaseModel):
    otlp_enabled: bool = Field(default=False)
    otlp_endpoint: str = Field(default="http://otel-collector:4318")
    service_name: str = Field(default="ledger-core")
    environment: str = Field(default="staging")

class SentrySettings(BaseModel):
    enabled: bool = Field(default=False)
    dsn: str = Field(default="")
    traces_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)

class BootstrapSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LEDGER_", env_file=".env", extra="ignore")

    # Общие
    app_env: str = Field(default=os.getenv("APP_ENV", "staging"))
    version_file: str = Field(default=str(Path(__file__).resolve().parents[1] / "VERSION"))
    logging_yaml: str = Field(default=str(Path(__file__).resolve().parents[2] / "ops" / "configs" / "logging.yaml"))
    apply_migrations: bool = Field(default=bool(os.getenv("APPLY_MIGRATIONS", "false").lower() == "true"))
    graceful_shutdown_timeout_s: int = Field(default=20, ge=5, le=120)

    # БД/Телеметрия/Ошибки
    db: DatabaseSettings
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    sentry: SentrySettings = Field(default_factory=SentrySettings)


# ============================ Утилиты ============================

def _read_version(version_file: str) -> str:
    try:
        return Path(version_file).read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0+unknown"

def _env_expand(obj: Any) -> Any:
    """
    Рекурсивная подстановка ENV в YAML через синтаксис ${VAR:-default}.
    """
    import re, os as _os
    var_re = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*) (?::-(.*?))?\}", re.X)

    def _subst(s: str) -> str:
        def rep(m):
            k = m.group(1)
            d = m.group(2) if m.group(2) is not None else ""
            return _os.getenv(k, d)
        return var_re.sub(rep, s)

    if isinstance(obj, str):
        return _subst(obj)
    if isinstance(obj, dict):
        return {k: _env_expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_env_expand(v) for v in obj]
    return obj

def _setup_logging(logging_yaml_path: str, version: str, app_env: str) -> None:
    if not Path(logging_yaml_path).exists():
        logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        logging.getLogger(__name__).warning("logging.yaml not found at %s, using basicConfig", logging_yaml_path)
        return
    data = yaml.safe_load(Path(logging_yaml_path).read_text(encoding="utf-8"))
    data = _env_expand(data)
    # Впрыснем базовые переменные
    os.environ.setdefault("APP_VERSION", version)
    os.environ.setdefault("APP_ENV", app_env)
    # Дополнительно разрешим dictConfig при схеме 'schema_version: 1'
    # Предполагаем адаптер, который понимает 'sinks/routes'; иначе fallback на консоль настроен выше.
    # Если в вашем проекте используется собственный загрузчик, подключите его здесь.
    # Здесь — консервативный вариант: переводим минимальную часть в logging.config.dictConfig при наличии ключа 'python_logging'.
    pylog = data.get("python_logging")
    if isinstance(pylog, dict):
        logging.config.dictConfig(pylog)
    else:
        # У многих проекты используют собственный адаптер; на всякий случай включим INFO.
        logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

def _init_sentry(s: SentrySettings, version: str, environment: str) -> None:
    if not s.enabled:
        return
    if "sentry_sdk" not in sys.modules:
        logging.getLogger(__name__).warning("sentry-sdk not installed; skip Sentry init")
        return
    sentry_sdk.init(
        dsn=s.dsn,
        traces_sample_rate=s.traces_sample_rate,
        release=version,
        environment=environment,
        send_default_pii=False,
        attach_stacktrace=True,
    )

def _init_otel(t: TelemetrySettings, version: str) -> Optional[TracerProvider]:
    if not t.otlp_enabled or "opentelemetry" not in sys.modules:
        return None
    resource = Resource.create(
        {
            "service.name": t.service_name,
            "service.version": version,
            "deployment.environment": t.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=f"{t.otlp_endpoint}/v1/traces", timeout=3)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    return provider

async def _db_ping(engine: AsyncEngine, timeout: int = 5) -> None:
    async with asyncio.timeout(timeout):
        async with engine.connect() as conn:
            # Применяем statement_timeout на сессию, если конфиг > 0
            await conn.execute(text("SELECT 1;"))

def _alembic_apply_if_needed(settings: BootstrapSettings) -> None:
    if not settings.apply_migrations:
        logging.getLogger(__name__).info("migrations: skipped (APPLY_MIGRATIONS=false)")
        return
    if "alembic" not in sys.modules:
        logging.getLogger(__name__).warning("alembic not installed; cannot run migrations")
        return
    # Ищем alembic.ini рядом с репозиторием (настройте путь при иной структуре)
    proj_root = Path(__file__).resolve().parents[2]  # ledger-core/
    ini_path = proj_root / "alembic.ini"
    if not ini_path.exists():
        logging.getLogger(__name__).warning("alembic.ini not found at %s; skip migrations", ini_path)
        return
    cfg = AlembicConfig(str(ini_path))
    # Передадим URL через переменную окружения или alembic.ini (sqlalchemy.url = ...)
    os.environ.setdefault("SQLALCHEMY_URL", settings.db.url.replace("+asyncpg", ""))
    logging.getLogger(__name__).info("migrations: applying (alembic upgrade head)")
    alembic_command.upgrade(cfg, "head")


# ============================ Ресурсы приложения ============================

@dataclass
class AppResources:
    settings: BootstrapSettings
    version: str
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    tracer_provider: Optional[Any] = None

    async def health(self) -> Dict[str, Any]:
        ok = True
        errs: Dict[str, str] = {}
        # DB probe
        try:
            await _db_ping(self.engine, timeout=3)
        except Exception as e:
            ok = False
            errs["db"] = str(e)
        return {
            "status": "ok" if ok else "degraded",
            "version": self.version,
            "env": self.settings.app_env,
            "errors": errs,
            "ts": int(time.time()),
        }


class Bootstrap:
    """
    Async‑контекст: создает и держит ресурсы; гарантирует корректный shutdown.
    Использование:
        async with Bootstrap.create() as app:
            # app.resources.engine, app.resources.session_factory ...
    """
    def __init__(self, resources: AppResources, shutdown_timeout: int = 20):
        self.resources = resources
        self._shutdown_timeout = shutdown_timeout
        self._bg_tasks: set[asyncio.Task] = set()
        self._signals_bound = False
        self._log = logging.getLogger(__name__)

    # ---------- фабрика ----------
    @classmethod
    async def create(cls, settings: Optional[BootstrapSettings] = None) -> "Bootstrap":
        settings = settings or BootstrapSettings()
        version = _read_version(settings.version_file)

        _setup_logging(settings.logging_yaml, version, settings.app_env)
        _init_sentry(settings.sentry, version, settings.app_env)
        tracer_provider = _init_otel(settings.telemetry, version)

        # Async DB engine
        connect_args = {}
        if settings.db.statement_timeout_ms > 0:
            # Настроим statement_timeout на уровне параметров подключения
            connect_args["server_settings"] = {
                "statement_timeout": str(settings.db.statement_timeout_ms)
            }

        engine = create_async_engine(
            settings.db.url,
            pool_size=settings.db.pool_size,
            max_overflow=settings.db.max_overflow,
            pool_timeout=settings.db.pool_timeout_s,
            connect_args=connect_args,
        )
        session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        # Миграции (синхронно; Alembic использует блокирующие соединения)
        await asyncio.to_thread(_alembic_apply_if_needed, settings)

        # Health‑ping к БД
        await _db_ping(engine, timeout=settings.db.connect_timeout_s)

        res = AppResources(
            settings=settings,
            version=version,
            engine=engine,
            session_factory=session_factory,
            tracer_provider=tracer_provider,
        )
        bs = cls(resources=res, shutdown_timeout=settings.graceful_shutdown_timeout_s)
        bs._bind_signals()
        return bs

    # ---------- жизненный цикл ----------
    def _bind_signals(self) -> None:
        if self._signals_bound:
            return
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.shutdown(reason=f"signal:{s.name}")))
        self._signals_bound = True

    async def __aenter__(self) -> "Bootstrap":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.shutdown(reason="context-exit")

    async def shutdown(self, reason: str = "manual") -> None:
        self._log.info("shutdown: start reason=%s", reason)
        # Остановим фоновые задачи
        for t in list(self._bg_tasks):
            t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)

        # Закрытие БД
        try:
            await self.resources.engine.dispose()
        except Exception as e:
            self._log.warning("shutdown: engine.dispose failed: %s", e)

        # Отключение OTel
        if self.resources.tracer_provider:
            with contextlib.suppress(Exception):
                self.resources.tracer_provider.shutdown()

        self._log.info("shutdown: complete")

    # ---------- вспомогательные ----------
    def spawn_bg(self, coro: asyncio.coroutine) -> None:
        t = asyncio.create_task(coro)
        self._bg_tasks.add(t)
        t.add_done_callback(lambda fut: self._bg_tasks.discard(t))


# ============================ Интеграция с FastAPI/ASGI (опционально) ============================

def wire_fastapi(app, bootstrap: Bootstrap) -> None:
    """
    Подключает базовые health/version и передает ресурсы в app.state.
    """
    from fastapi import APIRouter
    router = APIRouter()

    @router.get("/health")
    async def health():
        return await bootstrap.resources.health()

    @router.get("/version")
    async def version():
        return {
            "version": bootstrap.resources.version,
            "env": bootstrap.resources.settings.app_env,
        }

    app.state.bootstrap = bootstrap
    app.state.settings = bootstrap.resources.settings
    app.state.db_session_factory = bootstrap.resources.session_factory
    app.include_router(router)


# ============================ Фабрика для внешнего кода ============================

async def create_app_resources(settings: Optional[BootstrapSettings] = None) -> Bootstrap:
    """
    Внешняя фабрика: подготовит Bootstrap c AppResources.
    Пример использования в HTTP‑стартере:
        bootstrap = await create_app_resources()
        app = FastAPI(...)
        wire_fastapi(app, bootstrap)
    """
    return await Bootstrap.create(settings=settings)
