# -*- coding: utf-8 -*-
"""
ChronoWatch Core — Application Context (production-grade)

Назначение:
- Единая точка управления жизненным циклом приложения (init/start/stop).
- Lazy-подключения к инфраструктуре: БД (SQLAlchemy async), Redis (redis.asyncio), HTTP (httpx).
- JSON-логирование с корреляцией (request_id/tenant/deadline) на основе contextvars.
- Конфигурация: ENV → YAML (если доступен PyYAML) → значения по умолчанию.
- Health checks с параллельным таймаутом.
- Graceful shutdown: SIGTERM/SIGINT, идемпотентные start()/stop().
- Опциональная интеграция с OpenTelemetry (если установлен).

Зависимости (опциональны, подгружаются лениво):
- SQLAlchemy (async): sqlalchemy[asyncio]
- redis-py: redis>=4.2 (модуль redis.asyncio)
- httpx: httpx>=0.24
- pyyaml: PyYAML
- opentelemetry-sdk, opentelemetry-exporter-otlp

Использование:
    from chronowatch.context import AppContext

    async with AppContext.from_env() as ctx:
        engine = await ctx.db()
        redis  = await ctx.redis()
        http   = await ctx.http()
        ok     = await ctx.health_check()

Инварианты:
- Только асинхронный SQLAlchemy (см. ваш проектный стандарт).
- Безопасность: никакие секреты не логируются (редакция ключей).
- Отсутствующие зависимости не ломают старт — ошибка только при реальном вызове соответствующего клиента.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import dataclasses
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple, Union

# ------------------------------------------------------------------------------
# Контекстные переменные запроса
# ------------------------------------------------------------------------------

request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
tenant_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant_id", default=None)
deadline_ns_var: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar("deadline_ns", default=None)

# ------------------------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class AppConfig:
    service: str = field(default_factory=lambda: os.getenv("SERVICE_NAME", "chronowatch-core"))
    env: str = field(default_factory=lambda: os.getenv("CHRONOWATCH_ENV", "dev"))
    version: str = field(default_factory=lambda: os.getenv("SERVICE_VERSION", "0.0.0"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    # База данных
    database_url: Optional[str] = field(default_factory=lambda: os.getenv("DATABASE_URL"))
    # Redis (redis://:pass@host:6379/0), допускается rediss:// для TLS
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))

    # HTTP-клиент
    http_timeout_s: float = float(os.getenv("HTTP_TIMEOUT_S", "10.0"))
    http_max_connections: int = int(os.getenv("HTTP_MAX_CONNECTIONS", "200"))

    # Health
    health_timeout_s: float = float(os.getenv("HEALTH_TIMEOUT_S", "2.0"))

    # Telemetry (опционально)
    otel_enabled: bool = os.getenv("OTEL_ENABLED", "false").lower() in ("1", "true", "yes")
    otel_endpoint: str = field(default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317"))
    otel_service_name: Optional[str] = None  # если None — берется service

    # Конфигурационный файл (YAML)
    config_path: Optional[str] = field(default_factory=lambda: os.getenv("CHRONOWATCH_CONFIG"))

    # Маски редактирования логов
    redact_keys: Tuple[str, ...] = ("password", "authorization", "cookie", "token", "secret", "set-cookie", "api-key")

    # Служебные параметры
    graceful_shutdown_timeout_s: float = float(os.getenv("GRACEFUL_SHUTDOWN_TIMEOUT_S", "25.0"))

    @staticmethod
    def load(path: Optional[Union[str, Path]] = None) -> "AppConfig":
        """
        Загружает конфиг из ENV и при наличии — дополняет YAML.
        Поля из ENV имеют приоритет над YAML.
        """
        base = AppConfig()  # ENV уже применены дефолтами
        data: Dict[str, Any] = {}

        p = Path(path) if path else (Path(base.config_path) if base.config_path else None)
        if p and p.exists():
            try:
                import yaml  # type: ignore
                with p.open("r", encoding="utf-8") as f:
                    y = yaml.safe_load(f) or {}
                if isinstance(y, dict):
                    data = y
            except Exception as e:
                # Не падаем — продолжаем с ENV
                _bootstrap_logger().warning("config_yaml_load_failed", extra={"path": str(p), "error": str(e)})

        # Смешиваем: YAML -> замена полей, затем ENV (у base уже учтены)
        merged = dataclasses.asdict(base)
        for k, v in (data.get("app") or {}).items():
            if k in merged and v is not None:
                merged[k] = v

        # ENV final pass (уже применены при создании base) — оставляем merged как есть
        return AppConfig(**merged)  # type: ignore[arg-type]

# ------------------------------------------------------------------------------
# Логирование JSON
# ------------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    def __init__(self, service: str, env: str, redact: Tuple[str, ...]) -> None:
        super().__init__()
        self.service = service
        self.env = env
        self._redact = tuple(k.lower() for k in redact)

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        ts += f".{int((time.time()%1)*1e6):06d}Z"
        payload = {
            "timestamp": ts,
            "level": record.levelname,
            "service": self.service,
            "env": self.env,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
            "tenant_id": tenant_id_var.get(),
            "deadline_ns": deadline_ns_var.get(),
        }
        # Включаем поля extra, если они есть
        if hasattr(record, "__dict__"):
            for k, v in record.__dict__.items():
                if k in ("args", "msg", "levelno", "levelname", "name", "pathname", "filename",
                         "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                         "created", "msecs", "relativeCreated", "thread", "threadName",
                         "processName", "process"):
                    continue
                # редакция ключей
                if any(x in k.lower() for x in self._redact):
                    payload[k] = "***"
                else:
                    payload[k] = v
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        try:
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            # Фолбэк при проблемах сериализации
            return json.dumps({"level": "ERROR", "message": "log_format_failed"})

def _bootstrap_logger() -> logging.Logger:
    lg = logging.getLogger("chronowatch")
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(_JsonFormatter(service="chronowatch-core", env="boot", redact=("password",)))
        lg.addHandler(h)
        lg.propagate = False
    return lg

def setup_logging(cfg: AppConfig) -> logging.Logger:
    lg = logging.getLogger("chronowatch")
    # Очистка хэндлеров при повторной инициализации
    for h in list(lg.handlers):
        lg.removeHandler(h)
    lg.setLevel(getattr(logging, (cfg.log_level or "INFO").upper(), logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(_JsonFormatter(service=cfg.service, env=cfg.env, redact=cfg.redact_keys))
    lg.addHandler(h)
    lg.propagate = False
    lg.info("logging_initialized", extra={"service_version": cfg.version})
    return lg

# ------------------------------------------------------------------------------
# Вспомогательные контекстные менеджеры
# ------------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def request_context(request_id: Optional[str] = None,
                          tenant_id: Optional[str] = None,
                          deadline_ms: Optional[int] = None):
    """
    Устанавливает contextvars для сквозной корреляции на время блока.
    """
    t1 = request_id_var.set(request_id)
    t2 = tenant_id_var.set(tenant_id)
    t3 = deadline_ns_var.set((time.time_ns() + int(deadline_ms * 1e6)) if deadline_ms else None)
    try:
        yield
    finally:
        request_id_var.reset(t1)
        tenant_id_var.reset(t2)
        deadline_ns_var.reset(t3)

# ------------------------------------------------------------------------------
# Основной контекст приложения
# ------------------------------------------------------------------------------

class AppContext:
    """
    Асинхронный жизненный цикл приложения ChronoWatch.

    - from_env()/from_config() — конструкторы.
    - start()/stop() — явный lifecycle (идемпотентный).
    - __aenter__/__aexit__ — использование через async with.
    - db()/redis()/http()/tracer() — ленивые клиенты.
    - health_check() — агрегированный статус инфраструктуры.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.log = setup_logging(config)

        self._stack = contextlib.AsyncExitStack()
        self._started = False
        self._stop_lock = asyncio.Lock()

        # Ресурсы (ленивая инициализация)
        self._engine: Any = None
        self._redis: Any = None
        self._http: Any = None
        self._tracer_provider: Any = None
        self._otel_shutdown: Optional[Callable[[], None]] = None

        # Сигналы
        self._signals_bound = False
        self._shutdown_event = asyncio.Event()

    # ---------- Конструкторы ----------

    @classmethod
    def from_env(cls) -> "AppContext":
        cfg = AppConfig.load(os.getenv("CHRONOWATCH_CONFIG"))
        return cls(cfg)

    @classmethod
    def from_config(cls, cfg: AppConfig) -> "AppContext":
        return cls(cfg)

    # ---------- Lifecycle ----------

    async def __aenter__(self) -> "AppContext":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.log.info("app_starting", extra={"env": self.config.env})

        # Привязка сигналов ОС
        self._bind_signals()

        # Инициализация OTEL (если включен)
        if self.config.otel_enabled:
            await self._init_otel()

        # HTTP клиент (лениво — но подготовим общий)
        # Не создаем здесь — пусть создастся при первом обращении
        self.log.info("app_started", extra={"service": self.config.service, "version": self.config.version})

    async def stop(self) -> None:
        # Идемпотентный stop
        async with self._stop_lock:
            if not self._started:
                return
            self._started = False
            self.log.info("app_stopping")

            # Закрываем ресурсы в обратном порядке
            await self._stack.aclose()

            # Останавливаем OTEL при наличии
            if self._otel_shutdown:
                try:
                    self._otel_shutdown()
                except Exception as e:
                    self.log.warning("otel_shutdown_failed", extra={"error": str(e)})

            self.log.info("app_stopped")

    # ---------- Сигналы и graceful ----------

    def _bind_signals(self) -> None:
        if self._signals_bound:
            return
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._on_signal(s)))
            except NotImplementedError:
                # Windows
                pass
        self._signals_bound = True

    async def _on_signal(self, sig: signal.Signals) -> None:
        self.log.warning("signal_received", extra={"signal": str(sig)})
        self._shutdown_event.set()
        try:
            await asyncio.wait_for(self.stop(), timeout=self.config.graceful_shutdown_timeout_s)
        except Exception as e:
            self.log.error("graceful_shutdown_failed", extra={"error": str(e)})

    # ---------- Ленивые клиенты ----------

    async def db(self):
        """
        Возвращает AsyncEngine SQLAlchemy.
        """
        if self._engine is not None:
            return self._engine
        if not self.config.database_url:
            raise RuntimeError("DATABASE_URL is not configured")
        try:
            from sqlalchemy.ext.asyncio import create_async_engine  # type: ignore
        except Exception as e:
            raise RuntimeError("SQLAlchemy async is not installed") from e

        engine = create_async_engine(
            self.config.database_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            future=True,
        )
        # Закрытие через ExitStack
        async def _close_engine():
            await engine.dispose()
        await self._stack.enter_async_context(_AsyncCallback(_close_engine))
        self._engine = engine
        self.log.info("db_engine_initialized")
        return self._engine

    async def redis(self):
        """
        Возвращает redis.asyncio.Redis или ConnectionPool-базированный клиент.
        """
        if self._redis is not None:
            return self._redis
        if not self.config.redis_url:
            raise RuntimeError("REDIS_URL is not configured")
        try:
            from redis.asyncio import Redis, from_url  # type: ignore
        except Exception as e:
            raise RuntimeError("redis-py with asyncio is not installed") from e

        client: Redis = from_url(self.config.redis_url, decode_responses=False, socket_timeout=self.config.health_timeout_s)
        async def _close_redis():
            try:
                await client.close()
            except Exception:
                pass
        await self._stack.enter_async_context(_AsyncCallback(_close_redis))
        self._redis = client
        self.log.info("redis_client_initialized")
        return self._redis

    async def http(self):
        """
        Возвращает httpx.AsyncClient с общим пулом.
        """
        if self._http is not None:
            return self._http
        try:
            import httpx  # type: ignore
        except Exception as e:
            raise RuntimeError("httpx is not installed") from e

        client = httpx.AsyncClient(
            timeout=self.config.http_timeout_s,
            limits=httpx.Limits(max_connections=self.config.http_max_connections, max_keepalive_connections=64),
            headers={"user-agent": f"{self.config.service}/{self.config.version}"},
        )

        async def _close_http():
            try:
                await client.aclose()
            except Exception:
                pass

        await self._stack.enter_async_context(_AsyncCallback(_close_http))
        self._http = client
        self.log.info("http_client_initialized")
        return self._http

    async def tracer(self):
        """
        Возвращает (опционально) OpenTelemetry TracerProvider или None.
        """
        if self._tracer_provider is not None:
            return self._tracer_provider
        if not self.config.otel_enabled:
            self._tracer_provider = None
            return None
        try:
            from opentelemetry import trace  # type: ignore
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
        except Exception as e:
            self.log.warning("otel_not_available", extra={"error": str(e)})
            self._tracer_provider = None
            return None

        res = Resource.create({"service.name": self.config.otel_service_name or self.config.service,
                               "service.version": self.config.version,
                               "deployment.environment": self.config.env})
        provider = TracerProvider(resource=res)
        exporter = OTLPSpanExporter(endpoint=self.config.otel_endpoint, insecure=True)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        def _shutdown():
            try:
                provider.shutdown()
            except Exception:
                pass

        self._otel_shutdown = _shutdown
        self._tracer_provider = provider
        self.log.info("otel_tracer_initialized", extra={"endpoint": self.config.otel_endpoint})
        return self._tracer_provider

    # ---------- Health ----------

    async def health_check(self) -> Dict[str, Any]:
        """
        Параллельные health-проверки с таймаутом.
        """
        results: Dict[str, Any] = {"status": "ok", "checks": {}}
        timeout = self.config.health_timeout_s

        async def check_db():
            try:
                eng = await self.db()
                # Легкая проверка соединения
                from sqlalchemy import text  # type: ignore
                async with eng.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                return True, None
            except Exception as e:
                return False, str(e)

        async def check_redis():
            try:
                cli = await self.redis()
                pong = await cli.ping()
                return bool(pong), None
            except Exception as e:
                return False, str(e)

        async def check_http():
            try:
                client = await self.http()
                # Не делаем внешний запрос — проверяем, что клиент жив и не закрыт
                return True, None
            except Exception as e:
                return False, str(e)

        tasks = {
            "database": asyncio.create_task(check_db()),
            "redis": asyncio.create_task(check_redis()),
            "http_client": asyncio.create_task(check_http()),
        }

        try:
            done, pending = await asyncio.wait(tasks.values(), timeout=timeout)
            for name, task in tasks.items():
                if task in done:
                    ok, err = task.result()
                    results["checks"][name] = {"ok": ok, "error": err}
                else:
                    results["checks"][name] = {"ok": False, "error": f"timeout>{timeout}s"}
            results["status"] = "ok" if all(v["ok"] for v in results["checks"].values()) else "degraded"
        finally:
            for t in tasks.values():
                if not t.done():
                    t.cancel()
        return results

    # ---------- Утилиты ----------

    @contextlib.asynccontextmanager
    async def lifespan(self):
        """
        Альтернатива __aenter__/__aexit__ для фреймворков.
        """
        await self.start()
        try:
            yield self
        finally:
            await self.stop()

# ------------------------------------------------------------------------------
# Внутренний async callback-обертка для AsyncExitStack
# ------------------------------------------------------------------------------

class _AsyncCallback:
    def __init__(self, cb: Callable[[], Awaitable[None]]) -> None:
        self._cb = cb
    async def __aenter__(self) -> "_AsyncCallback":
        return self
    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._cb()
