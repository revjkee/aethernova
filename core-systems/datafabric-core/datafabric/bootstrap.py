# datafabric-core/datafabric/bootstrap.py
"""
Bootstrap ядра DataFabric.

Назначение:
- Единая инициализация инфраструктуры: конфиг, логирование, метрики, трассировка, БД, кэш, брокеры.
- Чёткий жизненный цикл: init -> start -> run/await -> stop -> close.
- Безопасное завершение (graceful shutdown) и health-пробы.
- Минимум обязательных зависимостей, опциональные модули подключаются по факту.

Интеграция (пример):
    from datafabric.bootstrap import Bootstrap

    async def main():
        async with Bootstrap.auto() as app:
            # регистрируем роутеры/воркеры, получаем ресурсы:
            engine = app.resources.db
            redis  = app.resources.redis
            # ...
            await app.run_until_stopped()

Стандарты:
- Конфиг из env + .env (если есть), строгая валидация.
- Структурные JSON-логи (STDOUT) + корелляция trace_id/span_id при наличии OTel.
- Prometheus metrics HTTP (если включено), OpenTelemetry (если включено).
- Ресурсы создаются лениво и закрываются надёжно.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
import sys
import time
import typing as t
from dataclasses import dataclass, field
from ipaddress import ip_address

# -----------------------------
# Конфигурация (pydantic без жёсткой привязки к v2)
# -----------------------------
try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception:  # pragma: no cover
    raise RuntimeError("pydantic is required for bootstrap")

# -----------------------------
# Утилиты логирования
# -----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        # Вытянем trace_id/span_id, если OTel лог-хэндлеры положили их в record
        for key in ("otelTraceID", "otelSpanID"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    # Очистим хэндлеры, чтобы избежать дублирования при повторной инициализации
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


# -----------------------------
# Ядро настроек
# -----------------------------

def _env(key: str, default: t.Optional[str] = None) -> t.Optional[str]:
    v = os.getenv(key, default)
    return v if (v is not None and str(v).strip() != "") else default

class Settings(BaseModel):
    # Общие
    APP_NAME: str = Field(default="datafabric-core")
    ENV: str = Field(default="dev")  # dev|staging|prod
    LOG_LEVEL: str = Field(default="INFO")
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)

    # Метрики/трассировка
    METRICS_ENABLED: bool = Field(default=True)
    METRICS_PORT: int = Field(default=9000)
    OTEL_ENABLED: bool = Field(default=False)
    OTEL_EXPORTER_OTLP_ENDPOINT: t.Optional[str] = Field(default=None)
    OTEL_SERVICE_NAME: t.Optional[str] = Field(default=None)

    # БД/кэш
    POSTGRES_DSN: t.Optional[str] = Field(default=None)  # example: postgresql+asyncpg://user:pass@host:5432/db
    REDIS_DSN: t.Optional[str] = Field(default=None)     # example: redis://localhost:6379/0

    # Брокеры (опционально)
    NATS_URL: t.Optional[str] = Field(default=None)      # nats://localhost:4222
    KAFKA_BOOTSTRAP: t.Optional[str] = Field(default=None)  # host1:9092,host2:9092

    # Фичи/лимиты
    FEATURE_FLAGS: dict = Field(default_factory=dict)
    STARTUP_TIMEOUT_SEC: int = Field(default=30)
    SHUTDOWN_TIMEOUT_SEC: int = Field(default=30)

    @field_validator("HOST")
    @classmethod
    def validate_host(cls, v: str) -> str:
        try:
            ip_address(v)  # позволит 0.0.0.0, 127.0.0.1, :: и т.п.
            return v
        except Exception:
            # допускаем DNS-имя
            try:
                socket.getaddrinfo(v, None)
            except Exception as ex:
                raise ValueError(f"Invalid HOST '{v}': {ex}") from ex
            return v

    @classmethod
    def load(cls) -> "Settings":
        # Поддержка .env при наличии python-dotenv
        dotenv_loaded = False
        if os.path.exists(".env"):
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
                dotenv_loaded = True
            except Exception:
                pass
        # Собираем словарь с приоритетом env
        data = {
            "APP_NAME": _env("APP_NAME", "datafabric-core"),
            "ENV": _env("ENV", "dev"),
            "LOG_LEVEL": _env("LOG_LEVEL", "INFO"),
            "HOST": _env("HOST", "0.0.0.0"),
            "PORT": int(_env("PORT", "8000")),
            "METRICS_ENABLED": _env("METRICS_ENABLED", "true").lower() == "true",
            "METRICS_PORT": int(_env("METRICS_PORT", "9000")),
            "OTEL_ENABLED": _env("OTEL_ENABLED", "false").lower() == "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": _env("OTEL_EXPORTER_OTLP_ENDPOINT"),
            "OTEL_SERVICE_NAME": _env("OTEL_SERVICE_NAME"),
            "POSTGRES_DSN": _env("POSTGRES_DSN"),
            "REDIS_DSN": _env("REDIS_DSN"),
            "NATS_URL": _env("NATS_URL"),
            "KAFKA_BOOTSTRAP": _env("KAFKA_BOOTSTRAP"),
            "STARTUP_TIMEOUT_SEC": int(_env("STARTUP_TIMEOUT_SEC", "30")),
            "SHUTDOWN_TIMEOUT_SEC": int(_env("SHUTDOWN_TIMEOUT_SEC", "30")),
        }
        # FEATURE_FLAGS можно задать JSON-строкой
        flags_raw = _env("FEATURE_FLAGS")
        if flags_raw:
            try:
                data["FEATURE_FLAGS"] = json.loads(flags_raw)
            except Exception as ex:
                raise ValueError(f"FEATURE_FLAGS must be JSON: {ex}") from ex
        s = cls(**data)
        logging.getLogger(__name__).info(
            "settings_loaded",
            extra={"dotenv": dotenv_loaded, "env": s.ENV},
        )
        return s


# -----------------------------
# Ресурсы (ленивая инициализация)
# -----------------------------

@dataclass
class DBResources:
    engine: t.Any = None  # AsyncEngine
    pool_ready: bool = False

@dataclass
class CacheResources:
    redis: t.Any = None

@dataclass
class BrokerResources:
    nats: t.Any = None
    kafka: t.Any = None

@dataclass
class ObservabilityResources:
    metrics_task: t.Optional[asyncio.Task] = None
    otel_provider: t.Any = None

@dataclass
class AppResources:
    db: DBResources = field(default_factory=DBResources)
    cache: CacheResources = field(default_factory=CacheResources)
    broker: BrokerResources = field(default_factory=BrokerResources)
    obs: ObservabilityResources = field(default_factory=ObservabilityResources)


# -----------------------------
# DI контейнер (простой регистр)
# -----------------------------

class Container(dict):
    """
    Простой DI: контейнер фабрик/синглтонов.
    container["service"] -> объект/фабрика.
    """
    def bind(self, key: str, value: t.Any) -> None:
        self[key] = value

    def get_or(self, key: str, default: t.Any = None) -> t.Any:
        return self.get(key, default)


# -----------------------------
# Health/Ready
# -----------------------------

class HealthState:
    def __init__(self) -> None:
        self._healthy = True
        self._ready = False
        self._errors: list[str] = []

    def set_healthy(self, ok: bool, err: str | None = None) -> None:
        self._healthy = ok
        if err:
            self._errors.append(err)

    def set_ready(self, ok: bool) -> None:
        self._ready = ok

    @property
    def healthy(self) -> bool:
        return self._healthy

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def details(self) -> dict:
        return {"healthy": self._healthy, "ready": self._ready, "errors": self._errors}


# -----------------------------
# Bootstrap
# -----------------------------

class Bootstrap:
    """
    Управляет жизненным циклом приложения и его ресурсами.
    """
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.resources = AppResources()
        self.container = Container()
        self.health = HealthState()

        self._stop = asyncio.Event()
        self._started = False
        self._log = logging.getLogger("datafabric.bootstrap")

    # --------- Фабрики ---------

    async def _init_db(self) -> None:
        if not self.settings.POSTGRES_DSN:
            return
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except Exception as ex:  # pragma: no cover
            raise RuntimeError("sqlalchemy[asyncio] required for DB") from ex

        self.resources.db.engine = create_async_engine(
            self.settings.POSTGRES_DSN,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_timeout=30,
            echo=False,
        )
        # прогрев пула
        try:
            async with self.resources.db.engine.connect() as conn:
                await conn.execute("SELECT 1")
            self.resources.db.pool_ready = True
            self._log.info("db_ready")
        except Exception as ex:
            self.health.set_healthy(False, f"DB init failed: {ex}")
            raise

    async def _init_redis(self) -> None:
        if not self.settings.REDIS_DSN:
            return
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as ex:
            raise RuntimeError("redis-py >= 4 with asyncio is required") from ex

        self.resources.cache.redis = redis.from_url(self.settings.REDIS_DSN, decode_responses=False)
        try:
            pong = await self.resources.cache.redis.ping()
            if pong is True:
                self._log.info("redis_ready")
        except Exception as ex:
            self.health.set_healthy(False, f"Redis init failed: {ex}")
            raise

    async def _init_nats(self) -> None:
        if not self.settings.NATS_URL:
            return
        try:
            import nats  # type: ignore
        except Exception as ex:
            raise RuntimeError("nats-py is required for NATS integration") from ex

        try:
            self.resources.broker.nats = await nats.connect(self.settings.NATS_URL, max_reconnect_attempts=60)
            self._log.info("nats_ready")
        except Exception as ex:
            self.health.set_healthy(False, f"NATS init failed: {ex}")
            raise

    async def _init_kafka(self) -> None:
        if not self.settings.KAFKA_BOOTSTRAP:
            return
        try:
            from aiokafka import AIOKafkaProducer  # type: ignore
        except Exception as ex:
            raise RuntimeError("aiokafka is required for Kafka integration") from ex

        producer = AIOKafkaProducer(bootstrap_servers=self.settings.KAFKA_BOOTSTRAP.split(","))
        try:
            await producer.start()
            self.resources.broker.kafka = producer
            self._log.info("kafka_ready")
        except Exception as ex:
            self.health.set_healthy(False, f"Kafka init failed: {ex}")
            raise

    def _init_metrics(self) -> None:
        if not self.settings.METRICS_ENABLED:
            return
        try:
            from prometheus_client import start_http_server, REGISTRY  # type: ignore
            # Запуск сервера метрик в отдельном потоке не подойдёт для контейнеров с жёстким контролем,
            # поэтому поднимем в asyncio Task через loop.run_in_executor — но Prometheus стартует sync.
            # Для простоты позовём start_http_server, это стандартный путь.
            start_http_server(self.settings.METRICS_PORT)
            self._log.info("metrics_started", extra={"port": self.settings.METRICS_PORT, "collectors": len(list(REGISTRY.collect()))})
        except Exception as ex:
            # Метрики не критичны — логируем предупреждение
            logging.getLogger(__name__).warning("metrics_init_failed: %s", ex)

    def _init_tracing(self) -> None:
        if not self.settings.OTEL_ENABLED:
            return
        try:
            from opentelemetry import trace  # type: ignore
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

            resource = Resource.create({"service.name": self.settings.OTEL_SERVICE_NAME or self.settings.APP_NAME})
            provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=self.settings.OTEL_EXPORTER_OTLP_ENDPOINT or "http://localhost:4318/v1/traces")
            processor = BatchSpanProcessor(exporter)
            provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)
            self.resources.obs.otel_provider = provider
            self._log.info("otel_started", extra={"endpoint": self.settings.OTEL_EXPORTER_OTLP_ENDPOINT})
        except Exception as ex:
            logging.getLogger(__name__).warning("otel_init_failed: %s", ex)

    # --------- Lifecycle ---------

    async def init(self) -> "Bootstrap":
        _setup_logging(self.settings.LOG_LEVEL)
        self._log.info("bootstrap_init", extra={"app": self.settings.APP_NAME, "env": self.settings.ENV})

        # Observability
        self._init_metrics()
        self._init_tracing()

        # Ресурсы
        await asyncio.wait_for(self._init_db(), timeout=self.settings.STARTUP_TIMEOUT_SEC)
        await asyncio.wait_for(self._init_redis(), timeout=self.settings.STARTUP_TIMEOUT_SEC)
        # Брокеры — по необходимости
        if self.settings.NATS_URL:
            await asyncio.wait_for(self._init_nats(), timeout=self.settings.STARTUP_TIMEOUT_SEC)
        if self.settings.KAFKA_BOOTSTRAP:
            await asyncio.wait_for(self._init_kafka(), timeout=self.settings.STARTUP_TIMEOUT_SEC)

        # DI биндинги
        self.container.bind("settings", self.settings)
        self.container.bind("resources", self.resources)
        self.container.bind("health", self.health)

        # Health: инициализировано, готовность позже (после регистрации модулей пользователем)
        self.health.set_ready(False)
        self._started = True
        return self

    async def start(self) -> None:
        if not self._started:
            await self.init()
        # пользователь может здесь навесить фоновые задачи/воркеры
        self.health.set_ready(True)
        self._install_signal_handlers()
        self._log.info("bootstrap_started")

    async def stop(self) -> None:
        self._log.info("bootstrap_stopping")
        # Сначала запретим приём работы
        self.health.set_ready(False)

        # Корректно закрываем брокеры
        with contextlib.suppress(Exception):
            if self.resources.broker.kafka:
                await self.resources.broker.kafka.stop()
                self.resources.broker.kafka = None
        with contextlib.suppress(Exception):
            if self.resources.broker.nats:
                await self.resources.broker.nats.drain()
                await self.resources.broker.nats.close()
                self.resources.broker.nats = None

        # Кэш
        with contextlib.suppress(Exception):
            if self.resources.cache.redis:
                await self.resources.cache.redis.close()
                self.resources.cache.redis = None

        # DB
        with contextlib.suppress(Exception):
            if self.resources.db.engine:
                await self.resources.db.engine.dispose()
                self.resources.db.engine = None

        # OTel
        with contextlib.suppress(Exception):
            if self.resources.obs.otel_provider:
                # Закрываем процессоры экспорта
                self.resources.obs.otel_provider.shutdown()
                self.resources.obs.otel_provider = None

        self._log.info("bootstrap_stopped")

    async def close(self) -> None:
        await asyncio.wait_for(self.stop(), timeout=self.settings.SHUTDOWN_TIMEOUT_SEC)

    # --------- Контекстный менеджер ---------

    async def __aenter__(self) -> "Bootstrap":
        await self.init()
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # --------- Управление сигналами/ожидание ---------

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._on_signal(s)))

    async def _on_signal(self, sig: signal.Signals) -> None:
        self._log.info("signal_received", extra={"signal": int(sig)})
        self._stop.set()

    async def run_until_stopped(self) -> None:
        await self._stop.wait()

    # --------- Утилиты доступа ---------

    @property
    def features(self) -> dict:
        return self.settings.FEATURE_FLAGS

    @classmethod
    async def auto(cls) -> "Bootstrap":
        """
        Упрощённая точка входа: загрузить настройки из окружения, подготовить bootstrap.
        Использование:
            async with Bootstrap.auto() as app:
                ...
        """
        try:
            settings = Settings.load()
        except (ValidationError, ValueError) as ex:
            _setup_logging("ERROR")
            logging.getLogger("datafabric.bootstrap").error("settings_validation_failed: %s", ex)
            raise
        app = cls(settings)
        await app.init()
        await app.start()
        return app


# -----------------------------
# Простейшие тестовые хелс‑хендлеры (без FastAPI, на случай unit-тестов)
# -----------------------------

async def probe_health(bootstrap: Bootstrap) -> dict:
    """
    Вернёт агрегированное состояние для unit-тестов/cli.
    """
    return {
        "app": bootstrap.settings.APP_NAME,
        "env": bootstrap.settings.ENV,
        "state": bootstrap.health.details,
        "db": bool(bootstrap.resources.db.engine and bootstrap.resources.db.pool_ready),
        "redis": bool(bootstrap.resources.cache.redis),
        "nats": bool(bootstrap.resources.broker.nats),
        "kafka": bool(bootstrap.resources.broker.kafka),
        "metrics": bootstrap.settings.METRICS_ENABLED,
        "otel": bootstrap.settings.OTEL_ENABLED,
    }


# -----------------------------
# CLI-запуск для отладки (необязательный)
# -----------------------------

async def _dev_main() -> int:
    try:
        async with Bootstrap.auto() as app:
            logging.getLogger(__name__).info("dev_started")
            await app.run_until_stopped()
    except Exception as ex:
        logging.getLogger(__name__).error("dev_failed: %s", ex)
        return 1
    return 0

if __name__ == "__main__":  # pragma: no cover
    # Позволяет: `python -m datafabric.bootstrap`
    try:
        asyncio.run(_dev_main())
    except KeyboardInterrupt:
        pass
