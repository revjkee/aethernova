from __future__ import annotations

import asyncio
import contextlib
import contextvars
import dataclasses
import json
import logging
import os
import signal
import socket
import sys
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Optional, Tuple

# ------------------------------ Optional deps (graceful) ------------------------------
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

try:
    import grpc  # type: ignore
    import grpc.aio as grpc_aio  # type: ignore
except Exception:  # pragma: no cover
    grpc = None  # type: ignore
    grpc_aio = None  # type: ignore

try:
    from prometheus_client import start_http_server, Counter, Gauge, CollectorRegistry  # type: ignore
except Exception:  # pragma: no cover
    start_http_server = None  # type: ignore
    Counter = None  # type: ignore
    Gauge = None  # type: ignore
    CollectorRegistry = None  # type: ignore

try:
    # opentelemetry is optional
    from opentelemetry import trace, metrics  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
    from opentelemetry.sdk.metrics import MeterProvider  # type: ignore
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    metrics = None  # type: ignore
    Resource = None  # type: ignore
    TracerProvider = None  # type: ignore
    BatchSpanProcessor = None  # type: ignore
    OTLPSpanExporter = None  # type: ignore
    MeterProvider = None  # type: ignore
    PeriodicExportingMetricReader = None  # type: ignore
    OTLPMetricExporter = None  # type: ignore


# ---------------------------------- Configuration ----------------------------------

def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key)
    return v if v is not None and str(v).strip() != "" else default

def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y")

def _env_int(key: str, default: int) -> int:
    v = os.getenv(key)
    if v is None or str(v).strip() == "":
        return default
    try:
        return int(v)
    except Exception:
        return default

def _env_tuple(key: str, default: Tuple[str, ...] = ()) -> Tuple[str, ...]:
    v = os.getenv(key)
    if not v:
        return default
    items = [x.strip() for x in v.replace(";", ",").split(",") if x.strip()]
    return tuple(items) if items else default


@dataclass(frozen=True)
class AppConfig:
    # Service identity
    service_name: str = field(default_factory=lambda: _env("PIC_SERVICE_NAME", "physical-integration-core"))
    service_instance: str = field(default_factory=lambda: _env("PIC_INSTANCE", socket.gethostname()))
    environment: str = field(default_factory=lambda: _env("PIC_ENV", "prod"))
    version: str = field(default_factory=lambda: _env("PIC_VERSION", "0.0.0"))

    # Logging
    log_level: str = field(default_factory=lambda: _env("PIC_LOG_LEVEL", "INFO"))
    log_json: bool = field(default_factory=lambda: _env_bool("PIC_LOG_JSON", True))

    # HTTP client
    http_enabled: bool = field(default_factory=lambda: _env_bool("PIC_HTTP_ENABLED", True))
    http_timeout_connect_s: float = field(default_factory=lambda: float(_env("PIC_HTTP_CONNECT_TIMEOUT_S", "5")))
    http_timeout_read_s: float = field(default_factory=lambda: float(_env("PIC_HTTP_READ_TIMEOUT_S", "30")))
    http_max_keepalive: int = field(default_factory=lambda: _env_int("PIC_HTTP_MAX_CONNECTIONS", 200))

    # Postgres
    pg_dsn: Optional[str] = field(default_factory=lambda: _env("PIC_PG_DSN"))
    pg_min_size: int = field(default_factory=lambda: _env_int("PIC_PG_MIN_SIZE", 1))
    pg_max_size: int = field(default_factory=lambda: _env_int("PIC_PG_MAX_SIZE", 10))

    # Kafka
    kafka_brokers: Tuple[str, ...] = field(default_factory=lambda: _env_tuple("PIC_KAFKA_BROKERS"))
    kafka_acks: str = field(default_factory=lambda: _env("PIC_KAFKA_ACKS", "all"))
    kafka_compression: str = field(default_factory=lambda: _env("PIC_KAFKA_COMPRESSION", "gzip"))

    # gRPC
    grpc_target: Optional[str] = field(default_factory=lambda: _env("PIC_GRPC_TARGET"))
    grpc_secure: bool = field(default_factory=lambda: _env_bool("PIC_GRPC_SECURE", False))

    # Telemetry / metrics
    prometheus_bind: Optional[str] = field(default_factory=lambda: _env("PIC_PROMETHEUS_BIND", "0.0.0.0:9400"))
    otel_enabled: bool = field(default_factory=lambda: _env_bool("PIC_OTEL_ENABLED", False))
    otel_endpoint: Optional[str] = field(default_factory=lambda: _env("PIC_OTEL_ENDPOINT"))
    otel_headers: Tuple[str, ...] = field(default_factory=lambda: _env_tuple("PIC_OTEL_HEADERS"))

    # Shutdown
    shutdown_grace_s: int = field(default_factory=lambda: _env_int("PIC_SHUTDOWN_GRACE_S", 25))


# ---------------------------------- Logging setup ----------------------------------

def setup_logging(cfg: AppConfig) -> logging.Logger:
    logger = logging.getLogger()
    logger.handlers.clear()
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logger.setLevel(level)

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
                "lvl": record.levelname,
                "msg": record.getMessage(),
                "logger": record.name,
                "service": cfg.service_name,
                "instance": cfg.service_instance,
                "env": cfg.environment,
            }
            if record.exc_info:
                payload["exc_info"] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False)

    handler = logging.StreamHandler(sys.stdout)
    if cfg.log_json:
        handler.setFormatter(_JsonFormatter())
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
    logger.addHandler(handler)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    return logger


# ---------------------------------- App Context ----------------------------------

_current_ctx: contextvars.ContextVar["AppContext"] = contextvars.ContextVar("pic_current_ctx", default=None)  # type: ignore


@dataclass
class AppContext:
    config: AppConfig
    logger: logging.Logger

    # Optional resources
    http: Optional["httpx.AsyncClient"] = None
    pg_pool: Any = None
    kafka_producer: Any = None
    grpc_channel: Any = None

    # Telemetry
    prometheus_registry: Any = None
    _prom_server_started: bool = False
    _m_health: Any = None  # Gauge
    _m_ready: Any = None   # Gauge

    # OpenTelemetry
    tracer_provider: Any = None
    meter_provider: Any = None

    # Internal
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _started: bool = False
    _signal_handlers_installed: bool = False

    async def start(self) -> None:
        async with self._lock:
            if self._started:
                return
            self.logger.info("context.start: initializing resources")

            # HTTP client
            if self.config.http_enabled and httpx is not None:
                limits = httpx.Limits(max_keepalive_connections=self.config.http_max_keepalive, max_connections=self.config.http_max_keepalive)
                timeout = httpx.Timeout(connect=self.config.http_timeout_connect_s, read=self.config.http_timeout_read_s)
                self.http = httpx.AsyncClient(limits=limits, timeout=timeout)
                self.logger.info("context.start: httpx client initialized", extra={"max_conn": self.config.http_max_keepalive})

            # Postgres
            if self.config.pg_dsn and asyncpg is not None:
                self.pg_pool = await asyncpg.create_pool(
                    dsn=self.config.pg_dsn,
                    min_size=self.config.pg_min_size,
                    max_size=self.config.pg_max_size,
                )
                # Лёгкая проверка соединения
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                self.logger.info("context.start: postgres pool ready", extra={"min": self.config.pg_min_size, "max": self.config.pg_max_size})

            # Kafka Producer
            if self.config.kafka_brokers and AIOKafkaProducer is not None:
                self.kafka_producer = AIOKafkaProducer(
                    bootstrap_servers=",".join(self.config.kafka_brokers),
                    acks=self.config.kafka_acks,
                    compression_type=self.config.kafka_compression,
                )
                await self.kafka_producer.start()
                self.logger.info("context.start: kafka producer started", extra={"brokers": list(self.config.kafka_brokers)})

            # gRPC channel
            if self.config.grpc_target and grpc_aio is not None:
                if self.config.grpc_secure:
                    # Без конкретных кредов – системные корни по умолчанию
                    creds = grpc.ssl_channel_credentials() if grpc else None  # type: ignore
                    self.grpc_channel = grpc_aio.secure_channel(self.config.grpc_target, creds)  # type: ignore
                else:
                    self.grpc_channel = grpc_aio.insecure_channel(self.config.grpc_target)  # type: ignore
                self.logger.info("context.start: grpc channel created", extra={"target": self.config.grpc_target})

            # Prometheus
            if CollectorRegistry and Counter and Gauge:
                self.prometheus_registry = CollectorRegistry()
                # Регистрация собственных метрик может быть расширена
                self._m_health = Gauge("pic_app_health", "App health status (1=ok)", registry=self.prometheus_registry)
                self._m_ready = Gauge("pic_app_ready", "App readiness (1=ready)", registry=self.prometheus_registry)
                self._m_health.set(1)
                self._m_ready.set(0)
                if self.config.prometheus_bind and start_http_server:
                    host, port = self.config.prometheus_bind.split(":")
                    start_http_server(addr=host, port=int(port), registry=self.prometheus_registry)  # type: ignore
                    self._prom_server_started = True
                    self.logger.info("context.start: prometheus server bound", extra={"bind": self.config.prometheus_bind})

            # OpenTelemetry
            if self.config.otel_enabled and trace and metrics and TracerProvider and MeterProvider:
                res = Resource.create({
                    "service.name": self.config.service_name,
                    "service.instance.id": self.config.service_instance,
                    "service.version": self.config.version,
                    "deployment.environment": self.config.environment,
                })
                # Traces
                self.tracer_provider = TracerProvider(resource=res)
                if self.config.otel_endpoint and OTLPSpanExporter and BatchSpanProcessor:
                    sp_exp = OTLPSpanExporter(endpoint=self.config.otel_endpoint, headers=dict(h.split("=", 1) for h in self.config.otel_headers if "=" in h))
                    self.tracer_provider.add_span_processor(BatchSpanProcessor(sp_exp))
                trace.set_tracer_provider(self.tracer_provider)  # type: ignore

                # Metrics
                if self.config.otel_endpoint and OTLPMetricExporter and PeriodicExportingMetricReader:
                    mp_reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=self.config.otel_endpoint))
                    self.meter_provider = MeterProvider(resource=res, metric_readers=[mp_reader])
                    metrics.set_meter_provider(self.meter_provider)  # type: ignore

                self.logger.info("context.start: opentelemetry configured", extra={"endpoint": self.config.otel_endpoint})

            # Signals
            self._install_signal_handlers()
            self._started = True
            if self._m_ready:
                self._m_ready.set(1)
            self.logger.info("context.start: ready")

    async def close(self) -> None:
        async with self._lock:
            if not self._started:
                return
            self.logger.info("context.close: shutting down")
            if self._m_ready:
                self._m_ready.set(0)

            # Close in reverse order
            with contextlib.suppress(Exception):
                if self.grpc_channel is not None:
                    await self.grpc_channel.close()  # type: ignore
                    self.logger.info("context.close: grpc channel closed")

            with contextlib.suppress(Exception):
                if self.kafka_producer is not None:
                    await self.kafka_producer.stop()  # type: ignore
                    self.logger.info("context.close: kafka producer stopped")

            with contextlib.suppress(Exception):
                if self.pg_pool is not None:
                    await self.pg_pool.close()
                    self.logger.info("context.close: postgres pool closed")

            with contextlib.suppress(Exception):
                if self.http is not None:
                    await self.http.aclose()
                    self.logger.info("context.close: httpx client closed")

            # OpenTelemetry providers do not require explicit close in typical OTLP HTTP exporters
            self._started = False
            if self._m_health:
                self._m_health.set(0)
            self.logger.info("context.close: done")

    # ------------------------------ Utilities ------------------------------

    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "service": self.config.service_name,
            "instance": self.config.service_instance,
            "env": self.config.environment,
            "version": self.config.version,
            "http": bool(self.http is not None),
            "pg": bool(self.pg_pool is not None),
            "kafka": bool(self.kafka_producer is not None),
            "grpc": bool(self.grpc_channel is not None),
            "otel": bool(self.tracer_provider is not None or self.meter_provider is not None),
            "prometheus": bool(self._prom_server_started),
            "started": bool(self._started),
        }

    def _install_signal_handlers(self) -> None:
        if self._signal_handlers_installed:
            return
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._graceful_shutdown(s)))
            except NotImplementedError:  # Windows
                pass
        self._signal_handlers_installed = True

    async def _graceful_shutdown(self, sig: signal.Signals) -> None:
        self.logger.warning("signal.received: %s", sig.name)
        try:
            await asyncio.wait_for(self.close(), timeout=self.config.shutdown_grace_s)
        except asyncio.TimeoutError:
            self.logger.error("shutdown.timeout: forced exit after %ss", self.config.shutdown_grace_s)
        finally:
            # Завершаем цикл после закрытия (если используем самостоятельный runner)
            pass


# ---------------------------------- Context helpers ----------------------------------

def create_context(config: Optional[AppConfig] = None) -> AppContext:
    cfg = config or AppConfig()
    logger = setup_logging(cfg)
    ctx = AppContext(config=cfg, logger=logger)
    return ctx

@contextlib.asynccontextmanager
async def context_scope(ctx: AppContext) -> AsyncIterator[AppContext]:
    token = _current_ctx.set(ctx)
    try:
        await ctx.start()
        yield ctx
    finally:
        await ctx.close()
        _current_ctx.reset(token)

def get_context() -> Optional[AppContext]:
    return _current_ctx.get()


# ---------------------------------- FastAPI/Starlette lifespan ----------------------------------

def lifespan_factory(ctx: Optional[AppContext] = None):
    """
    Использование:
        app = FastAPI(lifespan=lifespan_factory())  # создаст контекст из ENV
        # или:
        ctx = create_context(custom_config)
        app = FastAPI(lifespan=lifespan_factory(ctx))
    """
    app_ctx = ctx or create_context()

    @contextlib.asynccontextmanager
    async def lifespan(app):  # type: ignore
        token = _current_ctx.set(app_ctx)
        await app_ctx.start()
        try:
            yield
        finally:
            await app_ctx.close()
            _current_ctx.reset(token)

    return lifespan


# ---------------------------------- Example (manual runner) ----------------------------------

if __name__ == "__main__":
    async def _main():
        ctx = create_context()
        async with context_scope(ctx):
            ctx.logger.info("example: context started", extra=ctx.health_snapshot())
            # имитация работы
            await asyncio.sleep(1.0)
            ctx.logger.info("example: context running")
            await asyncio.sleep(1.0)

    asyncio.run(_main())
