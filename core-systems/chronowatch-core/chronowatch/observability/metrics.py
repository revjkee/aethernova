# chronowatch-core/chronowatch/observability/metrics.py
from __future__ import annotations

import asyncio
import os
import socket
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Iterable, Optional

try:
    # prometheus_client>=0.20.0
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        Info,
        Enum as PromEnum,
        CONTENT_TYPE_LATEST,
        generate_latest,
        start_http_server,
        PROCESS_COLLECTOR,
        PLATFORM_COLLECTOR,
        GC_COLLECTOR,
    )
    from prometheus_client import multiprocess  # type: ignore
    try:
        # 0.20+ предоставляет готовый ASGI-приложение
        from prometheus_client import make_asgi_app  # type: ignore
    except Exception:
        make_asgi_app = None  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("prometheus_client is required for metrics subsystem") from e

# OpenTelemetry — опционально
try:  # pragma: no cover
    from opentelemetry import metrics as otel_metrics, trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False  # мягкая деградация

DEFAULT_BUCKETS: tuple[float, ...] = (
    0.001, 0.003, 0.005, 0.01,
    0.025, 0.05, 0.1, 0.25,
    0.5, 1.0, 2.5, 5.0, 10.0, 30.0
)

@dataclass(frozen=True)
class MetricsConfig:
    service_name: str = field(default_factory=lambda: os.getenv("SERVICE_NAME", "chronowatch-core"))
    service_version: str = field(default_factory=lambda: os.getenv("SERVICE_VERSION", "0.0.0"))
    instance_id: str = field(default_factory=lambda: os.getenv("POD_NAME", socket.gethostname()))
    namespace: str = field(default_factory=lambda: os.getenv("SERVICE_NAMESPACE", "chronowatch"))
    enable_http_exporter: bool = field(default_factory=lambda: os.getenv("METRICS_HTTP_EXPORTER", "true").lower() == "true")
    http_host: str = field(default_factory=lambda: os.getenv("METRICS_HOST", "0.0.0.0"))
    http_port: int = field(default_factory=lambda: int(os.getenv("METRICS_PORT", "9464")))
    multiprocess_dir: Optional[str] = field(default_factory=lambda: os.getenv("PROMETHEUS_MULTIPROC_DIR"))
    default_buckets: tuple[float, ...] = DEFAULT_BUCKETS
    # OpenTelemetry (опционально)
    enable_otel: bool = field(default_factory=lambda: os.getenv("OTEL_METRICS_ENABLED", "false").lower() == "true")
    otel_endpoint: str = field(default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"))
    otel_period_sec: int = field(default_factory=lambda: int(os.getenv("OTEL_METRICS_PERIOD_SEC", "10")))


class Metrics:
    """
    Промышленная подсистема метрик:
    - Prometheus (registry + экспорт /metrics)
    - Multiprocess поддержка (gunicorn/uvicorn workers)
    - Хелперы/декораторы для измерений
    - Опциональная инициализация OpenTelemetry OTLP metrics
    """
    _instance: "Metrics | None" = None

    @classmethod
    def init(cls, cfg: MetricsConfig | None = None) -> "Metrics":
        if cls._instance is None:
            cls._instance = cls(cfg or MetricsConfig())
        return cls._instance

    def __init__(self, cfg: MetricsConfig) -> None:
        self.cfg = cfg
        self.registry = self._build_registry()
        self._http_server_started = False

        # Служебные метрики/лейблы сервиса
        self.info = Info(
            "service_info",
            "Static info about service instance",
            registry=self.registry,
        )
        self.info.info({  # один раз
            "service": self.cfg.service_name,
            "version": self.cfg.service_version,
            "instance": self.cfg.instance_id,
            "namespace": self.cfg.namespace,
        })

        self.status = PromEnum(
            "service_status",
            "Service lifecycle status",
            states=["starting", "ready", "draining", "stopped"],
            registry=self.registry,
        )
        self.status.state("starting")

        # Базовые метрики Chronowatch для задач/планировщика
        self.request_total = Counter(
            "cw_requests_total",
            "Requests total by handler and outcome",
            ["handler", "result"],
            registry=self.registry,
        )
        self.request_exceptions = Counter(
            "cw_request_exceptions_total",
            "Exceptions raised by handler",
            ["handler", "exc_type"],
            registry=self.registry,
        )
        self.request_latency = Histogram(
            "cw_request_duration_seconds",
            "Request duration seconds by handler",
            ["handler"],
            buckets=self.cfg.default_buckets,
            registry=self.registry,
        )
        self.inprogress = Gauge(
            "cw_inprogress_requests",
            "In-progress requests by handler",
            ["handler"],
            registry=self.registry,
        )

        # Метрики планировщика (jobs)
        self.jobs_total = Counter(
            "cw_jobs_total",
            "Total jobs by type and status",
            ["job_type", "status"],
            registry=self.registry,
        )
        self.job_latency = Histogram(
            "cw_job_duration_seconds",
            "Job execution duration seconds by type",
            ["job_type"],
            buckets=self.cfg.default_buckets,
            registry=self.registry,
        )
        self.scheduled_triggers = Counter(
            "cw_scheduled_triggers_total",
            "Scheduled triggers fired by schedule_kind",
            ["schedule_kind"],
            registry=self.registry,
        )
        self.scheduler_lag = Histogram(
            "cw_scheduler_lag_seconds",
            "Lag between expected and actual trigger time",
            ["schedule_kind"],
            buckets=(0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10, 30, 60),
            registry=self.registry,
        )

        # Опциональный OTEL экспорт (мягко)
        self._otel_started = False
        if self.cfg.enable_otel and _OTEL_AVAILABLE:
            try:
                self._init_otel()
                self._otel_started = True
            except Exception:
                # Мягкая деградация без падения сервиса
                self._otel_started = False

    # ------------------------------
    # Registry / HTTP / ASGI
    # ------------------------------

    def _build_registry(self) -> CollectorRegistry:
        """
        Создаёт Prometheus registry с учетом multiprocess режима.
        """
        mp_dir = self.cfg.multiprocess_dir
        if mp_dir:
            os.environ["PROMETHEUS_MULTIPROC_DIR"] = mp_dir
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)  # type: ignore
            # В multiprocess режиме процесс/платформа/GC собираются аггрегатором
            return registry

        # single-process: регистрируем стандартные коллекторы
        registry = CollectorRegistry()
        PROCESS_COLLECTOR(registry)      # cpu, rss, fds, и т.д.
        PLATFORM_COLLECTOR(registry)     # python интерпретатор
        GC_COLLECTOR(registry)           # gc статистика
        return registry

    def start_http_exporter(self) -> None:
        """
        Запуск встроенного HTTP-экспортера (если нужен side-car, отключите флагом).
        """
        if not self.cfg.enable_http_exporter or self._http_server_started:
            return
        # Простой HTTP сервер prometheus_client (не ASGI)
        start_http_server(self.cfg.http_port, addr=self.cfg.http_host, registry=self.registry)
        self._http_server_started = True
        self.status.state("ready")

    def get_asgi_app(self):
        """
        Возвращает ASGI-приложение /metrics. Требует prometheus_client с make_asgi_app.
        """
        if make_asgi_app is None:
            raise RuntimeError("prometheus_client.make_asgi_app is not available in this version")
        return make_asgi_app(registry=self.registry)

    # Fallback для ручной отдачи метрик (например, внутри FastAPI route)
    def render_latest(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST

    # ------------------------------
    # OpenTelemetry (optional)
    # ------------------------------

    def _init_otel(self) -> None:  # pragma: no cover
        resource = Resource.create({
            "service.name": self.cfg.service_name,
            "service.version": self.cfg.service_version,
            "service.namespace": self.cfg.namespace,
            "service.instance.id": self.cfg.instance_id,
        })
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=self.cfg.otel_endpoint, timeout=10.0),
            export_interval_millis=self.cfg.otel_period_sec * 1000,
        )
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        otel_metrics.set_meter_provider(provider)

    # ------------------------------
    # Decorators / helpers
    # ------------------------------

    @contextmanager
    def track(self, handler: str):
        """
        Синхронный контекст измерения запросов/операций.
        """
        self.inprogress.labels(handler).inc()
        started = time.perf_counter()
        try:
            yield
            self.request_total.labels(handler, "ok").inc()
        except Exception as e:
            self.request_total.labels(handler, "error").inc()
            self.request_exceptions.labels(handler, e.__class__.__name__).inc()
            raise
        finally:
            self.inprogress.labels(handler).dec()
            self.request_latency.labels(handler).observe(time.perf_counter() - started)

    @asynccontextmanager
    async def track_async(self, handler: str):
        """
        Асинхронный контекст измерения запросов/операций.
        """
        self.inprogress.labels(handler).inc()
        started = time.perf_counter()
        try:
            yield
            self.request_total.labels(handler, "ok").inc()
        except Exception as e:
            self.request_total.labels(handler, "error").inc()
            self.request_exceptions.labels(handler, e.__class__.__name__).inc()
            raise
        finally:
            self.inprogress.labels(handler).dec()
            self.request_latency.labels(handler).observe(time.perf_counter() - started)

    def timed(self, handler: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Декоратор синхронных функций.
        """
        def _wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            def _inner(*args: Any, **kwargs: Any) -> Any:
                with self.track(handler):
                    return fn(*args, **kwargs)
            _inner.__name__ = fn.__name__
            return _inner
        return _wrap

    def timed_async(self, handler: str) -> Callable[[Callable[..., Coroutine[Any, Any, Any]]], Callable[..., Coroutine[Any, Any, Any]]]:
        """
        Декоратор асинхронных функций.
        """
        def _wrap(fn: Callable[..., Coroutine[Any, Any, Any]]) -> Callable[..., Coroutine[Any, Any, Any]]:
            async def _inner(*args: Any, **kwargs: Any) -> Any:
                async with self.track_async(handler):
                    return await fn(*args, **kwargs)
            _inner.__name__ = fn.__name__
            return _inner
        return _wrap

    # ------------------------------
    # Scheduler-specific helpers
    # ------------------------------

    def observe_job(self, job_type: str, duration_sec: float, status: str = "ok") -> None:
        """
        Зафиксировать выполнение job.
        """
        self.job_latency.labels(job_type).observe(max(0.0, duration_sec))
        self.jobs_total.labels(job_type, status).inc()

    def trigger_fired(self, schedule_kind: str, lag_seconds: float | None = None) -> None:
        """
        Зафиксировать срабатывание триггера планировщика.
        """
        self.scheduled_triggers.labels(schedule_kind).inc()
        if lag_seconds is not None:
            self.scheduler_lag.labels(schedule_kind).observe(max(0.0, lag_seconds))

    # ------------------------------
    # Lifecycle
    # ------------------------------

    def set_ready(self) -> None:
        self.status.state("ready")

    def set_draining(self) -> None:
        self.status.state("draining")

    def set_stopped(self) -> None:
        self.status.state("stopped")


# ------------------------------
# Module-level singleton & shortcuts
# ------------------------------

_metrics = Metrics.init()

def init_metrics(cfg: MetricsConfig | None = None) -> Metrics:
    """
    Переинициализация метрик с новой конфигурацией (используйте на старте сервиса).
    """
    global _metrics
    _metrics = Metrics.init(cfg)
    return _metrics

def start_http_exporter() -> None:
    _metrics.start_http_exporter()

def get_asgi_app():
    return _metrics.get_asgi_app()

@contextmanager
def track(handler: str):
    with _metrics.track(handler) as ctx:
        yield ctx

@asynccontextmanager
async def track_async(handler: str):
    async with _metrics.track_async(handler) as ctx:
        yield ctx

def timed(handler: str):
    return _metrics.timed(handler)

def timed_async(handler: str):
    return _metrics.timed_async(handler)

def observe_job(job_type: str, duration_sec: float, status: str = "ok") -> None:
    _metrics.observe_job(job_type, duration_sec, status)

def trigger_fired(schedule_kind: str, lag_seconds: float | None = None) -> None:
    _metrics.trigger_fired(schedule_kind, lag_seconds)

def set_ready() -> None:
    _metrics.set_ready()

def set_draining() -> None:
    _metrics.set_draining()

def set_stopped() -> None:
    _metrics.set_stopped()
