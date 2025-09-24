# ledger-core/ledger/telemetry/metrics.py
from __future__ import annotations

import asyncio
import contextvars
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

# -------------------------------
# Опциональные зависимости
# -------------------------------

_OTEL_AVAILABLE = False
_PROM_AVAILABLE = False

try:
    # OpenTelemetry (sync metrics API, SDK и OTLP экспортеры)
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.metrics import get_meter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    try:
        # HTTP экспортер (предпочтительно)
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter as OTLPMetricExporterHttp
        _OTLP_HTTP = True
    except Exception:
        _OTLP_HTTP = False
    try:
        # gRPC экспортер как фолбэк
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter as OTLPMetricExporterGrpc
        _OTLP_GRPC = True
    except Exception:
        _OTLP_GRPC = False

    # Утилиты ресурса
    from opentelemetry.sdk.resources import Resource
    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False

try:
    from prometheus_client import Counter as PromCounter
    from prometheus_client import Histogram as PromHistogram
    from prometheus_client import Gauge as PromGauge
    from prometheus_client import start_http_server as prom_start_http_server
    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False


# -------------------------------
# Конфигурация
# -------------------------------

@dataclass(frozen=True)
class MetricsConfig:
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "ledger-core")
    service_namespace: str = os.getenv("OTEL_SERVICE_NAMESPACE", "ledger")
    service_version: str = os.getenv("APP_VERSION", "0.0.0")
    deployment_env: str = os.getenv("APP_ENV", "development")
    exporter: str = os.getenv("METRICS_EXPORTER", os.getenv("OTEL_METRICS_EXPORTER", "otlp")).lower()  # otlp|prom|noop
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    otlp_headers: str = os.getenv("OTEL_EXPORTER_OTLP_HEADERS", "")  # key=val, key2=val2
    prom_port: int = int(os.getenv("PROMETHEUS_PORT", "8000"))
    prom_addr: str = os.getenv("PROMETHEUS_ADDR", "0.0.0.0")
    # Безопасность кардинальности
    max_label_value_len: int = int(os.getenv("METRICS_MAX_LABEL_VALUE_LEN", "120"))
    # Бакеты по умолчанию для latency (в секундах)
    latency_buckets: Tuple[float, ...] = tuple(
        float(x) for x in os.getenv(
            "METRICS_LATENCY_BUCKETS",
            "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1.0,2.5,5.0"
        ).split(",")
    )


# -------------------------------
# Вспомогательное
# -------------------------------

_ctx_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("metrics_request_id", default=None)
_ctx_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar("metrics_tenant", default=None)

def set_context(request_id: Optional[str] = None, tenant_id: Optional[str] = None) -> None:
    if request_id is not None:
        _ctx_request_id.set(request_id)
    if tenant_id is not None:
        _ctx_tenant.set(tenant_id)

def _safe_labels(cfg: MetricsConfig, labels: Mapping[str, Any] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if labels:
        for k, v in labels.items():
            if v is None:
                continue
            s = str(v)
            if len(s) > cfg.max_label_value_len:
                s = s[: cfg.max_label_value_len] + "...trunc"
            # запрещаем слишком много уникальных значений: ответственность на стороне вызывающего
            out[str(k)] = s
    # добавляем сквозные контекстные метки
    rid = _ctx_request_id.get()
    tnt = _ctx_tenant.get()
    if rid:
        out.setdefault("request_id", rid)
    if tnt:
        out.setdefault("tenant_id", tnt)
    # стандартные
    out.setdefault("env", cfg.deployment_env)
    return out


# -------------------------------
# Абстракции инструментов
# -------------------------------

class _NoopInstrument:
    def add(self, amount: float, labels: Mapping[str, str] | None = None) -> None:
        return

    def record(self, amount: float, labels: Mapping[str, str] | None = None) -> None:
        return

    def set(self, value: float, labels: Mapping[str, str] | None = None) -> None:
        return

class _Counter:
    def __init__(self, otel_obj=None, prom_obj=None, cfg: MetricsConfig | None = None) -> None:
        self._otel = otel_obj
        self._prom = prom_obj
        self._cfg = cfg or MetricsConfig()

    def add(self, amount: float = 1.0, labels: Mapping[str, Any] | None = None) -> None:
        if amount < 0:
            return
        lab = _safe_labels(self._cfg, labels)
        if self._otel:
            self._otel.add(amount, attributes=lab)
        if self._prom:
            self._prom.labels(**lab).inc(amount)

class _UpDownCounter:
    def __init__(self, otel_obj=None, prom_obj=None, cfg: MetricsConfig | None = None) -> None:
        self._otel = otel_obj
        self._prom = prom_obj
        self._cfg = cfg or MetricsConfig()

    def add(self, amount: float, labels: Mapping[str, Any] | None = None) -> None:
        lab = _safe_labels(self._cfg, labels)
        if self._otel:
            self._otel.add(amount, attributes=lab)
        if self._prom:
            self._prom.labels(**lab).inc(amount)

class _Histogram:
    def __init__(self, otel_obj=None, prom_obj=None, cfg: MetricsConfig | None = None) -> None:
        self._otel = otel_obj
        self._prom = prom_obj
        self._cfg = cfg or MetricsConfig()

    def record(self, amount: float, labels: Mapping[str, Any] | None = None) -> None:
        lab = _safe_labels(self._cfg, labels)
        if self._otel:
            self._otel.record(amount, attributes=lab)
        if self._prom:
            self._prom.labels(**lab).observe(amount)

class _Gauge:
    def __init__(self, prom_obj=None, cfg: MetricsConfig | None = None) -> None:
        # OpenTelemetry Gauge в стабильном API отсутствует как синхронный set; используем Prometheus gauge при наличии
        self._prom = prom_obj
        self._cfg = cfg or MetricsConfig()

    def set(self, value: float, labels: Mapping[str, Any] | None = None) -> None:
        lab = _safe_labels(self._cfg, labels)
        if self._prom:
            self._prom.labels(**lab).set(value)


# -------------------------------
# Основной класс Metrics
# -------------------------------

class Metrics:
    """
    Унифицированный слой метрик. Инициализируется из ENV.
    Поддерживает:
      - OpenTelemetry OTLP (http/grpc) через SDK;
      - Prometheus client со своим HTTP endpoint;
      - No-op режим при отсутствии зависимостей.
    """
    def __init__(self, cfg: Optional[MetricsConfig] = None) -> None:
        self.cfg = cfg or MetricsConfig()
        self._exporter = self.cfg.exporter
        self._meter = None
        self._prom_registry_labels: Sequence[str] = ()
        self._initialized = False

    def init(self) -> None:
        if self._initialized:
            return

        if self._exporter == "otlp" and _OTEL_AVAILABLE:
            self._init_otel()
        elif self._exporter == "prom" and _PROM_AVAILABLE:
            self._init_prometheus()
        elif _OTEL_AVAILABLE:
            # по умолчанию пробуем otlp, если не получилось, но otel есть
            self._init_otel()
        elif _PROM_AVAILABLE:
            self._init_prometheus()
        else:
            # no-op
            self._meter = None

        self._initialized = True

    # ---------- фабрики инструментов ----------

    def counter(self, name: str, description: str = "", unit: str = "1", label_names: Sequence[str] = ()) -> _Counter:
        self.init()
        if self._meter:
            try:
                c = self._meter.create_counter(name, description=description, unit=unit)
                return _Counter(otel_obj=c, prom_obj=None, cfg=self.cfg)
            except Exception:
                pass
        if _PROM_AVAILABLE and hasattr(self, "_prom_namespace"):
            prom = PromCounter(name, description, list(label_names) + self._static_label_names(), namespace=self._prom_namespace, subsystem=self._prom_subsystem)
            return _Counter(otel_obj=None, prom_obj=prom, cfg=self.cfg)
        return _Counter(cfg=self.cfg)

    def updown_counter(self, name: str, description: str = "", unit: str = "1", label_names: Sequence[str] = ()) -> _UpDownCounter:
        self.init()
        if self._meter:
            try:
                c = self._meter.create_up_down_counter(name, description=description, unit=unit)
                return _UpDownCounter(otel_obj=c, prom_obj=None, cfg=self.cfg)
            except Exception:
                pass
        if _PROM_AVAILABLE and hasattr(self, "_prom_namespace"):
            prom = PromGauge(name, description, list(label_names) + self._static_label_names(), namespace=self._prom_namespace, subsystem=self._prom_subsystem)
            return _UpDownCounter(otel_obj=None, prom_obj=prom, cfg=self.cfg)
        return _UpDownCounter(cfg=self.cfg)

    def histogram(self, name: str, description: str = "", unit: str = "s", label_names: Sequence[str] = (), buckets: Optional[Sequence[float]] = None) -> _Histogram:
        self.init()
        if self._meter:
            try:
                h = self._meter.create_histogram(name, description=description, unit=unit)
                return _Histogram(otel_obj=h, prom_obj=None, cfg=self.cfg)
            except Exception:
                pass
        if _PROM_AVAILABLE and hasattr(self, "_prom_namespace"):
            prom = PromHistogram(
                name,
                description,
                list(label_names) + self._static_label_names(),
                buckets=tuple(buckets or self.cfg.latency_buckets),
                namespace=self._prom_namespace,
                subsystem=self._prom_subsystem,
            )
            return _Histogram(otel_obj=None, prom_obj=prom, cfg=self.cfg)
        return _Histogram(cfg=self.cfg)

    def gauge(self, name: str, description: str = "", label_names: Sequence[str] = ()) -> _Gauge:
        self.init()
        if _PROM_AVAILABLE and hasattr(self, "_prom_namespace"):
            prom = PromGauge(name, description, list(label_names) + self._static_label_names(), namespace=self._prom_namespace, subsystem=self._prom_subsystem)
            return _Gauge(prom_obj=prom, cfg=self.cfg)
        return _Gauge(cfg=self.cfg)

    # ---------- таймеры/декораторы ----------

    def timer(self, histogram: _Histogram, labels: Mapping[str, Any] | None = None):
        """
        Контекстный менеджер для измерения времени и записи в гистограмму в секундах.
        """
        class _Timer:
            def __enter__(_self):
                _self.t0 = time.perf_counter()
                return _self
            def __exit__(_self, exc_type, exc, tb):
                dt = time.perf_counter() - _self.t0
                histogram.record(dt, labels=labels or {})
        return _Timer()

    def time_async(self, histogram: _Histogram, labels: Mapping[str, Any] | None = None):
        """
        Декоратор для асинхронных функций (histogram в секундах).
        """
        def _wrap(fn: Callable[..., Any]):
            async def _inner(*args, **kwargs):
                t0 = time.perf_counter()
                try:
                    return await fn(*args, **kwargs)
                finally:
                    dt = time.perf_counter() - t0
                    histogram.record(dt, labels=labels or {})
            return _inner
        return _wrap

    def time_sync(self, histogram: _Histogram, labels: Mapping[str, Any] | None = None):
        """
        Декоратор для синхронных функций.
        """
        def _wrap(fn: Callable[..., Any]):
            def _inner(*args, **kwargs):
                t0 = time.perf_counter()
                try:
                    return fn(*args, **kwargs)
                finally:
                    dt = time.perf_counter() - t0
                    histogram.record(dt, labels=labels or {})
            return _inner
        return _wrap

    # ---------- интеграции ----------

    def asgi_middleware(self, app, service_label: str = "http"):
        """
        Простая ASGI мидлварь для HTTP запросов (FastAPI/Starlette совместимо).
        Собирает счетчики/латенции и коды ответов.
        """
        request_counter = self.counter(f"{service_label}_requests_total", "Total HTTP requests", label_names=("method", "route", "status"))
        request_latency = self.histogram(f"{service_label}_request_duration_seconds", "HTTP request duration", unit="s", label_names=("method", "route", "status"))

        class _Middleware:
            def __init__(self, app):
                self.app = app
            async def __call__(self, scope, receive, send):
                if scope["type"] != "http":
                    return await self.app(scope, receive, send)
                method = scope.get("method", "GET")
                route = scope.get("path", "/")
                status_holder = {"code": "500"}

                async def _send(ev):
                    if ev["type"] == "http.response.start":
                        status_holder["code"] = str(ev.get("status", 200))
                    await send(ev)

                with self.timer(request_latency, labels={"method": method, "route": route, "status": status_holder["code"]}):
                    try:
                        await self.app(scope, receive, _send)
                    finally:
                        request_counter.add(1.0, labels={"method": method, "route": route, "status": status_holder["code"]})
        return _Middleware(app)

    def instrument_async_task(self, name: str):
        """
        Декоратор для фоновых задач: latency, success/failure.
        """
        h = self.histogram(f"task_{name}_duration_seconds", f"Task {name} duration", unit="s", label_names=("result",))
        c = self.counter(f"task_{name}_runs_total", f"Task {name} runs", label_names=("result",))

        def _wrap(fn: Callable[..., Any]):
            if asyncio.iscoroutinefunction(fn):
                async def _inner(*args, **kwargs):
                    t0 = time.perf_counter()
                    try:
                        res = await fn(*args, **kwargs)
                        c.add(1, {"result": "ok"})
                        return res
                    except Exception:
                        c.add(1, {"result": "error"})
                        raise
                    finally:
                        h.record(time.perf_counter() - t0, {"result": "ok"})
                return _inner
            else:
                def _inner(*args, **kwargs):
                    t0 = time.perf_counter()
                    try:
                        res = fn(*args, **kwargs)
                        c.add(1, {"result": "ok"})
                        return res
                    except Exception:
                        c.add(1, {"result": "error"})
                        raise
                    finally:
                        h.record(time.perf_counter() - t0, {"result": "ok"})
                return _inner
        return _wrap

    # ---------- внутреннее: инициализация экспортеров ----------

    def _init_otel(self) -> None:
        resource = Resource.create({
            "service.name": self.cfg.service_name,
            "service.namespace": self.cfg.service_namespace,
            "service.version": self.cfg.service_version,
            "deployment.environment": self.cfg.deployment_env,
        })

        exporter = None
        headers = self._parse_headers(self.cfg.otlp_headers)

        if _OTLP_HTTP:
            exporter = OTLPMetricExporterHttp(endpoint=self._normalize_otlp_http(self.cfg.otlp_endpoint), headers=headers)
        elif _OTLP_GRPC:
            exporter = OTLPMetricExporterGrpc(endpoint=self._normalize_otlp_grpc(self.cfg.otlp_endpoint), headers=headers)
        else:
            # Нет экспортера — останемся без метрик
            self._meter = None
            return

        reader = PeriodicExportingMetricReader(exporter, export_interval_millis= int(os.getenv("OTEL_EXPORT_INTERVAL_MS", "30000")))
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        otel_metrics.set_meter_provider(provider)
        self._meter = get_meter(self.cfg.service_name)

    def _init_prometheus(self) -> None:
        # Поднимаем HTTP endpoint
        try:
            prom_start_http_server(self.cfg.prom_port, addr=self.cfg.prom_addr)
        except OSError:
            # Уже поднят
            pass
        # Namespace/subsystem для единообразия
        self._prom_namespace = self.cfg.service_namespace
        self._prom_subsystem = self.cfg.service_name
        # статические лейблы добавляем как обязательные имена для всех инструментов
        self._prom_registry_labels = self._static_label_names()

    def _static_label_names(self) -> Tuple[str, ...]:
        return ("env", "request_id", "tenant_id")

    @staticmethod
    def _parse_headers(h: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for pair in (h or "").split(","):
            if not pair.strip():
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _normalize_otlp_http(endpoint: str) -> str:
        # Ожидается базовый URL, SDK сам допишет /v1/metrics
        return endpoint.rstrip("/")

    @staticmethod
    def _normalize_otlp_grpc(endpoint: str) -> str:
        # Для gRPC endpoint может быть host:port без схемы
        return endpoint.replace("http://", "").replace("https://", "")


# -------------------------------
# Глобальный синглтон и удобные фабрики
# -------------------------------

_global_metrics: Optional[Metrics] = None

def get_metrics() -> Metrics:
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = Metrics()
        _global_metrics.init()
    return _global_metrics

# Удобные шорткаты
def counter(name: str, description: str = "", unit: str = "1", label_names: Sequence[str] = ()) -> _Counter:
    return get_metrics().counter(name, description, unit, label_names)

def histogram(name: str, description: str = "", unit: str = "s", label_names: Sequence[str] = (), buckets: Optional[Sequence[float]] = None) -> _Histogram:
    return get_metrics().histogram(name, description, unit, label_names, buckets)

def gauge(name: str, description: str = "", label_names: Sequence[str] = ()) -> _Gauge:
    return get_metrics().gauge(name, description, label_names)

def updown_counter(name: str, description: str = "", unit: str = "1", label_names: Sequence[str] = ()) -> _UpDownCounter:
    return get_metrics().updown_counter(name, description, unit, label_names)
