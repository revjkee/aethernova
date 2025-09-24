# File: security-core/security/telemetry/metrics.py
# Purpose: Industrial-grade metrics abstraction with Prometheus and optional OpenTelemetry backends.
# Python: 3.10+

from __future__ import annotations

import os
import re
import time
import types
import typing as t
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from time import perf_counter

import contextvars

# Optional deps
_PROM_AVAILABLE = False
_OTEL_AVAILABLE = False

try:
    # pip install prometheus_client>=0.16
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
    from prometheus_client.multiprocess import MultiProcessCollector  # type: ignore
    _PROM_AVAILABLE = True
except Exception:
    pass

try:
    # pip install opentelemetry-api opentelemetry-sdk
    from opentelemetry import metrics as otel_metrics  # type: ignore
    from opentelemetry.metrics import Meter  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:
    pass

try:
    # FastAPI/Starlette are optional, only for middleware/exporter
    from fastapi import FastAPI, Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import PlainTextResponse
except Exception:
    FastAPI = None  # type: ignore
    BaseHTTPMiddleware = object  # type: ignore
    Request = Response = PlainTextResponse = object  # type: ignore


# =========================
# Errors and utils
# =========================

class MetricsError(Exception):
    pass


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in {"1", "true", "yes", "on"}


def _ns() -> str:
    return os.getenv("METRICS_NAMESPACE", "security_core")


# =========================
# Label context (safe, low-cardinality)
# =========================

# Контекстные метки, автоматически добавляемые к метрикам HTTP и по желанию пользователя.
_label_ctx: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar("metrics_labels", default={})

SAFE_LABEL_KEYS = {"tenant", "subject", "endpoint"}

@contextmanager
def labels(**kv: str):
    """
    Контекстный менеджер для безопасных меток.
    Пример:
        with labels(tenant="acme", subject="user:123"):
            metrics.counter("my_events_total", "My events").inc({"event":"login"})
    """
    cur = _label_ctx.get().copy()
    for k, v in kv.items():
        if k in SAFE_LABEL_KEYS and isinstance(v, str):
            cur[k] = v
    token = _label_ctx.set(cur)
    try:
        yield
    finally:
        _label_ctx.reset(token)

def _current_labels() -> dict[str, str]:
    return dict(_label_ctx.get())


# =========================
# Backend abstraction
# =========================

class CounterHandle(t.Protocol):
    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None: ...

class GaugeHandle(t.Protocol):
    def set(self, value: float, labels: dict[str, str] | None = None) -> None: ...
    def add(self, delta: float, labels: dict[str, str] | None = None) -> None: ...

class HistogramHandle(t.Protocol):
    def observe(self, value: float, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None: ...

class MetricsBackend(t.Protocol):
    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> CounterHandle: ...
    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> GaugeHandle: ...
    def histogram(self, name: str, help: str, labelnames: tuple[str, ...] = (), buckets: tuple[float, ...] = ()) -> HistogramHandle: ...


# =========================
# Noop backend (default)
# =========================

class _NoopCounter:
    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        return

class _NoopGauge:
    def __init__(self) -> None:
        self._v = 0.0
    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        self._v = float(value)
    def add(self, delta: float, labels: dict[str, str] | None = None) -> None:
        self._v += float(delta)

class _NoopHistogram:
    def observe(self, value: float, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        return

class NoopBackend:
    def __init__(self) -> None:
        self._c: dict[str, _NoopCounter] = {}
        self._g: dict[str, _NoopGauge] = {}
        self._h: dict[str, _NoopHistogram] = {}
    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> CounterHandle:
        return self._c.setdefault(name, _NoopCounter())
    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> GaugeHandle:
        return self._g.setdefault(name, _NoopGauge())
    def histogram(self, name: str, help: str, labelnames: tuple[str, ...] = (), buckets: tuple[float, ...] = ()) -> HistogramHandle:
        return self._h.setdefault(name, _NoopHistogram())


# =========================
# Prometheus backend
# =========================

@dataclass
class PrometheusConfig:
    namespace: str = field(default_factory=_ns)
    registry: CollectorRegistry | None = None
    default_buckets: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

class PrometheusBackend:
    def __init__(self, cfg: PrometheusConfig | None = None) -> None:
        if not _PROM_AVAILABLE:
            raise MetricsError("prometheus_client is not installed")
        cfg = cfg or PrometheusConfig()
        self.cfg = cfg
        if cfg.registry:
            self.registry = cfg.registry
        else:
            mp_dir = os.getenv("PROMETHEUS_MULTIPROC_DIR")
            if mp_dir:
                # multiprocess mode
                reg = CollectorRegistry()
                MultiProcessCollector(reg)  # type: ignore
                self.registry = reg
            else:
                self.registry = CollectorRegistry(auto_describe=True)
        self._c: dict[tuple[str, tuple[str, ...]], Counter] = {}
        self._g: dict[tuple[str, tuple[str, ...]], Gauge] = {}
        self._h: dict[tuple[str, tuple[str, ...], tuple[float, ...]], Histogram] = {}

    def _sanitize(self, name: str) -> str:
        n = re.sub(r"[^a-zA-Z0-9_:]", "_", name)
        if not n.startswith(self.cfg.namespace + "_"):
            n = f"{self.cfg.namespace}_{n}"
        return n

    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> CounterHandle:
        key = (name, labelnames)
        metric = self._c.get(key)
        if metric is None:
            metric = Counter(self._sanitize(name), help, labelnames=labelnames, registry=self.registry)
            self._c[key] = metric
        return _PromCounter(metric, labelnames)

    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> GaugeHandle:
        key = (name, labelnames)
        metric = self._g.get(key)
        if metric is None:
            metric = Gauge(self._sanitize(name), help, labelnames=labelnames, registry=self.registry, multiprocess_mode="livesum")
            self._g[key] = metric
        return _PromGauge(metric, labelnames)

    def histogram(self, name: str, help: str, labelnames: tuple[str, ...] = (), buckets: tuple[float, ...] = ()) -> HistogramHandle:
        if not buckets:
            buckets = self.cfg.default_buckets
        key = (name, labelnames, buckets)
        metric = self._h.get(key)
        if metric is None:
            metric = Histogram(self._sanitize(name), help, labelnames=labelnames, registry=self.registry, buckets=buckets)
            self._h[key] = metric
        return _PromHistogram(metric, labelnames)

class _PromCounter:
    def __init__(self, metric: Counter, labelnames: tuple[str, ...]) -> None:
        self.m = metric
        self.labelnames = labelnames
    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        ls = labels or {}
        if self.labelnames:
            c = self.m.labels(*[ls.get(k, "") for k in self.labelnames])
            try:
                c.inc(amount, exemplar=exemplar)  # type: ignore[arg-type]
            except TypeError:
                c.inc(amount)
        else:
            try:
                self.m.inc(amount, exemplar=exemplar)  # type: ignore[arg-type]
            except TypeError:
                self.m.inc(amount)

class _PromGauge:
    def __init__(self, metric: Gauge, labelnames: tuple[str, ...]) -> None:
        self.m = metric
        self.labelnames = labelnames
    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        ls = labels or {}
        if self.labelnames:
            self.m.labels(*[ls.get(k, "") for k in self.labelnames]).set(value)
        else:
            self.m.set(value)
    def add(self, delta: float, labels: dict[str, str] | None = None) -> None:
        ls = labels or {}
        if self.labelnames:
            self.m.labels(*[ls.get(k, "") for k in self.labelnames]).inc(delta)
        else:
            self.m.inc(delta)

class _PromHistogram:
    def __init__(self, metric: Histogram, labelnames: tuple[str, ...]) -> None:
        self.m = metric
        self.labelnames = labelnames
    def observe(self, value: float, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        ls = labels or {}
        if self.labelnames:
            h = self.m.labels(*[ls.get(k, "") for k in self.labelnames])
            try:
                h.observe(value, exemplar=exemplar)  # type: ignore[arg-type]
            except TypeError:
                h.observe(value)
        else:
            try:
                self.m.observe(value, exemplar=exemplar)  # type: ignore[arg-type]
            except TypeError:
                self.m.observe(value)


# =========================
# OpenTelemetry backend (optional, best-effort)
# =========================

@dataclass
class OTelConfig:
    name: str = field(default_factory=_ns)

class OTelBackend:
    def __init__(self, cfg: OTelConfig | None = None) -> None:
        if not _OTEL_AVAILABLE:
            raise MetricsError("opentelemetry API is not installed")
        cfg = cfg or OTelConfig()
        self.meter: Meter = otel_metrics.get_meter(cfg.name)
        self._c: dict[tuple[str, tuple[str, ...]], t.Any] = {}
        self._h: dict[tuple[str, tuple[str, ...]], t.Any] = {}
        self._g: dict[tuple[str, tuple[str, ...]], t.Any] = {}

    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> CounterHandle:
        key = (name, labelnames)
        inst = self._c.get(key)
        if inst is None:
            inst = self.meter.create_counter(name, description=help)  # type: ignore[attr-defined]
            self._c[key] = inst
        return _OTelCounter(inst, labelnames)

    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> GaugeHandle:
        key = (name, labelnames)
        inst = self._g.get(key)
        if inst is None:
            try:
                inst = self.meter.create_observable_gauge(name, callbacks=[], description=help)  # pull-based
            except Exception:
                inst = self.meter.create_up_down_counter(name, description=help)  # fallback push-based
            self._g[key] = inst
        return _OTelGauge(inst, labelnames)

    def histogram(self, name: str, help: str, labelnames: tuple[str, ...] = (), buckets: tuple[float, ...] = ()) -> HistogramHandle:
        key = (name, labelnames)
        inst = self._h.get(key)
        if inst is None:
            inst = self.meter.create_histogram(name, description=help)  # type: ignore[attr-defined]
            self._h[key] = inst
        return _OTelHistogram(inst, labelnames)

class _OTelCounter:
    def __init__(self, inst: t.Any, labelnames: tuple[str, ...]) -> None:
        self.i = inst
        self.labelnames = labelnames
    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        attrs = {(k): (labels or {}).get(k, "") for k in self.labelnames}
        try:
            self.i.add(amount, attributes=attrs)  # type: ignore[attr-defined]
        except Exception:
            # best-effort across API versions
            self.i.add(amount)  # type: ignore

class _OTelGauge:
    def __init__(self, inst: t.Any, labelnames: tuple[str, ...]) -> None:
        self.i = inst
        self.labelnames = labelnames
        # only up_down_counter supports add; observable gauge is pull-based (no direct set)
        self._is_push = hasattr(inst, "add")
    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        if self._is_push:
            attrs = {(k): (labels or {}).get(k, "") for k in self.labelnames}
            try:
                self.i.add(value, attributes=attrs)  # type: ignore
            except Exception:
                self.i.add(value)  # type: ignore
        # else: ignore (pull model)
    def add(self, delta: float, labels: dict[str, str] | None = None) -> None:
        self.set(delta, labels)

class _OTelHistogram:
    def __init__(self, inst: t.Any, labelnames: tuple[str, ...]) -> None:
        self.i = inst
        self.labelnames = labelnames
    def observe(self, value: float, labels: dict[str, str] | None = None, exemplar: dict[str, str] | None = None) -> None:
        attrs = {(k): (labels or {}).get(k, "") for k in self.labelnames}
        try:
            self.i.record(value, attributes=attrs)  # type: ignore[attr-defined]
        except Exception:
            self.i.record(value)  # type: ignore


# =========================
# Public API facade
# =========================

@dataclass
class MetricSpec:
    name: str
    help: str
    labelnames: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()

class Metrics:
    """
    Унифицированный фасад над бэкендом.
    """
    def __init__(self, backend: MetricsBackend) -> None:
        self._backend = backend
        self._c: dict[str, CounterHandle] = {}
        self._g: dict[str, GaugeHandle] = {}
        self._h: dict[str, HistogramHandle] = {}

    # ---- Declarative accessors (lazy) ----
    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> CounterHandle:
        key = name + "|" + ",".join(labelnames)
        if key not in self._c:
            self._c[key] = self._backend.counter(name, help, labelnames)
        return self._c[key]

    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> GaugeHandle:
        key = name + "|" + ",".join(labelnames)
        if key not in self._g:
            self._g[key] = self._backend.gauge(name, help, labelnames)
        return self._g[key]

    def histogram(self, name: str, help: str, labelnames: tuple[str, ...] = (), buckets: tuple[float, ...] = ()) -> HistogramHandle:
        key = name + "|" + ",".join(labelnames) + "|" + ",".join(map(str, buckets))
        if key not in self._h:
            self._h[key] = self._backend.histogram(name, help, labelnames, buckets)
        return self._h[key]

    # ---- Convenience helpers ----
    def inc(self, name: str, help: str, labels: dict[str, str] | None = None, amount: float = 1.0, labelnames: tuple[str, ...] = ()) -> None:
        lb = self._merge_labels(labels)
        self.counter(name, help, labelnames or tuple(lb.keys())).inc(amount, lb)

    def set_gauge(self, name: str, help: str, value: float, labels: dict[str, str] | None = None, labelnames: tuple[str, ...] = ()) -> None:
        lb = self._merge_labels(labels)
        self.gauge(name, help, labelnames or tuple(lb.keys())).set(value, lb)

    def add_gauge(self, name: str, help: str, delta: float, labels: dict[str, str] | None = None, labelnames: tuple[str, ...] = ()) -> None:
        lb = self._merge_labels(labels)
        self.gauge(name, help, labelnames or tuple(lb.keys())).add(delta, lb)

    def observe(self, name: str, help: str, value: float, labels: dict[str, str] | None = None, buckets: tuple[float, ...] = (), labelnames: tuple[str, ...] = ()) -> None:
        lb = self._merge_labels(labels)
        self.histogram(name, help, labelnames or tuple(lb.keys()), buckets).observe(value, lb, _exemplar())

    @contextmanager
    def time(self, name: str, help: str, labels: dict[str, str] | None = None, buckets: tuple[float, ...] = (), labelnames: tuple[str, ...] = ()):
        start = perf_counter()
        try:
            yield
        finally:
            self.observe(name, help, perf_counter() - start, labels=labels, buckets=buckets, labelnames=labelnames)

    def _merge_labels(self, labels: dict[str, str] | None) -> dict[str, str]:
        base = _current_labels()
        if not labels:
            return base
        # ограждаем только строковые значения
        out = base.copy()
        for k, v in labels.items():
            if isinstance(v, str):
                out[k] = v
            else:
                out[k] = str(v)
        return out


# =========================
# HTTP instrumentation (FastAPI/Starlette)
# =========================

_DEFAULT_LAT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

class HTTPMetricsMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """
    Метрики HTTP уровня: latency, in-flight, request count.
    Метки: method, path_template, status, tenant.
    """
    def __init__(self, app, metrics: Metrics, *, buckets: tuple[float, ...] = _DEFAULT_LAT_BUCKETS):
        super().__init__(app)
        self.m = metrics
        self.buckets = buckets
        # Преддекларируем хэндлы (метки фиксированные для стабильности)
        self.h_latency = self.m.histogram(
            "http_server_request_duration_seconds",
            "HTTP server request latency seconds",
            labelnames=("method", "path", "status", "tenant"),
            buckets=self.buckets,
        )
        self.g_inflight = self.m.gauge(
            "http_server_in_flight_requests",
            "In-flight HTTP requests",
            labelnames=("method", "path", "tenant"),
        )
        self.c_total = self.m.counter(
            "http_server_requests_total",
            "Total HTTP requests",
            labelnames=("method", "path", "status", "tenant"),
        )

    async def dispatch(self, request: Request, call_next):
        start = perf_counter()
        method = (request.method or "GET").upper()
        path = _path_template(request)
        tenant = request.headers.get("X-Tenant-ID", "")[:64]
        self.g_inflight.add(1.0, {"method": method, "path": path, "tenant": tenant})
        status = "500"
        try:
            response: Response = await call_next(request)
            status = str(getattr(response, "status_code", 200))
            return response
        finally:
            dur = max(0.0, perf_counter() - start)
            ex = _exemplar()
            self.h_latency.observe(dur, {"method": method, "path": path, "status": status, "tenant": tenant}, exemplar=ex)
            self.c_total.inc(1.0, {"method": method, "path": path, "status": status, "tenant": tenant}, exemplar=ex)
            self.g_inflight.add(-1.0, {"method": method, "path": path, "tenant": tenant})


def _path_template(request: Request) -> str:
    # Низкая кардинальность: используем шаблон маршрута, иначе нормализуем
    route = request.scope.get("route")
    if route is not None:
        # FastAPI предоставляет .path_format, Starlette — .path
        tmpl = getattr(route, "path_format", None) or getattr(route, "path", None)
        if isinstance(tmpl, str):
            return tmpl
    # Fallback: нормализация параметров (цифры -> :id, UUID -> :uuid)
    path = request.url.path
    path = re.sub(r"/[0-9]+", "/:id", path)
    path = re.sub(r"/[0-9a-fA-F-]{36}", "/:uuid", path)
    return path


def _exemplar() -> dict[str, str] | None:
    """
    Экземплар для Prometheus (если поддерживается в клиенте) — trace_id, если доступен из W3C traceparent.
    Вызов в бэкенде защищён try/except; здесь просто собираем словарь.
    """
    # В этом модуле нет доступа к текущему Request; можно расширить через contextvar при подключении трассировки.
    trace_id = os.getenv("TRACE_ID")  # допускаем интеграцию через внешнее наполнение
    if not trace_id:
        return None
    if len(trace_id) > 64:
        trace_id = trace_id[:64]
    return {"trace_id": trace_id}


# =========================
# Prometheus exporter (ASGI)
# =========================

class PrometheusExporterApp:
    """
    Простой ASGI-обработчик для /metrics (Prometheus text format).
    """
    def __init__(self, backend: PrometheusBackend) -> None:
        self.backend = backend

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 500, "headers": []})
            await send({"type": "http.response.body", "body": b"Unsupported", "more_body": False})
            return
        if not _PROM_AVAILABLE:
            await send({"type": "http.response.start", "status": 500, "headers": []})
            await send({"type": "http.response.body", "body": b"Prometheus not available", "more_body": False})
            return
        body = generate_latest(backend_registry(self.backend))
        headers = [(b"content-type", CONTENT_TYPE_LATEST.encode("ascii"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})


def backend_registry(backend: PrometheusBackend) -> CollectorRegistry:
    return backend.registry  # type: ignore[attr-defined]


# =========================
# Builders / wiring
# =========================

@dataclass
class BuildConfig:
    backend: t.Literal["auto", "prometheus", "otel", "noop"] = "auto"
    namespace: str = field(default_factory=_ns)
    prometheus_registry: CollectorRegistry | None = None
    prometheus_buckets: tuple[float, ...] = _DEFAULT_LAT_BUCKETS

def build_backend(cfg: BuildConfig | None = None) -> MetricsBackend:
    cfg = cfg or BuildConfig()
    if cfg.backend == "noop":
        return NoopBackend()
    if cfg.backend == "prometheus" or (cfg.backend == "auto" and _PROM_AVAILABLE):
        return PrometheusBackend(PrometheusConfig(namespace=cfg.namespace, registry=cfg.prometheus_registry, default_buckets=cfg.prometheus_buckets))
    if cfg.backend == "otel" or (cfg.backend == "auto" and _OTEL_AVAILABLE):
        return OTelBackend(OTelConfig(name=cfg.namespace))
    return NoopBackend()

def build_metrics(cfg: BuildConfig | None = None) -> Metrics:
    return Metrics(build_backend(cfg))

def instrument_fastapi(app: FastAPI, metrics: Metrics, *, buckets: tuple[float, ...] = _DEFAULT_LAT_BUCKETS) -> None:
    """
    Подключает HTTP-метрики к FastAPI приложению.
    """
    if FastAPI is None or BaseHTTPMiddleware is object:
        raise MetricsError("FastAPI/Starlette are not installed")
    app.add_middleware(HTTPMetricsMiddleware, metrics=metrics, buckets=buckets)

def mount_prometheus_endpoint(app: FastAPI, backend: PrometheusBackend, path: str = "/metrics") -> None:
    """
    Монтирует /metrics. Для multiprocess режима укажите PROMETHEUS_MULTIPROC_DIR.
    """
    if FastAPI is None:
        raise MetricsError("FastAPI is not installed")
    app.mount(path, PrometheusExporterApp(backend))


# =========================
# Opinionated defaults ready-to-use
# =========================

# Экземпляр на «всё приложение», если требуется быстро начать:
_default_metrics: Metrics | None = None

def get_metrics() -> Metrics:
    global _default_metrics
    if _default_metrics is None:
        _default_metrics = build_metrics(BuildConfig(backend=os.getenv("METRICS_BACKEND", "auto")))
    return _default_metrics


# =========================
# Example: predefined metric helpers (optional)
# =========================

def record_db_query(duration_sec: float, *, outcome: str = "ok") -> None:
    """
    Пример доменной метрики БД.
    """
    m = get_metrics()
    m.observe(
        "db_query_duration_seconds",
        "DB query latency seconds",
        value=duration_sec,
        labels={"outcome": outcome},
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        labelnames=("outcome",) | tuple(_current_labels().keys()),  # стабильные метки
    )
