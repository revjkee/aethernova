# engine/telemetry/metrics.py
# Industrial-grade metrics facade with Prometheus & OpenTelemetry backends,
# runtime gauges, timers, FastAPI router, and safe fallbacks.
from __future__ import annotations

import atexit
import os
import time
import gc
import threading
import functools
import resource
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union

# ===== Optional deps detection =====
_PROM_OK = False
_OTEL_OK = False
_FASTAPI_OK = False

try:
    # prometheus_client >=0.13 recommended; supports multiprocess via env PROMETHEUS_MULTIPROC_DIR
    from prometheus_client import (
        CollectorRegistry,
        Counter as PmCounter,
        Gauge as PmGauge,
        Histogram as PmHistogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
        start_http_server as prom_start_http_server,
        PROCESS_COLLECTOR,
        PLATFORM_COLLECTOR,
        GC_COLLECTOR,
    )
    _PROM_OK = True
except Exception:
    _PROM_OK = False

try:
    # OpenTelemetry metrics (stable API in 1.24+). We guard usage.
    from opentelemetry import metrics as ot_metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter as OTLPMetricExporterHTTP
    _OTEL_OK = True
except Exception:
    _OTEL_OK = False

try:
    # FastAPI/Starlette optional router factory
    from fastapi import APIRouter, Response
    _FASTAPI_OK = True
except Exception:
    _FASTAPI_OK = False


# ===== Configuration =====

@dataclass(frozen=True)
class MetricsConfig:
    backend: str = "prometheus"  # "prometheus" | "otlp" | "noop"
    service_name: str = "engine-core"
    service_namespace: str = "default"
    instance_id: str = field(default_factory=lambda: f"{socket.gethostname()}-{os.getpid()}")
    default_labels: Dict[str, str] = field(default_factory=dict)
    # Prometheus options
    prometheus_port: Optional[int] = None         # If set, starts builtin HTTP server
    prometheus_addr: str = "0.0.0.0"
    enable_process_collectors: bool = True        # process, platform, gc
    # OTLP options
    otlp_endpoint: Optional[str] = None           # e.g. "http://otel-collector:4318"
    otlp_export_interval_sec: float = 10.0
    # Runtime gauges
    enable_runtime_gauges: bool = True
    runtime_poll_interval_sec: float = 5.0


def _normalize_labels(labels: Optional[Mapping[str, str]]) -> Dict[str, str]:
    d = dict(labels or {})
    # Prometheus label constraints: [a-zA-Z_][a-zA-Z0-9_]*
    # We minimally normalize common keys.
    normalized = {}
    for k, v in d.items():
        nk = k.replace("-", "_").replace(".", "_")
        if nk and nk[0].isdigit():
            nk = "_" + nk
        normalized[nk] = str(v)
    return normalized


# ===== Backend interface =====

class _CounterIF:
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None: ...


class _HistogramIF:
    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None: ...


class _GaugeIF:
    def set(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None: ...
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None: ...
    def dec(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None: ...


class _BackendIF:
    def counter(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _CounterIF: ...
    def histogram(self, name: str, description: str = "", label_names: Iterable[str] = (),
                  buckets: Optional[Iterable[float]] = None) -> _HistogramIF: ...
    def gauge(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _GaugeIF: ...
    def shutdown(self) -> None: ...


# ===== Prometheus backend =====

class _PromCounter(_CounterIF):
    def __init__(self, metric: PmCounter, default_labels: Mapping[str, str]):
        self._m = metric
        self._defaults = default_labels

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        lbls = {**self._defaults, **_normalize_labels(labels)}
        self._m.labels(**lbls).inc(amount)


class _PromHistogram(_HistogramIF):
    def __init__(self, metric: PmHistogram, default_labels: Mapping[str, str]):
        self._m = metric
        self._defaults = default_labels

    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        lbls = {**self._defaults, **_normalize_labels(labels)}
        self._m.labels(**lbls).observe(value)


class _PromGauge(_GaugeIF):
    def __init__(self, metric: PmGauge, default_labels: Mapping[str, str]):
        self._m = metric
        self._defaults = default_labels

    def set(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        lbls = {**self._defaults, **_normalize_labels(labels)}
        self._m.labels(**lbls).set(value)

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        lbls = {**self._defaults, **_normalize_labels(labels)}
        self._m.labels(**lbls).inc(amount)

    def dec(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        lbls = {**self._defaults, **_normalize_labels(labels)}
        self._m.labels(**lbls).dec(amount)


class PrometheusBackend(_BackendIF):
    def __init__(self, cfg: MetricsConfig):
        if not _PROM_OK:
            raise RuntimeError("prometheus_client is not available")
        # Multiprocess setup (Gunicorn/Uvicorn workers): if PROMETHEUS_MULTIPROC_DIR set, lib auto‑switches
        self._registry = CollectorRegistry()
        self._label_base = _normalize_labels({
            "service_name": cfg.service_name,
            "service_ns": cfg.service_namespace,
            "instance_id": cfg.instance_id,
            **cfg.default_labels,
        })
        # Register default collectors
        if cfg.enable_process_collectors:
            try:
                self._registry.register(PROCESS_COLLECTOR)
                self._registry.register(PLATFORM_COLLECTOR)
                self._registry.register(GC_COLLECTOR)
            except Exception:
                # already registered in multiprocess mode; ignore
                pass
        self._metrics_cache: Dict[Tuple[str, str], Any] = {}
        self._lock = threading.RLock()

        # Optional embedded HTTP server
        self._http_server_started = False
        if cfg.prometheus_port:
            prom_start_http_server(addr=cfg.prometheus_addr, port=cfg.prometheus_port, registry=self._registry)
            self._http_server_started = True

    def _labels(self, extra: Iterable[str]) -> Tuple[str, ...]:
        # Ensure stable, sorted label schema
        base = tuple(sorted(self._label_base.keys()))
        ex = tuple(sorted(_normalize_labels({k: "x" for k in extra}).keys()))
        # Merge preserving base first then extras minus duplicates
        merged = base + tuple(k for k in ex if k not in base)
        return merged

    def counter(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _CounterIF:
        key = ("counter", name)
        with self._lock:
            if key not in self._metrics_cache:
                label_schema = self._labels(label_names)
                m = PmCounter(name, description, labelnames=label_schema, registry=self._registry)
                self._metrics_cache[key] = _PromCounter(m, self._label_base)
            return self._metrics_cache[key]

    def histogram(self, name: str, description: str = "", label_names: Iterable[str] = (),
                  buckets: Optional[Iterable[float]] = None) -> _HistogramIF:
        key = ("histogram", name)
        with self._lock:
            if key not in self._metrics_cache:
                label_schema = self._labels(label_names)
                m = PmHistogram(name, description, labelnames=label_schema,
                                registry=self._registry, buckets=tuple(buckets) if buckets else None)
                self._metrics_cache[key] = _PromHistogram(m, self._label_base)
            return self._metrics_cache[key]

    def gauge(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _GaugeIF:
        key = ("gauge", name)
        with self._lock:
            if key not in self._metrics_cache:
                label_schema = self._labels(label_names)
                m = PmGauge(name, description, labelnames=label_schema, registry=self._registry)
                self._metrics_cache[key] = _PromGauge(m, self._label_base)
            return self._metrics_cache[key]

    def generate_latest(self) -> bytes:
        return generate_latest(self._registry)

    def shutdown(self) -> None:
        # Nothing special for client library
        pass


# ===== OpenTelemetry backend =====

class _OtelCounter(_CounterIF):
    def __init__(self, inst, defaults: Mapping[str, str]):
        self._inst = inst
        self._defaults = defaults

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        attrs = {**self._defaults, **(labels or {})}
        self._inst.add(amount, attributes=attrs)


class _OtelHistogram(_HistogramIF):
    def __init__(self, inst, defaults: Mapping[str, str]):
        self._inst = inst
        self._defaults = defaults

    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        attrs = {**self._defaults, **(labels or {})}
        self._inst.record(value, attributes=attrs)


class _OtelGauge(_GaugeIF):
    # Use synchronous "last value" via internal state + observable gauge callback pattern
    def __init__(self, meter, name: str, description: str, defaults: Mapping[str, str]):
        self._value = 0.0
        self._lock = threading.Lock()
        self._defaults = defaults
        self._obs = meter.create_observable_gauge(
            name,
            callbacks=[self._callback],
            description=description,
        )

    def _callback(self, observer):
        with self._lock:
            observer.observe(self._value, attributes=self._defaults)

    def set(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            self._value = float(value)

    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            self._value += float(amount)

    def dec(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        with self._lock:
            self._value -= float(amount)


class OpenTelemetryBackend(_BackendIF):
    def __init__(self, cfg: MetricsConfig):
        if not _OTEL_OK:
            raise RuntimeError("opentelemetry metrics not available")
        self._label_base = {
            "service.name": cfg.service_name,
            "service.namespace": cfg.service_namespace,
            "service.instance.id": cfg.instance_id,
            **cfg.default_labels,
        }
        exporter_endpoint = cfg.otlp_endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if not exporter_endpoint:
            # We still allow a MeterProvider, but nothing will be exported
            exporter = None
            self._reader = None
        else:
            exporter = OTLPMetricExporterHTTP(endpoint=exporter_endpoint)  # HTTP/4318
            self._reader = PeriodicExportingMetricReader(exporter, export_interval_millis=int(cfg.otlp_export_interval_sec * 1000))
        provider = MeterProvider(metric_readers=[self._reader] if self._reader else None)
        ot_metrics.set_meter_provider(provider)
        self._meter = ot_metrics.get_meter(cfg.service_name)
        self._metrics_cache: Dict[Tuple[str, str], Any] = {}
        self._lock = threading.RLock()
        self._provider = provider

    def counter(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _CounterIF:
        key = ("counter", name)
        with self._lock:
            if key not in self._metrics_cache:
                inst = self._meter.create_counter(name, description=description)
                self._metrics_cache[key] = _OtelCounter(inst, self._label_base)
            return self._metrics_cache[key]

    def histogram(self, name: str, description: str = "", label_names: Iterable[str] = (),
                  buckets: Optional[Iterable[float]] = None) -> _HistogramIF:
        # OTel explicit bucket histograms configured on collector side; we just record.
        key = ("histogram", name)
        with self._lock:
            if key not in self._metrics_cache:
                inst = self._meter.create_histogram(name, description=description)
                self._metrics_cache[key] = _OtelHistogram(inst, self._label_base)
            return self._metrics_cache[key]

    def gauge(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _GaugeIF:
        key = ("gauge", name)
        with self._lock:
            if key not in self._metrics_cache:
                g = _OtelGauge(self._meter, name, description, self._label_base)
                self._metrics_cache[key] = g
            return self._metrics_cache[key]

    def shutdown(self) -> None:
        try:
            self._provider.shutdown()
        except Exception:
            pass


# ===== No-op backend =====

class _NoopCounter(_CounterIF):
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        return None

class _NoopHistogram(_HistogramIF):
    def observe(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        return None

class _NoopGauge(_GaugeIF):
    def set(self, value: float, labels: Optional[Mapping[str, str]] = None) -> None:
        return None
    def inc(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        return None
    def dec(self, amount: float = 1.0, labels: Optional[Mapping[str, str]] = None) -> None:
        return None

class NoopBackend(_BackendIF):
    def counter(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _CounterIF:
        return _NoopCounter()
    def histogram(self, name: str, description: str = "", label_names: Iterable[str] = (),
                  buckets: Optional[Iterable[float]] = None) -> _HistogramIF:
        return _NoopHistogram()
    def gauge(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _GaugeIF:
        return _NoopGauge()
    def shutdown(self) -> None:
        return None


# ===== Facade / Registry =====

class _MetricsFacade:
    def __init__(self, backend: _BackendIF, cfg: MetricsConfig):
        self._backend = backend
        self._cfg = cfg
        self._runtime_thread: Optional[threading.Thread] = None
        self._runtime_stop = threading.Event()
        # Common metrics
        self._m_req_total = self.counter("app_requests_total", "Total application requests", ("route", "method", "code"))
        self._m_req_latency = self.histogram(
            "app_request_latency_seconds",
            "Request latency in seconds",
            ("route", "method", "code"),
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        )
        if cfg.enable_runtime_gauges:
            self._g_cpu = self.gauge("process_cpu_seconds_total", "User+System CPU seconds (approx)")
            self._g_rss = self.gauge("process_resident_memory_bytes", "RSS bytes")
            self._g_gc_gen0 = self.gauge("python_gc_gen0_objects", "GC gen0 objects")
            self._g_gc_gen1 = self.gauge("python_gc_gen1_objects", "GC gen1 objects")
            self._g_gc_gen2 = self.gauge("python_gc_gen2_objects", "GC gen2 objects")
            self._start_runtime_poll()

        atexit.register(self.shutdown)

    # Factories
    def counter(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _CounterIF:
        return self._backend.counter(name, description, label_names)

    def histogram(self, name: str, description: str = "", label_names: Iterable[str] = (),
                  buckets: Optional[Iterable[float]] = None) -> _HistogramIF:
        return self._backend.histogram(name, description, label_names, buckets)

    def gauge(self, name: str, description: str = "", label_names: Iterable[str] = ()) -> _GaugeIF:
        return self._backend.gauge(name, description, label_names)

    # Helpers
    def observe_request(self, route: str, method: str, code: Union[int, str], latency_s: float) -> None:
        labels = {"route": route, "method": method, "code": str(code)}
        self._m_req_total.inc(1.0, labels=labels)
        self._m_req_latency.observe(latency_s, labels=labels)

    def metrics_timer(self, name: str, description: str = "", label_names: Iterable[str] = ()):
        """Decorator + context manager to record elapsed seconds into histogram."""
        hist = self.histogram(name, description, label_names, buckets=(0.001,0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5,10))

        class _TimerCtx:
            def __init__(self, labels: Optional[Mapping[str, str]] = None):
                self._labels = labels
            def __enter__(self):
                self._t = time.perf_counter()
                return self
            def __exit__(self, exc_type, exc, tb):
                dt = time.perf_counter() - self._t
                hist.observe(dt, labels=self._labels)

        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                try:
                    return func(*args, **kwargs)
                finally:
                    hist.observe(time.perf_counter() - start, labels=None)
            return wrapper
        decorator.context = _TimerCtx  # type: ignore
        return decorator

    def _start_runtime_poll(self):
        if self._runtime_thread:
            return
        def _poll():
            last_cpu = resource.getrusage(resource.RUSAGE_SELF)
            while not self._runtime_stop.wait(self._cfg.runtime_poll_interval_sec):
                r = resource.getrusage(resource.RUSAGE_SELF)
                cpu_sec = float(r.ru_utime + r.ru_stime)
                self._g_cpu.set(cpu_sec)
                # RSS in kilobytes on Linux via ru_maxrss; convert to bytes
                rss_bytes = int(r.ru_maxrss) * 1024
                self._g_rss.set(float(rss_bytes))
                # GC stats
                try:
                    gen = gc.get_count()
                    self._g_gc_gen0.set(float(gen[0] if len(gen) > 0 else 0))
                    self._g_gc_gen1.set(float(gen[1] if len(gen) > 1 else 0))
                    self._g_gc_gen2.set(float(gen[2] if len(gen) > 2 else 0))
                except Exception:
                    pass
                last_cpu = r
        t = threading.Thread(target=_poll, name="metrics-runtime-poller", daemon=True)
        t.start()
        self._runtime_thread = t

    # FastAPI router (optional)
    def make_fastapi_router(self):
        if not _FASTAPI_OK:
            raise RuntimeError("FastAPI is not installed")
        if not isinstance(self._backend, PrometheusBackend):
            # Only Prometheus provides plaintext exposition
            raise RuntimeError("FastAPI /metrics is supported with Prometheus backend")
        router = APIRouter()
        content_type = CONTENT_TYPE_LATEST

        @router.get("/metrics")
        def metrics_endpoint():
            data = self._backend.generate_latest()  # type: ignore
            return Response(content=data, media_type=content_type)

        return router

    def start_http_server(self, port: int, addr: str = "0.0.0.0"):
        if not isinstance(self._backend, PrometheusBackend):
            raise RuntimeError("Embedded HTTP /metrics works only with Prometheus backend")
        prom_start_http_server(port=port, addr=addr, registry=self._backend._registry)  # type: ignore

    def shutdown(self):
        self._runtime_stop.set()
        try:
            self._backend.shutdown()
        except Exception:
            pass


# ===== Global singleton =====

_lock = threading.RLock()
_singleton: Optional[_MetricsFacade] = None
_cfg: Optional[MetricsConfig] = None

def init_metrics(config: MetricsConfig) -> _MetricsFacade:
    global _singleton, _cfg
    with _lock:
        backend_name = (config.backend or "prometheus").lower()
        if backend_name == "prometheus" and _PROM_OK:
            backend = PrometheusBackend(config)
        elif backend_name == "otlp" and _OTEL_OK:
            backend = OpenTelemetryBackend(config)
        elif backend_name == "noop":
            backend = NoopBackend()
        else:
            # Fallback if requested backend not available
            backend = PrometheusBackend(config) if _PROM_OK else (OpenTelemetryBackend(config) if _OTEL_OK else NoopBackend())
        _singleton = _MetricsFacade(backend, config)
        _cfg = config
        return _singleton

def metrics() -> _MetricsFacade:
    if _singleton is None:
        # Implicit init with noop to avoid crashes before explicit init
        init_metrics(MetricsConfig(backend="noop"))
    return _singleton  # type: ignore


# ===== Convenience decorators & helpers =====

def metrics_timer(name: str, description: str = "", label_names: Iterable[str] = ()):
    """Shortcut for metrics().metrics_timer(...)"""
    return metrics().metrics_timer(name, description, label_names)

def observe_request(route: str, method: str, code: Union[int, str], latency_s: float) -> None:
    metrics().observe_request(route, method, code, latency_s)


# ===== Example of minimal FastAPI integration (optional) =====
# (not executed automatically; for reference usage)
"""
from fastapi import FastAPI
from engine.telemetry.metrics import init_metrics, MetricsConfig, metrics

app = FastAPI()
init_metrics(MetricsConfig(backend="prometheus", service_name="api", prometheus_port=None))
app.include_router(metrics().make_fastapi_router())  # exposes GET /metrics
"""
