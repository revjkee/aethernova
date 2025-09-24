# oblivionvault-core/oblivionvault/observability/metrics.py
"""
Industrial-grade metrics facade for OblivionVault.

Features:
- Unified API for Prometheus and OpenTelemetry (OTLP), or both, with graceful NOOP fallback.
- Pydantic-based configuration (with ENV overrides).
- Safe multiprocess Prometheus (PROMETHEUS_MULTIPROC_DIR) + process/platform/GC collectors.
- OTLP exporter with PeriodicExportingMetricReader (gRPC/HTTP), proper shutdown.
- Thread-safe instrument caches, strict label sanitation, global constant labels.
- Counters, Histograms (with tuned buckets), Observable Gauges.
- Timing helpers: context manager and decorator to track latencies.
- HTTP snapshot for Prometheus text exposition when embedding in existing web servers.

Env hints (examples):
  OV_METRICS_BACKEND=prometheus|otlp|both|noop
  OV_PROM_ADDR=0.0.0.0
  OV_PROM_PORT=9090
  OV_SERVICE_NAME=oblivionvault
  OV_SERVICE_VERSION=1.0.0
  OV_ENV=prod
  OV_REGION=eu-central
  OV_INSTANCE_ID=$(hostname)
  # OTLP (standard OpenTelemetry envs also supported)
  OV_OTLP_ENDPOINT=http://otel-collector:4318
  OV_OTLP_PROTOCOL=http/protobuf    # or grpc
  OV_OTLP_TIMEOUT_MS=10000
"""

from __future__ import annotations

import atexit
import os
import re
import threading
import time
from contextlib import ContextDecorator, contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

# ---- Optional deps gates ------------------------------------------------------

_PROM_OK = False
_OTEL_OK = False

# Prometheus client (optional)
try:
    from prometheus_client import (
        CollectorRegistry,
        Counter as P8sCounter,
        Histogram as P8sHistogram,
        Gauge as P8sGauge,
        generate_latest,
        CONTENT_TYPE_LATEST,
        start_http_server as _p8s_start_http_server,
        multiprocess as p8s_mp,
    )
    # process/platform/GC collectors are version-dependent: guard safely
    try:
        from prometheus_client import ProcessCollector, PlatformCollector, GCCollector
        _PROM_STD_COLLECTORS = ("ProcessCollector", "PlatformCollector", "GCCollector")
    except Exception:  # pragma: no cover
        ProcessCollector = PlatformCollector = GCCollector = None  # type: ignore
        _PROM_STD_COLLECTORS = ()
    _PROM_OK = True
except Exception:  # pragma: no cover
    _PROM_OK = False

# OpenTelemetry (optional)
try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter as OTLPMetricExporterGRPC
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter as OTLPMetricExporterHTTP
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.metrics import Observation
    _OTEL_OK = True
except Exception:  # pragma: no cover
    _OTEL_OK = False

# Pydantic config (optional)
try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    class BaseModel:  # type: ignore
        pass
    def Field(default=None, **kwargs):  # type: ignore
        return default


# ---- Errors -------------------------------------------------------------------

class MetricsError(Exception):
    pass


# ---- Configuration ------------------------------------------------------------

class MetricsBackend:
    PROMETHEUS = "prometheus"
    OTLP = "otlp"
    BOTH = "both"
    NOOP = "noop"


class MetricsConfig(BaseModel):
    backend: str = Field(default=os.getenv("OV_METRICS_BACKEND", MetricsBackend.BOTH))
    service_name: str = Field(default=os.getenv("OV_SERVICE_NAME", "oblivionvault"))
    service_version: str = Field(default=os.getenv("OV_SERVICE_VERSION", "0.0.0"))
    environment: str = Field(default=os.getenv("OV_ENV", "dev"))
    region: str = Field(default=os.getenv("OV_REGION", "local"))
    instance_id: str = Field(default=os.getenv("OV_INSTANCE_ID", "unknown"))

    # Prometheus exposition
    prom_addr: str = Field(default=os.getenv("OV_PROM_ADDR", "0.0.0.0"))
    prom_port: int = Field(default=int(os.getenv("OV_PROM_PORT", "0")))  # 0 disables server
    prom_histogram_buckets: Tuple[float, ...] = Field(
        default=(
            0.001, 0.002, 0.005,
            0.01, 0.02, 0.05,
            0.1, 0.2, 0.5,
            1.0, 2.0, 5.0, 10.0
        ),
        description="Latency buckets in seconds."
    )

    # OTLP exporter
    otlp_endpoint: Optional[str] = Field(default=os.getenv("OV_OTLP_ENDPOINT"))
    otlp_protocol: str = Field(default=os.getenv("OV_OTLP_PROTOCOL", "grpc"))  # grpc | http/protobuf
    otlp_timeout_ms: int = Field(default=int(os.getenv("OV_OTLP_TIMEOUT_MS", "10000")))
    otlp_export_interval_s: float = Field(default=float(os.getenv("OV_OTLP_EXPORT_INTERVAL_S", "10")))

    # Label limits to curb cardinality explosions
    max_label_key_len: int = Field(default=64)
    max_label_val_len: int = Field(default=256)
    max_labels: int = Field(default=10)

    @classmethod
    def from_env(cls) -> "MetricsConfig":
        return cls()  # all fields already take env by default


# ---- Label sanitizer ----------------------------------------------------------

_LABEL_KEY_RE = re.compile(r"[^a-zA-Z0-9_:]")  # Prom-friendly
def _sanitize_labels(
    cfg: MetricsConfig,
    labels: Optional[Mapping[str, Any]],
    global_labels: Mapping[str, str],
) -> Dict[str, str]:
    merged: Dict[str, str] = dict(global_labels)
    if labels:
        for k, v in labels.items():
            if len(merged) >= cfg.max_labels + len(global_labels):
                break
            sk = _LABEL_KEY_RE.sub("_", str(k))[: cfg.max_label_key_len]
            sv = str(v)
            if len(sv) > cfg.max_label_val_len:
                sv = sv[: cfg.max_label_val_len]
            merged[sk] = sv
    return merged


# ---- Facade implementation ----------------------------------------------------

@dataclass(frozen=True)
class _InstrumentKey:
    name: str
    unit: Optional[str]
    description: Optional[str]
    label_names: Tuple[str, ...]


class _NoopCounter:
    def inc(self, amount: float = 1.0, **labels): pass  # noqa: E701
    def add(self, amount: float = 1.0, **labels): pass  # alias


class _NoopHistogram:
    def observe(self, value: float, **labels): pass  # noqa: E701
    def record(self, value: float, **labels): pass   # alias


class _NoopGauge:
    def set(self, value: float, **labels): pass  # noqa: E701


class Metrics:
    """
    Unified metrics facade.

    Use:
      metrics = get_metrics()
      metrics.counter_inc("vault_storage_ops_total", labels={"op":"write","status":"ok"})
      with metrics.time_block("vault_storage_latency_seconds", labels={"op":"write"}):
          ...
    """
    def __init__(self, cfg: MetricsConfig):
        self._cfg = cfg
        self._lock = threading.RLock()
        self._global_labels = {
            "service": cfg.service_name,
            "version": cfg.service_version,
            "env": cfg.environment,
            "region": cfg.region,
            "instance": cfg.instance_id,
        }

        # Decide active backends
        backend = (cfg.backend or MetricsBackend.BOTH).lower()
        if backend not in (MetricsBackend.PROMETHEUS, MetricsBackend.OTLP, MetricsBackend.BOTH, MetricsBackend.NOOP):
            backend = MetricsBackend.NOOP

        self._use_prom = backend in (MetricsBackend.PROMETHEUS, MetricsBackend.BOTH)
        self._use_otel = backend in (MetricsBackend.OTLP, MetricsBackend.BOTH)

        # Backends init
        self._prom_registry: Optional["CollectorRegistry"] = None
        self._prom_counters: Dict[_InstrumentKey, "P8sCounter"] = {}
        self._prom_hist: Dict[_InstrumentKey, "P8sHistogram"] = {}
        self._prom_gauges: Dict[_InstrumentKey, "P8sGauge"] = {}

        self._otel_provider: Optional["MeterProvider"] = None
        self._otel_meter = None
        self._otel_counters: Dict[_InstrumentKey, Any] = {}
        self._otel_hist: Dict[_InstrumentKey, Any] = {}
        self._otel_gauges: Dict[_InstrumentKey, Callable[[], float]] = {}
        self._otel_reader: Optional["PeriodicExportingMetricReader"] = None

        self._init_prometheus()
        self._init_opentelemetry()

        # Optional Prometheus HTTP server (non-blocking)
        if self._use_prom and self._cfg.prom_port and _PROM_OK:
            try:
                _p8s_start_http_server(self._cfg.prom_port, addr=self._cfg.prom_addr, registry=self._prom_registry)
            except Exception:
                # Do not raise on binding errors
                pass

        # Ensure clean shutdown for OTel
        atexit.register(self._shutdown)

    # ---- Init: Prometheus -----------------------------------------------------

    def _init_prometheus(self) -> None:
        if not self._use_prom or not _PROM_OK:
            return
        if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
            reg = CollectorRegistry()
            # MultiProcessCollector merges child registries
            p8s_mp.MultiProcessCollector(reg)
            self._prom_registry = reg
            return

        reg = CollectorRegistry()
        # register standard collectors if available
        try:
            if ProcessCollector:
                ProcessCollector(registry=reg)  # type: ignore
            if PlatformCollector:
                PlatformCollector(registry=reg)  # type: ignore
            if GCCollector:
                GCCollector(registry=reg)  # type: ignore
        except Exception:
            # If collectors unavailable — continue
            pass
        self._prom_registry = reg

    # ---- Init: OpenTelemetry --------------------------------------------------

    def _init_opentelemetry(self) -> None:
        if not self._use_otel or not _OTEL_OK:
            return
        endpoint = self._cfg.otlp_endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        protocol = (self._cfg.otlp_protocol or os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL") or "grpc").lower()
        timeout_ms = self._cfg.otlp_timeout_ms

        exporter = None
        try:
            if protocol == "http" or protocol == "http/protobuf":
                exporter = OTLPMetricExporterHTTP(endpoint=endpoint, timeout=timeout_ms / 1000.0)
            else:
                exporter = OTLPMetricExporterGRPC(endpoint=endpoint, timeout=timeout_ms / 1000.0)
        except Exception:
            exporter = None

        readers = []
        if exporter is not None:
            try:
                reader = PeriodicExportingMetricReader(exporter, export_interval_millis=int(self._cfg.otlp_export_interval_s * 1000))
                readers.append(reader)
                self._otel_reader = reader
            except Exception:
                pass

        resource = Resource.create({
            "service.name": self._cfg.service_name,
            "service.version": self._cfg.service_version,
            "deployment.environment": self._cfg.environment,
            "service.instance.id": self._cfg.instance_id,
            "cloud.region": self._cfg.region,
        })
        try:
            provider = MeterProvider(resource=resource, metric_readers=readers)
            otel_metrics.set_meter_provider(provider)
            self._otel_provider = provider
            self._otel_meter = otel_metrics.get_meter(self._cfg.service_name, self._cfg.service_version)
        except Exception:
            self._otel_provider = None
            self._otel_meter = None

    # ---- Public API: counters -------------------------------------------------

    def counter_inc(
        self,
        name: str,
        amount: Union[int, float] = 1,
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        """Increment a counter instrument."""
        label_map = _sanitize_labels(self._cfg, labels, self._global_labels)

        if self._use_prom and _PROM_OK:
            c = self._get_prom_counter(name, unit, description, tuple(sorted(label_map.keys())))
            try:
                c.labels(**label_map).inc(amount)
            except Exception:
                pass

        if self._use_otel and _OTEL_OK and self._otel_meter is not None:
            c = self._get_otel_counter(name, unit, description, tuple(sorted(label_map.keys())))
            try:
                c.add(amount, attributes=label_map)
            except Exception:
                pass

    # ---- Public API: histograms ----------------------------------------------

    def histogram_observe(
        self,
        name: str,
        value: Union[int, float],
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: Optional[str] = "s",
        description: Optional[str] = None,
        buckets: Optional[Iterable[float]] = None,
    ) -> None:
        """Record an observation into a histogram."""
        label_map = _sanitize_labels(self._cfg, labels, self._global_labels)
        buckets = tuple(buckets) if buckets is not None else self._cfg.prom_histogram_buckets

        if self._use_prom and _PROM_OK:
            h = self._get_prom_histogram(name, unit, description, tuple(sorted(label_map.keys())), buckets)
            try:
                h.labels(**label_map).observe(float(value))
            except Exception:
                pass

        if self._use_otel and _OTEL_OK and self._otel_meter is not None:
            h = self._get_otel_histogram(name, unit, description, tuple(sorted(label_map.keys())))
            try:
                h.record(float(value), attributes=label_map)
            except Exception:
                pass

    # ---- Public API: gauges ---------------------------------------------------

    def gauge_set(
        self,
        name: str,
        value: Union[int, float],
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        """
        Set a gauge value (Prometheus). For OTel, prefer observable gauges via register_observable_gauge().
        """
        label_map = _sanitize_labels(self._cfg, labels, self._global_labels)

        if self._use_prom and _PROM_OK:
            g = self._get_prom_gauge(name, unit, description, tuple(sorted(label_map.keys())))
            try:
                g.labels(**label_map).set(float(value))
            except Exception:
                pass
        # OTel direct-set gauge is not in the stable API; use observable callback.

    def register_observable_gauge(
        self,
        name: str,
        callback: Callable[[], float],
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        """
        Register an observable gauge.
        - Prometheus: emulate via periodic set() calls is out-of-scope here;
          use gauge_set() from your scheduler if needed.
        - OTel: register callback that gets pulled by the reader.
        """
        label_map = _sanitize_labels(self._cfg, labels, self._global_labels)

        # Keep a prom gauge around for manual .set if caller wants to push
        if self._use_prom and _PROM_OK:
            self._get_prom_gauge(name, unit, description, tuple(sorted(label_map.keys())))

        if self._use_otel and _OTEL_OK and self._otel_meter is not None:
            key = self._key(name, unit, description, tuple(sorted(label_map.keys())))
            with self._lock:
                if key not in self._otel_gauges:
                    def _cb(_opts=None):
                        try:
                            val = float(callback())
                        except Exception:
                            return []
                        return [Observation(val, attributes=label_map)]
                    try:
                        self._otel_meter.create_observable_gauge(
                            name,
                            [ _cb ],  # list of callbacks
                            unit=unit,
                            description=description,
                        )
                        self._otel_gauges[key] = callback
                    except Exception:
                        pass

    # ---- Timing utilities -----------------------------------------------------

    @contextmanager
    def time_block(
        self,
        histogram_name: str,
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: str = "s",
        description: Optional[str] = None,
        buckets: Optional[Iterable[float]] = None,
    ):
        """Context manager to measure latency and record to histogram."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.histogram_observe(
                histogram_name,
                elapsed,
                labels=labels,
                unit=unit,
                description=description,
                buckets=buckets,
            )

    def timeit(
        self,
        histogram_name: str,
        *,
        labels: Optional[Mapping[str, Any]] = None,
        unit: str = "s",
        description: Optional[str] = None,
        buckets: Optional[Iterable[float]] = None,
    ) -> ContextDecorator:
        """Decorator to measure function latency and record to histogram."""
        metrics = self
        class _Decorator(ContextDecorator):
            def __call__(self, fn):
                def _wrapper(*args, **kwargs):
                    with metrics.time_block(histogram_name, labels=labels, unit=unit, description=description, buckets=buckets):
                        return fn(*args, **kwargs)
                return _wrapper
        return _Decorator()

    # ---- HTTP snapshot for Prometheus ----------------------------------------

    def metrics_as_text(self) -> Tuple[str, str]:
        """
        Return (content_type, payload) suitable for HTTP response.
        Works only for Prometheus; returns empty payload otherwise.
        """
        if self._use_prom and _PROM_OK and self._prom_registry is not None:
            try:
                payload = generate_latest(self._prom_registry).decode("utf-8", errors="replace")
                return CONTENT_TYPE_LATEST, payload
            except Exception:
                return "text/plain; charset=utf-8", ""
        return "text/plain; charset=utf-8", ""

    def start_prometheus_http_server(self, port: int, addr: str = "0.0.0.0") -> None:
        """Start Prometheus exposition server (non-blocking)."""
        if self._use_prom and _PROM_OK and self._prom_registry is not None:
            try:
                _p8s_start_http_server(port, addr=addr, registry=self._prom_registry)
            except Exception:
                pass

    # ---- Internals: instrument caches ----------------------------------------

    def _key(
        self,
        name: str,
        unit: Optional[str],
        description: Optional[str],
        label_names: Tuple[str, ...],
    ) -> _InstrumentKey:
        return _InstrumentKey(name=name, unit=unit, description=description, label_names=label_names)

    def _get_prom_counter(self, name: str, unit: Optional[str], description: Optional[str], label_names: Tuple[str, ...]) -> "P8sCounter":
        key = self._key(name, unit, description, label_names)
        with self._lock:
            inst = self._prom_counters.get(key)
            if inst:
                return inst
            # Prometheus: name must be snake_case and unit usually appended to name if desired
            help_text = description or ""
            inst = P8sCounter(name, help_text, labelnames=list(label_names), registry=self._prom_registry)
            self._prom_counters[key] = inst
            return inst

    def _get_prom_histogram(
        self,
        name: str,
        unit: Optional[str],
        description: Optional[str],
        label_names: Tuple[str, ...],
        buckets: Tuple[float, ...],
    ) -> "P8sHistogram":
        key = self._key(name, unit, description, label_names)
        with self._lock:
            inst = self._prom_hist.get(key)
            if inst:
                return inst
            help_text = description or ""
            inst = P8sHistogram(name, help_text, labelnames=list(label_names), buckets=buckets, registry=self._prom_registry)
            self._prom_hist[key] = inst
            return inst

    def _get_prom_gauge(self, name: str, unit: Optional[str], description: Optional[str], label_names: Tuple[str, ...]) -> "P8sGauge":
        key = self._key(name, unit, description, label_names)
        with self._lock:
            inst = self._prom_gauges.get(key)
            if inst:
                return inst
            help_text = description or ""
            inst = P8sGauge(name, help_text, labelnames=list(label_names), registry=self._prom_registry)
            self._prom_gauges[key] = inst
            return inst

    def _get_otel_counter(self, name: str, unit: Optional[str], description: Optional[str], label_names: Tuple[str, ...]):
        key = self._key(name, unit, description, label_names)
        with self._lock:
            inst = self._otel_counters.get(key)
            if inst:
                return inst
            if self._otel_meter is None:
                return _NoopCounter()
            try:
                inst = self._otel_meter.create_counter(name, unit=unit, description=description)
                self._otel_counters[key] = inst
                return inst
            except Exception:
                return _NoopCounter()

    def _get_otel_histogram(self, name: str, unit: Optional[str], description: Optional[str], label_names: Tuple[str, ...]):
        key = self._key(name, unit, description, label_names)
        with self._lock:
            inst = self._otel_hist.get(key)
            if inst:
                return inst
            if self._otel_meter is None:
                return _NoopHistogram()
            try:
                inst = self._otel_meter.create_histogram(name, unit=unit, description=description)
                self._otel_hist[key] = inst
                return inst
            except Exception:
                return _NoopHistogram()

    # ---- Shutdown -------------------------------------------------------------

    def _shutdown(self) -> None:
        """Ensure OTel providers/readers are flushed on exit."""
        if self._otel_provider and hasattr(self._otel_provider, "shutdown"):
            try:
                self._otel_provider.shutdown()
            except Exception:
                pass


# ---- Global accessor ----------------------------------------------------------

_global_metrics: Optional[Metrics] = None
_global_lock = threading.Lock()

def get_metrics(cfg: Optional[MetricsConfig] = None) -> Metrics:
    """
    Get process-level Metrics singleton.
    """
    global _global_metrics
    if _global_metrics is not None:
        return _global_metrics
    with _global_lock:
        if _global_metrics is None:
            cfg = cfg or MetricsConfig.from_env()
            # Downgrade backend if deps are missing
            backend = cfg.backend.lower()
            if backend in (MetricsBackend.PROMETHEUS, MetricsBackend.BOTH) and not _PROM_OK:
                backend = MetricsBackend.OTLP if _OTEL_OK else MetricsBackend.NOOP
            if backend in (MetricsBackend.OTLP, MetricsBackend.BOTH) and not _OTEL_OK:
                backend = MetricsBackend.PROMETHEUS if _PROM_OK else MetricsBackend.NOOP
            cfg.backend = backend
            _global_metrics = Metrics(cfg)
    return _global_metrics


# ---- Convenience top-level functions -----------------------------------------

def counter_inc(name: str, amount: Union[int, float] = 1, *, labels: Optional[Mapping[str, Any]] = None, unit: Optional[str] = None, description: Optional[str] = None) -> None:
    get_metrics().counter_inc(name, amount, labels=labels, unit=unit, description=description)

def histogram_observe(name: str, value: Union[int, float], *, labels: Optional[Mapping[str, Any]] = None, unit: Optional[str] = "s", description: Optional[str] = None, buckets: Optional[Iterable[float]] = None) -> None:
    get_metrics().histogram_observe(name, value, labels=labels, unit=unit, description=description, buckets=buckets)

def gauge_set(name: str, value: Union[int, float], *, labels: Optional[Mapping[str, Any]] = None, unit: Optional[str] = None, description: Optional[str] = None) -> None:
    get_metrics().gauge_set(name, value, labels=labels, unit=unit, description=description)

def register_observable_gauge(name: str, callback: Callable[[], float], *, labels: Optional[Mapping[str, Any]] = None, unit: Optional[str] = None, description: Optional[str] = None) -> None:
    get_metrics().register_observable_gauge(name, callback, labels=labels, unit=unit, description=description)

@contextmanager
def time_block(histogram_name: str, *, labels: Optional[Mapping[str, Any]] = None, unit: str = "s", description: Optional[str] = None, buckets: Optional[Iterable[float]] = None):
    with get_metrics().time_block(histogram_name, labels=labels, unit=unit, description=description, buckets=buckets):
        yield

def timeit(histogram_name: str, *, labels: Optional[Mapping[str, Any]] = None, unit: str = "s", description: Optional[str] = None, buckets: Optional[Iterable[float]] = None) -> ContextDecorator:
    return get_metrics().timeit(histogram_name, labels=labels, unit=unit, description=description, buckets=buckets)

def metrics_as_text() -> Tuple[str, str]:
    return get_metrics().metrics_as_text()

def start_prometheus_http_server(port: int, addr: str = "0.0.0.0") -> None:
    get_metrics().start_prometheus_http_server(port, addr=addr)
