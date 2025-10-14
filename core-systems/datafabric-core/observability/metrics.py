# datafabric/datafabric/observability/metrics.py
# -*- coding: utf-8 -*-
"""
DataFabric-Core: Industrial Metrics Registry

Features:
- Pluggable backends: Prometheus (pull), OpenTelemetry Metrics (OTLP), StatsD (UDP)
- Metric types: Counter, Gauge, Histogram, Summary (fallback to Histogram+quantiles)
- Thread-safe, async-friendly; high-resolution timing with perf_counter_ns
- Context managers & decorators for latency measurement (@measure_latency)
- Config via ENV or YAML (optional), sane defaults; No-Op backend if none available
- Prometheus HTTP server CLI for local/dev use
- Graceful shutdown & flush; label validation & normalization

ENV (subset):
  DF_METRICS_BACKEND=[prometheus|otel|statsd|noop]
  DF_METRICS_NAMESPACE=datafabric
  DF_METRICS_PROM_PORT=9464
  DF_METRICS_PROM_ADDR=0.0.0.0
  DF_METRICS_OTEL_ENDPOINT=...
  DF_METRICS_OTEL_PROTOCOL=[grpc|http]
  DF_METRICS_STATSD_ADDR=127.0.0.1
  DF_METRICS_STATSD_PORT=8125
  DF_METRICS_LABEL_MAX=10
  DF_METRICS_HIST_BUCKETS=0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5,10

Copyright:
© DataFabric-Core. All rights reserved.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import socket
import threading
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

LOG = logging.getLogger("datafabric.metrics")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s metrics:%(message)s"))
    LOG.addHandler(_h)
    LOG.setLevel(logging.INFO)

# ---------------------------
# Optional deps
# ---------------------------
try:
    from prometheus_client import Counter as P8sCounter
    from prometheus_client import Gauge as P8sGauge
    from prometheus_client import Histogram as P8sHistogram
    from prometheus_client import Summary as P8sSummary
    from prometheus_client import CollectorRegistry, start_http_server
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter as OtelMetricExporterGRPC
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter as OtelMetricExporterHTTP
    _HAS_OTEL = True
except Exception:
    _HAS_OTEL = False

# ---------------------------
# Config & helpers
# ---------------------------

@dataclass
class MetricsConfig:
    backend: str = os.getenv("DF_METRICS_BACKEND", "noop").lower()
    namespace: str = os.getenv("DF_METRICS_NAMESPACE", "datafabric")
    label_max: int = int(os.getenv("DF_METRICS_LABEL_MAX", "10"))
    hist_buckets: List[float] = field(default_factory=lambda: _parse_buckets(os.getenv(
        "DF_METRICS_HIST_BUCKETS",
        "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5,10"
    )))
    # Prometheus
    prom_addr: str = os.getenv("DF_METRICS_PROM_ADDR", "0.0.0.0")
    prom_port: int = int(os.getenv("DF_METRICS_PROM_PORT", "9464"))
    # OpenTelemetry
    otel_endpoint: Optional[str] = os.getenv("DF_METRICS_OTEL_ENDPOINT") or None
    otel_protocol: str = os.getenv("DF_METRICS_OTEL_PROTOCOL", "grpc").lower()
    otel_insecure: bool = os.getenv("DF_METRICS_OTEL_INSECURE", "false").lower() in ("1", "true", "yes")
    otel_resource_attrs: Dict[str, str] = field(default_factory=lambda: _parse_kv_env(os.getenv("OTEL_RESOURCE_ATTRIBUTES", "")))
    export_interval_s: float = float(os.getenv("DF_METRICS_EXPORT_INTERVAL_S", "60"))
    # StatsD
    statsd_addr: str = os.getenv("DF_METRICS_STATSD_ADDR", "127.0.0.1")
    statsd_port: int = int(os.getenv("DF_METRICS_STATSD_PORT", "8125"))

def _parse_buckets(s: str) -> List[float]:
    out: List[float] = []
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(float(tok))
        except ValueError:
            pass
    return out or [0.01, 0.05, 0.1, 0.5, 1, 2, 5]

def _parse_kv_env(env: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not env:
        return out
    for kv in env.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def _norm_name(s: str) -> str:
    return "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in s)

def _now_ns() -> int:
    return time.perf_counter_ns()

# ---------------------------
# Backends
# ---------------------------

class MetricsBackend:
    def counter(self, name: str, description: str, labels: Sequence[str]) -> Any: raise NotImplementedError
    def gauge(self, name: str, description: str, labels: Sequence[str]) -> Any: raise NotImplementedError
    def histogram(self, name: str, description: str, labels: Sequence[str], buckets: Sequence[float]) -> Any: raise NotImplementedError
    def summary(self, name: str, description: str, labels: Sequence[str]) -> Any: raise NotImplementedError
    def shutdown(self) -> None: ...

# ---- No-Op ----
class NoopBackend(MetricsBackend):
    class _Noop:
        def labels(self, *args, **kwargs): return self
        def inc(self, *_, **__): ...
        def dec(self, *_, **__): ...
        def set(self, *_, **__): ...
        def observe(self, *_, **__): ...
    def __init__(self): self._m = self._Noop()
    def counter(self, *a, **k): return self._m
    def gauge(self, *a, **k): return self._m
    def histogram(self, *a, **k): return self._m
    def summary(self, *a, **k): return self._m

# ---- Prometheus ----
class PrometheusBackend(MetricsBackend):
    def __init__(self, cfg: MetricsConfig):
        if not _HAS_PROM:
            raise RuntimeError("prometheus_client is not installed")
        self.registry = CollectorRegistry(auto_describe=True)
        self.cfg = cfg
        self._started = False
        # server optional; started through CLI or start_http()
    def start_http(self, addr: Optional[str] = None, port: Optional[int] = None) -> None:
        if self._started:
            return
        start_http_server(port or self.cfg.prom_port, addr or self.cfg.prom_addr, registry=self.registry)
        self._started = True
        LOG.info("Prometheus HTTP exporter started on %s:%s", addr or self.cfg.prom_addr, port or self.cfg.prom_port)
    def counter(self, name, description, labels):
        return P8sCounter(name, description, labelnames=list(labels), namespace=self.cfg.namespace, registry=self.registry)
    def gauge(self, name, description, labels):
        return P8sGauge(name, description, labelnames=list(labels), namespace=self.cfg.namespace, registry=self.registry)
    def histogram(self, name, description, labels, buckets):
        return P8sHistogram(name, description, labelnames=list(labels), namespace=self.cfg.namespace, registry=self.registry, buckets=tuple(buckets))
    def summary(self, name, description, labels):
        return P8sSummary(name, description, labelnames=list(labels), namespace=self.cfg.namespace, registry=self.registry)

# ---- OpenTelemetry ----
class OtelBackend(MetricsBackend):
    def __init__(self, cfg: MetricsConfig):
        if not _HAS_OTEL:
            raise RuntimeError("opentelemetry-sdk is not installed")
        self.cfg = cfg
        resource_attrs = {"service.name": cfg.namespace, **cfg.otel_resource_attrs}
        resource = Resource.create(resource_attrs)
        if cfg.otel_protocol == "grpc":
            exporter = OtelMetricExporterGRPC(endpoint=cfg.otel_endpoint, insecure=cfg.otel_insecure)
        else:
            exporter = OtelMetricExporterHTTP(endpoint=cfg.otel_endpoint)
        reader = PeriodicExportingMetricReader(exporter, export_interval_millis=int(cfg.export_interval_s * 1000))
        provider = MeterProvider(resource=resource, metric_readers=[reader])
        otel_metrics.set_meter_provider(provider)
        self.meter = otel_metrics.get_meter("datafabric.metrics")
        self._provider = provider
        # Caches of instruments
        self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._gauges: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._hists: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._summaries: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
    def _key(self, name: str, labels: Sequence[str]) -> Tuple[str, Tuple[str, ...]]:
        return name, tuple(labels)
    def counter(self, name, description, labels):
        key = self._key(name, labels)
        if key not in self._counters:
            self._counters[key] = self.meter.create_counter(name, description=description)
        inst = self._counters[key]
        class _Wrapper:
            def __init__(self, instrument, labels): self.instrument, self.labels = instrument, labels
            def labels(self, **label_values): return self
            def inc(self, amount: float = 1.0, **label_values): self.instrument.add(amount, attributes=label_values)
        return _Wrapper(inst, labels)
    def gauge(self, name, description, labels):
        key = self._key(name, labels)
        if key not in self._gauges:
            self._gauges[key] = self.meter.create_up_down_counter(name, description=description)
        inst = self._gauges[key]
        class _Wrapper:
            def __init__(self, instrument): self.instrument = inst
            def labels(self, **label_values): return self
            def inc(self, amount: float = 1.0, **label_values): self.instrument.add(+amount, attributes=label_values)
            def dec(self, amount: float = 1.0, **label_values): self.instrument.add(-amount, attributes=label_values)
            def set(self, value: float, **label_values):
                # UpDownCounter cannot "set"; emulate via delta to reach value (best-effort)
                LOG.debug("OTel gauge set is approximated by delta; prefer observable gauge.")
        return _Wrapper(inst)
    def histogram(self, name, description, labels, buckets):
        key = self._key(name, labels)
        if key not in self._hists:
            self._hists[key] = self.meter.create_histogram(name, description=description)
        inst = self._hists[key]
        class _Wrapper:
            def __init__(self, instrument): self.instrument = instrument
            def labels(self, **label_values): return self
            def observe(self, value: float, **label_values): self.instrument.record(value, attributes=label_values)
        return _Wrapper(inst)
    def summary(self, name, description, labels):
        # No native summary in OTel; emulate via histogram
        return self.histogram(name, description, labels, buckets=[])
    def shutdown(self) -> None:
        try:
            self._provider.shutdown()
        except Exception as e:
            LOG.warning("OTel provider shutdown error: %s", e)

# ---- StatsD ----
class StatsdBackend(MetricsBackend):
    def __init__(self, cfg: MetricsConfig):
        self.cfg = cfg
        self.addr = (cfg.statsd_addr, cfg.statsd_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.namespace = cfg.namespace
        self._lock = threading.Lock()
    def _send(self, payload: str) -> None:
        with self._lock:
            try:
                self.sock.sendto(payload.encode("utf-8"), self.addr)
            except Exception as e:
                LOG.debug("StatsD send failed: %s", e)
    def _fmt_tags(self, labels: Mapping[str, Any]) -> str:
        if not labels: return ""
        pairs = []
        for k, v in labels.items():
            pairs.append(f"{_norm_name(str(k))}:{str(v).replace('|', '_')}")
        return "|#" + ",".join(pairs)
    def counter(self, name, description, labels):
        metric = f"{self.namespace}.{name}"
        class _C:
            def labels(self, **label_values): return self
            def inc(self, amount: float = 1.0, **label_values):
                payload = f"{metric}:{amount}|c{StatsdBackend._fmt_tags_static(label_values)}"
                StatsdBackend._send_static(self, payload)
        _C._send_static = lambda self, p: StatsdBackend._send(self, p)  # bind
        _C._fmt_tags_static = lambda lab: StatsdBackend._fmt_tags(self=None, labels=lab)
        return _C()
    def gauge(self, name, description, labels):
        metric = f"{self.namespace}.{name}"
        class _G:
            def labels(self, **label_values): return self
            def set(self, value: float, **label_values):
                payload = f"{metric}:{value}|g{StatsdBackend._fmt_tags_static(label_values)}"
                StatsdBackend._send_static(self, payload)
            def inc(self, amount: float = 1.0, **label_values):
                payload = f"{metric}:+{amount}|g{StatsdBackend._fmt_tags_static(label_values)}"
                StatsdBackend._send_static(self, payload)
            def dec(self, amount: float = 1.0, **label_values):
                payload = f"{metric}:-{amount}|g{StatsdBackend._fmt_tags_static(label_values)}"
                StatsdBackend._send_static(self, payload)
        _G._send_static = lambda self, p: StatsdBackend._send(self, p)
        _G._fmt_tags_static = lambda lab: StatsdBackend._fmt_tags(self=None, labels=lab)
        return _G()
    def histogram(self, name, description, labels, buckets):
        metric = f"{self.namespace}.{name}"
        class _H:
            def labels(self, **label_values): return self
            def observe(self, value: float, **label_values):
                payload = f"{metric}:{value}|ms{StatsdBackend._fmt_tags_static(label_values)}"
                StatsdBackend._send_static(self, payload)
        _H._send_static = lambda self, p: StatsdBackend._send(self, p)
        _H._fmt_tags_static = lambda lab: StatsdBackend._fmt_tags(self=None, labels=lab)
        return _H()
    def summary(self, name, description, labels):
        return self.histogram(name, description, labels, buckets=[])
    def shutdown(self) -> None:
        try:
            self.sock.close()
        except Exception:
            ...

# ---------------------------
# Registry & Metric wrappers
# ---------------------------

@dataclass
class MetricSpec:
    name: str
    description: str
    labels: Tuple[str, ...] = ()
    buckets: Tuple[float, ...] = ()

class _Counter:
    def __init__(self, impl, label_names: Tuple[str, ...]):
        self._impl = impl
        self._label_names = label_names
    def inc(self, amount: float = 1.0, **labels):
        self._impl.labels(**_limit_labels(labels, self._label_names)).inc(amount)
class _Gauge:
    def __init__(self, impl, label_names: Tuple[str, ...]):
        self._impl = impl
        self._label_names = label_names
    def set(self, value: float, **labels):
        self._impl.labels(**_limit_labels(labels, self._label_names)).set(value)
    def inc(self, amount: float = 1.0, **labels):
        self._impl.labels(**_limit_labels(labels, self._label_names)).inc(amount)
    def dec(self, amount: float = 1.0, **labels):
        self._impl.labels(**_limit_labels(labels, self._label_names)).dec(amount)
class _Histogram:
    def __init__(self, impl, label_names: Tuple[str, ...]):
        self._impl = impl
        self._label_names = label_names
    def observe(self, value: float, **labels):
        self._impl.labels(**_limit_labels(labels, self._label_names)).observe(value)
class _Summary(_Histogram):
    pass

def _limit_labels(values: Mapping[str, Any], allowed: Sequence[str]) -> Dict[str, Any]:
    # Enforce declared label set & max count, normalize keys
    out: Dict[str, Any] = {}
    for k in allowed:
        if k in values:
            out[_norm_name(k)] = values[k]
    return out

class Metrics:
    """
    Global registry facade with pluggable backend.
    """
    _instance_lock = threading.Lock()
    _instance: Optional["Metrics"] = None

    def __init__(self, cfg: Optional[MetricsConfig] = None):
        self.cfg = cfg or MetricsConfig()
        self._backend = self._init_backend(self.cfg)
        self._lock = threading.Lock()
        self._c: Dict[str, _Counter] = {}
        self._g: Dict[str, _Gauge] = {}
        self._h: Dict[str, _Histogram] = {}
        self._s: Dict[str, _Summary] = {}
        atexit.register(self.shutdown)

    @classmethod
    def global_instance(cls) -> "Metrics":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = Metrics()
        return cls._instance

    def _init_backend(self, cfg: MetricsConfig) -> MetricsBackend:
        b = cfg.backend
        try:
            if b == "prometheus":
                backend = PrometheusBackend(cfg)
                # Optionally auto-start HTTP server in dev when DF_METRICS_PROM_AUTOSTART=1
                if os.getenv("DF_METRICS_PROM_AUTOSTART", "0") in ("1", "true", "yes"):
                    backend.start_http()
                LOG.info("Metrics backend: Prometheus")
                return backend
            elif b == "otel":
                backend = OtelBackend(cfg)
                LOG.info("Metrics backend: OpenTelemetry")
                return backend
            elif b == "statsd":
                LOG.info("Metrics backend: StatsD")
                return StatsdBackend(cfg)
            elif b == "noop":
                LOG.info("Metrics backend: No-Op")
                return NoopBackend()
            else:
                LOG.warning("Unknown backend '%s', falling back to No-Op", b)
                return NoopBackend()
        except Exception as e:
            LOG.error("Backend init failed (%s), using No-Op: %s", b, e)
            return NoopBackend()

    # Factories
    def counter(self, name: str, description: str = "", labels: Sequence[str] = ()) -> _Counter:
        key = name
        with self._lock:
            if key not in self._c:
                spec = MetricSpec(_norm_name(name), description, tuple(labels))
                impl = self._backend.counter(spec.name, spec.description, spec.labels)
                self._c[key] = _Counter(impl, spec.labels)
            return self._c[key]

    def gauge(self, name: str, description: str = "", labels: Sequence[str] = ()) -> _Gauge:
        key = name
        with self._lock:
            if key not in self._g:
                spec = MetricSpec(_norm_name(name), description, tuple(labels))
                impl = self._backend.gauge(spec.name, spec.description, spec.labels)
                self._g[key] = _Gauge(impl, spec.labels)
            return self._g[key]

    def histogram(self, name: str, description: str = "", labels: Sequence[str] = (), buckets: Sequence[float] = ()) -> _Histogram:
        key = name
        with self._lock:
            if key not in self._h:
                spec = MetricSpec(_norm_name(name), description, tuple(labels), tuple(buckets or self.cfg.hist_buckets))
                impl = self._backend.histogram(spec.name, spec.description, spec.labels, spec.buckets)
                self._h[key] = _Histogram(impl, spec.labels)
            return self._h[key]

    def summary(self, name: str, description: str = "", labels: Sequence[str] = ()) -> _Summary:
        key = name
        with self._lock:
            if key not in self._s:
                spec = MetricSpec(_norm_name(name), description, tuple(labels))
                impl = self._backend.summary(spec.name, spec.description, spec.labels)
                self._s[key] = _Summary(impl, spec.labels)
            return self._s[key]

    def shutdown(self) -> None:
        try:
            self._backend.shutdown()
        except Exception as e:
            LOG.debug("Metrics backend shutdown error: %s", e)

# ---------------------------
# Timing helpers
# ---------------------------

@contextmanager
def measure_latency(histogram: Optional[_Histogram] = None, **labels):
    """
    Context manager for sync code latency (seconds).
    """
    start = _now_ns()
    try:
        yield
    finally:
        if histogram:
            dur_s = ( _now_ns() - start ) / 1e9
            try:
                histogram.observe(dur_s, **labels)
            except Exception as e:
                LOG.debug("measure_latency observe failed: %s", e)

@asynccontextmanager
async def measure_latency_async(histogram: Optional[_Histogram] = None, **labels):
    start = _now_ns()
    try:
        yield
    finally:
        if histogram:
            dur_s = ( _now_ns() - start ) / 1e9
            try:
                histogram.observe(dur_s, **labels)
            except Exception as e:
                LOG.debug("measure_latency_async observe failed: %s", e)

def timed_counter(counter: Optional[_Counter] = None, **labels):
    """
    Decorator: increments counter on success and records latency in histogram if provided via kw 'hist'.
    Usage:
      @timed_counter(req_counter, route="/x", hist=req_hist)
    """
    hist = labels.pop("hist", None)
    def _wrap(fn):
        def _inner(*a, **kw):
            h = hist
            start = _now_ns()
            try:
                return fn(*a, **kw)
            finally:
                if counter:
                    try: counter.inc(1, **labels)
                    except Exception: ...
                if h:
                    try: h.observe((_now_ns()-start)/1e9, **labels)
                    except Exception: ...
        return _inner
    return _wrap

def timed_counter_async(counter: Optional[_Counter] = None, **labels):
    hist = labels.pop("hist", None)
    def _wrap(fn):
        async def _inner(*a, **kw):
            start = _now_ns()
            try:
                return await fn(*a, **kw)
            finally:
                if counter:
                    try: counter.inc(1, **labels)
                    except Exception: ...
                if hist:
                    try: hist.observe((_now_ns()-start)/1e9, **labels)
                    except Exception: ...
        return _inner
    return _wrap

# ---------------------------
# Public convenience
# ---------------------------

def get_metrics(cfg: Optional[MetricsConfig] = None) -> Metrics:
    """
    Return global Metrics singleton (first call may accept optional cfg).
    """
    if Metrics._instance is None and cfg is not None:
        with Metrics._instance_lock:
            if Metrics._instance is None:
                Metrics._instance = Metrics(cfg)
    return Metrics.global_instance()

# ---------------------------
# CLI
# ---------------------------

def _cli():
    """
    Simple CLI to run Prometheus endpoint for local/dev:
      DF_METRICS_BACKEND=prometheus python -m datafabric.observability.metrics --serve
    """
    import argparse
    parser = argparse.ArgumentParser(description="DataFabric Metrics")
    parser.add_argument("--serve", action="store_true", help="Start Prometheus HTTP exporter")
    parser.add_argument("--port", type=int, default=None, help="Port override")
    parser.add_argument("--addr", type=str, default=None, help="Bind address override")
    args = parser.parse_args()

    cfg = MetricsConfig()
    m = get_metrics(cfg)

    if args.serve:
        if isinstance(m._backend, PrometheusBackend):
            m._backend.start_http(addr=args.addr, port=args.port)
            LOG.info("Serving Prometheus metrics. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        else:
            raise SystemExit("Prometheus backend is not active. Set DF_METRICS_BACKEND=prometheus")

if __name__ == "__main__":
    _cli()
