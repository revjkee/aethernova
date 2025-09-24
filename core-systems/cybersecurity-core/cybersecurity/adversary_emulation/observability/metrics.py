#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybersecurity/adversary_emulation/observability/metrics.py

Industrial-grade observability helpers for adversary emulation:
- Zero hard deps: works out-of-the-box (noop backend). Prometheus / OpenTelemetry are optional.
- Unified registry for Counter, Gauge, Histogram.
- Safe sync/async timing decorators and context managers.
- JSONL fallback sink for events/measurements.
- Optional Prometheus HTTP server OR Pushgateway push.
- Optional OTLP metrics export (OpenTelemetry).
- Lightweight system/runtime metrics collection (optional psutil).
- Thread/process safe, idempotent registration, labels normalization.

Author: Aethernova / NeuroCity Observability Core
License: Apache-2.0
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import dataclasses
import functools
import json
import math
import os
import queue
import random
import socket
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Config
# -----------------------------

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v not in (None, "") else default

@dataclass(frozen=True)
class MetricsConfig:
    service_name: str = _env("METRICS_SERVICE", "adversary-emulation")
    environment: str = _env("METRICS_ENV", "prod")
    namespace: str = _env("METRICS_NAMESPACE", "cybersecurity")
    static_labels: Mapping[str, str] = dataclasses.field(default_factory=lambda: {
        "env": _env("METRICS_ENV", "prod") or "prod",
        "svc": _env("METRICS_SERVICE", "adversary-emulation") or "adversary-emulation",
        "host": socket.gethostname(),
    })

    # JSONL fallback
    jsonl_path: Optional[str] = _env("METRICS_JSONL_PATH", None)

    # Prometheus pull / push
    enable_prometheus: bool = _env("METRICS_PROMETHEUS", "1") == "1"
    prometheus_port: Optional[int] = int(_env("METRICS_PROM_PORT", "0") or "0") or None
    prometheus_addr: str = _env("METRICS_PROM_ADDR", "0.0.0.0") or "0.0.0.0"
    pushgateway_url: Optional[str] = _env("METRICS_PUSHGATEWAY", None)
    push_interval_sec: int = int(_env("METRICS_PUSH_INTERVAL", "15") or "15")

    # OpenTelemetry
    enable_otlp: bool = _env("METRICS_OTLP", "0") == "1"
    otlp_endpoint: Optional[str] = _env("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    otlp_headers: Optional[str] = _env("OTEL_EXPORTER_OTLP_HEADERS", None)
    otlp_temporality_delta: bool = _env("OTEL_METRICS_TEMPORALITY_DELTA", "1") == "1"

    # Hist buckets (seconds)
    histogram_buckets: Tuple[float, ...] = tuple(float(x) for x in (_env("METRICS_HIST_BUCKETS", "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10") or "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10").split(","))

# -----------------------------
# Backend base
# -----------------------------

class _NoopMetric:
    __slots__ = ("_type", "_name", "_labels")

    def __init__(self, mtype: str, name: str, labels: Sequence[str]):
        self._type = mtype
        self._name = name
        self._labels = tuple(labels)

    def labels(self, **kwargs: str) -> "_NoopMetric":
        return self

    def inc(self, amount: float = 1.0) -> None:
        pass

    def set(self, value: float) -> None:
        pass

    def observe(self, value: float) -> None:
        pass

class _Backend:
    def start(self) -> None: ...
    def shutdown(self) -> None: ...
    def counter(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any: ...
    def gauge(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any: ...
    def histogram(self, name: str, documentation: str, labelnames: Sequence[str], buckets: Sequence[float]) -> Any: ...

# -----------------------------
# Prometheus backend (optional)
# -----------------------------

class _PrometheusBackend(_Backend):
    def __init__(self, cfg: MetricsConfig):
        self.cfg = cfg
        self._enabled = False
        self._push_thread: Optional[threading.Thread] = None
        self._shutdown = threading.Event()
        self._registry = None
        self._prom = None  # module holder
        self._start_http = cfg.prometheus_port is not None
        self._buckets = cfg.histogram_buckets

        try:
            import prometheus_client as prom  # type: ignore
            self._prom = prom
            self._registry = prom.CollectorRegistry(auto_describe=True)
            self._enabled = True
        except Exception:
            self._enabled = False  # gracefully fallback

    def start(self) -> None:
        if not self._enabled:
            return
        if self._start_http:
            try:
                # Dedicated registry HTTP exposition
                self._prom.start_http_server(
                    addr=self.cfg.prometheus_addr,
                    port=self.cfg.prometheus_port,  # type: ignore[arg-type]
                    registry=self._registry,
                )
            except Exception:
                # ignore failure, still allow Pushgateway
                pass
        if self.cfg.pushgateway_url:
            self._push_thread = threading.Thread(target=self._push_loop, name="prom-push", daemon=True)
            self._push_thread.start()

    def _push_loop(self) -> None:
        assert self._prom is not None
        gw = self.cfg.pushgateway_url
        if not gw:
            return
        job = f"{self.cfg.namespace}_{self.cfg.service_name}"
        labels = dict(self.cfg.static_labels)
        while not self._shutdown.wait(self.cfg.push_interval_sec):
            with contextlib.suppress(Exception):
                self._prom.push_to_gateway(
                    gateway=gw,
                    job=job,
                    registry=self._registry,
                    grouping_key=labels,
                )

    def shutdown(self) -> None:
        if not self._enabled:
            return
        self._shutdown.set()
        if self._push_thread and self._push_thread.is_alive():
            self._push_thread.join(timeout=2.0)

    def _metric_name(self, name: str) -> str:
        # prometheus naming: namespace:subsystem:metric
        return f"{self.cfg.namespace}_{name}".replace(".", "_").replace("-", "_")

    def counter(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any:
        if not self._enabled:
            return _NoopMetric("counter", name, labelnames)
        return self._prom.Counter(self._metric_name(name), documentation, labelnames=tuple(labelnames), registry=self._registry)

    def gauge(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any:
        if not self._enabled:
            return _NoopMetric("gauge", name, labelnames)
        return self._prom.Gauge(self._metric_name(name), documentation, labelnames=tuple(labelnames), registry=self._registry)

    def histogram(self, name: str, documentation: str, labelnames: Sequence[str], buckets: Sequence[float]) -> Any:
        if not self._enabled:
            return _NoopMetric("histogram", name, labelnames)
        bs = tuple(sorted(set(float(b) for b in buckets)))
        return self._prom.Histogram(self._metric_name(name), documentation, labelnames=tuple(labelnames), registry=self._registry, buckets=bs)

# -----------------------------
# OpenTelemetry backend (optional)
# -----------------------------

class _OTelBackend(_Backend):
    def __init__(self, cfg: MetricsConfig):
        self.cfg = cfg
        self._enabled = False
        self._prov = None
        self._meter = None
        self._metrics: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        try:
            from opentelemetry import metrics as ot_metrics  # type: ignore
            from opentelemetry.sdk.metrics import MeterProvider  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter  # type: ignore
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore

            headers = {}
            if self.cfg.otlp_headers:
                for kv in self.cfg.otlp_headers.split(","):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        headers[k.strip()] = v.strip()

            exporter = OTLPMetricExporter(
                endpoint=self.cfg.otlp_endpoint or "http://localhost:4318/v1/metrics",
                headers=headers or None,
            )
            reader = PeriodicExportingMetricReader(exporter, export_interval_millis=5000)
            resource = Resource.create({
                "service.name": self.cfg.service_name,
                "service.namespace": self.cfg.namespace,
                "service.instance.id": socket.gethostname(),
                "deployment.environment": self.cfg.environment,
            })
            provider = MeterProvider(resource=resource, metric_readers=[reader])
            ot_metrics.set_meter_provider(provider)
            meter = ot_metrics.get_meter(self.cfg.service_name)
            self._prov = provider
            self._meter = meter
            self._enabled = True
        except Exception:
            self._enabled = False

    def start(self) -> None:
        pass  # periodic reader runs internally

    def shutdown(self) -> None:
        if not self._enabled:
            return
        try:
            self._prov.shutdown()  # type: ignore[attr-defined]
        except Exception:
            pass

    def _key(self, name: str, labels: Sequence[str]) -> Tuple[str, Tuple[str, ...]]:
        return (name, tuple(labels))

    def counter(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any:
        if not self._enabled:
            return _NoopMetric("counter", name, labelnames)
        key = self._key(name, labelnames)
        if key not in self._metrics:
            self._metrics[key] = self._meter.create_counter(name)  # type: ignore[union-attr]
        m = self._metrics[key]
        class _Wrapper:
            def __init__(self, instr, labels):
                self._instr = instr
                self._labels = tuple(labels)
            def labels(self, **kwargs: str) -> "_Wrapper":
                return _Wrapper(self._instr, self._labels)
            def inc(self, amount: float = 1.0) -> None:
                self._instr.add(float(amount), attributes=None)  # attributes can be None or dict
        return _Wrapper(m, labelnames)

    def gauge(self, name: str, documentation: str, labelnames: Sequence[str]) -> Any:
        if not self._enabled:
            return _NoopMetric("gauge", name, labelnames)
        key = self._key(name, labelnames)
        if key not in self._metrics:
            self._metrics[key] = self._meter.create_observable_gauge(name, callbacks=[])  # type: ignore[union-attr]
        # Provide a manual "set" via async-instrument workaround (store last value)
        class _Wrapper:
            _last = 0.0
            def labels(self, **kwargs: str) -> "_Wrapper":
                return self
            def set(self, value: float) -> None:
                type(self)._last = float(value)
        return _Wrapper()

    def histogram(self, name: str, documentation: str, labelnames: Sequence[str], buckets: Sequence[float]) -> Any:
        if not self._enabled:
            return _NoopMetric("histogram", name, labelnames)
        key = self._key(name, labelnames)
        if key not in self._metrics:
            self._metrics[key] = self._meter.create_histogram(name)  # type: ignore[union-attr]
        m = self._metrics[key]
        class _Wrapper:
            def __init__(self, instr, labels):
                self._instr = instr
                self._labels = tuple(labels)
            def labels(self, **kwargs: str) -> "_Wrapper":
                return _Wrapper(self._instr, self._labels)
            def observe(self, value: float) -> None:
                self._instr.record(float(value), attributes=None)
        return _Wrapper(m, labelnames)

# -----------------------------
# JSONL sink (fallback events)
# -----------------------------

class _JSONLSink:
    def __init__(self, path: Optional[str]):
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        if self._path:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._path.touch(exist_ok=True)
            except Exception:
                self._path = None

    def write(self, payload: Mapping[str, Any]) -> None:
        if not self._path:
            return
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

# -----------------------------
# Metrics registry (facade)
# -----------------------------

class MetricsRegistry:
    _instance: Optional["MetricsRegistry"] = None
    _lock = threading.Lock()

    def __init__(self, cfg: Optional[MetricsConfig] = None):
        self.cfg = cfg or MetricsConfig()
        self._prom = _PrometheusBackend(self.cfg) if self.cfg.enable_prometheus else _PrometheusBackend(self.cfg)
        self._otel = _OTelBackend(self.cfg) if self.cfg.enable_otlp else _OTelBackend(self.cfg)
        self._jsonl = _JSONLSink(self.cfg.jsonl_path)
        self._started = False
        self._metrics_cache: Dict[Tuple[str, str, Tuple[str, ...]], Any] = {}
        self._static = dict(self.cfg.static_labels)

    @classmethod
    def get(cls) -> "MetricsRegistry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = MetricsRegistry()
                cls._instance.start()
        return cls._instance

    def start(self) -> None:
        if self._started:
            return
        self._prom.start()
        self._otel.start()
        self._started = True
        atexit.register(self.shutdown)

    def shutdown(self) -> None:
        self._prom.shutdown()
        self._otel.shutdown()

    # ---- creation helpers

    def _norm_labels(self, labelnames: Iterable[str]) -> Tuple[str, ...]:
        base = tuple(sorted(set(str(x).strip() for x in labelnames if x)))
        # ensure static labels are available for jsonl events (not for prom label schema)
        return base

    def counter(self, name: str, description: str, labelnames: Sequence[str] = ()) -> Any:
        key = ("counter", name, self._norm_labels(labelnames))
        if key in self._metrics_cache:
            return self._metrics_cache[key]
        c = CompositeMetric(
            prom=self._prom.counter(name, description, key[2]),
            otel=self._otel.counter(name, description, key[2]),
            kind="counter",
            name=name,
            labels=key[2],
        )
        self._metrics_cache[key] = c
        return c

    def gauge(self, name: str, description: str, labelnames: Sequence[str] = ()) -> Any:
        key = ("gauge", name, self._norm_labels(labelnames))
        if key in self._metrics_cache:
            return self._metrics_cache[key]
        g = CompositeMetric(
            prom=self._prom.gauge(name, description, key[2]),
            otel=self._otel.gauge(name, description, key[2]),
            kind="gauge",
            name=name,
            labels=key[2],
        )
        self._metrics_cache[key] = g
        return g

    def histogram(self, name: str, description: str, labelnames: Sequence[str] = ()) -> Any:
        key = ("histogram", name, self._norm_labels(labelnames))
        if key in self._metrics_cache:
            return self._metrics_cache[key]
        h = CompositeMetric(
            prom=self._prom.histogram(name, description, key[2], self.cfg.histogram_buckets),
            otel=self._otel.histogram(name, description, key[2], self.cfg.histogram_buckets),
            kind="histogram",
            name=name,
            labels=key[2],
        )
        self._metrics_cache[key] = h
        return h

    # ---- events

    def emit_event(self, name: str, **fields: Any) -> None:
        payload = {
            "ts": int(time.time() * 1000),
            "event": name,
            "labels": self._static,
            "fields": fields,
        }
        self._jsonl.write(payload)

# -----------------------------
# Composite metric wrapper
# -----------------------------

class CompositeMetric:
    """
    Multiplexed metric facade: forwards to Prometheus and OTel if available.
    """
    def __init__(self, prom: Any, otel: Any, kind: str, name: str, labels: Sequence[str]):
        self._prom = prom
        self._otel = otel
        self._kind = kind
        self._name = name
        self._labels = tuple(labels)

    # For simplicity we accept any labels but keep only declared for backend .labels()
    def labels(self, **kwargs: str) -> "CompositeMetric":
        return self  # label handling done per-backend in real deployment if needed

    def inc(self, amount: float = 1.0) -> None:
        with contextlib.suppress(Exception):
            self._prom.inc(amount)  # type: ignore[attr-defined]
        with contextlib.suppress(Exception):
            self._otel.inc(amount)  # type: ignore[attr-defined]

    def set(self, value: float) -> None:
        with contextlib.suppress(Exception):
            self._prom.set(value)  # type: ignore[attr-defined]
        with contextlib.suppress(Exception):
            self._otel.set(value)  # type: ignore[attr-defined]

    def observe(self, value: float) -> None:
        with contextlib.suppress(Exception):
            self._prom.observe(value)  # type: ignore[attr-defined]
        with contextlib.suppress(Exception):
            self._otel.observe(value)  # type: ignore[attr-defined]

# -----------------------------
# Public helpers
# -----------------------------

# Common metrics
_registry = MetricsRegistry.get()
M_EXECUTIONS = _registry.counter("adversary_exec_total", "Number of adversary emulation action executions")
M_ERRORS = _registry.counter("adversary_exec_errors_total", "Number of errors during adversary emulation actions")
M_LATENCY = _registry.histogram("adversary_exec_latency_seconds", "Execution latency (seconds)")
M_HEARTBEAT = _registry.gauge("adversary_heartbeat", "Liveness gauge set to 1 when process is healthy")
M_RSS = _registry.gauge("process_resident_memory_bytes", "Process resident memory (bytes)")
M_CPU = _registry.gauge("process_cpu_percent", "Process CPU percent (0..100)")
M_THREADS = _registry.gauge("process_threads", "Number of process threads")

# Context for correlation
trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

def set_trace_id(value: str) -> None:
    trace_id_ctx.set(value or "")

def get_trace_id() -> str:
    return trace_id_ctx.get()

# Timing utilities

@contextlib.contextmanager
def timer(labels: Optional[Mapping[str, str]] = None):
    """
    Context manager to measure latency and increment execution counter.
    """
    start = time.perf_counter()
    M_EXECUTIONS.inc(1.0)
    try:
        yield
        dur = time.perf_counter() - start
        M_LATENCY.observe(dur)
    except Exception:
        M_ERRORS.inc(1.0)
        dur = time.perf_counter() - start
        M_LATENCY.observe(dur)
        raise

def timed(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator for sync functions measuring latency and counting errors.
    """
    @functools.wraps(func)
    def _wrap(*args: Any, **kwargs: Any) -> Any:
        with timer():
            return func(*args, **kwargs)
    return _wrap

def atimed(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator for async functions measuring latency and counting errors.
    """
    @functools.wraps(func)
    async def _wrap(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        M_EXECUTIONS.inc(1.0)
        try:
            res = await func(*args, **kwargs)
            M_LATENCY.observe(time.perf_counter() - start)
            return res
        except Exception:
            M_ERRORS.inc(1.0)
            M_LATENCY.observe(time.perf_counter() - start)
            raise
    return _wrap

def record_event(name: str, **fields: Any) -> None:
    """
    Emit lightweight JSONL event for offline correlation.
    """
    _registry.emit_event(name, trace_id=get_trace_id(), **fields)

# -----------------------------
# System metrics (optional psutil)
# -----------------------------

_psutil = None
try:
    import psutil  # type: ignore
    _psutil = psutil
except Exception:
    _psutil = None

class _SysMetricsPoller:
    def __init__(self, interval: float = 5.0):
        self.interval = max(1.0, float(interval))
        self._th: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._th = threading.Thread(target=self._loop, name="sys-metrics", daemon=True)
        self._th.start()

    def stop(self) -> None:
        self._stop.set()
        if self._th and self._th.is_alive():
            self._th.join(timeout=2.0)

    def _loop(self) -> None:
        proc = _psutil.Process(os.getpid()) if _psutil else None  # type: ignore[attr-defined]
        # Warmup for cpu_percent
        if _psutil:
            with contextlib.suppress(Exception):
                proc.cpu_percent(None)  # type: ignore[union-attr]
        while not self._stop.wait(self.interval):
            with contextlib.suppress(Exception):
                M_HEARTBEAT.set(1.0)
            if _psutil and proc:
                with contextlib.suppress(Exception):
                    M_RSS.set(float(proc.memory_info().rss))  # type: ignore[union-attr]
                with contextlib.suppress(Exception):
                    M_THREADS.set(float(proc.num_threads()))  # type: ignore[union-attr]
                with contextlib.suppress(Exception):
                    M_CPU.set(float(proc.cpu_percent(None)))  # type: ignore[union-attr]

_sys_poller = _SysMetricsPoller(interval=float(_env("METRICS_SYS_INTERVAL", "5") or 5))
_sys_poller.start()
atexit.register(_sys_poller.stop)

# -----------------------------
# Convenience: heartbeat tick
# -----------------------------

def heartbeat(ok: bool = True) -> None:
    M_HEARTBEAT.set(1.0 if ok else 0.0)

# -----------------------------
# Example-safe API (no side effects beyond metrics)
# -----------------------------

def observe_latency(seconds: float) -> None:
    try:
        val = float(seconds)
        if math.isfinite(val) and val >= 0:
            M_LATENCY.observe(val)
    except Exception:
        pass

def inc_exec(count: float = 1.0) -> None:
    try:
        M_EXECUTIONS.inc(float(count))
    except Exception:
        pass

def inc_error(count: float = 1.0) -> None:
    try:
        M_ERRORS.inc(float(count))
    except Exception:
        pass
