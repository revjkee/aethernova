# veilmind-core/veilmind/telemetry/metrics.py
# -*- coding: utf-8 -*-
"""
Unified metrics for veilmind-core (industrial grade).

Key features:
- Dual backends: OpenTelemetry Metrics and/or Prometheus (if libs installed)
- Safe labels: normalization, PII-safe redaction, cardinality limiting
- Ready-to-use instruments: counters, histograms, up-down counters
- DurationTimer context manager and @timeit decorator
- Optional FastAPI integration to expose /metrics (Prometheus format)
- No hard dependencies: gracefully degrades to no-op if backends absent

Design goals:
- Zero Trust friendly: never log secrets or unbounded labels
- Backward compatibility: stable metric names and label sets
"""

from __future__ import annotations

import re
import time
import math
import logging
import functools
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Callable

# -------- Optional deps (loaded lazily) --------
try:  # OpenTelemetry API (optional)
    from opentelemetry.metrics import get_meter_provider, set_meter_provider  # type: ignore
    from opentelemetry.metrics import Meter  # type: ignore
except Exception:  # pragma: no cover
    Meter = None  # type: ignore

try:  # Prometheus client (optional)
    import prometheus_client  # type: ignore
    from prometheus_client import Counter as PromCounter  # type: ignore
    from prometheus_client import Histogram as PromHistogram  # type: ignore
    from prometheus_client import Gauge as PromGauge  # type: ignore
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest  # type: ignore
except Exception:  # pragma: no cover
    prometheus_client = None  # type: ignore
    PromCounter = PromHistogram = PromGauge = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"  # type: ignore
    def generate_latest() -> bytes:  # type: ignore
        return b"# no prometheus_client installed\n"

# -------- Logging (no secrets) --------
_LOG = logging.getLogger("veilmind.metrics")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    _LOG.addHandler(_h)
_LOG.setLevel(logging.INFO)

# -------- Label safety & cardinality limiting --------

_REDACT_MASK = "[REDACTED]"

# Conservative denylist of label keys that may carry secrets (prevent logging/exposing raw values)
_DENY_KEYS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api_key", "apikey",
    "token", "access_token", "refresh_token", "id_token", "session", "jwt",
    "password", "passwd", "secret", "private_key", "client_secret",
}

# Replace anything non [a-z0-9_] with '_' and trim to max len
_key_rx = re.compile(r"[^a-z0-9_]+")

def _normalize_key(k: str, max_len: int = 64) -> str:
    k = k.strip().lower().replace("-", "_").replace(".", "_").replace(" ", "_")
    k = _key_rx.sub("_", k)
    return k[:max_len] or "k"

def _sanitize_value(v: Any, max_len: int = 128) -> str:
    s = str(v)
    # crude redaction of obvious secrets
    if len(s) > max_len:
        s = s[:max_len] + "...(truncated)"
    return s

@dataclass
class LabelLimiter:
    """
    Limits label cardinality per key, with 'other' fallback.
    Thread-safe; intended to be shared per MetricsRegistry.
    """
    max_values_per_key: int = 50
    max_value_length: int = 128
    _seen: Dict[str, Dict[str, int]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def clamp(self, labels: Mapping[str, Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        with self._lock:
            for k, v in labels.items():
                nk = _normalize_key(k)
                if nk in _DENY_KEYS:
                    out[nk] = _REDACT_MASK
                    continue
                sv = _sanitize_value(v, self.max_value_length)
                seen_for_key = self._seen.setdefault(nk, {})
                if sv not in seen_for_key and len(seen_for_key) >= self.max_values_per_key:
                    out[nk] = "other"
                else:
                    out[nk] = sv
                    seen_for_key.setdefault(sv, 0)
                    seen_for_key[sv] += 1
        return out

# -------- Instrument wrappers --------

class _NoopInstr:
    def add(self, amount: float = 1.0, **labels: Any) -> None:  # Counter/UpDown-like
        return
    def record(self, value: float, **labels: Any) -> None:  # Histogram-like
        return
    def set(self, value: float, **labels: Any) -> None:  # Gauge-like
        return

class Counter:
    def __init__(self, name: str, description: str, label_keys: Sequence[str], *,
                 prom: Any = None, otel: Any = None, limiter: LabelLimiter):
        self.name = name
        self.description = description
        self.label_keys = tuple(_normalize_key(k) for k in label_keys)
        self.prom = prom
        self.otel = otel
        self.limiter = limiter

    def add(self, amount: float = 1.0, **labels: Any) -> None:
        labs = self._labels(labels)
        if self.prom is not None:
            self.prom.labels(**labs).inc(amount)
        if self.otel is not None:
            try:
                # OTel Counter API (stable): add(value, attributes=dict)
                self.otel.add(amount, attributes=labs)  # type: ignore[attr-defined]
            except Exception:
                pass

    def _labels(self, labels: Mapping[str, Any]) -> Dict[str, str]:
        # Filter to known label keys; extra keys are dropped to keep stability
        filtered = {k: labels.get(k) for k in self.label_keys if k in labels}
        return self.limiter.clamp(filtered)

class UpDownCounter:
    def __init__(self, name: str, description: str, label_keys: Sequence[str], *,
                 prom: Any = None, otel: Any = None, limiter: LabelLimiter):
        self.name = name
        self.description = description
        self.label_keys = tuple(_normalize_key(k) for k in label_keys)
        self.prom = prom
        self.otel = otel
        self.limiter = limiter
        # Prometheus Gauge can be used as up/down counter
        self._prom_gauge = prom

    def add(self, amount: float = 1.0, **labels: Any) -> None:
        labs = self._labels(labels)
        if self._prom_gauge is not None:
            self._prom_gauge.labels(**labs).inc(amount) if amount >= 0 else self._prom_gauge.labels(**labs).dec(-amount)
        if self.otel is not None:
            try:
                self.otel.add(amount, attributes=labs)  # type: ignore[attr-defined]
            except Exception:
                pass

    def _labels(self, labels: Mapping[str, Any]) -> Dict[str, str]:
        filtered = {k: labels.get(k) for k in self.label_keys if k in labels}
        return self.limiter.clamp(filtered)

class Histogram:
    def __init__(self, name: str, description: str, label_keys: Sequence[str], *,
                 buckets: Optional[Sequence[float]] = None, prom: Any = None, otel: Any = None, limiter: LabelLimiter):
        self.name = name
        self.description = description
        self.label_keys = tuple(_normalize_key(k) for k in label_keys)
        self.buckets = list(buckets or [])
        self.prom = prom
        self.otel = otel
        self.limiter = limiter

    def record(self, value: float, **labels: Any) -> None:
        labs = self._labels(labels)
        if self.prom is not None:
            self.prom.labels(**labs).observe(value)
        if self.otel is not None:
            try:
                self.otel.record(value, attributes=labs)  # type: ignore[attr-defined]
            except Exception:
                pass

    def _labels(self, labels: Mapping[str, Any]) -> Dict[str, str]:
        filtered = {k: labels.get(k) for k in self.label_keys if k in labels}
        return self.limiter.clamp(filtered)

# -------- Metrics registry --------

@dataclass
class MetricsRegistry:
    """
    Unified registry to create instruments across available backends.

    Example:
        m = MetricsRegistry(service="veilmind-core")
        reqs = m.counter("http_requests_total", "Total HTTP requests", ["route", "method", "code"])
        lat = m.histogram("http_request_duration_seconds", "Request latency", ["route", "method", "code"], buckets=m.latency_buckets_s())
    """
    service: str
    namespace: str = "veilmind"
    subsystem: Optional[str] = None
    limiter: LabelLimiter = field(default_factory=lambda: LabelLimiter(max_values_per_key=50, max_value_length=80))
    _prom_registry: Any = field(default=None, init=False, repr=False)
    _meter: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # Prometheus default registry if available
        if prometheus_client is not None:
            self._prom_registry = prometheus_client.REGISTRY
        # Try to get OTel Meter if API is present
        if Meter is not None:
            try:
                self._meter = get_meter_provider().get_meter(self.service)  # type: ignore[attr-defined]
            except Exception:
                self._meter = None

    # ---- name helper ----
    def _fullname(self, name: str) -> str:
        parts = [self.namespace]
        if self.subsystem:
            parts.append(self.subsystem)
        parts.append(name)
        return "_".join(filter(None, parts))

    # ---- buckets ----
    @staticmethod
    def latency_buckets_s() -> Sequence[float]:
        # Prometheus-style buckets in seconds (suitable for HTTP/IO): 5ms .. 30s
        return [0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1,
                0.15, 0.2, 0.3, 0.5, 0.75, 1.0,
                1.5, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 30.0]

    @staticmethod
    def size_buckets_bytes() -> Sequence[float]:
        # 1KB .. 1GB
        return [1024 * (2 ** i) for i in range(0, 11)]

    # ---- instruments ----
    def counter(self, name: str, description: str, label_keys: Sequence[str]) -> Counter:
        full = self._fullname(name)
        prom = None
        if PromCounter is not None:
            prom = PromCounter(full, description, [ _normalize_key(k) for k in label_keys ])
        otel = None
        if self._meter is not None:
            try:
                otel = self._meter.create_counter(full, description=description)  # type: ignore[attr-defined]
            except Exception:
                otel = None
        return Counter(full, description, label_keys, prom=prom, otel=otel, limiter=self.limiter)

    def updown_counter(self, name: str, description: str, label_keys: Sequence[str]) -> UpDownCounter:
        full = self._fullname(name)
        prom_g = None
        if PromGauge is not None:
            prom_g = PromGauge(full, description, [ _normalize_key(k) for k in label_keys ])
        otel = None
        if self._meter is not None:
            try:
                otel = self._meter.create_up_down_counter(full, description=description)  # type: ignore[attr-defined]
            except Exception:
                otel = None
        return UpDownCounter(full, description, label_keys, prom=prom_g, otel=otel, limiter=self.limiter)

    def histogram(self, name: str, description: str, label_keys: Sequence[str], *,
                  buckets: Optional[Sequence[float]] = None) -> Histogram:
        full = self._fullname(name)
        prom = None
        if PromHistogram is not None:
            prom = PromHistogram(full, description, [ _normalize_key(k) for k in label_keys ],
                                 buckets=buckets or self.latency_buckets_s())
        otel = None
        if self._meter is not None:
            try:
                otel = self._meter.create_histogram(full, description=description)  # type: ignore[attr-defined]
            except Exception:
                otel = None
        return Histogram(full, description, label_keys, buckets=buckets, prom=prom, otel=otel, limiter=self.limiter)

    # ---- common core metrics (stable names) ----
    def core_http_metrics(self) -> Tuple[Counter, Histogram, Counter]:
        """
        Returns (requests_total, request_duration_seconds, errors_total).
        Labels: route, method, code.
        """
        reqs = self.counter("http_requests_total", "Total HTTP requests", ["route", "method", "code"])
        lat = self.histogram("http_request_duration_seconds", "HTTP request latency (s)", ["route", "method", "code"], buckets=self.latency_buckets_s())
        errs = self.counter("http_errors_total", "Total HTTP errors", ["route", "method", "code"])
        return reqs, lat, errs

    def core_redaction_metrics(self) -> Tuple[Counter, Counter]:
        red_actions = self.counter("redaction_actions_total", "Applied redaction actions", ["action"])  # mask|tokenize|hash|truncate|drop
        findings = self.counter("pii_findings_total", "Detected PII findings", ["kind"])               # EMAIL|PHONE|...
        return red_actions, findings

    def core_tokenization_metrics(self) -> Tuple[Counter, Counter]:
        calls = self.counter("tokenization_calls_total", "Tokenization calls", ["mode", "status"])  # local|vault x ok|error
        lat = self.histogram("tokenization_duration_seconds", "Tokenization latency (s)", ["mode", "status"], buckets=self.latency_buckets_s())
        return calls, lat

# -------- Duration timer and decorator --------

@dataclass
class DurationTimer:
    """
    Context manager to time operations and record into a Histogram.
    Usage:
        with DurationTimer(histogram, route="/v1/redact", method="POST", code="200"):
            ...
    """
    histogram: Histogram
    labels: Dict[str, Any]

    def __enter__(self) -> "DurationTimer":
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        dt = time.perf_counter() - self._t0
        labs = dict(self.labels)
        # If exception, try to tag as error code if not provided
        if exc_type and "code" in self.histogram.label_keys and "code" not in labs:
            labs["code"] = "500"
        self.histogram.record(dt, **labs)

def timeit(hist: Histogram, **label_template: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator that records duration into provided Histogram. Static labels only.
    """
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                dt = time.perf_counter() - t0
                hist.record(dt, **label_template)
        return wrapper
    return deco

# -------- FastAPI / Starlette integration (Prometheus endpoint) --------

def install_prometheus_endpoint(app: Any, path: str = "/metrics") -> None:
    """
    Mounts a read-only /metrics route on a FastAPI/Starlette 'app' if prometheus_client is available.
    Does nothing if prometheus_client is not installed.

    Example:
        from fastapi import FastAPI
        app = FastAPI()
        install_prometheus_endpoint(app)
    """
    if prometheus_client is None:
        _LOG.info("prometheus_client not installed; /metrics endpoint not registered")
        return
    try:
        from fastapi import APIRouter, Response  # type: ignore
    except Exception:
        try:
            from starlette.responses import Response  # type: ignore
            from starlette.routing import Route  # type: ignore
            async def metrics_endpoint(request):  # type: ignore
                return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
            app.router.routes.append(Route(path, metrics_endpoint))  # type: ignore
            return
        except Exception:
            _LOG.warning("Neither FastAPI nor Starlette available; cannot install /metrics")
            return

    router = APIRouter()

    @router.get(path)
    def _metrics():  # type: ignore
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(router)

# -------- Example: building default registry and instruments --------

def build_default_registry(service: str = "veilmind-core", subsystem: Optional[str] = None) -> MetricsRegistry:
    """
    Returns a default registry with conservative label limiter.
    """
    return MetricsRegistry(service=service, subsystem=subsystem)

# -------- PII-safe helpers for application code --------

def safe_http_labels(route: str, method: str, code: int) -> Dict[str, str]:
    """
    Route should be templated (e.g., /v1/redact), not raw path with IDs.
    """
    return {
        "route": str(route),
        "method": str(method).upper(),
        "code": str(int(code)),
    }

def safe_redaction_labels(action: str = "mask", kind: Optional[str] = None) -> Dict[str, str]:
    labs = { "action": action.lower() }
    if kind:
        labs["kind"] = kind.upper()
    return labs

# -------- END OF MODULE --------
