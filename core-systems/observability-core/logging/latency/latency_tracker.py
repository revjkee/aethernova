# path: observability-core/logging/latency/latency_tracker.py
# License: MIT
# Industrial Latency Tracker:
# - Prometheus-compatible histogram export (_bucket/_sum/_count)
# - Online quantiles via P² algorithm (0.5, 0.95, 0.99) without storing all samples
# - EWMA mean/sigma anomaly signal (z-score)
# - Thread-safe + async-safe
# - Context manager + sync/async decorators
# - Optional ASGI/Starlette/FastAPI integration
# - Minimal deps; falls back gracefully if frameworks are absent

from __future__ import annotations

import os
import time
import math
import threading
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Callable, Awaitable, Any, List, Iterable

# ----------------------------
# Time & units
# ----------------------------
_NS_IN_MS = 1_000_000

def _now_ms() -> float:
    return (time.perf_counter_ns() / _NS_IN_MS)

# ----------------------------
# Prometheus label helpers
# ----------------------------
def _escape_label_value(v: str) -> str:
    # Prometheus exposition escape for backslash, quote, newline
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")

def _merge_labels(base: Tuple[Tuple[str, str], ...], extra: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
    if not extra:
        return base
    merged = dict(base)
    merged.update(extra)
    return tuple(sorted(merged.items()))

def _labels_str(lbls: Tuple[Tuple[str, str], ...]) -> str:
    if not lbls:
        return ""
    inside = ",".join(f'{k}="{_escape_label_value(v)}"' for k, v in lbls)
    return "{" + inside + "}"

# ----------------------------
# Online Quantiles: P² estimator
# Reference: Jain, Chlamtac (1985)
# ----------------------------
class P2Quantile:
    __slots__ = ("q", "initialized", "n", "q_pos", "marker_heights", "marker_positions", "desired_positions", "incr")

    def __init__(self, q: float) -> None:
        if not (0.0 < q < 1.0):
            raise ValueError("q must be in (0,1)")
        self.q = q
        self.initialized = False
        self.n = 0
        self.q_pos = 0.0
        self.marker_heights: List[float] = []
        self.marker_positions: List[float] = []
        self.desired_positions: List[float] = []
        self.incr: List[float] = []

    def add(self, x: float) -> None:
        # Collect first 5 samples verbatim to bootstrap
        if not self.initialized:
            self.marker_heights.append(x)
            self.n += 1
            if self.n == 5:
                self.marker_heights.sort()
                self.marker_positions = [1.0, 2.0, 3.0, 4.0, 5.0]
                self.desired_positions = [1.0, 1.0 + 2 * self.q, 1.0 + 4 * self.q, 3.0 + 2 * self.q, 5.0]
                self.incr = [0.0, self.q / 2.0, self.q, (1.0 + self.q) / 2.0, 1.0]
                self.initialized = True
            return

        # Locate cell k
        k = 0
        if x < self.marker_heights[0]:
            self.marker_heights[0] = x
            k = 0
        elif x >= self.marker_heights[4]:
            self.marker_heights[4] = x
            k = 3
        else:
            for i in range(1, 5):
                if x < self.marker_heights[i]:
                    k = i - 1
                    break

        # Increment positions
        for i in range(5):
            if i <= k:
                self.marker_positions[i] += 1.0
            self.desired_positions[i] += self.incr[i]

        # Adjust heights using parabolic or linear steps
        for i in range(1, 4):
            d = self.desired_positions[i] - self.marker_positions[i]
            if (d >= 1.0 and (self.marker_positions[i + 1] - self.marker_positions[i]) > 1.0) or \
               (d <= -1.0 and (self.marker_positions[i - 1] - self.marker_positions[i]) < -1.0):
                d_sign = 1.0 if d > 0 else -1.0
                # Parabolic prediction
                hp = self._parabolic(i, d_sign)
                if self.marker_heights[i - 1] < hp < self.marker_heights[i + 1]:
                    self.marker_heights[i] = hp
                else:
                    # Linear step if parabolic out of bounds
                    self.marker_heights[i] = self._linear(i, d_sign)
                self.marker_positions[i] += d_sign

    def value(self) -> Optional[float]:
        if not self.initialized:
            if self.n == 0:
                return None
            # If <5 samples, return empirical quantile
            s = sorted(self.marker_heights)
            idx = max(0, min(len(s) - 1, int(math.ceil(self.q * len(s)) - 1)))
            return float(s[idx])
        return float(self.marker_heights[2])

    def _parabolic(self, i: int, d_sign: float) -> float:
        hp = self.marker_heights
        np_ = self.marker_positions
        return hp[i] + d_sign * (
            (np_[i] - np_[i - 1] + d_sign) * (hp[i + 1] - hp[i]) / (np_[i + 1] - np_[i]) +
            (np_[i + 1] - np_[i] - d_sign) * (hp[i] - hp[i - 1]) / (np_[i] - np_[i - 1])
        )

    def _linear(self, i: int, d_sign: float) -> float:
        return self.marker_heights[i] + d_sign * (self.marker_heights[i + int(d_sign)] - self.marker_heights[i]) / \
               (self.marker_positions[i + int(d_sign)] - self.marker_positions[i])

# ----------------------------
# EWMA mean/sigma for anomaly scoring
# ----------------------------
@dataclass
class EWMA:
    alpha: float
    mean: Optional[float] = None
    variance: Optional[float] = None  # approximate running variance

    def update(self, x: float) -> Tuple[float, float]:
        if self.mean is None:
            self.mean = x
            self.variance = 0.0
            return self.mean, 0.0
        prev_mean = self.mean
        self.mean = self.alpha * x + (1.0 - self.alpha) * self.mean
        # Approximate variance update around EWMA mean
        delta = x - prev_mean
        self.variance = (1.0 - self.alpha) * (self.variance or 0.0) + self.alpha * (delta * (x - self.mean))
        sigma = math.sqrt(max(self.variance or 0.0, 0.0))
        return self.mean, sigma

# ----------------------------
# Histogram
# ----------------------------
_DEFAULT_BUCKETS_MS = tuple(
    int(x) for x in (
        1, 2, 5,
        10, 20, 50,
        100, 200, 400,
        800, 1500, 3000, 5000, 10000
    )
)

@dataclass
class Histogram:
    buckets_ms: Tuple[int, ...] = field(default_factory=lambda: _DEFAULT_BUCKETS_MS)
    counts: List[int] = field(init=False)
    sum_ms: float = 0.0
    observations: int = 0

    def __post_init__(self) -> None:
        # N buckets + +Inf
        self.counts = [0 for _ in self.buckets_ms] + [0]

    def observe(self, value_ms: float) -> None:
        self.sum_ms += value_ms
        self.observations += 1
        # Binary search bucket
        lo, hi = 0, len(self.buckets_ms) - 1
        placed = False
        while lo <= hi:
            mid = (lo + hi) // 2
            if value_ms <= self.buckets_ms[mid]:
                placed = True
                hi = mid - 1
            else:
                lo = mid + 1
        if placed:
            self.counts[lo] += 1  # lo is the first bucket >= value
        else:
            self.counts[-1] += 1  # +Inf

# ----------------------------
# Metric identity
# ----------------------------
@dataclass(frozen=True, order=True)
class MetricKey:
    name: str
    labels: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)

# ----------------------------
# Latency Metric aggregate
# ----------------------------
class LatencyMetric:
    __slots__ = ("hist", "q50", "q95", "q99", "ewma")

    def __init__(self, buckets_ms: Tuple[int, ...], ewma_alpha: float) -> None:
        self.hist = Histogram(buckets_ms=buckets_ms)
        self.q50 = P2Quantile(0.5)
        self.q95 = P2Quantile(0.95)
        self.q99 = P2Quantile(0.99)
        self.ewma = EWMA(alpha=ewma_alpha)

    def observe(self, value_ms: float) -> None:
        self.hist.observe(value_ms)
        self.q50.add(value_ms)
        self.q95.add(value_ms)
        self.q99.add(value_ms)
        self.ewma.update(value_ms)

# ----------------------------
# Registry
# ----------------------------
class LatencyRegistry:
    def __init__(
        self,
        buckets_ms: Optional[Iterable[int]] = None,
        ewma_alpha: Optional[float] = None,
    ) -> None:
        # Configurable via env for ops
        env_buckets = os.getenv("LATENCY_BUCKETS_MS")
        if env_buckets:
            try:
                buckets = tuple(int(x.strip()) for x in env_buckets.split(",") if x.strip())
            except Exception:
                buckets = _DEFAULT_BUCKETS_MS
        else:
            buckets = tuple(buckets_ms) if buckets_ms else _DEFAULT_BUCKETS_MS

        env_alpha = os.getenv("LATENCY_EWMA_ALPHA")
        if env_alpha:
            try:
                alpha = float(env_alpha)
            except Exception:
                alpha = 0.2
        else:
            alpha = ewma_alpha if ewma_alpha is not None else 0.2

        self._buckets = buckets
        self._alpha = alpha
        self._lock = threading.RLock()
        self._metrics: Dict[MetricKey, LatencyMetric] = {}

    def _get_metric(self, key: MetricKey) -> LatencyMetric:
        m = self._metrics.get(key)
        if m is None:
            m = LatencyMetric(buckets_ms=self._buckets, ewma_alpha=self._alpha)
            self._metrics[key] = m
        return m

    def observe(self, name: str, value_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
        if labels is None:
            labels = {}
        key = MetricKey(name=name, labels=tuple(sorted(labels.items())))
        with self._lock:
            metric = self._get_metric(key)
            metric.observe(value_ms)

    # Async-friendly helper: runs synchronous observe
    async def observe_async(self, name: str, value_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
        self.observe(name, value_ms, labels)

    # Export Prometheus exposition text
    def export_prometheus(self) -> str:
        lines: List[str] = []
        with self._lock:
            for key, metric in self._metrics.items():
                # Buckets (cumulative)
                cum = 0
                for i, b in enumerate(metric.hist.buckets_ms):
                    cum += metric.hist.counts[i]
                    base = key.labels
                    lbls = _merge_labels(base, {"le": str(b)})
                    lines.append(f'{key.name}_bucket{_labels_str(lbls)} {cum}')
                # +Inf bucket
                cum += metric.hist.counts[-1]
                lbls = _merge_labels(key.labels, {"le": "+Inf"})
                lines.append(f'{key.name}_bucket{_labels_str(lbls)} {cum}')
                # sum & count
                lines.append(f'{key.name}_sum{_labels_str(key.labels)} {metric.hist.sum_ms}')
                lines.append(f'{key.name}_count{_labels_str(key.labels)} {metric.hist.observations}')
                # Quantiles as gauges
                for q, tag, getter in (
                    (0.5, "0.5", metric.q50),
                    (0.95, "0.95", metric.q95),
                    (0.99, "0.99", metric.q99),
                ):
                    v = getter.value()
                    if v is not None and math.isfinite(v):
                        qlbls = _merge_labels(key.labels, {"quantile": tag})
                        lines.append(f'{key.name}_quantile{_labels_str(qlbls)} {v}')
                # EWMA mean & sigma
                if metric.ewma.mean is not None:
                    lines.append(f'{key.name}_ewma_mean{_labels_str(key.labels)} {metric.ewma.mean}')
                    sigma = math.sqrt(max(metric.ewma.variance or 0.0, 0.0))
                    lines.append(f'{key.name}_ewma_sigma{_labels_str(key.labels)} {sigma}')
        return "\n".join(lines) + "\n"

    def anomaly_zscore(
        self,
        name: str,
        labels: Optional[Dict[str, str]] = None,
        value_ms: Optional[float] = None
    ) -> Optional[float]:
        if labels is None:
            labels = {}
        key = MetricKey(name=name, labels=tuple(sorted(labels.items())))
        with self._lock:
            metric = self._metrics.get(key)
            if not metric or metric.ewma.mean is None:
                return None
            sigma = math.sqrt(max(metric.ewma.variance or 0.0, 0.0))
            if sigma == 0.0:
                return 0.0
            x = value_ms if value_ms is not None else metric.ewma.mean
            return abs(x - metric.ewma.mean) / sigma

# Global registry
_registry = LatencyRegistry()

# ----------------------------
# Public API
# ----------------------------
class LatencyTimer:
    def __init__(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        self.name = name
        self.labels = labels or {}
        self.start_ns = 0

    def __enter__(self) -> "LatencyTimer":
        self.start_ns = time.perf_counter_ns()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        dur_ms = (time.perf_counter_ns() - self.start_ns) / _NS_IN_MS
        _registry.observe(self.name, dur_ms, self.labels)

    async def __aenter__(self) -> "LatencyTimer":
        self.start_ns = time.perf_counter_ns()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        dur_ms = (time.perf_counter_ns() - self.start_ns) / _NS_IN_MS
        await _registry.observe_async(self.name, dur_ms, self.labels)

def track_latency(name: str, labels: Optional[Dict[str, str]] = None) -> LatencyTimer:
    return LatencyTimer(name=name, labels=labels)

def track_latency_deco(name: str, labels: Optional[Dict[str, str]] = None) -> Callable:
    """
    Decorator that works for both sync and async callables.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if _is_coro_func(func):
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                async with LatencyTimer(name, labels):
                    return await func(*args, **kwargs)
            return wrapper
        else:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                with LatencyTimer(name, labels):
                    return func(*args, **kwargs)
            return wrapper
    return decorator

def export_prometheus() -> str:
    return _registry.export_prometheus()

def anomaly_zscore(name: str, labels: Optional[Dict[str, str]] = None, value_ms: Optional[float] = None) -> Optional[float]:
    return _registry.anomaly_zscore(name, labels, value_ms)

def _is_coro_func(fn: Callable[..., Any]) -> bool:
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False

# ----------------------------
# Optional ASGI/Starlette/FastAPI integration
# ----------------------------
# 1) Raw ASGI middleware (no dependencies)
class ASGILatencyMiddleware:
    """
    Drop-in ASGI middleware:
        app = ASGILatencyMiddleware(app, metric_name="http_request_latency_ms")
    """
    def __init__(self, app: Callable, metric_name: str = "http_request_latency_ms") -> None:
        self.app = app
        self.metric_name = metric_name

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        start_ns = time.perf_counter_ns()
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        status_holder = {"status": None}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            dur_ms = (time.perf_counter_ns() - start_ns) / _NS_IN_MS
            _registry.observe(self.metric_name, dur_ms, {"method": method, "route": path, "code": str(status_holder["status"] or 200)})

# 2) Starlette/FastAPI middleware if available
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from fastapi import Request, Response

    class LatencyMiddleware(BaseHTTPMiddleware):
        def __init__(self, app, metric_name: str = "http_request_latency_ms") -> None:
            super().__init__(app)
            self.metric_name = metric_name

        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            start_ns = time.perf_counter_ns()
            response: Response = await call_next(request)
            dur_ms = (time.perf_counter_ns() - start_ns) / _NS_IN_MS
            labels = {
                "method": request.method,
                "route": request.url.path,
                "code": str(response.status_code),
            }
            _registry.observe(self.metric_name, dur_ms, labels)
            return response

    async def prometheus_endpoint() -> str:
        # Use in FastAPI route; ensure to set the correct content-type in your app if needed
        return export_prometheus()

except Exception:
    # Middleware helpers unavailable
    LatencyMiddleware = None  # type: ignore
    async def prometheus_endpoint() -> str:  # type: ignore
        return export_prometheus()

# ----------------------------
# Optional OpenTelemetry export (metrics) — minimal shim
# If OTel is present, expose a hook to record as histogram too.
# ----------------------------
def otel_record(name: str, value_ms: float, labels: Optional[Dict[str, str]] = None) -> None:
    try:
        from opentelemetry import metrics
        meter = metrics.get_meter(__name__)
        hist = meter.create_histogram(name, unit="ms")
        attributes = dict(labels or {})
        hist.record(value_ms, attributes=attributes)
    except Exception:
        # OTel not installed or not configured; ignore silently
        pass

# ----------------------------
# Example helper for direct timing
# ----------------------------
def time_block_ms(func: Callable[..., Any], *args: Any, **kwargs: Any) -> float:
    start = _now_ms()
    func(*args, **kwargs)
    return _now_ms() - start
