# cybersecurity/observability/metrics.py
# Industrial-grade metrics module for Aethernova cybersecurity-core
from __future__ import annotations

import math
import os
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

__all__ = [
    "MetricsRegistry",
    "Counter",
    "Gauge",
    "Histogram",
    "Timer",
    "time_calls",
    "time_calls_async",
    "default_latency_buckets",
    "make_prometheus_asgi_app",
    "start_process_metrics_collector",
    "push_to_pushgateway",
]

# =========================
# Utilities
# =========================

def _now_ts() -> float:
    return time.time()

def _perf() -> float:
    return time.perf_counter()

def _iso8601(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()

def _sanitize_name(name: str, *, allow_colon: bool = True) -> str:
    # Prometheus: [a-zA-Z_:][a-zA-Z0-9_:]*
    valid_first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_" + (":" if allow_colon else "")
    valid_rest = valid_first + "0123456789"
    if not name:
        return "_"
    s = []
    first = name[0]
    s.append(first if first in valid_first else "_")
    for ch in name[1:]:
        s.append(ch if ch in valid_rest else "_")
    return "".join(s)

def _sanitize_label_key(key: str) -> str:
    # [a-zA-Z_][a-zA-Z0-9_]*
    valid_first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
    valid_rest = valid_first + "0123456789"
    if not key:
        return "_"
    s = []
    first = key[0]
    s.append(first if first in valid_first else "_")
    for ch in key[1:]:
        s.append(ch if ch in valid_rest else "_")
    return "".join(s)

def _escape_label_value(value: str) -> str:
    # Prometheus exposition escaping for label values
    return (
        value.replace("\\", r"\\")
        .replace("\n", r"\n")
        .replace("\"", r"\"")
    )

def default_latency_buckets() -> Tuple[float, ...]:
    # Exponential-ish latency buckets (seconds)
    return (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# =========================
# Base metric classes
# =========================

@dataclass
class _CellCounter:
    value: float = 0.0

@dataclass
class _CellGauge:
    value: float = 0.0

@dataclass
class _CellHistogram:
    # cumulative bucket counts aligned with self.buckets on metric
    counts: List[int] = field(default_factory=list)
    sum: float = 0.0
    count: int = 0

class MetricError(Exception):
    pass

class LabelCardinalityExceeded(MetricError):
    pass

class Metric:
    def __init__(
        self,
        registry: "MetricsRegistry",
        name: str,
        help: str = "",
        labelnames: Optional[Sequence[str]] = None,
        unit: Optional[str] = None,
    ):
        self._registry = registry
        self.name = _sanitize_name(name)
        self.help = help or ""
        self.unit = unit
        self._labelnames = tuple(_sanitize_label_key(k) for k in (labelnames or ()))
        self._cells: Dict[Tuple[str, ...], Any] = {}
        self._lock = threading.RLock()
        self._registry._register(self)

    # --------- API ---------

    def labels(self, **labelvalues: str) -> "Metric":
        values = self._normalize_labelvalues(labelvalues)
        self._ensure_cell(values)
        # return a bound child that proxies operations with fixed labels
        return _BoundMetric(self, values)

    def _normalize_labelvalues(self, labelvalues: Mapping[str, str]) -> Tuple[str, ...]:
        if set(labelvalues.keys()) != set(self._labelnames):
            missing = set(self._labelnames) - set(labelvalues.keys())
            extra = set(labelvalues.keys()) - set(self._labelnames)
            raise MetricError(f"label mismatch, missing={missing} extra={extra}")
        return tuple(str(labelvalues[k]) for k in self._labelnames)

    # implemented in subclasses
    def _ensure_cell(self, labelvalues: Tuple[str, ...]) -> Any:
        raise NotImplementedError

    def _render(self) -> str:
        raise NotImplementedError

class _BoundMetric:
    """Proxy with bound labels"""
    def __init__(self, metric: Metric, labelvalues: Tuple[str, ...]):
        self._m = metric
        self._lv = labelvalues

    # Counter
    def inc(self, amount: float = 1.0) -> None:
        if hasattr(self._m, "inc"):
            self._m.inc(amount, _bound=self._lv)  # type: ignore[attr-defined]
        else:
            raise MetricError("inc not supported for this metric")

    # Gauge
    def set(self, value: float) -> None:
        if hasattr(self._m, "set"):
            self._m.set(value, _bound=self._lv)  # type: ignore[attr-defined]
        else:
            raise MetricError("set not supported for this metric")

    def add(self, amount: float) -> None:
        if hasattr(self._m, "add"):
            self._m.add(amount, _bound=self._lv)  # type: ignore[attr-defined]
        else:
            raise MetricError("add not supported for this metric")

    # Histogram
    def observe(self, value: float) -> None:
        if hasattr(self._m, "observe"):
            self._m.observe(value, _bound=self._lv)  # type: ignore[attr-defined]
        else:
            raise MetricError("observe not supported for this metric")

    # Timer helpers
    def time(self) -> "Timer":
        if hasattr(self._m, "observe"):
            return Timer(self._m, self._lv)  # type: ignore[arg-type]
        raise MetricError("time() only for histogram metrics")

# =========================
# Concrete metrics
# =========================

class Counter(Metric):
    TYPE = "counter"

    def _ensure_cell(self, labelvalues: Tuple[str, ...]) -> _CellCounter:
        with self._lock:
            cell = self._cells.get(labelvalues)
            if cell is not None:
                return cell
            self._registry._enforce_cardinality(self, self._cells)
            cell = _CellCounter()
            self._cells[labelvalues] = cell
            return cell

    def inc(self, amount: float = 1.0, *, _bound: Optional[Tuple[str, ...]] = None) -> None:
        if amount < 0:
            raise MetricError("counter cannot be decreased")
        values = _bound if _bound is not None else self._normalize_labelvalues({k: "" for k in self._labelnames})  # type: ignore
        with self._lock:
            cell = self._ensure_cell(values)
            cell.value += float(amount)

    def _render(self) -> str:
        lines = []
        help_line = f"# HELP {self.name} {self.help}"
        type_line = f"# TYPE {self.name} {self.TYPE}"
        lines.extend([help_line, type_line])
        with self._lock:
            for lv, cell in self._cells.items():
                labels = self._format_labels(lv)
                lines.append(f"{self.name}{labels} {cell.value:.10g}")
        return "\n".join(lines)

    def _format_labels(self, lv: Tuple[str, ...]) -> str:
        if not self._labelnames:
            return ""
        pairs = [f'{k}="{_escape_label_value(v)}"' for k, v in zip(self._labelnames, lv)]
        return "{" + ",".join(pairs) + "}"

class Gauge(Metric):
    TYPE = "gauge"

    def _ensure_cell(self, labelvalues: Tuple[str, ...]) -> _CellGauge:
        with self._lock:
            cell = self._cells.get(labelvalues)
            if cell is not None:
                return cell
            self._registry._enforce_cardinality(self, self._cells)
            cell = _CellGauge()
            self._cells[labelvalues] = cell
            return cell

    def set(self, value: float, *, _bound: Optional[Tuple[str, ...]] = None) -> None:
        values = _bound if _bound is not None else self._normalize_labelvalues({k: "" for k in self._labelnames})  # type: ignore
        with self._lock:
            cell = self._ensure_cell(values)
            cell.value = float(value)

    def add(self, amount: float, *, _bound: Optional[Tuple[str, ...]] = None) -> None:
        values = _bound if _bound is not None else self._normalize_labelvalues({k: "" for k in self._labelnames})  # type: ignore
        with self._lock:
            cell = self._ensure_cell(values)
            cell.value += float(amount)

    def _render(self) -> str:
        lines = []
        lines.append(f"# HELP {self.name} {self.help}")
        lines.append(f"# TYPE {self.name} {self.TYPE}")
        with self._lock:
            for lv, cell in self._cells.items():
                labels = self._format_labels(lv)
                lines.append(f"{self.name}{labels} {cell.value:.10g}")
        return "\n".join(lines)

    def _format_labels(self, lv: Tuple[str, ...]) -> str:
        if not self._labelnames:
            return ""
        pairs = [f'{k}="{_escape_label_value(v)}"' for k, v in zip(self._labelnames, lv)]
        return "{" + ",".join(pairs) + "}"

class Histogram(Metric):
    TYPE = "histogram"

    def __init__(
        self,
        registry: "MetricsRegistry",
        name: str,
        help: str = "",
        labelnames: Optional[Sequence[str]] = None,
        buckets: Optional[Sequence[float]] = None,
        unit: Optional[str] = None,
    ):
        self.buckets = tuple(sorted(set([float(b) for b in (buckets or default_latency_buckets())])))
        super().__init__(registry, name, help, labelnames, unit)

    def _ensure_cell(self, labelvalues: Tuple[str, ...]) -> _CellHistogram:
        with self._lock:
            cell = self._cells.get(labelvalues)
            if cell is not None:
                return cell
            self._registry._enforce_cardinality(self, self._cells)
            cell = _CellHistogram(counts=[0 for _ in self.buckets])
            self._cells[labelvalues] = cell
            return cell

    def observe(self, value: float, *, _bound: Optional[Tuple[str, ...]] = None) -> None:
        v = float(value)
        if math.isnan(v) or math.isinf(v):
            return
        if v < 0:
            v = 0.0
        values = _bound if _bound is not None else self._normalize_labelvalues({k: "" for k in self._labelnames})  # type: ignore
        with self._lock:
            cell = self._ensure_cell(values)
            # find bucket index
            for i, b in enumerate(self.buckets):
                if v <= b:
                    cell.counts[i] += 1
            cell.sum += v
            cell.count += 1

    def _render(self) -> str:
        lines = []
        lines.append(f"# HELP {self.name} {self.help}")
        lines.append(f"# TYPE {self.name} {self.TYPE}")
        with self._lock:
            for lv, cell in self._cells.items():
                base_labels = {k: v for k, v in zip(self._labelnames, lv)}
                # buckets
                prev = 0
                for i, b in enumerate(self.buckets):
                    count = cell.counts[i]
                    labels = dict(base_labels)
                    labels["le"] = f"{self.buckets[i]:.16g}"
                    lines.append(f"{self.name}_bucket{_format_labels(labels)} {count}")
                    prev = count
                # +Inf bucket equals total count
                labels = dict(base_labels)
                labels["le"] = "+Inf"
                lines.append(f"{self.name}_bucket{_format_labels(labels)} {cell.count}")
                # sum and count
                lines.append(f"{self.name}_sum{_format_labels(base_labels)} {cell.sum:.10g}")
                lines.append(f"{self.name}_count{_format_labels(base_labels)} {cell.count}")
        return "\n".join(lines)

def _format_labels(kv: Mapping[str, str]) -> str:
    if not kv:
        return ""
    parts = [f'{_sanitize_label_key(k)}="{_escape_label_value(str(v))}"' for k, v in sorted(kv.items(), key=lambda x: x[0])]
    return "{" + ",".join(parts) + "}"

# =========================
# Registry & exposition
# =========================

class MetricsRegistry:
    """
    Потокобезопасный реестр метрик с ограничением кардинальности.
    """
    def __init__(self, *, max_labelsets_per_metric: int = 10_000):
        self._metrics: Dict[str, Metric] = {}
        self._lock = threading.RLock()
        self.max_labelsets_per_metric = max_labelsets_per_metric
        # системные счетчики
        self._dropped_labelsets = Counter(self, "metrics_labelsets_dropped_total", "Labelsets dropped due to cardinality limit")

    # Registration is internal from Metric.__init__
    def _register(self, metric: Metric) -> None:
        with self._lock:
            if metric.name in self._metrics:
                raise MetricError(f"metric already registered: {metric.name}")
            self._metrics[metric.name] = metric

    def counter(self, name: str, help: str = "", labelnames: Optional[Sequence[str]] = None, unit: Optional[str] = None) -> Counter:
        return Counter(self, name, help, labelnames, unit)

    def gauge(self, name: str, help: str = "", labelnames: Optional[Sequence[str]] = None, unit: Optional[str] = None) -> Gauge:
        return Gauge(self, name, help, labelnames, unit)

    def histogram(self, name: str, help: str = "", labelnames: Optional[Sequence[str]] = None, buckets: Optional[Sequence[float]] = None, unit: Optional[str] = None) -> Histogram:
        return Histogram(self, name, help, labelnames, buckets, unit)

    def _enforce_cardinality(self, metric: Metric, cells: MutableMapping[Tuple[str, ...], Any]) -> None:
        if len(cells) >= self.max_labelsets_per_metric:
            # drop by incrementing system metric
            self._dropped_labelsets.inc(1.0)
            raise LabelCardinalityExceeded(f"label cardinality exceeded for {metric.name}")

    # --------- exposition ---------

    def render_prometheus_text(self) -> str:
        """
        Сериализация всех метрик в текстовом формате Prometheus.
        """
        lines: List[str] = [f"# Aethernova cybersecurity-core metrics", f"# Scrape-Timestamp {int(_now_ts())}"]
        with self._lock:
            # stable order by metric name
            for name in sorted(self._metrics.keys()):
                try:
                    lines.append(self._metrics[name]._render())
                except Exception as e:
                    # never break exposition
                    lines.append(f"# ERROR rendering {name}: {e}")
        return "\n".join(lines) + "\n"

# =========================
# Timers & decorators
# =========================

class Timer:
    """
    Контекст-менеджер/таймер для Histogram.observe().
    """
    def __init__(self, histogram: Histogram, labelvalues: Optional[Tuple[str, ...]] = None):
        self._h = histogram
        self._lv = labelvalues
        self._t0 = 0.0

    def __enter__(self) -> "Timer":
        self._t0 = _perf()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        dt = max(0.0, _perf() - self._t0)
        self._h.observe(dt, _bound=self._lv)

def time_calls(hist: Histogram, **labelvalues: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для измерения длительности синхронных вызовов в гистограмму.
    """
    bound = hist.labels(**labelvalues) if labelvalues else hist
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs):
            t0 = _perf()
            try:
                return fn(*args, **kwargs)
            finally:
                dt = max(0.0, _perf() - t0)
                if isinstance(bound, _BoundMetric):
                    bound.observe(dt)  # type: ignore[attr-defined]
                else:
                    hist.observe(dt)
        return wrapper
    return deco

def time_calls_async(hist: Histogram, **labelvalues: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для измерения длительности асинхронных вызовов в гистограмму.
    """
    bound = hist.labels(**labelvalues) if labelvalues else hist
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        async def wrapper(*args, **kwargs):
            t0 = _perf()
            try:
                return await fn(*args, **kwargs)
            finally:
                dt = max(0.0, _perf() - t0)
                if isinstance(bound, _BoundMetric):
                    bound.observe(dt)  # type: ignore[attr-defined]
                else:
                    hist.observe(dt)
        return wrapper
    return deco

# =========================
# Process metrics collector
# =========================

class _ProcessMetricsCollector(threading.Thread):
    def __init__(self, registry: MetricsRegistry, interval_sec: float = 5.0):
        super().__init__(name="proc-metrics", daemon=True)
        self._r = registry
        self._interval = max(0.5, float(interval_sec))
        self._stop = threading.Event()
        # metrics
        self._cpu = self._r.gauge("process_cpu_seconds_total", "Total user+system CPU time spent in seconds")
        self._rss = self._r.gauge("process_resident_memory_bytes", "Resident memory size in bytes")
        self._fds = self._r.gauge("process_open_fds", "Number of open file descriptors (best-effort)")
        self._start = self._r.gauge("process_start_time_seconds", "Start time of the process since unix epoch in seconds")
        self._threads = self._r.gauge("process_threads", "Number of OS threads in the process")

        try:
            import psutil  # type: ignore
            self._psutil = psutil.Process(os.getpid())
            self._boot_time = getattr(psutil, "boot_time", lambda: 0.0)()
            self._has_psutil = True
        except Exception:
            self._psutil = None
            self._boot_time = 0.0
            self._has_psutil = False

        self._proc_start = time.time()
        self._start.set(self._proc_start)

    def run(self) -> None:
        last_cpu = 0.0
        while not self._stop.is_set():
            try:
                if self._has_psutil and self._psutil:
                    cpu_times = self._psutil.cpu_times()
                    cpu_total = float(getattr(cpu_times, "user", 0.0) + getattr(cpu_times, "system", 0.0))
                    self._cpu.set(cpu_total)
                    mem = self._psutil.memory_info()
                    self._rss.set(float(getattr(mem, "rss", 0)))
                    try:
                        fds = self._psutil.num_fds()  # type: ignore[attr-defined]
                    except Exception:
                        # Windows fallback
                        fds = 0
                    self._fds.set(float(fds))
                    try:
                        self._threads.set(float(self._psutil.num_threads()))
                    except Exception:
                        self._threads.set(0.0)
                else:
                    # Fallbacks
                    # CPU time approximation
                    cpu_total = last_cpu + self._interval * 0.0
                    self._cpu.set(cpu_total)
                    # RSS unknown
                    self._rss.set(0.0)
                    self._fds.set(0.0)
                    self._threads.set(0.0)
                last_cpu = cpu_total
            except Exception:
                # never crash the collector
                pass
            finally:
                self._stop.wait(self._interval)

    def stop(self) -> None:
        self._stop.set()

def start_process_metrics_collector(registry: MetricsRegistry, interval_sec: float = 5.0) -> _ProcessMetricsCollector:
    c = _ProcessMetricsCollector(registry, interval_sec=interval_sec)
    c.start()
    return c

# =========================
# Pushgateway (optional)
# =========================

def push_to_pushgateway(
    registry: MetricsRegistry,
    endpoint: str,
    job: str,
    grouping: Optional[Mapping[str, str]] = None,
    timeout: float = 5.0,
) -> Tuple[int, str]:
    """
    Отправка метрик в Prometheus Pushgateway (строго по необходимости).
    endpoint: 'http(s)://host:9091'
    """
    text = registry.render_prometheus_text().encode("utf-8")
    job_path = urllib.parse.quote(_sanitize_name(job), safe="")
    parts = [f"/metrics/job/{job_path}"]
    for k, v in (grouping or {}).items():
        parts.append(f"/{urllib.parse.quote(_sanitize_label_key(k), safe='')}/{urllib.parse.quote(str(v), safe='')}")
    url = endpoint.rstrip("/") + "".join(parts)
    req = urllib.request.Request(url=url, data=text, method="PUT")
    req.add_header("Content-Type", "text/plain; version=0.0.4")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, f"push failed: {e}"

# =========================
# ASGI app for /metrics (optional)
# =========================

def make_prometheus_asgi_app(registry: MetricsRegistry):
    """
    Небольшое ASGI-приложение для экспозиции метрик без зависимостей.
    Пример:
        app = make_prometheus_asgi_app(registry)
        # монтировать под /metrics в вашем ASGI-роутере
    """
    async def app(scope, receive, send):
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 400, "headers": []})
            await send({"type": "http.response.body", "body": b"bad scope"})
            return
        path = scope.get("path", "")
        if path not in ("/", "", "/metrics"):
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b"not found"})
            return
        text = registry.render_prometheus_text().encode("utf-8")
        headers = [
            (b"content-type", b"text/plain; version=0.0.4; charset=utf-8"),
            (b"cache-control", b"no-cache"),
        ]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": text})
    return app

# =========================
# Usage example (manual)
# =========================

if __name__ == "__main__":  # pragma: no cover
    r = MetricsRegistry(max_labelsets_per_metric=1000)
    # core metrics
    reqs = r.counter("http_requests_total", "Total HTTP requests", labelnames=("method", "code"))
    inflight = r.gauge("http_inflight_requests", "In-flight HTTP requests")
    lat = r.histogram("http_request_duration_seconds", "HTTP request latency", labelnames=("method",), buckets=default_latency_buckets())

    # simulate updates
    reqs.labels(method="GET", code="200").inc()
    inflight.set(3)
    with lat.labels(method="GET").time():
        time.sleep(0.02)

    # process metrics
    start_process_metrics_collector(r, interval_sec=2.0)

    # dump exposition
    print(r.render_prometheus_text())
