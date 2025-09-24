# mythos-core/mythos/observability/metrics.py
"""
Единый слой метрик для Mythos Core.
Особенности:
- Prometheus (prometheus_client) с fallback в no-op при отсутствии зависимости.
- Мультипроцессный режим (gunicorn/uvicorn workers) через PROMETHEUS_MULTIPROC_DIR.
- Фабрики Counter/Gauge/Histogram с ограничением кардинальности меток.
- Таймеры (context manager) и декораторы @track (sync/async), observe_exception.
- ASGI middleware для HTTP-метрик FastAPI/Starlette + /metrics ASGI endpoint.
- Утилиты для измерения SQL/кэша/внешних вызовов.

ENV:
  METRICS_NAMESPACE=mythos
  PROMETHEUS_MULTIPROC_DIR=/var/run/prom
  METRICS_HTTP_BUCKETS=0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10,30
  METRICS_SQL_BUCKETS=0.001,0.002,0.005,0.01,0.02,0.05,0.1,0.25,0.5,1
  METRICS_MAX_LABEL_VALUES=200   # мягкая защита от кардинальности на метрику

Автор: platform@mythos.local
"""

from __future__ import annotations

import os
import time
import functools
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Union, Awaitable

# ====== Prometheus bootstrap (optional) ======

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        CONTENT_TYPE_LATEST,
        generate_latest,
        PROCESS_COLLECTOR,
        PLATFORM_COLLECTOR,
        GC_COLLECTOR,
        multiprocess,
        make_asgi_app,
        start_http_server
    )  # type: ignore
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    CollectorRegistry = Counter = Gauge = Histogram = None  # type: ignore
    PROCESS_COLLECTOR = PLATFORM_COLLECTOR = GC_COLLECTOR = None  # type: ignore
    multiprocess = None  # type: ignore
    make_asgi_app = start_http_server = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    _PROM_AVAILABLE = False

# ====== No-op stubs (when prometheus_client is absent) ======

class _NoMetric:
    def labels(self, *a, **k): return self
    def inc(self, *a, **k): pass
    def dec(self, *a, **k): pass
    def set(self, *a, **k): pass
    def observe(self, *a, **k): pass

class _NoRegistry:
    def __init__(self, *a, **k): pass

# ====== Label cardinality guard ======

class LabelSanitizer:
    """
    Ограничивает кардинальность: хранит наборы значений для каждой метрики и метки.
    При превышении порога — подставляет значение "_other".
    """
    def __init__(self, max_values: int = 200) -> None:
        self.max_values = max_values
        self._seen: Dict[Tuple[str, str], set] = {}

    def sanitize_labels(self, metric_name: str, labels: Dict[str, str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in labels.items():
            key = (metric_name, k)
            bucket = self._seen.setdefault(key, set())
            val = str(v) if v is not None else "none"
            if val not in bucket and len(bucket) >= self.max_values:
                out[k] = "_other"
            else:
                bucket.add(val)
                out[k] = val
        return out

# ====== Metrics registry and factories ======

class Metrics:
    """
    Главный фасад метрик.
    """
    def __init__(self,
                 namespace: Optional[str] = None,
                 registry: Optional[Any] = None,
                 max_label_values: Optional[int] = None) -> None:
        self.enabled = _PROM_AVAILABLE
        self.namespace = namespace or os.getenv("METRICS_NAMESPACE", "mythos")
        self.registry = registry or (CollectorRegistry() if self.enabled else _NoRegistry())
        self.sanitizer = LabelSanitizer(max_values=int(os.getenv("METRICS_MAX_LABEL_VALUES", str(max_label_values or 200))))
        self._init_default_collectors()

        # кэш фабрик по (name, tuple(labelnames))
        self._counters: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._gauges: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
        self._hists: Dict[Tuple[str, Tuple[str, ...]], Any] = {}

    def _init_default_collectors(self) -> None:
        if not self.enabled:
            return
        # Multi-process
        mp_dir = os.getenv("PROMETHEUS_MULTIPROC_DIR")
        if mp_dir and multiprocess:
            # В мультипроцессном режиме нельзя регистрировать стандартные коллектора,
            # используется MultiprocessCollector.
            multiprocess.MultiProcessCollector(self.registry)  # type: ignore[attr-defined]
        else:
            # Процессные/платформенные/GC метрики
            try:
                self.registry.register(PROCESS_COLLECTOR)
                self.registry.register(PLATFORM_COLLECTOR)
                self.registry.register(GC_COLLECTOR)
            except Exception:
                pass

    # ---- factories ----

    def counter(self, name: str, description: str, labelnames: Iterable[str] = ()) -> Any:
        key = (name, tuple(labelnames))
        if key in self._counters:
            return self._counters[key]
        if not self.enabled:
            m = _NoMetric()
        else:
            m = Counter(f"{self.namespace}_{name}", description, labelnames=tuple(labelnames), registry=self.registry)
        self._counters[key] = m
        return m

    def gauge(self, name: str, description: str, labelnames: Iterable[str] = ()) -> Any:
        key = (name, tuple(labelnames))
        if key in self._gauges:
            return self._gauges[key]
        if not self.enabled:
            m = _NoMetric()
        else:
            m = Gauge(f"{self.namespace}_{name}", description, labelnames=tuple(labelnames), registry=self.registry)
        self._gauges[key] = m
        return m

    def histogram(self, name: str, description: str, labelnames: Iterable[str] = (), buckets: Optional[Iterable[float]] = None) -> Any:
        key = (name, tuple(labelnames))
        if key in self._hists:
            return self._hists[key]
        if not self.enabled:
            m = _NoMetric()
        else:
            m = Histogram(f"{self.namespace}_{name}", description, labelnames=tuple(labelnames), buckets=buckets, registry=self.registry)
        self._hists[key] = m
        return m

    # ---- helpers ----

    def timer(self, hist_metric: Any, labels: Dict[str, str]) -> "Timer":
        return Timer(hist_metric, self.sanitizer.sanitize_labels(getattr(hist_metric, "_name", "timer"), labels))

    def expose_asgi(self):
        """
        Возвращает ASGI-приложение /metrics. Если прометей недоступен — простая заглушка.
        """
        if self.enabled and make_asgi_app:
            return make_asgi_app(registry=self.registry)
        async def _noop_app(scope, receive, send):
            if scope["type"] != "http":
                return
            content = b"# metrics disabled\n"
            headers = [(b"content-type", CONTENT_TYPE_LATEST.encode())]
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": content})
        return _noop_app

    def start_standalone_http(self, port: int = 9000, addr: str = "0.0.0.0") -> None:
        if self.enabled and start_http_server:
            start_http_server(port, addr=addr, registry=self.registry)

# ====== Timer context manager ======

class Timer:
    def __init__(self, hist_metric: Any, labels: Dict[str, str]) -> None:
        self.hist = hist_metric
        self.labels = labels
        self._t0 = 0.0

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        dt = time.perf_counter() - self._t0
        try:
            self.hist.labels(**self.labels).observe(dt)
        except Exception:
            pass

# ====== Decorators (sync/async) ======

def track(metrics: Metrics,
          name: str,
          description: str = "function duration",
          labelnames: Iterable[str] = (),
          labels: Optional[Callable[..., Dict[str, str]]] = None,
          buckets: Optional[Iterable[float]] = None):
    """
    Декоратор: измерить длительность вызова, инкрементировать started/handled и ошибки.
    """
    h = metrics.histogram(f"{name}_seconds", description, labelnames=labelnames, buckets=buckets)
    c_started = metrics.counter(f"{name}_started_total", "calls started", labelnames=labelnames)
    c_handled = metrics.counter(f"{name}_handled_total", "calls handled", labelnames=[*labelnames, "result"])

    def _labels(args, kwargs) -> Dict[str, str]:
        base = labels(*args, **kwargs) if labels else {}
        return metrics.sanitizer.sanitize_labels(name, base)

    def decorator(fn: Callable[..., Any]):
        if _is_coroutine(fn):
            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                lbs = _labels(args, kwargs)
                try:
                    c_started.labels(**lbs).inc()
                    t0 = time.perf_counter()
                    res = await fn(*args, **kwargs)
                    dt = time.perf_counter() - t0
                    h.labels(**lbs).observe(dt)
                    c_handled.labels(**{**lbs, "result": "ok"}).inc()
                    return res
                except Exception:
                    c_handled.labels(**{**lbs, "result": "error"}).inc()
                    raise
            return wrapper
        else:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                lbs = _labels(args, kwargs)
                try:
                    c_started.labels(**lbs).inc()
                    t0 = time.perf_counter()
                    res = fn(*args, **kwargs)
                    dt = time.perf_counter() - t0
                    h.labels(**lbs).observe(dt)
                    c_handled.labels(**{**lbs, "result": "ok"}).inc()
                    return res
                except Exception:
                    c_handled.labels(**{**lbs, "result": "error"}).inc()
                    raise
            return wrapper
    return decorator

def _is_coroutine(fn: Callable[..., Any]) -> bool:
    return getattr(fn, "__code__", None) and fn.__code__.co_flags & 0x80 == 0x80  # CO_COROUTINE

# ====== HTTP (ASGI) middleware ======

class PrometheusASGIMiddleware:
    """
    Лёгкая ASGI-мидлварь для HTTP-метрик.
    Лейблы: method, route, code
    """
    def __init__(self, app, metrics: Metrics, buckets: Optional[Iterable[float]] = None):
        self.app = app
        self.metrics = metrics
        buckets = buckets or _parse_buckets(os.getenv("METRICS_HTTP_BUCKETS",
            "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10,30"))
        self.req_hist = metrics.histogram("http_server_requests_seconds",
                                          "HTTP server request duration seconds",
                                          labelnames=("method", "route", "code"),
                                          buckets=buckets)
        self.req_started = metrics.counter("http_server_requests_started_total",
                                           "HTTP server requests started", labelnames=("method", "route"))
        self.req_inflight = metrics.gauge("http_server_inflight",
                                          "In-flight HTTP requests", labelnames=("method", "route"))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method", "GET").upper()
        route = self._extract_route(scope)
        lbs_base = self.metrics.sanitizer.sanitize_labels("http", {"method": method, "route": route})
        self.req_started.labels(**lbs_base).inc()
        self.req_inflight.labels(**lbs_base).inc()
        t0 = time.perf_counter()
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            return await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            dt = time.perf_counter() - t0
            lbs = {**lbs_base, "code": _code_class(status_code)}
            try:
                self.req_hist.labels(**lbs).observe(dt)
            except Exception:
                pass
            self.req_inflight.labels(**lbs_base).dec()

    @staticmethod
    def _extract_route(scope) -> str:
        # Пытаемся достать шаблон пути из Starlette/FastAPI
        route = scope.get("path", "/")
        try:
            route_obj = scope.get("route")
            if route_obj and getattr(route_obj, "path", None):
                return route_obj.path
        except Exception:
            pass
        return route

def _code_class(code: int) -> str:
    return f"{code//100}xx"

def _parse_buckets(s: str) -> Tuple[float, ...]:
    try:
        return tuple(float(x) for x in s.split(",") if x)
    except Exception:
        return (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)

# ====== Predefined metrics for DB/Cache/External calls ======

def build_standard_metrics(metrics: Metrics) -> Dict[str, Any]:
    """
    Создаёт стандартный набор метрик и возвращает их словарь.
    """
    sql_buckets = _parse_buckets(os.getenv("METRICS_SQL_BUCKETS",
                                           "0.001,0.002,0.005,0.01,0.02,0.05,0.1,0.25,0.5,1"))
    http_buckets = _parse_buckets(os.getenv("METRICS_HTTP_BUCKETS",
                                            "0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10,30"))
    return {
        "db_exec_seconds": metrics.histogram("db_exec_seconds", "DB execution seconds",
                                             labelnames=("op", "table"), buckets=sql_buckets),
        "cache_op_seconds": metrics.histogram("cache_op_seconds", "Cache operation seconds",
                                              labelnames=("op", "key"), buckets=sql_buckets),
        "external_call_seconds": metrics.histogram("external_call_seconds", "External call seconds",
                                                   labelnames=("system", "op"), buckets=http_buckets),
        "background_task_seconds": metrics.histogram("background_task_seconds", "Background task seconds",
                                                     labelnames=("task",), buckets=http_buckets),
        "background_task_started_total": metrics.counter("background_task_started_total",
                                                         "Background tasks started", labelnames=("task",)),
        "background_task_handled_total": metrics.counter("background_task_handled_total",
                                                         "Background tasks handled", labelnames=("task", "result")),
    }

# ====== Utilities ======

def time_block(metrics: Metrics, hist_name: str, description: str, labels: Dict[str, str],
               buckets: Optional[Iterable[float]] = None):
    """
    Быстрый таймер-контекст на лету (создаёт/использует гистограмму).
    """
    h = metrics.histogram(hist_name, description, labelnames=labels.keys(), buckets=buckets)
    return metrics.timer(h, labels)

async def wrap_task(coro: Awaitable[Any], *,
                    metrics: Metrics,
                    task_name: str,
                    std: Optional[Dict[str, Any]] = None) -> Any:
    """
    Инструментирует фоновую задачу.
    """
    std = std or build_standard_metrics(metrics)
    task_lbl = metrics.sanitizer.sanitize_labels("background_task", {"task": task_name})
    std["background_task_started_total"].labels(**task_lbl).inc()
    t0 = time.perf_counter()
    try:
        res = await coro
        std["background_task_seconds"].labels(**task_lbl).observe(time.perf_counter() - t0)
        std["background_task_handled_total"].labels(**{**task_lbl, "result": "ok"}).inc()
        return res
    except Exception:
        std["background_task_seconds"].labels(**task_lbl).observe(time.perf_counter() - t0)
        std["background_task_handled_total"].labels(**{**task_lbl, "result": "error"}).inc()
        raise

# ====== Convenience: instrument FastAPI app ======

def instrument_fastapi(app, metrics: Metrics, *, mount_endpoint: bool = True, endpoint_path: str = "/metrics") -> None:
    """
    Подключает HTTP-мидлварь и (опционально) точку /metrics к FastAPI/Starlette приложению.
    """
    app.add_middleware(PrometheusASGIMiddleware, metrics=metrics)
    if mount_endpoint:
        app.mount(endpoint_path, metrics.expose_asgi())

# ====== Singleton helper ======

_METRICS_SINGLETON: Optional[Metrics] = None

def get_metrics() -> Metrics:
    global _METRICS_SINGLETON
    if _METRICS_SINGLETON is None:
        _METRICS_SINGLETON = Metrics()
    return _METRICS_SINGLETON

# ====== Examples ======

if __name__ == "__main__":
    # Пример самостоятельного HTTP-экспортера Prometheus:
    m = get_metrics()
    m.start_standalone_http(port=9100)

    # Пример: замер SQL
    std = build_standard_metrics(m)
    with time_block(m, "db_exec_seconds", "DB execution seconds", {"op": "select", "table": "users"}):
        time.sleep(0.02)

    # Пример: декоратор
    @track(m, "job_process", description="Job processing", labelnames=("job",), labels=lambda j: {"job": j})
    def do_job(j: str):
        time.sleep(0.05)

    do_job("cleanup")

    print("Prometheus exporter is up on :9100")
