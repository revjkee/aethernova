# physical_integration/observability/metrics.py
# Промышленный модуль метрик: Prometheus + (опционально) OpenTelemetry.
# Возможности:
# - Единая инициализация реестра Prometheus (multiprocess/standalone)
# - build_info и runtime-гауги (CPU, RSS, FD, GC) при наличии psutil
# - HTTP/ASGI middleware для FastAPI/Starlette (pic_http_* метрики)
# - gRPC перехватчик (pic_grpc_* метрики)
# - Декораторы @track_task и таймеры для фоновых задач
# - Сбор лагов event-loop (pic_runtime_event_loop_lag_seconds)
# - Безопасные заглушки при отсутствии зависимостей
from __future__ import annotations

import asyncio
import gc
import os
import sys
import time
import types
import typing as t
from contextlib import suppress
from dataclasses import dataclass

# ---------- Опциональные зависимости ----------
try:
    import prometheus_client as prom
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Summary, PROCESS_COLLECTOR, PLATFORM_COLLECTOR, GC_COLLECTOR
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

try:
    import psutil  # для runtime-гаугов
    _HAS_PSUTIL = True
except Exception:  # pragma: no cover
    _HAS_PSUTIL = False

try:
    from opentelemetry import metrics as otel_metrics  # API v1
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    _HAS_STARLETTE = True
except Exception:  # pragma: no cover
    _HAS_STARLETTE = False

import logging
LOG = logging.getLogger(__name__)

# ---------- Конфигурация по умолчанию ----------
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10)
DEFAULT_SLOW_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30)

# ---------- Глобальное состояние ----------
_REGISTRY: "CollectorRegistry | None" = None
_METRICS_STARTED = False

# Базовые лейблы для унификации
@dataclass(frozen=True)
class BaseLabels:
    service: str = os.getenv("APP_NAME", "physical-integration-core")
    env: str = os.getenv("ENV", "prod")
    region: str | None = os.getenv("REGION") or None

# ---------- Вспомогательные утилиты ----------
def _sanitize_path(path: str) -> str:
    """
    Нормализует путь для снижения кардинальности.
    Пример: /v1/devices/123 -> /v1/devices/:id
    """
    # Простая эвристика: числа -> :id, UUID -> :uuid
    import re
    path = re.sub(r"[0-9]+", ":id", path)
    path = re.sub(r"[0-9a-fA-F-]{36}", ":uuid", path)
    return path

def _get_prom_registry(multiprocess: bool | None = None) -> "CollectorRegistry":
    """
    Возвращает глобальный реестр Prometheus.
    Если задан PROMETHEUS_MULTIPROC_DIR (или multiprocess=True) — настраивает MultiprocessCollector.
    """
    global _REGISTRY
    if not _HAS_PROM:
        raise RuntimeError("prometheus_client is not installed")
    if _REGISTRY is not None:
        return _REGISTRY

    mp_dir = os.getenv("PROMETHEUS_MULTIPROC_DIR")
    if multiprocess is None:
        multiprocess = bool(mp_dir)

    if multiprocess:
        if not mp_dir:
            raise RuntimeError("multiprocess enabled but PROMETHEUS_MULTIPROC_DIR is not set")
        os.makedirs(mp_dir, exist_ok=True)
        # Сборщики multiprocess используют специальный реестр
        _REGISTRY = CollectorRegistry()
        try:
            from prometheus_client.multiprocess import MultiProcessCollector, mark_process_dead
            MultiProcessCollector(_REGISTRY)
        except Exception as e:  # pragma: no cover
            LOG.warning("MultiprocessCollector init failed: %s", e)
            from prometheus_client import REGISTRY as _DEF
            _REGISTRY = _DEF
    else:
        _REGISTRY = CollectorRegistry()
        # Включаем стандартные коллекторы процесса/платформы/GC
        prom.ProcessCollector(registry=_REGISTRY)
        prom.PlatformCollector(registry=_REGISTRY)
        prom.GCCollector(registry=_REGISTRY)

    return _REGISTRY

# ---------- Инициализация и HTTP-экспорт ----------
def init_metrics(
    *,
    service: str | None = None,
    env: str | None = None,
    region: str | None = None,
    addr: str = "0.0.0.0",
    port: int = int(os.getenv("METRICS_PORT", "9090")),
    multiprocess: bool | None = None,
    start_http: bool = True,
) -> "CollectorRegistry | None":
    """
    Инициализация реестра, build_info, runtime-гаугов и (опционально) HTTP-экспортера.
    Идемпотентна: повторные вызовы не навредят.
    """
    global _METRICS_STARTED
    if not _HAS_PROM:
        LOG.warning("prometheus_client is not installed; metrics disabled")
        return None

    reg = _get_prom_registry(multiprocess=multiprocess)

    labels = BaseLabels(
        service=service or BaseLabels().service,
        env=env or BaseLabels().env,
        region=region or BaseLabels().region,
    )
    # build_info: gauge == 1 с метаданными
    build = Gauge(
        "pic_build_info",
        "Build and deployment info",
        ["service", "env", "region", "version", "git", "build_date"],
        registry=reg,
    )
    build.labels(
        labels.service, labels.env, labels.region or "", os.getenv("APP_VERSION", "0.0.0"), os.getenv("GIT_COMMIT", "unknown"), os.getenv("BUILD_DATE", "unknown")
    ).set(1)

    # runtime-гауги (обновляются периодически)
    _register_runtime_gauges(reg)

    # Экспортёр
    if start_http and not _METRICS_STARTED:
        # Если multiprocess — лучше использовать отдельный gunicorn prometheus_multiproc_wsgi.
        try:
            prom.start_http_server(port, addr=addr, registry=reg)
            _METRICS_STARTED = True
            LOG.info("Prometheus metrics on %s:%d/metrics", addr, port)
        except Exception as e:  # pragma: no cover
            LOG.warning("metrics HTTP server failed: %s", e)

    return reg

# ---------- Runtime gauges ----------
_RUNTIME_CPU = None
_RUNTIME_RSS = None
_RUNTIME_FD = None
_RUNTIME_THREADS = None
_RUNTIME_GC_GEN0 = None
_RUNTIME_GC_GEN1 = None
_RUNTIME_GC_GEN2 = None
_EVENT_LOOP_LAG = None

def _register_runtime_gauges(reg: "CollectorRegistry") -> None:
    global _RUNTIME_CPU, _RUNTIME_RSS, _RUNTIME_FD, _RUNTIME_THREADS, _RUNTIME_GC_GEN0, _RUNTIME_GC_GEN1, _RUNTIME_GC_GEN2, _EVENT_LOOP_LAG
    if not _HAS_PROM:
        return
    _RUNTIME_CPU = Gauge("pic_runtime_cpu_percent", "Process CPU percent (psutil)", ["service"], registry=reg)
    _RUNTIME_RSS = Gauge("pic_runtime_rss_bytes", "Resident Set Size in bytes (psutil)", ["service"], registry=reg)
    _RUNTIME_FD = Gauge("pic_runtime_open_fds", "Open file descriptors (psutil)", ["service"], registry=reg)
    _RUNTIME_THREADS = Gauge("pic_runtime_threads", "Thread count (psutil)", ["service"], registry=reg)
    _RUNTIME_GC_GEN0 = Gauge("pic_runtime_gc_gen0", "GC gen0 objects", ["service"], registry=reg)
    _RUNTIME_GC_GEN1 = Gauge("pic_runtime_gc_gen1", "GC gen1 objects", ["service"], registry=reg)
    _RUNTIME_GC_GEN2 = Gauge("pic_runtime_gc_gen2", "GC gen2 objects", ["service"], registry=reg)
    _EVENT_LOOP_LAG = Histogram("pic_runtime_event_loop_lag_seconds", "Event loop scheduling lag", ["service"], buckets=DEFAULT_BUCKETS, registry=reg)

async def start_runtime_collector(service: str | None = None, interval: float = 5.0) -> None:
    """
    Запускает фоновой сбор runtime-метрик. Вызывайте один раз при старте приложения.
    """
    if not _HAS_PROM:
        return
    svc = service or BaseLabels().service
    proc = psutil.Process(os.getpid()) if _HAS_PSUTIL else None
    loop = asyncio.get_event_loop()
    last = loop.time()

    while True:
        try:
            if _HAS_PSUTIL and proc:
                _RUNTIME_CPU.labels(svc).set(proc.cpu_percent(interval=0.0))
                with suppress(Exception):
                    _RUNTIME_RSS.labels(svc).set(proc.memory_info().rss)
                with suppress(Exception):
                    _RUNTIME_FD.labels(svc).set(proc.num_fds() if hasattr(proc, "num_fds") else 0)
                with suppress(Exception):
                    _RUNTIME_THREADS.labels(svc).set(proc.num_threads())
            if _HAS_PROM:
                # GC объекты
                gc_counts = gc.get_count()
                _RUNTIME_GC_GEN0.labels(svc).set(gc_counts[0])
                _RUNTIME_GC_GEN1.labels(svc).set(gc_counts[1])
                _RUNTIME_GC_GEN2.labels(svc).set(gc_counts[2])

                # Лаг event-loop
                now = loop.time()
                lag = max(0.0, now - last - interval)
                _EVENT_LOOP_LAG.labels(svc).observe(lag)
                last = now
        except Exception:  # pragma: no cover
            LOG.debug("runtime collector iteration failed", exc_info=True)

        await asyncio.sleep(interval)

# ---------- HTTP/ASGI middleware ----------
class _NullMiddleware:  # заглушка, если Starlette недоступен
    def __init__(self, *a, **k): pass

if _HAS_PROM:
    _HTTP_REQS = Counter("pic_http_requests_total", "HTTP requests", ["service", "env", "region", "method", "path", "code"])
    _HTTP_LAT = Histogram("pic_http_request_duration_seconds", "HTTP request duration", ["service", "env", "region", "method", "path"], buckets=DEFAULT_BUCKETS)
    _HTTP_INFLIGHT = Gauge("pic_http_inflight_requests", "In-flight HTTP requests", ["service", "env", "region", "method", "path"])
else:
    class _Dummy:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    _HTTP_REQS = _HTTP_LAT = _HTTP_INFLIGHT = _Dummy()

def instrument_asgi_app(app, *, service: str | None = None, env: str | None = None, region: str | None = None):
    """
    Оборачивает Starlette/FastAPI приложение middleware с метриками.
    Возвращает то же приложение.
    """
    if not _HAS_STARLETTE or not _HAS_PROM:
        return app

    labels = BaseLabels(service=service or BaseLabels().service, env=env or BaseLabels().env, region=region or BaseLabels().region)

    class MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            method = request.method
            # Получаем шаблон маршрута, если доступен; иначе нормализуем фактический путь
            route = request.scope.get("route")
            if route and hasattr(route, "path_format"):
                path = route.path_format
            else:
                path = _sanitize_path(request.url.path)

            key_labels = (labels.service, labels.env, labels.region or "", method, path)
            _HTTP_INFLIGHT.labels(*key_labels).inc()
            start = time.perf_counter()
            code = "500"
            try:
                response: Response = await call_next(request)
                code = str(response.status_code)
                return response
            except Exception:
                code = "500"
                raise
            finally:
                elapsed = time.perf_counter() - start
                _HTTP_LAT.labels(*key_labels).observe(elapsed)
                _HTTP_REQS.labels(*(labels.service, labels.env, labels.region or "", method, path, code)).inc()
                _HTTP_INFLIGHT.labels(*key_labels).dec()

    app.add_middleware(MetricsMiddleware)
    return app

# ---------- gRPC перехватчик ----------
if _HAS_PROM:
    _GRPC_REQ = Counter("pic_grpc_requests_total", "gRPC requests", ["service", "env", "region", "rpc", "code"])
    _GRPC_LAT = Histogram("pic_grpc_request_duration_seconds", "gRPC request duration", ["service", "env", "region", "rpc"], buckets=DEFAULT_BUCKETS)
    _GRPC_INFLIGHT = Gauge("pic_grpc_inflight_requests", "In-flight gRPC requests", ["service", "env", "region", "rpc"])
else:
    _GRPC_REQ = _GRPC_LAT = _GRPC_INFLIGHT = _Dummy()

def _split_full_method(full_method: str) -> str:
    # full_method: "/package.Service/Method" -> "package.Service/Method"
    try:
        return full_method.strip("/ ")
    except Exception:
        return "unknown"

class GRPCMetricsInterceptor:
    """
    Перехватчик для grpc.aio.Server. Использование:
      server = grpc.aio.server(interceptors=[GRPCMetricsInterceptor()])
    """
    def __init__(self, *, service: str | None = None, env: str | None = None, region: str | None = None):
        self.labels = BaseLabels(service=service or BaseLabels().service, env=env or BaseLabels().env, region=region or BaseLabels().region)

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler
        rpc = _split_full_method(handler_call_details.method)
        key = (self.labels.service, self.labels.env, self.labels.region or "", rpc)

        async def unary_unary(request, context):
            start = time.perf_counter()
            _GRPC_INFLIGHT.labels(*key).inc()
            code = "OK"
            try:
                resp = await handler.unary_unary(request, context)
                code = (context.code().name if context.code() else "OK") if hasattr(context, "code") else "OK"
                return resp
            except Exception as e:
                code = getattr(getattr(e, "code", lambda: types.SimpleNamespace(name="INTERNAL"))(), "name", "INTERNAL")
                raise
            finally:
                _GRPC_LAT.labels(*key).observe(time.perf_counter() - start)
                _GRPC_REQ.labels(*(self.labels.service, self.labels.env, self.labels.region or "", rpc, code)).inc()
                _GRPC_INFLIGHT.labels(*key).dec()

        async def unary_stream(request, context):
            start = time.perf_counter()
            _GRPC_INFLIGHT.labels(*key).inc()
            code = "OK"
            try:
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except Exception as e:
                code = getattr(getattr(e, "code", lambda: types.SimpleNamespace(name="INTERNAL"))(), "name", "INTERNAL")
                raise
            finally:
                _GRPC_LAT.labels(*key).observe(time.perf_counter() - start)
                _GRPC_REQ.labels(*(self.labels.service, self.labels.env, self.labels.region or "", rpc, code)).inc()
                _GRPC_INFLIGHT.labels(*key).dec()

        import grpc
        return grpc.aio.rpc_method_handler(
            unary_unary=unary_unary if handler.unary_unary else None,
            unary_stream=unary_stream if handler.unary_stream else None,
            request_streaming=handler.request_streaming,
            response_streaming=handler.response_streaming,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

# ---------- Декораторы и утилиты ----------
if _HAS_PROM:
    _TASK_LAT = Histogram("pic_task_duration_seconds", "Task duration", ["service", "env", "region", "task"], buckets=DEFAULT_SLOW_BUCKETS)
    _TASK_ERR = Counter("pic_task_errors_total", "Task exceptions", ["service", "env", "region", "task", "exc"])
else:
    _TASK_LAT = _TASK_ERR = _Dummy()

def track_task(name: str, *, service: str | None = None, env: str | None = None, region: str | None = None):
    """
    Декоратор для синхронных/асинхронных функций: измеряет длительность и считает ошибки.
    """
    labels = BaseLabels(service=service or BaseLabels().service, env=env or BaseLabels().env, region=region or BaseLabels().region)

    def _wrap(func):
        if asyncio.iscoroutinefunction(func):
            async def async_inner(*a, **k):
                start = time.perf_counter()
                try:
                    return await func(*a, **k)
                except Exception as e:
                    _TASK_ERR.labels(labels.service, labels.env, labels.region or "", name, e.__class__.__name__).inc()
                    raise
                finally:
                    _TASK_LAT.labels(labels.service, labels.env, labels.region or "", name).observe(time.perf_counter() - start)
            return async_inner
        else:
            def inner(*a, **k):
                start = time.perf_counter()
                try:
                    return func(*a, **k)
                except Exception as e:
                    _TASK_ERR.labels(labels.service, labels.env, labels.region or "", name, e.__class__.__name__).inc()
                    raise
                finally:
                    _TASK_LAT.labels(labels.service, labels.env, labels.region or "", name).observe(time.perf_counter() - start)
            return inner
    return _wrap

class TaskTimer:
    """
    Ручной таймер для блоков кода:
      with TaskTimer("normalize_batch"): ...
    """
    def __init__(self, name: str, *, service: str | None = None, env: str | None = None, region: str | None = None):
        self.labels = BaseLabels(service=service or BaseLabels().service, env=env or BaseLabels().env, region=region or BaseLabels().region)
        self.name = name
        self._start = None

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - (self._start or time.perf_counter())
        _TASK_LAT.labels(self.labels.service, self.labels.env, self.labels.region or "", self.name).observe(elapsed)
        if exc_type:
            _TASK_ERR.labels(self.labels.service, self.labels.env, self.labels.region or "", self.name, exc_type.__name__).inc()
        return False

# ---------- OpenTelemetry (опционально) ----------
class _OtelBridge:
    def __init__(self):
        self.meter = otel_metrics.get_meter(__name__) if _HAS_OTEL else None

    def counter(self, name: str, description: str = ""):
        if not self.meter:
            return lambda *_a, **_k: None
        c = self.meter.create_counter(name, description=description)
        return lambda add=1, **labels: c.add(add, attributes=labels)

    def histogram(self, name: str, description: str = ""):
        if not self.meter:
            return lambda *_a, **_k: None
        h = self.meter.create_histogram(name, description=description)
        return lambda value, **labels: h.record(value, attributes=labels)

_OTEL = _OtelBridge()

# ---------- Пример интеграции ----------
# В HTTP-приложении:
#   init_metrics(start_http=True)
#   instrument_asgi_app(app)
#   asyncio.create_task(start_runtime_collector())
#
# В gRPC-сервере:
#   init_metrics(start_http=True)
#   interceptors=[GRPCMetricsInterceptor(), ...]
#
# Для фоновых задач:
#   @track_task("device_sync")
#   async def device_sync(): ...

# ---------- Узкоспециальные метрики домена (пример) ----------
if _HAS_PROM:
    NORMALIZED_EVENTS = Counter("pic_norm_events_total", "Normalized telemetry events", ["route", "result"])
else:
    NORMALIZED_EVENTS = _Dummy()

def inc_normalized_events(route: str, result: str) -> None:
    """
    Удобная обертка: result = ok|error|drop.
    """
    NORMALIZED_EVENTS.labels(route, result).inc()
