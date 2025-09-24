# -*- coding: utf-8 -*-
"""
Prometheus/OpenMetrics exposition + HTTP instrumentation for FastAPI/Starlette.
Unverified: параметры окружения/версии не подтверждены. I cannot verify this.

Функции:
- setup_metrics(app, service_name=..., service_version=...) — регистрирует middleware и build_info.
- router с GET /metrics — корректный CONTENT_TYPE_LATEST, multiprocess-сбор (если PROMETHEUS_MULTIPROC_DIR задан).

Особенности:
- Multiprocess: для Gunicorn (несколько воркеров) используем отдельный CollectorRegistry
  и multiprocess.MultiProcessCollector. Процессные/GC метрики регистрируются только
  в single-process режиме.
- HTTP-метрики: Counter http_requests_total, Histogram http_request_duration_seconds,
  Gauge http_inflight_requests, лейблы: method, handler, status. handler — шаблон пути.
- Исключаем сам /metrics из наблюдения, чтобы избежать рекурсивной нагрузки.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from fastapi import APIRouter, Request, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)
from prometheus_client import gc_collector, platform_collector, process_collector  # type: ignore
from prometheus_client import multiprocess  # type: ignore

# ------------------------------------------------------------------------------
# Константы и глобалы
# ------------------------------------------------------------------------------

MULTIPROC_ENV = "PROMETHEUS_MULTIPROC_DIR"

HTTP_LATENCY_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

# Глобальные метрики (регистрируются в REGISTRY; это ок и в multiprocess — они
# вычисляются per-process, а сбор — через MultiProcessCollector)
HTTP_REQUESTS = Counter(
    "http_requests_total",
    "Total HTTP requests",
    labelnames=("method", "handler", "status"),
)
HTTP_INFLIGHT = Gauge(
    "http_inflight_requests",
    "In-progress HTTP requests",
    labelnames=("method", "handler"),
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    labelnames=("method", "handler", "status"),
    buckets=HTTP_LATENCY_BUCKETS,
)

# build_info как Info — безопасно для multiprocess, лейблы неизменны
SERVICE_BUILD_INFO = Info("service_build_info", "Service build information")


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------

def _is_multiproc() -> bool:
    return os.environ.get(MULTIPROC_ENV) not in (None, "")


def _ensure_single_process_collectors_registered() -> None:
    """
    Регистрирует стандартные коллектора process/platform/gc только в single-process.
    В multiprocess они должны быть выключены согласно рекомендациям prometheus_client.
    """
    if not _is_multiproc():
        try:
            process_collector.ProcessCollector(registry=REGISTRY)
        except Exception:
            pass
        try:
            platform_collector.PlatformCollector(registry=REGISTRY)
        except Exception:
            pass
        try:
            gc_collector.GCCollector(registry=REGISTRY)
        except Exception:
            pass


def _route_template_from_scope(scope: Scope) -> str:
    """
    Нормализует путь до шаблона (handler), избегая высокой кардинальности.
    FastAPI: route.path_format, Starlette: route.path
    """
    route = scope.get("route")
    if route is not None:
        # FastAPI route имеет path_format; Starlette — path
        fmt = getattr(route, "path_format", None) or getattr(route, "path", None)
        if isinstance(fmt, str) and fmt:
            return fmt
    # Фоллбек — реальный путь (менее желательно)
    p = scope.get("path")
    if isinstance(p, str) and p:
        return p
    raw = scope.get("raw_path", b"")
    return raw.decode("utf-8", "ignore") if isinstance(raw, (bytes, bytearray)) else "/unknown"


def _status_class(status_code: int) -> str:
    return f"{(status_code // 100) * 100}xx"


# ------------------------------------------------------------------------------
# Middleware для HTTP-инструментирования
# ------------------------------------------------------------------------------

class PrometheusHTTPMiddleware:
    """
    Лёгкий ASGI-middleware: считает in-flight, latency и total по handler/method/status.
    Исключает /metrics (по шаблону).
    """
    def __init__(self, app: ASGIApp, metrics_path: str = "/metrics") -> None:
        self.app = app
        self.metrics_path = metrics_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        handler = _route_template_from_scope(scope)
        # Не считаем сам /metrics
        if handler == self.metrics_path:
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        start = time.perf_counter()
        inflight_lbl = (method, handler)
        HTTP_INFLIGHT.labels(*inflight_lbl).inc()

        status_holder = {"status": 200}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - start
            status = status_holder["status"]
            status_lbl = str(status)
            HTTP_INFLIGHT.labels(*inflight_lbl).dec()
            # Total и latency
            HTTP_REQUESTS.labels(method, handler, status_lbl).inc()
            HTTP_LATENCY.labels(method, handler, status_lbl).observe(elapsed)


# ------------------------------------------------------------------------------
# Экспортёр /metrics (Prometheus/OpenMetrics)
# ------------------------------------------------------------------------------

router = APIRouter(tags=["metrics"])


@router.get("/metrics", include_in_schema=False)
async def metrics_endpoint(_: Request) -> Response:
    """
    Экспозиция метрик. В multiprocess создаём новый реестр и подключаем
    MultiProcessCollector, иначе возвращаем generate_latest(REGISTRY).
    """
    if _is_multiproc():
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        output = generate_latest(registry)
    else:
        output = generate_latest(REGISTRY)

    return Response(content=output, media_type=CONTENT_TYPE_LATEST)


# ------------------------------------------------------------------------------
# Публичная точка инициализации
# ------------------------------------------------------------------------------

def setup_metrics(
    app: ASGIApp,
    *,
    service_name: str = "neuroforge-core",
    service_version: Optional[str] = None,
    service_revision: Optional[str] = None,
    metrics_path: str = "/metrics",
) -> None:
    """
    Регистрирует middleware и build_info. Вызывайте один раз при старте приложения.

    Пример:
        from fastapi import FastAPI
        from neuroforge_core.api.http.routers.v1.metrics import router, setup_metrics

        app = FastAPI()
        setup_metrics(app, service_name="nf-api", service_version="1.2.3", service_revision="abc123")
        app.include_router(router, prefix="/api/v1")
    """
    _ensure_single_process_collectors_registered()

    # Build info публикуем как неизменяемые лейблы (Info())
    SERVICE_BUILD_INFO.info({
        "service": service_name,
        "version": service_version or os.environ.get("SERVICE_VERSION", "0.0.0"),
        "revision": service_revision or os.environ.get("SERVICE_REVISION", "unknown"),
    })

    # Подключаем middleware в корень приложения
    # Важно подключать до других middleware, которые могут short-circuit ответы.
    app.add_middleware(PrometheusHTTPMiddleware, metrics_path=metrics_path)
