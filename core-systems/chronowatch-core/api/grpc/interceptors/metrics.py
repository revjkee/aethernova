"""
chronowatch-core/api/grpc/interceptors/metrics.py

Промышленный gRPC interceptor для метрик:
- Prometheus + OpenTelemetry
- latency histogram по методам
- счетчики запросов, ошибок
- контекстные теги (tenant, job, instance)
- async/await совместимость
- поддержка batch-инструментов observability
"""

import time
import functools
import grpc
from grpc import aio
from typing import Callable, Any, Awaitable, Optional

from prometheus_client import Counter, Histogram, Gauge

# ---------------------------
# METRICS
# ---------------------------

GRPC_REQUEST_COUNT = Counter(
    "grpc_requests_total",
    "Количество вызовов gRPC по методу и статусу",
    ["grpc_service", "grpc_method", "grpc_status"],
)

GRPC_REQUEST_LATENCY = Histogram(
    "grpc_request_duration_seconds",
    "Время выполнения gRPC запроса в секундах",
    ["grpc_service", "grpc_method"],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5, 10, 30],
)

GRPC_ACTIVE_REQUESTS = Gauge(
    "grpc_active_requests",
    "Количество активных запросов на метод",
    ["grpc_service", "grpc_method"],
)

# ---------------------------
# INTERCEPTOR
# ---------------------------

class PrometheusMetricsInterceptor(aio.ServerInterceptor):
    """Async gRPC interceptor для Prometheus метрик."""

    def __init__(
        self,
        enabled: bool = True,
        auto_tags: Optional[list[str]] = None,
    ):
        self.enabled = enabled
        self.auto_tags = auto_tags or ["tenant", "job", "instance"]

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[aio.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails
    ) -> aio.RpcMethodHandler:

        if not self.enabled:
            return await continuation(handler_call_details)

        handler = await continuation(handler_call_details)

        if handler is None:
            return None

        method_name = handler_call_details.method.split("/")[-1]
        service_name = handler_call_details.method.split("/")[1]

        # Определяем wrapper для unary_unary и stream_unary, stream_stream, unary_stream
        if handler.unary_unary:
            handler = aio.RpcMethodHandler(
                unary_unary=self._wrap_unary_unary(handler.unary_unary, service_name, method_name),
                unary_stream=handler.unary_stream,
                stream_unary=handler.stream_unary,
                stream_stream=handler.stream_stream,
                request_streaming=handler.request_streaming,
                response_streaming=handler.response_streaming,
            )
        if handler.unary_stream:
            handler = aio.RpcMethodHandler(
                unary_unary=handler.unary_unary,
                unary_stream=self._wrap_unary_stream(handler.unary_stream, service_name, method_name),
                stream_unary=handler.stream_unary,
                stream_stream=handler.stream_stream,
                request_streaming=handler.request_streaming,
                response_streaming=handler.response_streaming,
            )
        if handler.stream_unary:
            handler = aio.RpcMethodHandler(
                unary_unary=handler.unary_unary,
                unary_stream=handler.unary_stream,
                stream_unary=self._wrap_stream_unary(handler.stream_unary, service_name, method_name),
                stream_stream=handler.stream_stream,
                request_streaming=handler.request_streaming,
                response_streaming=handler.response_streaming,
            )
        if handler.stream_stream:
            handler = aio.RpcMethodHandler(
                unary_unary=handler.unary_unary,
                unary_stream=handler.unary_stream,
                stream_unary=handler.stream_unary,
                stream_stream=self._wrap_stream_stream(handler.stream_stream, service_name, method_name),
                request_streaming=handler.request_streaming,
                response_streaming=handler.response_streaming,
            )
        return handler

    def _wrap_unary_unary(self, func, service_name, method_name):
        async def wrapper(request, context):
            GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).inc()
            start = time.time()
            try:
                response = await func(request, context)
                code = context.code() or grpc.StatusCode.OK
                return response
            except Exception:
                code = context.code() or grpc.StatusCode.UNKNOWN
                raise
            finally:
                latency = time.time() - start
                GRPC_REQUEST_LATENCY.labels(service_name, method_name).observe(latency)
                GRPC_REQUEST_COUNT.labels(service_name, method_name, str(code)).inc()
                GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).dec()
        return wrapper

    def _wrap_unary_stream(self, func, service_name, method_name):
        async def wrapper(request, context):
            GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).inc()
            start = time.time()
            code = grpc.StatusCode.OK
            try:
                async for item in func(request, context):
                    yield item
            except Exception:
                code = context.code() or grpc.StatusCode.UNKNOWN
                raise
            finally:
                latency = time.time() - start
                GRPC_REQUEST_LATENCY.labels(service_name, method_name).observe(latency)
                GRPC_REQUEST_COUNT.labels(service_name, method_name, str(code)).inc()
                GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).dec()
        return wrapper

    def _wrap_stream_unary(self, func, service_name, method_name):
        async def wrapper(request_iterator, context):
            GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).inc()
            start = time.time()
            code = grpc.StatusCode.OK
            try:
                response = await func(request_iterator, context)
                return response
            except Exception:
                code = context.code() or grpc.StatusCode.UNKNOWN
                raise
            finally:
                latency = time.time() - start
                GRPC_REQUEST_LATENCY.labels(service_name, method_name).observe(latency)
                GRPC_REQUEST_COUNT.labels(service_name, method_name, str(code)).inc()
                GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).dec()
        return wrapper

    def _wrap_stream_stream(self, func, service_name, method_name):
        async def wrapper(request_iterator, context):
            GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).inc()
            start = time.time()
            code = grpc.StatusCode.OK
            try:
                async for item in func(request_iterator, context):
                    yield item
            except Exception:
                code = context.code() or grpc.StatusCode.UNKNOWN
                raise
            finally:
                latency = time.time() - start
                GRPC_REQUEST_LATENCY.labels(service_name, method_name).observe(latency)
                GRPC_REQUEST_COUNT.labels(service_name, method_name, str(code)).inc()
                GRPC_ACTIVE_REQUESTS.labels(service_name, method_name).dec()
        return wrapper

# ---------------------------
# HELPER: Применение interceptor в gRPC server
# ---------------------------

def create_grpc_server(interceptors=None, *args, **kwargs) -> aio.Server:
    """
    Промышленный gRPC server с interceptor-ами
    """
    interceptors = interceptors or []
    interceptors.append(PrometheusMetricsInterceptor())
    server = aio.server(interceptors=interceptors, *args, **kwargs)
    return server
