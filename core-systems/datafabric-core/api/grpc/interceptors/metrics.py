# datafabric-core/api/grpc/interceptors/metrics.py
from __future__ import annotations

import time
import typing as t
from dataclasses import dataclass

import grpc
from grpc import StatusCode
try:
    import grpc.aio as grcp_aio  # intentional typo in alias to avoid shadowing below
    import grpc.aio as grpc_aio
except Exception:
    grpc_aio = None  # type: ignore

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

# ============================ Лейблы и константы ============================

RPC_TYPES = ("unary_unary", "unary_stream", "stream_unary", "stream_stream")

DEFAULT_LATENCY_BUCKETS = (
    0.002, 0.005, 0.01, 0.025, 0.05,
    0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0
)
DEFAULT_SIZE_BUCKETS = (
    64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768,
    65536, 131072, 262144, 524288, 1048576
)

# ============================ Вспомогательные утилиты ============================

def _parse_method(full_method: str) -> tuple[str, str]:
    # full_method: "/package.Service/Method"
    try:
        _, svc, mth = full_method.split("/", 2)
        return svc, mth
    except Exception:
        return "unknown", full_method or "unknown"

def _msg_size(msg) -> int:
    try:
        return len(msg.SerializeToString())  # type: ignore[attr-defined]
    except Exception:
        # fallback: best-effort, но избегаем дорогостоящих repr/json
        return 0

def _code_to_str(code: StatusCode | None) -> str:
    if code is None:
        return "OK"
    try:
        return code.name
    except Exception:
        return str(code)

@dataclass
class MetricsConfig:
    namespace: str = "datafabric"
    subsystem: str = "grpc"
    registry: CollectorRegistry | None = None
    latency_buckets: tuple[float, ...] = DEFAULT_LATENCY_BUCKETS
    size_buckets: tuple[float, ...] = DEFAULT_SIZE_BUCKETS

# ============================ Регистр метрик ============================

class GrpcMetrics:
    def __init__(self, cfg: MetricsConfig = MetricsConfig()) -> None:
        self.cfg = cfg
        ns = cfg.namespace
        ss = cfg.subsystem
        reg = cfg.registry

        label_base = ("service", "method", "type", "code")

        self.requests_total = Counter(
            name="requests_total",
            documentation="Total number of RPC requests",
            namespace=ns,
            subsystem=ss,
            labelnames=label_base,
            registry=reg,
        )

        self.in_progress = Gauge(
            name="in_progress",
            documentation="In-flight RPC requests",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method", "type"),
            registry=reg,
        )

        self.latency_seconds = Histogram(
            name="latency_seconds",
            documentation="RPC latency in seconds",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method", "type"),
            buckets=cfg.latency_buckets,
            registry=reg,
        )

        self.req_msg_bytes = Histogram(
            name="request_message_bytes",
            documentation="Size of request messages in bytes",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method", "type"),
            buckets=cfg.size_buckets,
            registry=reg,
        )

        self.resp_msg_bytes = Histogram(
            name="response_message_bytes",
            documentation="Size of response messages in bytes",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method", "type"),
            buckets=cfg.size_buckets,
            registry=reg,
        )

        self.stream_msgs_received = Counter(
            name="stream_messages_received_total",
            documentation="Number of messages received on the stream",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method"),
            registry=reg,
        )

        self.stream_msgs_sent = Counter(
            name="stream_messages_sent_total",
            documentation="Number of messages sent on the stream",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method"),
            registry=reg,
        )

        self.exceptions_total = Counter(
            name="exceptions_total",
            documentation="Number of RPC exceptions",
            namespace=ns,
            subsystem=ss,
            labelnames=("service", "method", "type"),
            registry=reg,
        )

# ============================ Серверный интерцептор (sync) ============================

class MetricsServerInterceptor(grpc.ServerInterceptor):
    """
    Промышленный gRPC sync interceptor с метриками Prometheus.
    Покрывает все 4 типа RPC.
    """

    def __init__(self, metrics: GrpcMetrics) -> None:
        self.m = metrics

    # ---- unary-unary ----
    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        full_method = handler_call_details.method or "/unknown/unknown"
        service, method = _parse_method(full_method)

        if handler.unary_unary:
            rpc_type = "unary_unary"

            def wrapper(request, context):
                start = time.perf_counter()
                self.m.in_progress.labels(service, method, rpc_type).inc()

                try:
                    # Размер входящего сообщения
                    self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(request))
                    resp = handler.unary_unary(request, context)
                    # Размер ответа
                    self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                    code = context.code() or StatusCode.OK
                    return resp
                except Exception:
                    self.m.exceptions_total.labels(service, method, rpc_type).inc()
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                    code = context.code() or StatusCode.OK
                    self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                    self.m.in_progress.labels(service, method, rpc_type).dec()

            return grpc.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            rpc_type = "unary_stream"

            def wrapper(request, context):
                start = time.perf_counter()
                self.m.in_progress.labels(service, method, rpc_type).inc()
                self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(request))

                try:
                    for resp in handler.unary_stream(request, context):
                        self.m.stream_msgs_sent.labels(service, method).inc()
                        self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                        yield resp
                except Exception:
                    self.m.exceptions_total.labels(service, method, rpc_type).inc()
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                    code = context.code() or StatusCode.OK
                    self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                    self.m.in_progress.labels(service, method, rpc_type).dec()

            return grpc.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            rpc_type = "stream_unary"

            def wrapper(request_iterator, context):
                start = time.perf_counter()
                self.m.in_progress.labels(service, method, rpc_type).inc()
                try:
                    def counting_iterator():
                        for req in request_iterator:
                            self.m.stream_msgs_received.labels(service, method).inc()
                            self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(req))
                            yield req
                    resp = handler.stream_unary(counting_iterator(), context)
                    self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                    return resp
                except Exception:
                    self.m.exceptions_total.labels(service, method, rpc_type).inc()
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                    code = context.code() or StatusCode.OK
                    self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                    self.m.in_progress.labels(service, method, rpc_type).dec()

            return grpc.stream_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            rpc_type = "stream_stream"

            def wrapper(request_iterator, context):
                start = time.perf_counter()
                self.m.in_progress.labels(service, method, rpc_type).inc()
                try:
                    def counting_req_iter():
                        for req in request_iterator:
                            self.m.stream_msgs_received.labels(service, method).inc()
                            self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(req))
                            yield req
                    for resp in handler.stream_stream(counting_req_iter(), context):
                        self.m.stream_msgs_sent.labels(service, method).inc()
                        self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                        yield resp
                except Exception:
                    self.m.exceptions_total.labels(service, method, rpc_type).inc()
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                    code = context.code() or StatusCode.OK
                    self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                    self.m.in_progress.labels(service, method, rpc_type).dec()

            return grpc.stream_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


# ============================ Серверный интерцептор (asyncio) ============================

if grpc_aio is not None:
    class MetricsAioServerInterceptor(grpc_aio.ServerInterceptor):  # type: ignore[misc]
        """
        Промышленный gRPC asyncio interceptor с метриками Prometheus.
        """
        def __init__(self, metrics: GrpcMetrics) -> None:
            self.m = metrics

        async def intercept_service(self, continuation, handler_call_details):
            handler = await continuation(handler_call_details)
            if handler is None:
                return None

            full_method = handler_call_details.method or "/unknown/unknown"
            service, method = _parse_method(full_method)

            if handler.unary_unary:
                rpc_type = "unary_unary"

                async def unary_unary(request, context):
                    start = time.perf_counter()
                    self.m.in_progress.labels(service, method, rpc_type).inc()
                    try:
                        self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(request))
                        resp = await handler.unary_unary(request, context)
                        self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                        return resp
                    except Exception:
                        self.m.exceptions_total.labels(service, method, rpc_type).inc()
                        raise
                    finally:
                        elapsed = time.perf_counter() - start
                        self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                        code = context.code() or StatusCode.OK
                        self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                        self.m.in_progress.labels(service, method, rpc_type).dec()

                return grpc_aio.unary_unary_rpc_method_handler(
                    unary_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.unary_stream:
                rpc_type = "unary_stream"

                async def unary_stream(request, context):
                    start = time.perf_counter()
                    self.m.in_progress.labels(service, method, rpc_type).inc()
                    self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(request))
                    try:
                        async for resp in handler.unary_stream(request, context):
                            self.m.stream_msgs_sent.labels(service, method).inc()
                            self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                            yield resp
                    except Exception:
                        self.m.exceptions_total.labels(service, method, rpc_type).inc()
                        raise
                    finally:
                        elapsed = time.perf_counter() - start
                        self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                        code = context.code() or StatusCode.OK
                        self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                        self.m.in_progress.labels(service, method, rpc_type).dec()

                return grpc_aio.unary_stream_rpc_method_handler(
                    unary_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.stream_unary:
                rpc_type = "stream_unary"

                async def stream_unary(request_iterator, context):
                    start = time.perf_counter()
                    self.m.in_progress.labels(service, method, rpc_type).inc()

                    async def counting_req_iter():
                        async for req in request_iterator:
                            self.m.stream_msgs_received.labels(service, method).inc()
                            self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(req))
                            yield req

                    try:
                        resp = await handler.stream_unary(counting_req_iter(), context)
                        self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                        return resp
                    except Exception:
                        self.m.exceptions_total.labels(service, method, rpc_type).inc()
                        raise
                    finally:
                        elapsed = time.perf_counter() - start
                        self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                        code = context.code() or StatusCode.OK
                        self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                        self.m.in_progress.labels(service, method, rpc_type).dec()

                return grpc_aio.stream_unary_rpc_method_handler(
                    stream_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.stream_stream:
                rpc_type = "stream_stream"

                async def stream_stream(request_iterator, context):
                    start = time.perf_counter()
                    self.m.in_progress.labels(service, method, rpc_type).inc()

                    async def counting_req_iter():
                        async for req in request_iterator:
                            self.m.stream_msgs_received.labels(service, method).inc()
                            self.m.req_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(req))
                            yield req

                    try:
                        async for resp in handler.stream_stream(counting_req_iter(), context):
                            self.m.stream_msgs_sent.labels(service, method).inc()
                            self.m.resp_msg_bytes.labels(service, method, rpc_type).observe(_msg_size(resp))
                            yield resp
                    except Exception:
                        self.m.exceptions_total.labels(service, method, rpc_type).inc()
                        raise
                    finally:
                        elapsed = time.perf_counter() - start
                        self.m.latency_seconds.labels(service, method, rpc_type).observe(elapsed)
                        code = context.code() or StatusCode.OK
                        self.m.requests_total.labels(service, method, rpc_type, _code_to_str(code)).inc()
                        self.m.in_progress.labels(service, method, rpc_type).dec()

                return grpc_aio.stream_stream_rpc_method_handler(
                    stream_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            return handler

# ============================ Фабрики подключения ============================

def create_metrics(
    *,
    namespace: str = "datafabric",
    subsystem: str = "grpc",
    registry: CollectorRegistry | None = None,
    latency_buckets: tuple[float, ...] = DEFAULT_LATENCY_BUCKETS,
    size_buckets: tuple[float, ...] = DEFAULT_SIZE_BUCKETS,
) -> GrpcMetrics:
    return GrpcMetrics(
        MetricsConfig(
            namespace=namespace,
            subsystem=subsystem,
            registry=registry,
            latency_buckets=latency_buckets,
            size_buckets=size_buckets,
        )
    )

def server_interceptor(metrics: GrpcMetrics | None = None) -> MetricsServerInterceptor:
    return MetricsServerInterceptor(metrics or create_metrics())

def aio_server_interceptor(metrics: GrpcMetrics | None = None):
    if grpc_aio is None:
        raise RuntimeError("grpc.aio is not available in this environment")
    return MetricsAioServerInterceptor(metrics or create_metrics())


# ============================ Пример интеграции ============================
# SYNC:
#   from prometheus_client import start_http_server
#   start_http_server(8000)  # экспорт метрик на :8000/metrics
#   metrics = create_metrics()
#   server = grpc.server(futures.ThreadPoolExecutor(max_workers=32), interceptors=[server_interceptor(metrics)])
#   # ... add servicers ...
#   server.add_insecure_port('[::]:50051')
#   server.start(); server.wait_for_termination()
#
# ASYNC:
#   from prometheus_client import start_http_server
#   start_http_server(8000)
#   metrics = create_metrics()
#   server = grpc.aio.server(interceptors=[aio_server_interceptor(metrics)])
#   # ... add servicers ...
#   server.add_insecure_port('[::]:50051')
#   await server.start(); await server.wait_for_termination()
