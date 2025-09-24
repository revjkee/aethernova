# neuroforge-core/api/grpc/interceptors/metrics.py
from __future__ import annotations

import time
import logging
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, Iterator, Optional, Tuple

import grpc

try:
    # Prometheus client is optional but recommended
    from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
except Exception as exc:  # pragma: no cover
    raise ImportError("prometheus_client is required for metrics interceptor: pip install prometheus-client") from exc

log = logging.getLogger(__name__)

# ---------------------------
# Лейблы и хелперы
# ---------------------------

def _split_method(full_method: str) -> Tuple[str, str]:
    # /package.Service/Method -> package.Service, Method
    try:
        _, tail = full_method.split("/", 1)
        service, method = tail.split("/", 1)
        return service, method
    except Exception:
        return "unknown", full_method or "unknown"

def _grpc_type_of(handler: grpc.RpcMethodHandler) -> str:
    if handler.unary_unary:
        return "unary_unary"
    if handler.unary_stream:
        return "unary_stream"
    if handler.stream_unary:
        return "stream_unary"
    if handler.stream_stream:
        return "stream_stream"
    return "unknown"

def _message_size_bytes(msg: Any) -> int:
    if msg is None:
        return 0
    # protobuf: ByteSize() — O(1), предпочтительнее SerializeToString()
    try:
        return int(msg.ByteSize())  # type: ignore[attr-defined]
    except Exception:
        try:
            return len(msg.SerializeToString())  # type: ignore[attr-defined]
        except Exception:
            try:
                return len(bytes(msg))
            except Exception:
                return 0

def _status_code_from_context_or_exc(ctx: grpc.ServicerContext, exc: Optional[BaseException]) -> grpc.StatusCode:
    # Если контекст уже проставил код — используем его
    try:
        code = ctx.code()
        if code is not None:
            return code
    except Exception:
        pass
    # Иначе — по исключению
    if isinstance(exc, grpc.RpcError):
        try:
            # у RpcError может быть код
            return exc.code()  # type: ignore[attr-defined]
        except Exception:
            return grpc.StatusCode.UNKNOWN
    # Нет исключения — OK
    return grpc.StatusCode.OK if exc is None else grpc.StatusCode.UNKNOWN

# ---------------------------
# Регистр метрик
# ---------------------------

class _Metrics:
    def __init__(self, *, registry: Optional[CollectorRegistry] = None, service_label: str = "neuroforge-core",
                 latency_buckets: Optional[Iterable[float]] = None) -> None:
        self.registry = registry
        self.service_label = service_label
        buckets = list(latency_buckets or (
            0.001, 0.002, 0.005, 0.01, 0.02, 0.05,
            0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0
        ))
        # Совместимые с grpc_prometheus метрики (без peer-лейблов, чтобы избежать кардинальности)
        self.rpc_started = Counter(
            "grpc_server_started_total",
            "RPCs started on the server.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )
        self.rpc_handled = Counter(
            "grpc_server_handled_total",
            "RPCs handled on the server, by code.",
            labelnames=("service", "method", "type", "code"),
            registry=registry,
        )
        self.rpc_handling_seconds = Histogram(
            "grpc_server_handling_seconds",
            "Histogram of response latency (seconds) of gRPC that had been application-level handled by the server.",
            labelnames=("service", "method", "type"),
            buckets=buckets,
            registry=registry,
        )
        self.in_flight = Gauge(
            "grpc_server_inflight_requests",
            "Number of gRPC requests currently being handled.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )
        self.msg_received_total = Counter(
            "grpc_server_msg_received_total",
            "Total number of RPC stream messages received.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )
        self.msg_sent_total = Counter(
            "grpc_server_msg_sent_total",
            "Total number of RPC stream messages sent.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )
        self.msg_received_bytes = Counter(
            "grpc_server_msg_received_bytes_total",
            "Total size in bytes of RPC stream messages received.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )
        self.msg_sent_bytes = Counter(
            "grpc_server_msg_sent_bytes_total",
            "Total size in bytes of RPC stream messages sent.",
            labelnames=("service", "method", "type"),
            registry=registry,
        )

# ---------------------------
# SYNC интерцептор
# ---------------------------

class ServerMetricsInterceptor(grpc.ServerInterceptor):
    """
    Серверный gRPC интерцептор (sync) с Prometheus-метриками.
    Подключение:
        metrics = ServerMetricsInterceptor()
        server = grpc.server(futures.ThreadPoolExecutor(...), interceptors=[metrics])
    Экспорт /metrics — в HTTP-слое вашего приложения.
    """
    def __init__(self, *, registry: Optional[CollectorRegistry] = None, service_label: str = "neuroforge-core",
                 latency_buckets: Optional[Iterable[float]] = None) -> None:
        self._m = _Metrics(registry=registry, service_label=service_label, latency_buckets=latency_buckets)

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler: grpc.RpcMethodHandler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)
        rtype = _grpc_type_of(handler)

        labels3 = (service, method, rtype)

        # Обертки для каждого типа RPC
        if handler.unary_unary:
            def _uu(request, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None
                # входящее сообщение: одно
                try:
                    self._m.msg_received_total.labels(*labels3).inc()
                    self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(request))
                    response = handler.unary_unary(request, context)
                    # исходящее сообщение: одно
                    self._m.msg_sent_total.labels(*labels3).inc()
                    self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(response))
                    return response
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.unary_unary_rpc_method_handler(
                _uu,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            def _us(request, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None
                self._m.msg_received_total.labels(*labels3).inc()
                self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(request))
                try:
                    inner_iter = handler.unary_stream(request, context)
                    for resp in inner_iter:
                        self._m.msg_sent_total.labels(*labels3).inc()
                        self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(resp))
                        yield resp
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.unary_stream_rpc_method_handler(
                _us,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            def _su(request_iterator, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None

                def _req_iter():
                    for req in request_iterator:
                        self._m.msg_received_total.labels(*labels3).inc()
                        self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(req))
                        yield req

                try:
                    response = handler.stream_unary(_req_iter(), context)
                    self._m.msg_sent_total.labels(*labels3).inc()
                    self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(response))
                    return response
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.stream_unary_rpc_method_handler(
                _su,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            def _ss(request_iterator, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None

                def _req_iter():
                    for req in request_iterator:
                        self._m.msg_received_total.labels(*labels3).inc()
                        self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(req))
                        yield req

                try:
                    inner_iter = handler.stream_stream(_req_iter(), context)
                    for resp in inner_iter:
                        self._m.msg_sent_total.labels(*labels3).inc()
                        self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(resp))
                        yield resp
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.stream_stream_rpc_method_handler(
                _ss,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Неизвестный тип — возвращаем как есть
        return handler

# ---------------------------
# AIO интерцептор
# ---------------------------

class AioServerMetricsInterceptor(grpc.aio.ServerInterceptor):
    """
    Серверный gRPC интерцептор (aio) с Prometheus-метриками.
    Подключение:
        metrics = AioServerMetricsInterceptor()
        server = grpc.aio.server(interceptors=[metrics])
    """
    def __init__(self, *, registry: Optional[CollectorRegistry] = None, service_label: str = "neuroforge-core",
                 latency_buckets: Optional[Iterable[float]] = None) -> None:
        self._m = _Metrics(registry=registry, service_label=service_label, latency_buckets=latency_buckets)

    async def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler: grpc.aio.RpcMethodHandler = await continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)
        rtype = (
            "unary_unary" if handler.unary_unary
            else "unary_stream" if handler.unary_stream
            else "stream_unary" if handler.stream_unary
            else "stream_stream" if handler.stream_stream
            else "unknown"
        )
        labels3 = (service, method, rtype)

        if handler.unary_unary:
            async def _uu(request, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None
                try:
                    self._m.msg_received_total.labels(*labels3).inc()
                    self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(request))
                    response = await handler.unary_unary(request, context)
                    self._m.msg_sent_total.labels(*labels3).inc()
                    self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(response))
                    return response
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)  # type: ignore[arg-type]
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.aio.unary_unary_rpc_method_handler(
                _uu,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            async def _us(request, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None
                self._m.msg_received_total.labels(*labels3).inc()
                self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(request))
                try:
                    inner = await handler.unary_stream(request, context)
                    async def gen():
                        async for resp in inner:
                            self._m.msg_sent_total.labels(*labels3).inc()
                            self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(resp))
                            yield resp
                    return gen()
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)  # type: ignore[arg-type]
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.aio.unary_stream_rpc_method_handler(
                _us,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            async def _su(request_iterator, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None

                async def _req_iter():
                    async for req in request_iterator:
                        self._m.msg_received_total.labels(*labels3).inc()
                        self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(req))
                        yield req

                try:
                    response = await handler.stream_unary(_req_iter(), context)
                    self._m.msg_sent_total.labels(*labels3).inc()
                    self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(response))
                    return response
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)  # type: ignore[arg-type]
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.aio.stream_unary_rpc_method_handler(
                _su,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            async def _ss(request_iterator, context):
                self._m.rpc_started.labels(*labels3).inc()
                self._m.in_flight.labels(*labels3).inc()
                start = time.perf_counter()
                exc: Optional[BaseException] = None

                async def _req_iter():
                    async for req in request_iterator:
                        self._m.msg_received_total.labels(*labels3).inc()
                        self._m.msg_received_bytes.labels(*labels3).inc(_message_size_bytes(req))
                        yield req

                try:
                    inner = await handler.stream_stream(_req_iter(), context)
                    async def gen():
                        async for resp in inner:
                            self._m.msg_sent_total.labels(*labels3).inc()
                            self._m.msg_sent_bytes.labels(*labels3).inc(_message_size_bytes(resp))
                            yield resp
                    return gen()
                except BaseException as e:
                    exc = e
                    raise
                finally:
                    dur = time.perf_counter() - start
                    code = _status_code_from_context_or_exc(context, exc)  # type: ignore[arg-type]
                    self._m.rpc_handling_seconds.labels(*labels3).observe(dur)
                    self._m.rpc_handled.labels(*labels3, code.name if hasattr(code, "name") else str(code)).inc()
                    self._m.in_flight.labels(*labels3).dec()
            return grpc.aio.stream_stream_rpc_method_handler(
                _ss,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler

__all__ = [
    "ServerMetricsInterceptor",
    "AioServerMetricsInterceptor",
]
