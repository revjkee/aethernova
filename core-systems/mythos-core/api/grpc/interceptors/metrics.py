# mythos-core/api/grpc/interceptors/metrics.py
"""
Промышленный интерсептор метрик для gRPC Python (sync и asyncio).

Собирает метрики Prometheus (если библиотека установлена), полностью безопасен к отсутствию зависимостей.
Учитываются все четыре типа RPC: unary-unary, unary-stream, stream-unary, stream-stream.

Метрики (лейблы: grpc_type, grpc_service, grpc_method):
- mythos_grpc_server_started_total           Counter
- mythos_grpc_server_handled_total           Counter{grpc_code}
- mythos_grpc_server_msg_received_total      Counter
- mythos_grpc_server_msg_sent_total          Counter
- mythos_grpc_server_inflight                Gauge
- mythos_grpc_server_handling_seconds        Histogram

Использование (sync):
    interceptor = PrometheusServerInterceptor()
    server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[interceptor])

Использование (asyncio):
    interceptor = PrometheusAioServerInterceptor()
    server = grpc.aio.server(interceptors=[interceptor])

Настройки:
- buckets: список границ гистограммы (по умолчанию экспоненциальные от 2 мс до 30 с)
- registry: реестр Prometheus (по умолчанию глобальный)
- namespace: префикс имён метрик (по умолчанию "mythos")
- include_peer: не рекомендуется в прод из-за кардинальности; по умолчанию False
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Awaitable, Callable, Iterator, Optional, Tuple

import grpc

try:
    from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry  # type: ignore
except Exception:
    Counter = Gauge = Histogram = CollectorRegistry = None  # type: ignore

# ---------------------------
# Вспомогательные функции
# ---------------------------

def _split_method(full_method: str) -> Tuple[str, str]:
    # full_method: "/package.Service/Method"
    try:
        _, path = full_method.split("/", 1)
        service, method = path.split("/", 1)
        return service, method
    except Exception:
        return "unknown", "unknown"

def _code_from_exception(exc: BaseException) -> grpc.StatusCode:
    if isinstance(exc, grpc.RpcError):
        # Для abort/abort_with_status
        try:
            return exc.code()  # type: ignore[attr-defined]
        except Exception:
            return grpc.StatusCode.UNKNOWN
    return grpc.StatusCode.UNKNOWN

def _ok() -> grpc.StatusCode:
    return grpc.StatusCode.OK

# ---------------------------
# База для метрик
# ---------------------------

class _Metrics:
    def __init__(
        self,
        *,
        registry: Optional[Any] = None,
        namespace: str = "mythos",
        buckets: Optional[list] = None,
    ) -> None:
        self.enabled = Counter is not None and Gauge is not None and Histogram is not None
        self.registry = registry
        self.namespace = namespace

        # По умолчанию логарифмические границы от ~2мс до 30с
        default_buckets = [0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]
        buckets = buckets or default_buckets

        if self.enabled:
            self.started = Counter(
                f"{namespace}_grpc_server_started_total",
                "gRPC server calls started",
                ["grpc_type", "grpc_service", "grpc_method"],
                registry=registry,
            )
            self.handled = Counter(
                f"{namespace}_grpc_server_handled_total",
                "gRPC server calls handled",
                ["grpc_type", "grpc_service", "grpc_method", "grpc_code"],
                registry=registry,
            )
            self.msg_recv = Counter(
                f"{namespace}_grpc_server_msg_received_total",
                "gRPC server stream messages received",
                ["grpc_type", "grpc_service", "grpc_method"],
                registry=registry,
            )
            self.msg_sent = Counter(
                f"{namespace}_grpc_server_msg_sent_total",
                "gRPC server stream messages sent",
                ["grpc_type", "grpc_service", "grpc_method"],
                registry=registry,
            )
            self.inflight = Gauge(
                f"{namespace}_grpc_server_inflight",
                "gRPC server in-flight requests",
                ["grpc_type", "grpc_service", "grpc_method"],
                registry=registry,
            )
            self.latency = Histogram(
                f"{namespace}_grpc_server_handling_seconds",
                "gRPC server handling seconds",
                ["grpc_type", "grpc_service", "grpc_method"],
                buckets=buckets,
                registry=registry,
            )

    def labels(self, grpc_type: str, service: str, method: str):
        if not self.enabled:
            return _NoopLabels()
        return _Labels(
            self.started.labels(grpc_type, service, method),
            self.handled,
            self.msg_recv.labels(grpc_type, service, method),
            self.msg_sent.labels(grpc_type, service, method),
            self.inflight.labels(grpc_type, service, method),
            self.latency.labels(grpc_type, service, method),
            grpc_type,
            service,
            method,
        )

class _NoopLabels:
    def inc_started(self): pass
    def inc_recv(self, n: int = 1): pass
    def inc_sent(self, n: int = 1): pass
    def inc_inflight(self): pass
    def dec_inflight(self): pass
    def observe_latency(self, seconds: float): pass
    def inc_handled(self, code: grpc.StatusCode): pass

class _Labels:
    def __init__(self, started, handled, recv, sent, inflight, latency, grpc_type, service, method):
        self._started = started
        self._handled = handled
        self._recv = recv
        self._sent = sent
        self._inflight = inflight
        self._latency = latency
        self._grpc_type = grpc_type
        self._service = service
        self._method = method

    def inc_started(self):
        self._started.inc()

    def inc_recv(self, n: int = 1):
        if n:
            self._recv.inc(n)

    def inc_sent(self, n: int = 1):
        if n:
            self._sent.inc(n)

    def inc_inflight(self):
        self._inflight.inc()

    def dec_inflight(self):
        self._inflight.dec()

    def observe_latency(self, seconds: float):
        self._latency.observe(seconds)

    def inc_handled(self, code: grpc.StatusCode):
        self._handled.labels(self._grpc_type, self._service, self._method, code.name).inc()

# ---------------------------
# Вспомогательные обёртки потоков
# ---------------------------

class _CountingIterator(Iterator):
    def __init__(self, inner: Iterator, on_item: Callable[[], None]):
        self._inner = inner
        self._on_item = on_item
    def __iter__(self): return self
    def __next__(self):
        item = next(self._inner)
        self._on_item()
        return item

class _AsyncCountingIterator(AsyncIterator):
    def __init__(self, inner: AsyncIterator, on_item: Callable[[], None]):
        self._inner = inner
        self._on_item = on_item
    def __aiter__(self): return self
    async def __anext__(self):
        item = await self._inner.__anext__()
        self._on_item()
        return item

# ---------------------------
# Sync server interceptor
# ---------------------------

class PrometheusServerInterceptor(grpc.ServerInterceptor):
    def __init__(self, *, registry: Optional[Any] = None, namespace: str = "mythos", buckets: Optional[list] = None) -> None:
        self._m = _Metrics(registry=registry, namespace=namespace, buckets=buckets)

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)

        # unary-unary
        if handler.unary_unary:
            def _wrapper(request, context):
                labels = self._m.labels("unary_unary", service, method)
                labels.inc_started()
                labels.inc_inflight()
                labels.inc_recv(1)
                t0 = time.perf_counter()
                code = _ok()
                try:
                    resp = handler.unary_unary(request, context)
                    labels.inc_sent(1)
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.unary_unary_rpc_method_handler(
                _wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # unary-stream
        if handler.unary_stream:
            def _gen_wrapper(request, context):
                labels = self._m.labels("unary_stream", service, method)
                labels.inc_started()
                labels.inc_inflight()
                labels.inc_recv(1)
                t0 = time.perf_counter()
                code = _ok()
                try:
                    for item in handler.unary_stream(request, context):
                        labels.inc_sent(1)
                        yield item
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.unary_stream_rpc_method_handler(
                _gen_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream-unary
        if handler.stream_unary:
            def _wrapper(request_iterator, context):
                labels = self._m.labels("stream_unary", service, method)
                labels.inc_started()
                labels.inc_inflight()
                t0 = time.perf_counter()
                code = _ok()
                try:
                    it = _CountingIterator(iter(request_iterator), lambda: labels.inc_recv(1))
                    resp = handler.stream_unary(it, context)
                    labels.inc_sent(1)
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.stream_unary_rpc_method_handler(
                _wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream-stream
        if handler.stream_stream:
            def _gen_wrapper(request_iterator, context):
                labels = self._m.labels("stream_stream", service, method)
                labels.inc_started()
                labels.inc_inflight()
                t0 = time.perf_counter()
                code = _ok()
                try:
                    it = _CountingIterator(iter(request_iterator), lambda: labels.inc_recv(1))
                    for item in handler.stream_stream(it, context):
                        labels.inc_sent(1)
                        yield item
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.stream_stream_rpc_method_handler(
                _gen_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # На всякий случай — возвращаем оригинальный handler
        return handler

# ---------------------------
# Asyncio server interceptor
# ---------------------------

class PrometheusAioServerInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, *, registry: Optional[Any] = None, namespace: str = "mythos", buckets: Optional[list] = None) -> None:
        self._m = _Metrics(registry=registry, namespace=namespace, buckets=buckets)

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)

        # unary-unary
        if handler.unary_unary:
            async def _wrapper(request, context):
                labels = self._m.labels("unary_unary", service, method)
                labels.inc_started()
                labels.inc_inflight()
                labels.inc_recv(1)
                t0 = time.perf_counter()
                code = _ok()
                try:
                    resp = await handler.unary_unary(request, context)
                    labels.inc_sent(1)
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.aio.unary_unary_rpc_method_handler(  # type: ignore[attr-defined]
                _wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # unary-stream
        if handler.unary_stream:
            async def _gen_wrapper(request, context):
                labels = self._m.labels("unary_stream", service, method)
                labels.inc_started()
                labels.inc_inflight()
                labels.inc_recv(1)
                t0 = time.perf_counter()
                code = _ok()
                try:
                    async for item in handler.unary_stream(request, context):
                        labels.inc_sent(1)
                        yield item
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.aio.unary_stream_rpc_method_handler(  # type: ignore[attr-defined]
                _gen_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream-unary
        if handler.stream_unary:
            async def _wrapper(request_iterator, context):
                labels = self._m.labels("stream_unary", service, method)
                labels.inc_started()
                labels.inc_inflight()
                t0 = time.perf_counter()
                code = _ok()
                try:
                    it = _AsyncCountingIterator(request_iterator, lambda: labels.inc_recv(1))
                    resp = await handler.stream_unary(it, context)
                    labels.inc_sent(1)
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.aio.stream_unary_rpc_method_handler(  # type: ignore[attr-defined]
                _wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream-stream
        if handler.stream_stream:
            async def _gen_wrapper(request_iterator, context):
                labels = self._m.labels("stream_stream", service, method)
                labels.inc_started()
                labels.inc_inflight()
                t0 = time.perf_counter()
                code = _ok()
                try:
                    it = _AsyncCountingIterator(request_iterator, lambda: labels.inc_recv(1))
                    async for item in handler.stream_stream(it, context):
                        labels.inc_sent(1)
                        yield item
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    labels.observe_latency(time.perf_counter() - t0)
                    labels.inc_handled(code)
                    labels.dec_inflight()
            return grpc.aio.stream_stream_rpc_method_handler(  # type: ignore[attr-defined]
                _gen_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler
