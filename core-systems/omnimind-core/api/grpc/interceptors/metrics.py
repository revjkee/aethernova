# path: ops/api/grpc/interceptors/metrics.py
from __future__ import annotations

import time
import types
import typing as t
import functools
import contextlib

import grpc
try:
    import grpc.aio as grpc_aio  # type: ignore
    _HAS_AIO = True
except Exception:  # pragma: no cover
    _HAS_AIO = False

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, REGISTRY

# ----------------------------- Types -----------------------------

_MethodKind = t.Literal["unary_unary", "unary_stream", "stream_unary", "stream_stream"]

# ------------------------- Helpers / Utils -----------------------


def _parse_method(full_method: str) -> tuple[str, str]:
    # full_method: "/package.Service/Method"
    try:
        _, rest = full_method.split("/", 1)
        service, method = rest.split("/", 1)
        return service, method
    except Exception:
        return "unknown", full_method or "unknown"


def _status_code_from_exc(exc: BaseException) -> grpc.StatusCode:
    if isinstance(exc, grpc.RpcError):
        try:
            return exc.code()  # type: ignore[attr-defined]
        except Exception:
            return grpc.StatusCode.UNKNOWN
    return grpc.StatusCode.UNKNOWN


def _now() -> float:
    return time.perf_counter()


@contextlib.contextmanager
def _timer() -> t.Iterator[t.Callable[[], float]]:
    start = _now()
    yield lambda: _now() - start


def _method_kind_from_handler(h: grpc.RpcMethodHandler) -> _MethodKind:
    if h.unary_unary:
        return "unary_unary"
    if h.unary_stream:
        return "unary_stream"
    if h.stream_unary:
        return "stream_unary"
    return "stream_stream"


def _iter_wrap_count(
    it: t.Iterable[t.Any],
    inc: t.Callable[[], None],
) -> t.Iterable[t.Any]:
    for item in it:
        inc()
        yield item


async def _aiter_wrap_count(
    ait: t.AsyncIterable[t.Any],
    inc: t.Callable[[], None],
) -> t.AsyncIterable[t.Any]:
    async for item in ait:
        inc()
        yield item


# ---------------------- Metrics Container ------------------------


class GrpcMetrics:
    """
    Реестр метрик gRPC. Позволяет переиспользовать на клиенте и сервере.
    """

    def __init__(
        self,
        registry: CollectorRegistry | None = None,
        *,
        buckets: tuple[float, ...] = (
            0.002, 0.005, 0.01, 0.025, 0.05,
            0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ),
        namespace: str = "grpc",
        subsystem_server: str = "server",
        subsystem_client: str = "client",
    ) -> None:
        reg = registry or REGISTRY

        # Общие лейблы: service, method, type (4 вида), code
        labelnames = ("service", "method", "type", "code")

        self.requests_total = Counter(
            name="requests_total",
            namespace=namespace,
            subsystem=subsystem_server,
            documentation="Total gRPC requests handled on server.",
            labelnames=labelnames,
            registry=reg,
        )
        self.client_requests_total = Counter(
            name="requests_total",
            namespace=namespace,
            subsystem=subsystem_client,
            documentation="Total gRPC client requests performed.",
            labelnames=labelnames,
            registry=reg,
        )

        self.msg_received_total = Counter(
            name="messages_received_total",
            namespace=namespace,
            subsystem=subsystem_server,
            documentation="Total gRPC messages received by server.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )
        self.msg_sent_total = Counter(
            name="messages_sent_total",
            namespace=namespace,
            subsystem=subsystem_server,
            documentation="Total gRPC messages sent by server.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )

        self.client_msg_received_total = Counter(
            name="messages_received_total",
            namespace=namespace,
            subsystem=subsystem_client,
            documentation="Total gRPC messages received by client.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )
        self.client_msg_sent_total = Counter(
            name="messages_sent_total",
            namespace=namespace,
            subsystem=subsystem_client,
            documentation="Total gRPC messages sent by client.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )

        self.handling_seconds = Histogram(
            name="handling_seconds",
            namespace=namespace,
            subsystem=subsystem_server,
            documentation="gRPC server handling time (seconds).",
            labelnames=("service", "method", "type"),
            buckets=buckets,
            registry=reg,
        )
        self.client_handling_seconds = Histogram(
            name="handling_seconds",
            namespace=namespace,
            subsystem=subsystem_client,
            documentation="gRPC client handling time (seconds).",
            labelnames=("service", "method", "type"),
            buckets=buckets,
            registry=reg,
        )

        self.in_flight = Gauge(
            name="in_flight",
            namespace=namespace,
            subsystem=subsystem_server,
            documentation="In-flight gRPC requests on server.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )
        self.client_in_flight = Gauge(
            name="in_flight",
            namespace=namespace,
            subsystem=subsystem_client,
            documentation="In-flight gRPC requests on client.",
            labelnames=("service", "method", "type"),
            registry=reg,
        )


# ------------------------- Server Interceptor --------------------


class ServerMetricsInterceptor(grpc.ServerInterceptor):
    def __init__(self, metrics: GrpcMetrics) -> None:
        self.m = metrics

    def intercept_service(
        self,
        continuation: t.Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:

        base_handler = continuation(handler_call_details)
        if base_handler is None:  # pragma: no cover
            return base_handler

        full_method = handler_call_details.method or ""
        service, method = _parse_method(full_method)
        mtype = _method_kind_from_handler(base_handler)

        # Wrap by kind
        if base_handler.unary_unary:
            def new_unary_unary(request, context):
                with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                    with _timer() as elapsed:
                        code_label = "OK"
                        self.m.msg_received_total.labels(service, method, mtype).inc()
                        try:
                            resp = base_handler.unary_unary(request, context)
                            self.m.msg_sent_total.labels(service, method, mtype).inc()
                            return resp
                        except BaseException as exc:
                            code_label = _status_code_from_exc(exc).name
                            raise
                        finally:
                            self.m.requests_total.labels(service, method, mtype, code_label).inc()
                            self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

            return grpc.unary_unary_rpc_method_handler(
                new_unary_unary,
                request_deserializer=base_handler.request_deserializer,
                response_serializer=base_handler.response_serializer,
            )

        if base_handler.unary_stream:
            def new_unary_stream(request, context):
                with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                    with _timer() as elapsed:
                        code_label = "OK"
                        self.m.msg_received_total.labels(service, method, mtype).inc()
                        try:
                            it = base_handler.unary_stream(request, context)
                            # wrap iterator to count sent messages
                            return _iter_wrap_count(
                                it,
                                lambda: self.m.msg_sent_total.labels(service, method, mtype).inc(),
                            )
                        except BaseException as exc:
                            code_label = _status_code_from_exc(exc).name
                            raise
                        finally:
                            self.m.requests_total.labels(service, method, mtype, code_label).inc()
                            self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

            return grpc.unary_stream_rpc_method_handler(
                new_unary_stream,
                request_deserializer=base_handler.request_deserializer,
                response_serializer=base_handler.response_serializer,
            )

        if base_handler.stream_unary:
            def new_stream_unary(request_iterator, context):
                with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                    with _timer() as elapsed:
                        code_label = "OK"
                        try:
                            wrapped_in = _iter_wrap_count(
                                request_iterator,
                                lambda: self.m.msg_received_total.labels(service, method, mtype).inc(),
                            )
                            resp = base_handler.stream_unary(wrapped_in, context)
                            self.m.msg_sent_total.labels(service, method, mtype).inc()
                            return resp
                        except BaseException as exc:
                            code_label = _status_code_from_exc(exc).name
                            raise
                        finally:
                            self.m.requests_total.labels(service, method, mtype, code_label).inc()
                            self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

            return grpc.stream_unary_rpc_method_handler(
                new_stream_unary,
                request_deserializer=base_handler.request_deserializer,
                response_serializer=base_handler.response_serializer,
            )

        # stream_stream
        def new_stream_stream(request_iterator, context):
            with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                with _timer() as elapsed:
                    code_label = "OK"
                    try:
                        wrapped_in = _iter_wrap_count(
                            request_iterator,
                            lambda: self.m.msg_received_total.labels(service, method, mtype).inc(),
                        )
                        it = base_handler.stream_stream(wrapped_in, context)
                        return _iter_wrap_count(
                            it,
                            lambda: self.m.msg_sent_total.labels(service, method, mtype).inc(),
                        )
                    except BaseException as exc:
                        code_label = _status_code_from_exc(exc).name
                        raise
                    finally:
                        self.m.requests_total.labels(service, method, mtype, code_label).inc()
                        self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

        return grpc.stream_stream_rpc_method_handler(
            new_stream_stream,
            request_deserializer=base_handler.request_deserializer,
            response_serializer=base_handler.response_serializer,
        )


# ------------------------- Client Interceptor --------------------


class _ClientBase:
    def __init__(self, metrics: GrpcMetrics) -> None:
        self.m = metrics

    def _labels_base(self, method: str, mtype: _MethodKind) -> tuple[str, str, str]:
        service, meth = _parse_method(method)
        return service, meth, mtype

    @contextlib.contextmanager
    def _track(self, service: str, method: str, mtype: _MethodKind) -> t.Iterator[t.Callable[[str], None]]:
        self.m.client_in_flight.labels(service, method, mtype).inc()
        with _timer() as elapsed:
            code_label = "OK"
            try:
                yield lambda code: None  # placeholder, code decided in finally
            finally:
                self.m.client_handling_seconds.labels(service, method, mtype).observe(elapsed())
                # requests_total инкрементируем в вызывающем блоке, зная code
                self.m.client_in_flight.labels(service, method, mtype).dec()


class ClientMetricsInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
    _ClientBase,
):
    """
    Клиентские перехватчики для sync gRPC.
    """

    def __init__(self, metrics: GrpcMetrics) -> None:
        _ClientBase.__init__(self, metrics)

    # unary-unary
    def intercept_unary_unary(self, continuation, client_call_details, request):
        service, method, mtype = self._labels_base(client_call_details.method, "unary_unary")
        with self._track(service, method, mtype):
            code = "OK"
            try:
                call = continuation(client_call_details, request)
                response = call
                return response
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_requests_total.labels(service, method, mtype, code).inc()
                self.m.client_msg_sent_total.labels(service, method, mtype).inc()
                # полученное сообщение инкрементируем только при успешном recv, но для unary_unary считаем как 1:
                if code == "OK":
                    self.m.client_msg_received_total.labels(service, method, mtype).inc()

    # unary-stream
    def intercept_unary_stream(self, continuation, client_call_details, request):
        service, method, mtype = self._labels_base(client_call_details.method, "unary_stream")
        with self._track(service, method, mtype):
            code = "OK"
            self.m.client_msg_sent_total.labels(service, method, mtype).inc()
            try:
                it = continuation(client_call_details, request)
                return _iter_wrap_count(
                    it,
                    lambda: self.m.client_msg_received_total.labels(service, method, mtype).inc(),
                )
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_requests_total.labels(service, method, mtype, code).inc()

    # stream-unary
    def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        service, method, mtype = self._labels_base(client_call_details.method, "stream_unary")
        with self._track(service, method, mtype):
            code = "OK"
            try:
                wrapped_in = _iter_wrap_count(
                    request_iterator,
                    lambda: self.m.client_msg_sent_total.labels(service, method, mtype).inc(),
                )
                resp = continuation(client_call_details, wrapped_in)
                if hasattr(resp, "result"):
                    # Future-like call: counting receive on result() access is out-of-scope here.
                    pass
                self.m.client_msg_received_total.labels(service, method, mtype).inc()
                return resp
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_requests_total.labels(service, method, mtype, code).inc()

    # stream-stream
    def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        service, method, mtype = self._labels_base(client_call_details.method, "stream_stream")
        with self._track(service, method, mtype):
            code = "OK"
            try:
                wrapped_in = _iter_wrap_count(
                    request_iterator,
                    lambda: self.m.client_msg_sent_total.labels(service, method, mtype).inc(),
                )
                it = continuation(client_call_details, wrapped_in)
                return _iter_wrap_count(
                    it,
                    lambda: self.m.client_msg_received_total.labels(service, method, mtype).inc(),
                )
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_requests_total.labels(service, method, mtype, code).inc()


# ------------------------- Async (aio) Interceptors --------------


if _HAS_AIO:

    class AioServerMetricsInterceptor(grpc_aio.ServerInterceptor):  # type: ignore[misc]
        def __init__(self, metrics: GrpcMetrics) -> None:
            self.m = metrics

        async def intercept_service(self, continuation, handler_call_details):
            base_handler = await continuation(handler_call_details)
            if base_handler is None:  # pragma: no cover
                return base_handler

            full_method = handler_call_details.method or ""
            service, method = _parse_method(full_method)
            mtype = _method_kind_from_handler(base_handler)

            if base_handler.unary_unary:
                async def new_unary_unary(request, context):
                    with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                        with _timer() as elapsed:
                            code_label = "OK"
                            self.m.msg_received_total.labels(service, method, mtype).inc()
                            try:
                                resp = await base_handler.unary_unary(request, context)
                                self.m.msg_sent_total.labels(service, method, mtype).inc()
                                return resp
                            except BaseException as exc:
                                code_label = _status_code_from_exc(exc).name
                                raise
                            finally:
                                self.m.requests_total.labels(service, method, mtype, code_label).inc()
                                self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

                return grpc_aio.unary_unary_rpc_method_handler(  # type: ignore[attr-defined]
                    new_unary_unary,
                    request_deserializer=base_handler.request_deserializer,
                    response_serializer=base_handler.response_serializer,
                )

            if base_handler.unary_stream:
                async def new_unary_stream(request, context):
                    with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                        with _timer() as elapsed:
                            code_label = "OK"
                            self.m.msg_received_total.labels(service, method, mtype).inc()
                            try:
                                ait = base_handler.unary_stream(request, context)
                                return _aiter_wrap_count(
                                    ait,
                                    lambda: self.m.msg_sent_total.labels(service, method, mtype).inc(),
                                )
                            except BaseException as exc:
                                code_label = _status_code_from_exc(exc).name
                                raise
                            finally:
                                self.m.requests_total.labels(service, method, mtype, code_label).inc()
                                self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

                return grpc_aio.unary_stream_rpc_method_handler(  # type: ignore[attr-defined]
                    new_unary_stream,
                    request_deserializer=base_handler.request_deserializer,
                    response_serializer=base_handler.response_serializer,
                )

            if base_handler.stream_unary:
                async def new_stream_unary(request_iterator, context):
                    with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                        with _timer() as elapsed:
                            code_label = "OK"
                            try:
                                wrapped_in = _aiter_wrap_count(
                                    request_iterator,
                                    lambda: self.m.msg_received_total.labels(service, method, mtype).inc(),
                                )
                                resp = await base_handler.stream_unary(wrapped_in, context)
                                self.m.msg_sent_total.labels(service, method, mtype).inc()
                                return resp
                            except BaseException as exc:
                                code_label = _status_code_from_exc(exc).name
                                raise
                            finally:
                                self.m.requests_total.labels(service, method, mtype, code_label).inc()
                                self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

                return grpc_aio.stream_unary_rpc_method_handler(  # type: ignore[attr-defined]
                    new_stream_unary,
                    request_deserializer=base_handler.request_deserializer,
                    response_serializer=base_handler.response_serializer,
                )

            async def new_stream_stream(request_iterator, context):
                with self.m.in_flight.labels(service, method, mtype).track_inprogress():
                    with _timer() as elapsed:
                        code_label = "OK"
                        try:
                            wrapped_in = _aiter_wrap_count(
                                request_iterator,
                                lambda: self.m.msg_received_total.labels(service, method, mtype).inc(),
                            )
                            ait = base_handler.stream_stream(wrapped_in, context)
                            return _aiter_wrap_count(
                                ait,
                                lambda: self.m.msg_sent_total.labels(service, method, mtype).inc(),
                            )
                        except BaseException as exc:
                            code_label = _status_code_from_exc(exc).name
                            raise
                        finally:
                            self.m.requests_total.labels(service, method, mtype, code_label).inc()
                            self.m.handling_seconds.labels(service, method, mtype).observe(elapsed())

            return grpc_aio.stream_stream_rpc_method_handler(  # type: ignore[attr-defined]
                new_stream_stream,
                request_deserializer=base_handler.request_deserializer,
                response_serializer=base_handler.response_serializer,
            )

    class AioClientMetricsInterceptor(
        grpc_aio.UnaryUnaryClientInterceptor,      # type: ignore[misc]
        grpc_aio.UnaryStreamClientInterceptor,     # type: ignore[misc]
        grpc_aio.StreamUnaryClientInterceptor,     # type: ignore[misc]
        grpc_aio.StreamStreamClientInterceptor,    # type: ignore[misc]
        _ClientBase,
    ):
        def __init__(self, metrics: GrpcMetrics) -> None:
            _ClientBase.__init__(self, metrics)

        async def intercept_unary_unary(self, continuation, client_call_details, request):
            service, method, mtype = self._labels_base(client_call_details.method, "unary_unary")
            self.m.client_in_flight.labels(service, method, mtype).inc()
            start = _now()
            code = "OK"
            try:
                call = await continuation(client_call_details, request)
                self.m.client_msg_sent_total.labels(service, method, mtype).inc()
                self.m.client_msg_received_total.labels(service, method, mtype).inc()
                return call
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_handling_seconds.labels(service, method, mtype).observe(_now() - start)
                self.m.client_requests_total.labels(service, method, mtype, code).inc()
                self.m.client_in_flight.labels(service, method, mtype).dec()

        async def intercept_unary_stream(self, continuation, client_call_details, request):
            service, method, mtype = self._labels_base(client_call_details.method, "unary_stream")
            self.m.client_in_flight.labels(service, method, mtype).inc()
            start = _now()
            code = "OK"
            try:
                ait = await continuation(client_call_details, request)
                self.m.client_msg_sent_total.labels(service, method, mtype).inc()
                return _aiter_wrap_count(
                    ait,
                    lambda: self.m.client_msg_received_total.labels(service, method, mtype).inc(),
                )
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_handling_seconds.labels(service, method, mtype).observe(_now() - start)
                self.m.client_requests_total.labels(service, method, mtype, code).inc()
                self.m.client_in_flight.labels(service, method, mtype).dec()

        async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
            service, method, mtype = self._labels_base(client_call_details.method, "stream_unary")
            self.m.client_in_flight.labels(service, method, mtype).inc()
            start = _now()
            code = "OK"
            try:
                wrapped_in = _aiter_wrap_count(
                    request_iterator,
                    lambda: self.m.client_msg_sent_total.labels(service, method, mtype).inc(),
                )
                resp = await continuation(client_call_details, wrapped_in)
                self.m.client_msg_received_total.labels(service, method, mtype).inc()
                return resp
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_handling_seconds.labels(service, method, mtype).observe(_now() - start)
                self.m.client_requests_total.labels(service, method, mtype, code).inc()
                self.m.client_in_flight.labels(service, method, mtype).dec()

        async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
            service, method, mtype = self._labels_base(client_call_details.method, "stream_stream")
            self.m.client_in_flight.labels(service, method, mtype).inc()
            start = _now()
            code = "OK"
            try:
                wrapped_in = _aiter_wrap_count(
                    request_iterator,
                    lambda: self.m.client_msg_sent_total.labels(service, method, mtype).inc(),
                )
                ait = await continuation(client_call_details, wrapped_in)
                return _aiter_wrap_count(
                    ait,
                    lambda: self.m.client_msg_received_total.labels(service, method, mtype).inc(),
                )
            except BaseException as exc:
                code = _status_code_from_exc(exc).name
                raise
            finally:
                self.m.client_handling_seconds.labels(service, method, mtype).observe(_now() - start)
                self.m.client_requests_total.labels(service, method, mtype, code).inc()
                self.m.client_in_flight.labels(service, method, mtype).dec()


# ------------------------- Factory helpers -----------------------


def make_metrics(
    registry: CollectorRegistry | None = None,
    *,
    buckets: tuple[float, ...] | None = None,
    namespace: str = "grpc",
) -> GrpcMetrics:
    return GrpcMetrics(
        registry=registry,
        buckets=buckets or (
            0.002, 0.005, 0.01, 0.025, 0.05,
            0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ),
        namespace=namespace,
    )


# ------------------------- Usage examples ------------------------
#
# Server (sync):
#   metrics = make_metrics()
#   server = grpc.server(
#       futures.ThreadPoolExecutor(),
#       interceptors=[ServerMetricsInterceptor(metrics)],
#   )
#
# Client (sync):
#   metrics = make_metrics()
#   interceptors = [ClientMetricsInterceptor(metrics)]
#   channel = grpc.intercept_channel(grpc.insecure_channel("localhost:50051"), *interceptors)
#
# Server (aio):
#   if _HAS_AIO:
#       metrics = make_metrics()
#       server = grpc_aio.server(interceptors=[AioServerMetricsInterceptor(metrics)])
#
# Client (aio):
#   if _HAS_AIO:
#       metrics = make_metrics()
#       interceptors = [AioClientMetricsInterceptor(metrics)]
#       channel = grpc_aio.insecure_channel("localhost:50051", interceptors=interceptors)
