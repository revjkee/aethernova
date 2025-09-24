# security-core/api/grpc/interceptors/metrics.py
"""
Industrial gRPC metrics interceptors for Python.

Features:
- Server & client interceptors (grpc.aio + sync grpc)
- Prometheus metrics with safe no-op fallback if prometheus_client not present
- Unary & streaming: counts, bytes, messages, in-flight, latency histograms
- Labels: direction (server|client), service, method, code
- Configurable histogram buckets, optional exemplar callbacks
- Minimal overhead; zero allocations on hot path where possible
- Works alongside tracing (OpenTelemetry) — no conflicts

Usage (server, asyncio):
    import grpc
    from grpc.aio import server
    from security_core.api.grpc.interceptors.metrics import (
        PrometheusMetrics, AioServerMetricsInterceptor
    )

    metrics = PrometheusMetrics(namespace="security_core", buckets=[0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2,5])
    srv = server(interceptors=[AioServerMetricsInterceptor(metrics)])
    # expose metrics elsewhere via prometheus_client.start_http_server(...)

Usage (client, asyncio):
    from security_core.api.grpc.interceptors.metrics import AioClientMetricsInterceptor
    ch = grpc.aio.insecure_channel("localhost:50051", interceptors=[AioClientMetricsInterceptor(metrics)])

Sync gRPC:
    from security_core.api.grpc.interceptors.metrics import SyncServerMetricsInterceptor, SyncClientMetricsInterceptor
    server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[SyncServerMetricsInterceptor(metrics)])
    channel = grpc.intercept_channel(grpc.insecure_channel(...), SyncClientMetricsInterceptor(metrics))

"""

from __future__ import annotations

import time
import functools
import typing as _t

try:
    import grpc
    from grpc import StatusCode
except Exception as _e:  # pragma: no cover
    raise RuntimeError("grpc is required") from _e

# Optional prometheus dependency with safe no-op fallback
try:  # pragma: no cover
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *_, **__): pass
        def labels(self, *_, **__): return self
        def observe(self, *_): pass
        def inc(self, *_): pass
        def dec(self, *_): pass
        def set(self, *_): pass

    Counter = Histogram = Gauge = _Noop  # type: ignore
    CollectorRegistry = object  # type: ignore

# -------- Metric container --------

class PrometheusMetrics:
    """
    Holds Prometheus metric instruments. Create once and reuse.
    """

    def __init__(
        self,
        *,
        namespace: str = "grpc",
        subsystem: str = "rpc",
        registry: _t.Optional[CollectorRegistry] = None,
        buckets: _t.Sequence[float] = (0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
        enable_bytes: bool = True,
        enable_in_flight: bool = True,
    ) -> None:
        ns = namespace
        ss = subsystem
        lbls = ["direction", "service", "method"]
        lbls_code = ["direction", "service", "method", "code"]

        self.requests_total = Counter(
            f"{ns}_{ss}_requests_total",
            "Total number of RPC requests (calls started).",
            lbls,
            registry=registry,
        )
        self.responses_total = Counter(
            f"{ns}_{ss}_responses_total",
            "Total number of RPC responses (calls finished).",
            lbls_code,
            registry=registry,
        )
        self.latency_seconds = Histogram(
            f"{ns}_{ss}_latency_seconds",
            "RPC latency in seconds (end-to-end per call).",
            lbls_code,
            buckets=tuple(buckets),
            registry=registry,
        )
        self.messages_total = Counter(
            f"{ns}_{ss}_messages_total",
            "Total number of RPC messages (streaming and unary).",
            lbls + ["stream", "direction_io"],  # direction_io: in|out (relative to direction)
            registry=registry,
        )
        self.in_flight = Gauge(
            f"{ns}_{ss}_in_flight",
            "Number of in-flight RPC calls.",
            lbls,
            registry=registry,
        ) if enable_in_flight else None

        self.bytes_total = Counter(
            f"{ns}_{ss}_bytes_total",
            "Total number of bytes across messages (payload size).",
            lbls + ["stream", "direction_io"],
            registry=registry,
        ) if enable_bytes else None

    # Helpers to compute common label sets
    @staticmethod
    def split_full_method(full_method: str) -> _t.Tuple[str, str]:
        # full_method: "/package.Service/Method"
        try:
            _, rest = full_method.split("/", 1)
            service, method = rest.split("/", 1)
            return service, method
        except Exception:  # pragma: no cover
            return "unknown", full_method.strip("/")


# --------- AsyncIO Server Interceptor ---------

class AioServerMetricsInterceptor(grpc.aio.ServerInterceptor):  # type: ignore[attr-defined]
    def __init__(self, metrics: PrometheusMetrics) -> None:
        self.m = metrics

    async def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        # Resolve handler to wrap; handler has attributes for method kinds
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        service, method = self.m.split_full_method(handler_call_details.method)
        base_labels = ("server", service, method)

        # Wrap per-method behavior
        if handler.unary_unary:
            inner = handler.unary_unary

            async def unary_unary(request, context):
                return await _observe_unary(
                    metrics=self.m,
                    base_labels=base_labels,
                    rpc_fn=inner,
                    request=request,
                    context=context,
                )
            return grpc.aio.unary_unary_rpc_method_handler(  # type: ignore[attr-defined]
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            async def unary_stream(request, context):
                return await _observe_unary_stream(
                    metrics=self.m,
                    base_labels=base_labels,
                    rpc_fn=inner,
                    request=request,
                    context=context,
                )
            return grpc.aio.unary_stream_rpc_method_handler(  # type: ignore[attr-defined]
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            inner = handler.stream_unary

            async def stream_unary(request_iter, context):
                wrapped_iter = _ObservedAioRequestIter(self.m, base_labels, direction="in")
                return await _observe_stream_unary(
                    metrics=self.m,
                    base_labels=base_labels,
                    rpc_fn=inner,
                    request_iter=_wrap_aio_request_iter(request_iter, wrapped_iter),
                    counter=wrapped_iter,
                    context=context,
                )
            return grpc.aio.stream_unary_rpc_method_handler(  # type: ignore[attr-defined]
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            inner = handler.stream_stream

            async def stream_stream(request_iter, context):
                in_counter = _ObservedAioRequestIter(self.m, base_labels, direction="in")
                resp_async_gen = await _observe_stream_stream(
                    metrics=self.m,
                    base_labels=base_labels,
                    rpc_fn=inner,
                    request_iter=_wrap_aio_request_iter(request_iter, in_counter),
                    in_counter=in_counter,
                    context=context,
                )
                return resp_async_gen
            return grpc.aio.stream_stream_rpc_method_handler(  # type: ignore[attr-defined]
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Unknown handler kind — return as is
        return handler


# --------- AsyncIO Client Interceptor ---------

class AioClientMetricsInterceptor(grpc.aio.ClientInterceptor):  # type: ignore[attr-defined]
    def __init__(self, metrics: PrometheusMetrics) -> None:
        self.m = metrics

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()

        try:
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(request))
                self.m.messages_total.labels(*base_labels, "unary", "out").inc()
            call = await continuation(client_call_details, request)
            resp = await call
            code = StatusCode.OK
            return resp
        except grpc.RpcError as e:  # propagate while recording
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()
        if self.m.bytes_total is not None:
            self.m.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(request))
        self.m.messages_total.labels(*base_labels, "stream", "out").inc()

        code = StatusCode.OK
        try:
            call = await continuation(client_call_details, request)
            async for msg in call:
                if self.m.bytes_total is not None:
                    self.m.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(msg))
                self.m.messages_total.labels(*base_labels, "stream", "in").inc()
                yield msg
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()

        wrapped_iter = _ObservedAioRequestIter(self.m, base_labels, direction="out")
        code = StatusCode.OK
        try:
            call = await continuation(client_call_details, _wrap_aio_request_iter(request_iterator, wrapped_iter))
            resp = await call
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "unary", "in").inc(_size_of(resp))
            self.m.messages_total.labels(*base_labels, "unary", "in").inc()
            return resp
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()

        out_counter = _ObservedAioRequestIter(self.m, base_labels, direction="out")
        code = StatusCode.OK
        try:
            call = await continuation(client_call_details, _wrap_aio_request_iter(request_iterator, out_counter))
            async for msg in call:
                if self.m.bytes_total is not None:
                    self.m.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(msg))
                self.m.messages_total.labels(*base_labels, "stream", "in").inc()
                yield msg
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)


# --------- Sync Server/Client interceptors ---------

class SyncServerMetricsInterceptor(grpc.ServerInterceptor):
    def __init__(self, metrics: PrometheusMetrics):
        self.m = metrics

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = self.m.split_full_method(handler_call_details.method)
        base_labels = ("server", service, method)

        if handler.unary_unary:
            inner = handler.unary_unary

            def unary_unary(request, context):
                return _observe_unary_sync(self.m, base_labels, inner, request, context)
            return grpc.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            def unary_stream(request, context):
                return _observe_unary_stream_sync(self.m, base_labels, inner, request, context)
            return grpc.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            inner = handler.stream_unary

            def stream_unary(request_iter, context):
                in_counter = _ObservedSyncRequestIter(self.m, base_labels, direction="in")
                return _observe_stream_unary_sync(
                    self.m, base_labels, inner,
                    _wrap_sync_request_iter(request_iter, in_counter), in_counter, context
                )
            return grpc.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            inner = handler.stream_stream

            def stream_stream(request_iter, context):
                in_counter = _ObservedSyncRequestIter(self.m, base_labels, direction="in")
                return _observe_stream_stream_sync(
                    self.m, base_labels, inner,
                    _wrap_sync_request_iter(request_iter, in_counter), in_counter, context
                )
            return grpc.stream_stream_rpc_method_handler(
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


class SyncClientMetricsInterceptor(grpc.UnaryUnaryClientInterceptor,
                                   grpc.UnaryStreamClientInterceptor,
                                   grpc.StreamUnaryClientInterceptor,
                                   grpc.StreamStreamClientInterceptor):
    def __init__(self, metrics: PrometheusMetrics):
        self.m = metrics

    def intercept_unary_unary(self, continuation, client_call_details, request):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()
        code = StatusCode.OK
        try:
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(request))
                self.m.messages_total.labels(*base_labels, "unary", "out").inc()
            response = continuation(client_call_details, request)
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "unary", "in").inc(_size_of(response))
            self.m.messages_total.labels(*base_labels, "unary", "in").inc()
            return response
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()
        code = StatusCode.OK
        try:
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(request))
            self.m.messages_total.labels(*base_labels, "stream", "out").inc()
            it = continuation(client_call_details, request)
            for msg in it:
                if self.m.bytes_total is not None:
                    self.m.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(msg))
                self.m.messages_total.labels(*base_labels, "stream", "in").inc()
                yield msg
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()
        code = StatusCode.OK
        try:
            out_counter = _ObservedSyncRequestIter(self.m, base_labels, direction="out")
            response = continuation(client_call_details, _wrap_sync_request_iter(request_iterator, out_counter))
            if self.m.bytes_total is not None:
                self.m.bytes_total.labels(*base_labels, "unary", "in").inc(_size_of(response))
            self.m.messages_total.labels(*base_labels, "unary", "in").inc()
            return response
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)

    def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        service, method = self.m.split_full_method(client_call_details.method)
        base_labels = ("client", service, method)
        start = time.perf_counter()
        _inc_inflight(self.m, base_labels, +1)
        self.m.requests_total.labels(*base_labels).inc()
        code = StatusCode.OK
        try:
            out_counter = _ObservedSyncRequestIter(self.m, base_labels, direction="out")
            it = continuation(client_call_details, _wrap_sync_request_iter(request_iterator, out_counter))
            for msg in it:
                if self.m.bytes_total is not None:
                    self.m.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(msg))
                self.m.messages_total.labels(*base_labels, "stream", "in").inc()
                yield msg
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        finally:
            dur = time.perf_counter() - start
            _inc_inflight(self.m, base_labels, -1)
            self.m.responses_total.labels(*base_labels, code.name).inc()
            self.m.latency_seconds.labels(*base_labels, code.name).observe(dur)


# --------- Common helpers ---------

def _inc_inflight(m: PrometheusMetrics, base_labels: _t.Tuple[str, str, str], delta: int) -> None:
    if m.in_flight is not None:
        if delta > 0:
            m.in_flight.labels(*base_labels).inc(delta)
        else:
            m.in_flight.labels(*base_labels).dec(-delta)


def _size_of(message: _t.Any) -> int:
    # Best-effort size estimation without accessing private members
    try:
        if hasattr(message, "ByteSize"):
            return int(message.ByteSize())  # protobuf messages
        if isinstance(message, (bytes, bytearray, memoryview)):
            return len(message)
        if isinstance(message, str):
            return len(message.encode("utf-8"))
        # Fallback to repr length (bounded)
        r = repr(message)
        return len(r.encode("utf-8"))
    except Exception:  # pragma: no cover
        return 0


# ----- Async server observation wrappers -----

async def _observe_unary(metrics: PrometheusMetrics, base_labels, rpc_fn, request, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    if metrics.bytes_total is not None:
        metrics.bytes_total.labels(*base_labels, "unary", "in").inc(_size_of(request))
    metrics.messages_total.labels(*base_labels, "unary", "in").inc()

    code = StatusCode.OK
    try:
        resp = await rpc_fn(request, context)
        if metrics.bytes_total is not None:
            metrics.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(resp))
        metrics.messages_total.labels(*base_labels, "unary", "out").inc()
        return resp
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)


async def _observe_unary_stream(metrics: PrometheusMetrics, base_labels, rpc_fn, request, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    if metrics.bytes_total is not None:
        metrics.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(request))
    metrics.messages_total.labels(*base_labels, "stream", "in").inc()

    code = StatusCode.OK
    try:
        async for msg in rpc_fn(request, context):
            if metrics.bytes_total is not None:
                metrics.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(msg))
            metrics.messages_total.labels(*base_labels, "stream", "out").inc()
            yield msg
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)


async def _observe_stream_unary(metrics: PrometheusMetrics, base_labels, rpc_fn, request_iter, counter, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()

    code = StatusCode.OK
    try:
        resp = await rpc_fn(request_iter, context)
        if metrics.bytes_total is not None:
            metrics.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(resp))
        metrics.messages_total.labels(*base_labels, "unary", "out").inc()
        return resp
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)
        counter.flush()  # ensure counts recorded


async def _observe_stream_stream(metrics: PrometheusMetrics, base_labels, rpc_fn, request_iter, in_counter, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()

    code = StatusCode.OK
    try:
        async for msg in rpc_fn(request_iter, context):
            if metrics.bytes_total is not None:
                metrics.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(msg))
            metrics.messages_total.labels(*base_labels, "stream", "out").inc()
            yield msg
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)
        in_counter.flush()


# ----- Sync server observation wrappers -----

def _observe_unary_sync(metrics: PrometheusMetrics, base_labels, rpc_fn, request, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    if metrics.bytes_total is not None:
        metrics.bytes_total.labels(*base_labels, "unary", "in").inc(_size_of(request))
    metrics.messages_total.labels(*base_labels, "unary", "in").inc()

    code = StatusCode.OK
    try:
        resp = rpc_fn(request, context)
        if metrics.bytes_total is not None:
            metrics.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(resp))
        metrics.messages_total.labels(*base_labels, "unary", "out").inc()
        return resp
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)


def _observe_unary_stream_sync(metrics: PrometheusMetrics, base_labels, rpc_fn, request, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    if metrics.bytes_total is not None:
        metrics.bytes_total.labels(*base_labels, "stream", "in").inc(_size_of(request))
    metrics.messages_total.labels(*base_labels, "stream", "in").inc()

    code = StatusCode.OK
    try:
        for msg in rpc_fn(request, context):
            if metrics.bytes_total is not None:
                metrics.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(msg))
            metrics.messages_total.labels(*base_labels, "stream", "out").inc()
            yield msg
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)


def _observe_stream_unary_sync(metrics: PrometheusMetrics, base_labels, rpc_fn, request_iter, in_counter, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    code = StatusCode.OK
    try:
        resp = rpc_fn(request_iter, context)
        if metrics.bytes_total is not None:
            metrics.bytes_total.labels(*base_labels, "unary", "out").inc(_size_of(resp))
        metrics.messages_total.labels(*base_labels, "unary", "out").inc()
        return resp
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)
        in_counter.flush()


def _observe_stream_stream_sync(metrics: PrometheusMetrics, base_labels, rpc_fn, request_iter, in_counter, context):
    start = time.perf_counter()
    _inc_inflight(metrics, base_labels, +1)
    metrics.requests_total.labels(*base_labels).inc()
    code = StatusCode.OK
    try:
        for msg in rpc_fn(request_iter, context):
            if metrics.bytes_total is not None:
                metrics.bytes_total.labels(*base_labels, "stream", "out").inc(_size_of(msg))
            metrics.messages_total.labels(*base_labels, "stream", "out").inc()
            yield msg
    except grpc.RpcError as e:
        code = e.code() or StatusCode.UNKNOWN
        raise
    except Exception:
        code = StatusCode.UNKNOWN
        raise
    finally:
        dur = time.perf_counter() - start
        _inc_inflight(metrics, base_labels, -1)
        metrics.responses_total.labels(*base_labels, code.name).inc()
        metrics.latency_seconds.labels(*base_labels, code.name).observe(dur)
        in_counter.flush()


# ----- Iteration wrappers to count inbound/outbound streams -----

class _ObservedAioRequestIter:
    def __init__(self, metrics: PrometheusMetrics, base_labels, direction: str):
        self.m = metrics
        self.base = base_labels
        self.direction = direction  # "in" or "out"
        self._bytes = 0
        self._msgs = 0

    def observe(self, msg) -> None:
        self._msgs += 1
        b = _size_of(msg)
        self._bytes += b
        if self.m.bytes_total is not None:
            self.m.bytes_total.labels(*self.base, "stream", self.direction).inc(b)
        self.m.messages_total.labels(*self.base, "stream", self.direction).inc()

    def flush(self) -> None:
        # Nothing persistent; counters already incremented on observe
        pass


def _wrap_aio_request_iter(source_async_iter, counter: _ObservedAioRequestIter):
    async def gen():
        async for m in source_async_iter:
            counter.observe(m)
            yield m
    return gen()


class _ObservedSyncRequestIter:
    def __init__(self, metrics: PrometheusMetrics, base_labels, direction: str):
        self.m = metrics
        self.base = base_labels
        self.direction = direction

    def observe(self, msg) -> None:
        if self.m.bytes_total is not None:
            self.m.bytes_total.labels(*self.base, "stream", self.direction).inc(_size_of(msg))
        self.m.messages_total.labels(*self.base, "stream", self.direction).inc()

    def flush(self) -> None:
        pass


def _wrap_sync_request_iter(source_iter, counter: _ObservedSyncRequestIter):
    def gen():
        for m in source_iter:
            counter.observe(m)
            yield m
    return gen()
