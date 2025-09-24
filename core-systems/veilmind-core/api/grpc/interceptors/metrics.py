# veilmind-core/api/grpc/interceptors/metrics.py
from __future__ import annotations

import time
import types
import uuid
import functools
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, Iterator, Optional, Tuple

import grpc

# -------- Prometheus backend (with graceful fallback) --------
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        CollectorRegistry,
        REGISTRY,
    )
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

    class _NoopMetric:
        def labels(self, *_, **__):  # type: ignore
            return self
        def inc(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass
        def dec(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass
        def observe(self, *_: Any, **__: Any) -> None:  # type: ignore
            pass

    class Counter(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    class Histogram(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    class Gauge(_NoopMetric):  # type: ignore
        def __init__(self, *_, **__): pass
    class CollectorRegistry:  # type: ignore
        pass
    REGISTRY = None  # type: ignore


# -------- Helpers --------
_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)
_SIZE_BUCKETS = (64, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576)  # bytes

def _split_full_method(full_method: str) -> Tuple[str, str]:
    # "/package.Service/Method" -> ("package.Service", "Method")
    try:
        _, tail = full_method.split("/", 1)
        service, method = tail.split("/", 1)
        return service, method
    except Exception:
        return "unknown", "unknown"

def _rpc_type_from_handler(handler: Any) -> str:
    if handler.unary_unary:
        return "unary_unary"
    if handler.unary_stream:
        return "unary_stream"
    if handler.stream_unary:
        return "stream_unary"
    if handler.stream_stream:
        return "stream_stream"
    return "unknown"

def _byte_size(msg: Any) -> int:
    try:
        # protobuf messages have fast ByteSize()
        if hasattr(msg, "ByteSize"):
            return int(msg.ByteSize())
        if hasattr(msg, "SerializeToString"):
            return len(msg.SerializeToString())  # type: ignore[attr-defined]
    except Exception:
        return 0
    return 0

def _status_code_from_exc(exc: BaseException) -> grpc.StatusCode:
    if isinstance(exc, grpc.RpcError):
        try:
            code = exc.code()  # type: ignore[call-arg]
            if isinstance(code, grpc.StatusCode):
                return code
        except Exception:
            pass
    return grpc.StatusCode.UNKNOWN

def _labels(service: str, method: str, rtype: str, code: Optional[grpc.StatusCode] = None) -> Dict[str, str]:
    # keep label cardinality low and stable
    base = {
        "grpc_service": service[:120],
        "grpc_method": method[:120],
        "grpc_type": rtype,
    }
    if code is not None:
        base["grpc_code"] = code.name
    return base


# -------- Metrics container --------
class GrpcPromMetrics:
    def __init__(
        self,
        registry: Optional[CollectorRegistry] = None,
        namespace: str = "veilmind",
        subsystem: str = "grpc",
        latency_buckets: Tuple[float, ...] = _LATENCY_BUCKETS,
        size_buckets: Tuple[float, ...] = _SIZE_BUCKETS,
    ) -> None:
        reg = registry or REGISTRY

        self.rpc_started = Counter(
            f"{namespace}_{subsystem}_server_rpc_started_total",
            "Number of RPCs started on the server.",
            ["grpc_service", "grpc_method", "grpc_type"],
            registry=reg,
        )
        self.rpc_in_progress = Gauge(
            f"{namespace}_{subsystem}_server_rpc_in_progress",
            "Current number of in-flight RPCs.",
            ["grpc_service", "grpc_method", "grpc_type"],
            registry=reg,
        )
        self.rpc_completed = Counter(
            f"{namespace}_{subsystem}_server_rpc_completed_total",
            "Number of completed RPCs by status code.",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
            registry=reg,
        )
        self.rpc_latency = Histogram(
            f"{namespace}_{subsystem}_server_handling_seconds",
            "RPC latency in seconds.",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
            buckets=latency_buckets,
            registry=reg,
        )
        self.request_bytes = Histogram(
            f"{namespace}_{subsystem}_server_request_bytes",
            "Request message size in bytes.",
            ["grpc_service", "grpc_method", "grpc_type"],
            buckets=size_buckets,
            registry=reg,
        )
        self.response_bytes = Histogram(
            f"{namespace}_{subsystem}_server_response_bytes",
            "Response message size in bytes.",
            ["grpc_service", "grpc_method", "grpc_type"],
            buckets=size_buckets,
            registry=reg,
        )
        self.stream_msgs_recv = Counter(
            f"{namespace}_{subsystem}_server_stream_messages_received_total",
            "Number of stream messages received.",
            ["grpc_service", "grpc_method", "grpc_type"],
            registry=reg,
        )
        self.stream_msgs_sent = Counter(
            f"{namespace}_{subsystem}_server_stream_messages_sent_total",
            "Number of stream messages sent.",
            ["grpc_service", "grpc_method", "grpc_type"],
            registry=reg,
        )
        self.rpc_exceptions = Counter(
            f"{namespace}_{subsystem}_server_exceptions_total",
            "Number of unexpected exceptions in handlers.",
            ["grpc_service", "grpc_method", "grpc_type", "exception"],
            registry=reg,
        )


# -------- Sync (grpc.ServerInterceptor) --------
class MetricsServerInterceptor(grpc.ServerInterceptor):
    def __init__(self, metrics: Optional[GrpcPromMetrics] = None) -> None:
        self.m = metrics or GrpcPromMetrics()

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = continuation(handler_call_details)
        if handler is None:
            return handler  # type: ignore[return-value]

        service, method = _split_full_method(handler_call_details.method)
        rtype = _rpc_type_from_handler(handler)

        # wrap each present behavior
        if handler.unary_unary:
            original = handler.unary_unary
            @functools.wraps(original)
            def _uu(request, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(request))
                    resp = original(request, context)
                    self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(resp))
                    return resp
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(unary_unary=_uu)

        if handler.unary_stream:
            original = handler.unary_stream
            @functools.wraps(original)
            def _us(request, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(request))
                    iterator = original(request, context)
                    return self._wrap_sync_response_stream(iterator, service, method, rtype, start)
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    if code is not grpc.StatusCode.OK:
                        self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(unary_stream=_us)

        if handler.stream_unary:
            original = handler.stream_unary
            @functools.wraps(original)
            def _su(request_iter, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    wrapped_iter = self._wrap_sync_request_stream(request_iter, service, method, rtype)
                    resp = original(wrapped_iter, context)
                    self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(resp))
                    return resp
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(stream_unary=_su)

        if handler.stream_stream:
            original = handler.stream_stream
            @functools.wraps(original)
            def _ss(request_iter, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    wrapped_iter = self._wrap_sync_request_stream(request_iter, service, method, rtype)
                    iterator = original(wrapped_iter, context)
                    return self._wrap_sync_response_stream(iterator, service, method, rtype, start)
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    if code is not grpc.StatusCode.OK:
                        self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(stream_stream=_ss)

        return handler

    # ---- sync helpers ----
    def _wrap_sync_request_stream(self, it: Iterator[Any], service: str, method: str, rtype: str) -> Iterator[Any]:
        for msg in it:
            self.m.stream_msgs_recv.labels(**_labels(service, method, rtype)).inc()
            self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(msg))
            yield msg

    def _wrap_sync_response_stream(self, it: Iterator[Any], service: str, method: str, rtype: str, start: float) -> Iterator[Any]:
        try:
            for msg in it:
                self.m.stream_msgs_sent.labels(**_labels(service, method, rtype)).inc()
                self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(msg))
                yield msg
            code = grpc.StatusCode.OK
            self._on_finish(service, method, rtype, code, start)
        except grpc.RpcError as e:
            code = _status_code_from_exc(e)
            self._on_finish(service, method, rtype, code, start)
            raise
        except Exception as e:  # pragma: no cover
            self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
            code = grpc.StatusCode.UNKNOWN
            self._on_finish(service, method, rtype, code, start)
            raise

    def _on_start(self, service: str, method: str, rtype: str) -> None:
        self.m.rpc_started.labels(**_labels(service, method, rtype)).inc()
        self.m.rpc_in_progress.labels(**_labels(service, method, rtype)).inc()

    def _on_finish(self, service: str, method: str, rtype: str, code: grpc.StatusCode, start: float) -> None:
        elapsed = max(0.0, time.perf_counter() - start)
        self.m.rpc_in_progress.labels(**_labels(service, method, rtype)).dec()
        self.m.rpc_completed.labels(**_labels(service, method, rtype, code)).inc()
        self.m.rpc_latency.labels(**_labels(service, method, rtype, code)).observe(elapsed)


# -------- Async (grpc.aio.ServerInterceptor) --------
class AioMetricsServerInterceptor(grpc.aio.ServerInterceptor):  # type: ignore[attr-defined]
    def __init__(self, metrics: Optional[GrpcPromMetrics] = None) -> None:
        self.m = metrics or GrpcPromMetrics()

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler  # type: ignore[return-value]

        service, method = _split_full_method(handler_call_details.method)
        rtype = _rpc_type_from_handler(handler)

        if handler.unary_unary:
            original = handler.unary_unary
            @functools.wraps(original)
            async def _uu(request, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(request))
                    resp = await original(request, context)
                    self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(resp))
                    return resp
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(unary_unary=_uu)

        if handler.unary_stream:
            original = handler.unary_stream
            @functools.wraps(original)
            async def _us(request, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(request))
                    ait = await original(request, context)
                    return self._wrap_async_response_stream(ait, service, method, rtype, start)
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    if code is not grpc.StatusCode.OK:
                        self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(unary_stream=_us)

        if handler.stream_unary:
            original = handler.stream_unary
            @functools.wraps(original)
            async def _su(request_iter, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    wrapped = self._wrap_async_request_stream(request_iter, service, method, rtype)
                    resp = await original(wrapped, context)
                    self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(resp))
                    return resp
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(stream_unary=_su)

        if handler.stream_stream:
            original = handler.stream_stream
            @functools.wraps(original)
            async def _ss(request_iter, context):
                self._on_start(service, method, rtype)
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    wrapped = self._wrap_async_request_stream(request_iter, service, method, rtype)
                    ait = await original(wrapped, context)
                    return self._wrap_async_response_stream(ait, service, method, rtype, start)
                except grpc.RpcError as e:
                    code = _status_code_from_exc(e)
                    raise
                except Exception as e:  # pragma: no cover
                    code = grpc.StatusCode.UNKNOWN
                    self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                    raise
                finally:
                    if code is not grpc.StatusCode.OK:
                        self._on_finish(service, method, rtype, code, start)
            handler = handler._replace(stream_stream=_ss)

        return handler

    # ---- async helpers ----
    def _wrap_async_request_stream(self, it: AsyncIterator[Any], service: str, method: str, rtype: str) -> AsyncIterator[Any]:
        async def gen():
            async for msg in it:
                self.m.stream_msgs_recv.labels(**_labels(service, method, rtype)).inc()
                self.m.request_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(msg))
                yield msg
        return gen()

    def _wrap_async_response_stream(self, it: AsyncIterator[Any], service: str, method: str, rtype: str, start: float) -> AsyncIterator[Any]:
        async def gen():
            try:
                async for msg in it:
                    self.m.stream_msgs_sent.labels(**_labels(service, method, rtype)).inc()
                    self.m.response_bytes.labels(**_labels(service, method, rtype)).observe(_byte_size(msg))
                    yield msg
                code = grpc.StatusCode.OK
                self._on_finish(service, method, rtype, code, start)
            except grpc.RpcError as e:
                code = _status_code_from_exc(e)
                self._on_finish(service, method, rtype, code, start)
                raise
            except Exception as e:  # pragma: no cover
                self.m.rpc_exceptions.labels(**_labels(service, method, rtype), exception=type(e).__name__).inc()
                code = grpc.StatusCode.UNKNOWN
                self._on_finish(service, method, rtype, code, start)
                raise
        return gen()

    def _on_start(self, service: str, method: str, rtype: str) -> None:
        self.m.rpc_started.labels(**_labels(service, method, rtype)).inc()
        self.m.rpc_in_progress.labels(**_labels(service, method, rtype)).inc()

    def _on_finish(self, service: str, method: str, rtype: str, code: grpc.StatusCode, start: float) -> None:
        elapsed = max(0.0, time.perf_counter() - start)
        self.m.rpc_in_progress.labels(**_labels(service, method, rtype)).dec()
        self.m.rpc_completed.labels(**_labels(service, method, rtype, code)).inc()
        self.m.rpc_latency.labels(**_labels(service, method, rtype, code)).observe(elapsed)


# -------- Factory --------
def metrics_interceptors(
    *,
    registry: Optional[CollectorRegistry] = None,
    namespace: str = "veilmind",
    subsystem: str = "grpc",
    latency_buckets: Tuple[float, ...] = _LATENCY_BUCKETS,
    size_buckets: Tuple[float, ...] = _SIZE_BUCKETS,
) -> Tuple[MetricsServerInterceptor, AioMetricsServerInterceptor]:
    """
    Возвращает пару перехватчиков (sync, async) с общим набором метрик.
    Используйте соответствующий для grpc.server(...) или grpc.aio.server(...).

    Пример (sync):
        sync_interceptor, _ = metrics_interceptors()
        server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[sync_interceptor])

    Пример (asyncio):
        _, aio_interceptor = metrics_interceptors()
        server = grpc.aio.server(interceptors=[aio_interceptor])
    """
    metrics = GrpcPromMetrics(registry=registry, namespace=namespace, subsystem=subsystem,
                              latency_buckets=latency_buckets, size_buckets=size_buckets)
    return MetricsServerInterceptor(metrics), AioMetricsServerInterceptor(metrics)
