# physical-integration-core/api/grpc/interceptors/metrics.py
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, Tuple

import grpc
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)
from prometheus_client import multiprocess  # type: ignore[attr-defined]

log = logging.getLogger(__name__)

# ---------------------------
# Metric container
# ---------------------------

@dataclass(frozen=True)
class _Metrics:
    started_total: Counter
    handled_total: Counter
    msg_received_total: Counter
    msg_sent_total: Counter
    in_flight: Gauge
    handling_seconds: Histogram


def _build_metrics(
    registry: Optional[CollectorRegistry] = None,
    *,
    latency_buckets: Optional[Tuple[float, ...]] = None,
) -> _Metrics:
    """
    Create Prometheus metrics following grpc_server_* naming conventions.
    """
    buckets = latency_buckets or (
        0.001, 0.002, 0.005,
        0.01, 0.02, 0.05,
        0.1, 0.2, 0.5,
        1.0, 2.0, 5.0,
        10.0, 30.0
    )

    started_total = Counter(
        "grpc_server_started_total",
        "Total number of RPCs started on the server.",
        ["grpc_service", "grpc_method", "grpc_type"],
        registry=registry,
    )
    handled_total = Counter(
        "grpc_server_handled_total",
        "Total number of RPCs completed on the server, regardless of success or failure.",
        ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
        registry=registry,
    )
    msg_received_total = Counter(
        "grpc_server_msg_received_total",
        "Total number of RPC stream messages received by the server.",
        ["grpc_service", "grpc_method", "grpc_type"],
        registry=registry,
    )
    msg_sent_total = Counter(
        "grpc_server_msg_sent_total",
        "Total number of RPC stream messages sent by the server.",
        ["grpc_service", "grpc_method", "grpc_type"],
        registry=registry,
    )
    in_flight = Gauge(
        "grpc_server_in_flight",
        "Current number of in-flight RPCs on the server.",
        ["grpc_service", "grpc_method", "grpc_type"],
        registry=registry,
        multiprocess_mode="livesum",
    )
    handling_seconds = Histogram(
        "grpc_server_handling_seconds",
        "Histogram of RPC handling latency (seconds) on the server.",
        ["grpc_service", "grpc_method", "grpc_type"],
        buckets=buckets,
        registry=registry,
    )

    return _Metrics(
        started_total=started_total,
        handled_total=handled_total,
        msg_received_total=msg_received_total,
        msg_sent_total=msg_sent_total,
        in_flight=in_flight,
        handling_seconds=handling_seconds,
    )

# ---------------------------
# Helpers
# ---------------------------

def _split_method(full_method: str) -> Tuple[str, str]:
    # full_method like "/package.Service/Method"
    try:
        _, rest = full_method.split("/", 1)
        service, method = rest.split("/", 1)
        return service, method
    except Exception:
        return "unknown", full_method or "unknown"

def _rpc_type(handler: grpc.RpcMethodHandler) -> str:
    if handler.request_streaming and handler.response_streaming:
        return "bidi_stream"
    if handler.request_streaming and not handler.response_streaming:
        return "client_stream"
    if not handler.request_streaming and handler.response_streaming:
        return "server_stream"
    return "unary"

def _code_name_from_exception(exc: BaseException) -> str:
    if isinstance(exc, grpc.RpcError):
        try:
            code = exc.code()
            return code.name if code is not None else "UNKNOWN"
        except Exception:
            return "UNKNOWN"
    return "UNKNOWN"

# ---------------------------
# Interceptor
# ---------------------------

class PrometheusServerInterceptor(grpc.ServerInterceptor):
    """
    Server-side gRPC interceptor exporting Prometheus metrics.

    Metrics:
      - grpc_server_started_total{service,method,type}
      - grpc_server_handled_total{service,method,type,code}
      - grpc_server_msg_received_total{service,method,type}
      - grpc_server_msg_sent_total{service,method,type}
      - grpc_server_in_flight{service,method,type}
      - grpc_server_handling_seconds_bucket|sum|count{service,method,type}
    """

    def __init__(
        self,
        registry: Optional[CollectorRegistry] = None,
        *,
        latency_buckets: Optional[Tuple[float, ...]] = None,
    ) -> None:
        # Support Prometheus multiprocess mode if env is set
        if registry is None and "PROMETHEUS_MULTIPROC_DIR" in os.environ:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)  # type: ignore[attr-defined]

        self._registry = registry
        self._m = _build_metrics(registry, latency_buckets=latency_buckets)

    # Core hook
    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> Optional[grpc.RpcMethodHandler]:
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)
        rtype = _rpc_type(handler)
        base_labels = (service, method, rtype)

        # Wrap per kind
        if not handler.request_streaming and not handler.response_streaming:
            return grpc.unary_unary_rpc_method_handler(
                self._wrap_unary_unary(handler.unary_unary, base_labels),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if not handler.request_streaming and handler.response_streaming:
            return grpc.unary_stream_rpc_method_handler(
                self._wrap_unary_stream(handler.unary_stream, base_labels),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.request_streaming and not handler.response_streaming:
            return grpc.stream_unary_rpc_method_handler(
                self._wrap_stream_unary(handler.stream_unary, base_labels),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        # bidi
        return grpc.stream_stream_rpc_method_handler(
            self._wrap_stream_stream(handler.stream_stream, base_labels),
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    # -----------------------
    # Wrappers
    # -----------------------

    def _wrap_unary_unary(
        self,
        inner: Callable[[Any, grpc.ServicerContext], Any],
        labels: Tuple[str, str, str],
    ):
        def _handler(request: Any, context: grpc.ServicerContext) -> Any:
            service, method, rtype = labels
            self._m.started_total.labels(service, method, rtype).inc()
            self._m.in_flight.labels(service, method, rtype).inc()
            self._m.msg_received_total.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = "OK"
            try:
                resp = inner(request, context)
                self._m.msg_sent_total.labels(service, method, rtype).inc()
                return resp
            except BaseException as e:
                code = _code_name_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                self._m.handling_seconds.labels(service, method, rtype).observe(elapsed)
                self._m.in_flight.labels(service, method, rtype).dec()
                self._m.handled_total.labels(service, method, rtype, code).inc()
        return _handler

    def _wrap_unary_stream(
        self,
        inner: Callable[[Any, grpc.ServicerContext], Iterable[Any]],
        labels: Tuple[str, str, str],
    ):
        def _handler(request: Any, context: grpc.ServicerContext) -> Iterator[Any]:
            service, method, rtype = labels
            self._m.started_total.labels(service, method, rtype).inc()
            self._m.in_flight.labels(service, method, rtype).inc()
            self._m.msg_received_total.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = "OK"
            try:
                for resp in inner(request, context):
                    self._m.msg_sent_total.labels(service, method, rtype).inc()
                    yield resp
            except BaseException as e:
                code = _code_name_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                self._m.handling_seconds.labels(service, method, rtype).observe(elapsed)
                self._m.in_flight.labels(service, method, rtype).dec()
                self._m.handled_total.labels(service, method, rtype, code).inc()
        return _handler

    def _wrap_stream_unary(
        self,
        inner: Callable[[Iterable[Any], grpc.ServicerContext], Any],
        labels: Tuple[str, str, str],
    ):
        def counting_request_iterator(it: Iterable[Any]) -> Iterator[Any]:
            for msg in it:
                self._m.msg_received_total.labels(*labels).inc()
                yield msg

        def _handler(request_iterator: Iterable[Any], context: grpc.ServicerContext) -> Any:
            service, method, rtype = labels
            self._m.started_total.labels(service, method, rtype).inc()
            self._m.in_flight.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = "OK"
            try:
                resp = inner(counting_request_iterator(request_iterator), context)
                self._m.msg_sent_total.labels(service, method, rtype).inc()
                return resp
            except BaseException as e:
                code = _code_name_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                self._m.handling_seconds.labels(service, method, rtype).observe(elapsed)
                self._m.in_flight.labels(service, method, rtype).dec()
                self._m.handled_total.labels(service, method, rtype, code).inc()
        return _handler

    def _wrap_stream_stream(
        self,
        inner: Callable[[Iterable[Any], grpc.ServicerContext], Iterable[Any]],
        labels: Tuple[str, str, str],
    ):
        def counting_request_iterator(it: Iterable[Any]) -> Iterator[Any]:
            for msg in it:
                self._m.msg_received_total.labels(*labels).inc()
                yield msg

        def _handler(request_iterator: Iterable[Any], context: grpc.ServicerContext) -> Iterator[Any]:
            service, method, rtype = labels
            self._m.started_total.labels(service, method, rtype).inc()
            self._m.in_flight.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = "OK"
            try:
                for resp in inner(counting_request_iterator(request_iterator), context):
                    self._m.msg_sent_total.labels(service, method, rtype).inc()
                    yield resp
            except BaseException as e:
                code = _code_name_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                self._m.handling_seconds.labels(service, method, rtype).observe(elapsed)
                self._m.in_flight.labels(service, method, rtype).dec()
                self._m.handled_total.labels(service, method, rtype, code).inc()
        return _handler

# ---------------------------
# Prometheus exposition helpers
# ---------------------------

def start_prometheus_http_exporter(
    port: int = 9464,
    addr: str = "0.0.0.0",
    registry: Optional[CollectorRegistry] = None,
) -> CollectorRegistry:
    """
    Start a Prometheus HTTP exporter in-process.

    If PROMETHEUS_MULTIPROC_DIR is set, a dedicated CollectorRegistry with
    MultiProcessCollector is created when registry is None.
    """
    if registry is None and "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)  # type: ignore[attr-defined]
    start_http_server(port, addr=addr, registry=registry)
    log.info("Prometheus exporter started on http://%s:%d/metrics", addr, port)
    return registry or CollectorRegistry()

try:
    # Optional ASGI exporter (prometheus_client>=0.18 has make_asgi_app)
    from prometheus_client import exposition as _expo  # type: ignore

    def make_prometheus_asgi_app(registry: Optional[CollectorRegistry] = None):
        """
        Return an ASGI app serving /metrics for embedding into FastAPI/Starlette.
        """
        if registry is None and "PROMETHEUS_MULTIPROC_DIR" in os.environ:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)  # type: ignore[attr-defined]
        if hasattr(_expo, "make_asgi_app"):
            return _expo.make_asgi_app(registry=registry)
        raise RuntimeError("prometheus_client.make_asgi_app is not available in your version.")
except Exception:
    # Exposition helpers remain available via start_prometheus_http_exporter
    pass

# ---------------------------
# Usage example (not executed here):
#
# interceptor = PrometheusServerInterceptor()
# server = grpc.server(futures.ThreadPoolExecutor(max_workers=16),
#                      interceptors=[interceptor])
# start_prometheus_http_exporter(port=9464)  # or mount ASGI app
# ---------------------------
