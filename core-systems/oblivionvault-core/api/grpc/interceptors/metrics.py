# -*- coding: utf-8 -*-
"""
Prometheus metrics interceptors for gRPC (sync and asyncio) — production-grade.

Exports:
- PrometheusServerInterceptor                  (grpc.ServerInterceptor)
- AioPrometheusServerInterceptor               (grpc.aio.ServerInterceptor)
- start_prometheus_http_server(port, addr)     # optional convenience
- get_metrics_registry()                       # current registry

Metrics (with labels: service, method, grpc_type, code):
- rpc_requests_total                           Counter
- rpc_in_progress                              Gauge  (no code label)
- rpc_latency_seconds                          Histogram
- rpc_messages_in_total                        Counter
- rpc_messages_out_total                       Counter
- rpc_request_bytes                            Histogram
- rpc_response_bytes                           Histogram

Notes:
- Size is measured via .ByteSize() or len(.SerializeToString()) when available.
- Code is derived from grpc.RpcError.code() when exceptions occur; otherwise "OK".
- Buckets chosen for general server RPC mix; adjust via env if needed.

Dependencies:
- grpcio (sync), grpcio>=1.32 and grpcio>=1.43 for aio, prometheus_client
"""

from __future__ import annotations

import os
import time
import types
import inspect
import functools
from typing import Any, AsyncIterator, Awaitable, Callable, Iterator, Optional, Tuple

import grpc

try:
    # Prometheus client is required in production; if missing, raise early.
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        start_http_server as _prom_start_http_server,
        REGISTRY as _DEFAULT_REGISTRY,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("prometheus_client is required for metrics interceptor") from e


# ------------------------------------------------------------------------------
# Registry & Metrics (singleton per process)
# ------------------------------------------------------------------------------

_REGISTRY: CollectorRegistry = _DEFAULT_REGISTRY

def get_metrics_registry() -> CollectorRegistry:
    return _REGISTRY

def _buckets_from_env(name: str, default: Tuple[float, ...]) -> Tuple[float, ...]:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return tuple(float(x.strip()) for x in raw.split(",") if x.strip())
    except Exception:
        return default

_LATENCY_BUCKETS = _buckets_from_env(
    "OV_GRPC_LATENCY_BUCKETS",
    (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
)
_BYTES_BUCKETS = _buckets_from_env(
    "OV_GRPC_BYTES_BUCKETS",
    (128, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
     131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216)
)

# Lazily created metrics (avoid duplicate registration on reload)
_METRICS_INIT = False

def _ensure_metrics() -> None:
    global _METRICS_INIT
    if _METRICS_INIT:
        return
    # Counters
    globals()["RPC_REQUESTS_TOTAL"] = Counter(
        "rpc_requests_total",
        "Total number of RPC requests started on the server.",
        ("service", "method", "grpc_type"),
        registry=_REGISTRY,
    )
    globals()["RPC_MESSAGES_IN_TOTAL"] = Counter(
        "rpc_messages_in_total",
        "Total number of streaming messages received.",
        ("service", "method", "grpc_type"),
        registry=_REGISTRY,
    )
    globals()["RPC_MESSAGES_OUT_TOTAL"] = Counter(
        "rpc_messages_out_total",
        "Total number of streaming messages sent.",
        ("service", "method", "grpc_type"),
        registry=_REGISTRY,
    )
    globals()["RPC_HANDLED_TOTAL"] = Counter(
        "rpc_handled_total",
        "Total number of RPCs completed on the server, regardless of success.",
        ("service", "method", "grpc_type", "code"),
        registry=_REGISTRY,
    )
    # Gauges
    globals()["RPC_IN_PROGRESS"] = Gauge(
        "rpc_in_progress",
        "Number of RPCs currently in progress on the server.",
        ("service", "method", "grpc_type"),
        registry=_REGISTRY,
    )
    # Histograms
    globals()["RPC_LATENCY"] = Histogram(
        "rpc_latency_seconds",
        "Latency of RPCs on the server (seconds).",
        ("service", "method", "grpc_type", "code"),
        buckets=_LATENCY_BUCKETS,
        registry=_REGISTRY,
    )
    globals()["RPC_REQUEST_BYTES"] = Histogram(
        "rpc_request_bytes",
        "Incoming request size in bytes (per RPC or per message for streaming).",
        ("service", "method", "grpc_type"),
        buckets=_BYTES_BUCKETS,
        registry=_REGISTRY,
    )
    globals()["RPC_RESPONSE_BYTES"] = Histogram(
        "rpc_response_bytes",
        "Outgoing response size in bytes (per RPC or per message for streaming).",
        ("service", "method", "grpc_type"),
        buckets=_BYTES_BUCKETS,
        registry=_REGISTRY,
    )
    _METRICS_INIT = True


def start_prometheus_http_server(port: int = 9090, addr: str = "0.0.0.0") -> None:
    """
    Optional helper to expose metrics without extra web server.
    """
    _prom_start_http_server(port, addr=addr, registry=_REGISTRY)


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _parse_method(method_path: str) -> Tuple[str, str]:
    # "/package.Service/Method" → ("package.Service", "Method")
    try:
        _, service, method = method_path.split("/", 2)
        return service, method
    except Exception:
        return "unknown", method_path or "unknown"

def _grpc_type(handler: grpc.RpcMethodHandler) -> str:
    # UU, US, SU, SS
    rs, rsps = handler.request_streaming, handler.response_streaming
    if not rs and not rsps:
        return "unary_unary"
    if not rs and rsps:
        return "unary_stream"
    if rs and not rsps:
        return "stream_unary"
    return "stream_stream"

def _msg_size(msg: Any) -> Optional[int]:
    try:
        if hasattr(msg, "ByteSize") and callable(msg.ByteSize):
            return int(msg.ByteSize())
        if hasattr(msg, "SerializeToString"):
            return len(msg.SerializeToString())
    except Exception:
        return None
    return None

def _observe_req(msg: Any, service: str, method: str, kind: str) -> None:
    size = _msg_size(msg)
    if size is not None:
        RPC_REQUEST_BYTES.labels(service, method, kind).observe(size)
    RPC_MESSAGES_IN_TOTAL.labels(service, method, kind).inc()

def _observe_resp(msg: Any, service: str, method: str, kind: str) -> None:
    size = _msg_size(msg)
    if size is not None:
        RPC_RESPONSE_BYTES.labels(service, method, kind).observe(size)
    RPC_MESSAGES_OUT_TOTAL.labels(service, method, kind).inc()

def _status_code_from_exc(exc: BaseException) -> str:
    if isinstance(exc, grpc.RpcError):
        try:
            c = exc.code()
            return c.name if hasattr(c, "name") else str(c)
        except Exception:
            return "UNKNOWN"
    return "INTERNAL"

# ------------------------------------------------------------------------------
# Sync interceptor
# ------------------------------------------------------------------------------

class PrometheusServerInterceptor(grpc.ServerInterceptor):
    """
    Synchronous gRPC server interceptor with Prometheus metrics.
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None) -> None:
        global _REGISTRY
        if registry is not None and registry is not _REGISTRY:
            _REGISTRY = registry
        _ensure_metrics()

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails
    ) -> grpc.RpcMethodHandler:
        orig = continuation(handler_call_details)
        if orig is None:
            return orig

        service, method = _parse_method(handler_call_details.method)
        kind = _grpc_type(orig)

        # Wrap according to type
        if not orig.request_streaming and not orig.response_streaming:
            # unary_unary
            def new_unary_unary(request, context):
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    _observe_req(request, service, method, kind)
                    resp = orig.unary_unary(request, context)
                    _observe_resp(resp, service, method, kind)
                    return resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.unary_unary_rpc_method_handler(
                new_unary_unary,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        if not orig.request_streaming and orig.response_streaming:
            # unary_stream
            def new_unary_stream(request, context) -> Iterator[Any]:
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    _observe_req(request, service, method, kind)
                    for resp in orig.unary_stream(request, context):
                        _observe_resp(resp, service, method, kind)
                        yield resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.unary_stream_rpc_method_handler(
                new_unary_stream,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        if orig.request_streaming and not orig.response_streaming:
            # stream_unary
            def wrapped_req_iter(request_iter: Iterator[Any]) -> Iterator[Any]:
                for msg in request_iter:
                    _observe_req(msg, service, method, kind)
                    yield msg

            def new_stream_unary(request_iterator, context):
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    resp = orig.stream_unary(wrapped_req_iter(request_iterator), context)
                    _observe_resp(resp, service, method, kind)
                    return resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.stream_unary_rpc_method_handler(
                new_stream_unary,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        # stream_stream
        def wrapped_req_iter(request_iter: Iterator[Any]) -> Iterator[Any]:
            for msg in request_iter:
                _observe_req(msg, service, method, kind)
                yield msg

        def new_stream_stream(request_iterator, context) -> Iterator[Any]:
            RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
            RPC_IN_PROGRESS.labels(service, method, kind).inc()
            t0 = time.perf_counter()
            code = "OK"
            try:
                for resp in orig.stream_stream(wrapped_req_iter(request_iterator), context):
                    _observe_resp(resp, service, method, kind)
                    yield resp
            except BaseException as e:
                code = _status_code_from_exc(e)
                raise
            finally:
                dt = time.perf_counter() - t0
                RPC_IN_PROGRESS.labels(service, method, kind).dec()
                RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                RPC_LATENCY.labels(service, method, kind, code).observe(dt)

        return grpc.stream_stream_rpc_method_handler(
            new_stream_stream,
            request_deserializer=orig.request_deserializer,
            response_serializer=orig.response_serializer,
        )


# ------------------------------------------------------------------------------
# Asyncio interceptor
# ------------------------------------------------------------------------------

class AioPrometheusServerInterceptor(grpc.aio.ServerInterceptor):
    """
    Async gRPC server interceptor with Prometheus metrics (grpc.aio).
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None) -> None:
        global _REGISTRY
        if registry is not None and registry is not _REGISTRY:
            _REGISTRY = registry
        _ensure_metrics()

    async def intercept_service(  # type: ignore[override]
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails
    ) -> grpc.RpcMethodHandler:
        orig = await continuation(handler_call_details)
        if orig is None:
            return orig

        service, method = _parse_method(handler_call_details.method)
        kind = _grpc_type(orig)

        if not orig.request_streaming and not orig.response_streaming:
            async def new_unary_unary(request, context):
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    _observe_req(request, service, method, kind)
                    resp = await orig.unary_unary(request, context)
                    _observe_resp(resp, service, method, kind)
                    return resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.aio.unary_unary_rpc_method_handler(
                new_unary_unary,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        if not orig.request_streaming and orig.response_streaming:
            async def new_unary_stream(request, context) -> AsyncIterator[Any]:
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    _observe_req(request, service, method, kind)
                    async for resp in orig.unary_stream(request, context):
                        _observe_resp(resp, service, method, kind)
                        yield resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.aio.unary_stream_rpc_method_handler(
                new_unary_stream,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        if orig.request_streaming and not orig.response_streaming:
            async def wrapped_req_aiter(aiter: AsyncIterator[Any]) -> AsyncIterator[Any]:
                async for msg in aiter:
                    _observe_req(msg, service, method, kind)
                    yield msg

            async def new_stream_unary(request_iterator, context):
                RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
                RPC_IN_PROGRESS.labels(service, method, kind).inc()
                t0 = time.perf_counter()
                code = "OK"
                try:
                    resp = await orig.stream_unary(wrapped_req_aiter(request_iterator), context)
                    _observe_resp(resp, service, method, kind)
                    return resp
                except BaseException as e:
                    code = _status_code_from_exc(e)
                    raise
                finally:
                    dt = time.perf_counter() - t0
                    RPC_IN_PROGRESS.labels(service, method, kind).dec()
                    RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                    RPC_LATENCY.labels(service, method, kind, code).observe(dt)
            return grpc.aio.stream_unary_rpc_method_handler(
                new_stream_unary,
                request_deserializer=orig.request_deserializer,
                response_serializer=orig.response_serializer,
            )

        async def wrapped_req_aiter(aiter: AsyncIterator[Any]) -> AsyncIterator[Any]:
            async for msg in aiter:
                _observe_req(msg, service, method, kind)
                yield msg

        async def new_stream_stream(request_iterator, context) -> AsyncIterator[Any]:
            RPC_REQUESTS_TOTAL.labels(service, method, kind).inc()
            RPC_IN_PROGRESS.labels(service, method, kind).inc()
            t0 = time.perf_counter()
            code = "OK"
            try:
                async for resp in orig.stream_stream(wrapped_req_aiter(request_iterator), context):
                    _observe_resp(resp, service, method, kind)
                    yield resp
            except BaseException as e:
                code = _status_code_from_exc(e)
                raise
            finally:
                dt = time.perf_counter() - t0
                RPC_IN_PROGRESS.labels(service, method, kind).dec()
                RPC_HANDLED_TOTAL.labels(service, method, kind, code).inc()
                RPC_LATENCY.labels(service, method, kind, code).observe(dt)

        return grpc.aio.stream_stream_rpc_method_handler(
            new_stream_stream,
            request_deserializer=orig.request_deserializer,
            response_serializer=orig.response_serializer,
        )
