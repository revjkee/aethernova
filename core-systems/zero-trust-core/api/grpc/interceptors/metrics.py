# zero-trust-core/api/grpc/interceptors/metrics.py
# Industrial-grade gRPC metrics interceptors (grpc.aio and sync grpc).
# - Prometheus counters/histograms/gauges with safe label sets
# - Stream message counters (recv/sent)
# - Request/response size histograms (best-effort)
# - Deadline histogram (from HandlerCallDetails.timeout, if present)
# - Exemplars with OpenTelemetry trace_id when available
# - Tenant label extraction from metadata (configurable)
#
# Dependencies:
#   - grpcio (and optionally grpcio-reflection)
#   - For asyncio servers: grpcio>=1.32 with grpc.aio
#   - prometheus_client (optional; otherwise no-op)
#   - opentelemetry-api (optional; for exemplars)
#
# Usage (async):
#   server = grpc.aio.server(interceptors=[AioMetricsInterceptor()])
# Usage (sync):
#   server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[SyncMetricsInterceptor()])
#
from __future__ import annotations

import time
import typing as _t
from dataclasses import dataclass

try:
    import grpc
except Exception as _e:  # pragma: no cover
    raise RuntimeError("grpc package is required for metrics interceptor") from _e

# Optional: prometheus client
try:  # pragma: no cover - import-time optional
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, REGISTRY, start_http_server
    _PROM = True
except Exception:
    Counter = Histogram = Gauge = object  # type: ignore
    CollectorRegistry = object  # type: ignore
    REGISTRY = None  # type: ignore
    start_http_server = None  # type: ignore
    _PROM = False

# Optional: OpenTelemetry trace context for exemplars
try:  # pragma: no cover - optional
    from opentelemetry import trace as _otel_trace
    _OTEL = True
except Exception:
    _OTEL = False

_LabelDict = _t.Dict[str, str]

# ------------------------------
# Helpers
# ------------------------------

def _split_full_method(full_method: str) -> _t.Tuple[str, str]:
    # full_method: "/package.Service/Method"
    try:
        _, service, method = full_method.split("/", 2)
    except ValueError:
        return ("unknown", "unknown")
    return (service, method)

def _grpc_type_name(handler: _t.Any) -> str:
    # grpc.RpcMethodHandler has attributes: request_streaming, response_streaming
    try:
        if handler.request_streaming and handler.response_streaming:
            return "bidi_stream"
        if handler.request_streaming and not handler.response_streaming:
            return "stream_unary"
        if not handler.request_streaming and handler.response_streaming:
            return "unary_stream"
        return "unary_unary"
    except Exception:
        return "unknown"

def _status_code_name(code: _t.Any) -> str:
    try:
        return code.name
    except Exception:
        return "UNKNOWN"

def _best_effort_size(msg: _t.Any) -> int:
    # Avoid heavy reflection; try protobuf-like interface
    try:
        return len(msg.SerializeToString())  # type: ignore[attr-defined]
    except Exception:
        return 0

def _now() -> float:
    return time.time()

def _get_tenant_from_metadata(md: _t.Optional[_t.Iterable[_t.Tuple[str, str]]], *, tenant_keys: _t.Tuple[str, ...]) -> str:
    if not md:
        return "unknown"
    low_keys = {k.lower(): v for k, v in md}
    for k in tenant_keys:
        v = low_keys.get(k)
        if v:
            # clamp length to prevent high cardinality explosions
            return v[:64]
    return "unknown"

def _otel_exemplar() -> _t.Optional[dict]:
    if not _OTEL:
        return None
    try:
        span = _otel_trace.get_current_span()
        sc = span.get_span_context()
        if not sc.is_valid:
            return None
        # hex trace id
        return {"trace_id": f"{sc.trace_id:032x}"}
    except Exception:
        return None

# ------------------------------
# Metrics registry abstraction
# ------------------------------

@dataclass
class MetricsConfig:
    registry: _t.Optional[CollectorRegistry] = None  # Prometheus registry
    service_label: str = "grpc_server"
    buckets_seconds: _t.Tuple[float, ...] = (0.001, 0.005, 0.01, 0.025, 0.05,
                                             0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0)
    buckets_bytes: _t.Tuple[float, ...] = tuple(2 ** p for p in range(5, 21))  # 32 .. 1MiB
    buckets_deadline: _t.Tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300)
    tenant_metadata_keys: _t.Tuple[str, ...] = ("tenant", "x-tenant", "x-org", "x-ztc-tenant")
    enable_exemplars: bool = True

class _NoopMetric:
    def labels(self, *_, **__):  # pragma: no cover
        return self
    def inc(self, *_args, **_kwargs):  # pragma: no cover
        pass
    def dec(self, *_args, **_kwargs):  # pragma: no cover
        pass
    def observe(self, *_args, **_kwargs):  # pragma: no cover
        pass
    def set(self, *_args, **_kwargs):  # pragma: no cover
        pass

class Metrics:
    def __init__(self, cfg: MetricsConfig = MetricsConfig()):
        self.cfg = cfg
        if not _PROM:
            # No prometheus client — make no-op metrics
            self.requests_total = _NoopMetric()
            self.in_progress = _NoopMetric()
            self.handling_seconds = _NoopMetric()
            self.deadline_seconds = _NoopMetric()
            self.recv_msg_total = _NoopMetric()
            self.sent_msg_total = _NoopMetric()
            self.request_bytes = _NoopMetric()
            self.response_bytes = _NoopMetric()
            return

        reg = cfg.registry or REGISTRY

        # Counters / Gauges / Histograms
        self.requests_total = Counter(
            "ztc_grpc_server_requests_total",
            "Total number of RPCs by code.",
            labelnames=("grpc_service", "grpc_method", "grpc_type", "code", "tenant"),
            registry=reg,
        )
        self.in_progress = Gauge(
            "ztc_grpc_server_requests_in_progress",
            "Number of RPCs currently in progress.",
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.handling_seconds = Histogram(
            "ztc_grpc_server_handling_seconds",
            "RPC handling latency in seconds.",
            buckets=cfg.buckets_seconds,
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.deadline_seconds = Histogram(
            "ztc_grpc_server_deadline_seconds",
            "Requested RPC deadline in seconds.",
            buckets=cfg.buckets_deadline,
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.recv_msg_total = Counter(
            "ztc_grpc_server_stream_messages_received_total",
            "Stream messages received (server).",
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.sent_msg_total = Counter(
            "ztc_grpc_server_stream_messages_sent_total",
            "Stream messages sent (server).",
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.request_bytes = Histogram(
            "ztc_grpc_server_request_bytes",
            "Best-effort request size (bytes).",
            buckets=cfg.buckets_bytes,
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )
        self.response_bytes = Histogram(
            "ztc_grpc_server_response_bytes",
            "Best-effort response size (bytes).",
            buckets=cfg.buckets_bytes,
            labelnames=("grpc_service", "grpc_method", "grpc_type", "tenant"),
            registry=reg,
        )

    # convenience exemplar injection
    def _ex(self):
        if not self.cfg.enable_exemplars:
            return None
        return _otel_exemplar()

# ------------------------------
# Asyncio interceptor
# ------------------------------

class AioMetricsInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, metrics: Metrics | None = None, cfg: MetricsConfig | None = None):
        self.metrics = metrics or Metrics(cfg or MetricsConfig())

    async def intercept_service(self, continuation, handler_call_details: grpc.HandlerCallDetails):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_full_method(handler_call_details.method)
        grpc_type = _grpc_type_name(handler)
        tenant = _get_tenant_from_metadata(handler_call_details.invocation_metadata,
                                           tenant_keys=self.metrics.cfg.tenant_metadata_keys)

        # Deadline from details.timeout (seconds)
        try:
            timeout = float(handler_call_details.timeout) if handler_call_details.timeout is not None else None  # type: ignore[attr-defined]
        except Exception:
            timeout = None
        if timeout is not None:
            self.metrics.deadline_seconds.labels(service, method, grpc_type, tenant).observe(timeout, exemplar=self.metrics._ex())

        # Wrap per type
        if handler.request_streaming and handler.response_streaming:
            return grpc.aio.RpcMethodHandler(
                request_streaming=True,
                response_streaming=True,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
                unary_unary=None,
                unary_stream=None,
                stream_unary=self._wrap_aio_stream_unary(handler.stream_unary, service, method, grpc_type, tenant),
                stream_stream=self._wrap_aio_stream_stream(handler.stream_stream, service, method, grpc_type, tenant),
            )
        if handler.request_streaming and not handler.response_streaming:
            return grpc.aio.RpcMethodHandler(
                request_streaming=True,
                response_streaming=False,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
                unary_unary=None,
                unary_stream=None,
                stream_unary=self._wrap_aio_stream_unary(handler.stream_unary, service, method, grpc_type, tenant),
                stream_stream=None,
            )
        if not handler.request_streaming and handler.response_streaming:
            return grpc.aio.RpcMethodHandler(
                request_streaming=False,
                response_streaming=True,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
                unary_unary=None,
                unary_stream=self._wrap_aio_unary_stream(handler.unary_stream, service, method, grpc_type, tenant),
                stream_unary=None,
                stream_stream=None,
            )
        # unary-unary
        return grpc.aio.RpcMethodHandler(
            request_streaming=False,
            response_streaming=False,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
            unary_unary=self._wrap_aio_unary_unary(handler.unary_unary, service, method, grpc_type, tenant),
            unary_stream=None,
            stream_unary=None,
            stream_stream=None,
        )

    # --- wrappers (aio) ---

    def _wrap_aio_unary_unary(self, inner, service, method, grpc_type, tenant):
        async def _handler(request, context: grpc.aio.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            if request is not None:
                self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(request), exemplar=ex)
            code = grpc.StatusCode.OK
            try:
                response = await inner(request, context)
                if response is not None:
                    self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(response), exemplar=ex)
                return response
            except grpc.RpcError as e:
                code = e.code() or grpc.StatusCode.UNKNOWN
                raise
            except Exception:
                code = grpc.StatusCode.UNKNOWN
                raise
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                # Prefer context.code() if set by handler
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_aio_unary_stream(self, inner, service, method, grpc_type, tenant):
        async def _handler(request, context: grpc.aio.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            if request is not None:
                self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(request), exemplar=ex)
            code = grpc.StatusCode.OK

            async def _gen():
                nonlocal code
                try:
                    async for resp in inner(request, context):
                        if resp is not None:
                            self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(resp), exemplar=ex)
                        self.metrics.sent_msg_total.labels(*labels).inc(exemplar=ex)
                        yield resp
                except grpc.RpcError as e:
                    code = e.code() or grpc.StatusCode.UNKNOWN
                    raise
                except Exception:
                    code = grpc.StatusCode.UNKNOWN
                    raise

            try:
                async for item in _gen():
                    yield item
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_aio_stream_unary(self, inner, service, method, grpc_type, tenant):
        async def _handler(request_iter, context: grpc.aio.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            code = grpc.StatusCode.OK

            async def _req_iter():
                nonlocal labels
                async for req in request_iter:
                    if req is not None:
                        self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(req), exemplar=ex)
                    self.metrics.recv_msg_total.labels(*labels).inc(exemplar=ex)
                    yield req

            try:
                response = await inner(_req_iter(), context)
                if response is not None:
                    self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(response), exemplar=ex)
                return response
            except grpc.RpcError as e:
                code = e.code() or grpc.StatusCode.UNKNOWN
                raise
            except Exception:
                code = grpc.StatusCode.UNKNOWN
                raise
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_aio_stream_stream(self, inner, service, method, grpc_type, tenant):
        async def _handler(request_iter, context: grpc.aio.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            code = grpc.StatusCode.OK

            async def _req_iter():
                async for req in request_iter:
                    if req is not None:
                        self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(req), exemplar=ex)
                    self.metrics.recv_msg_total.labels(*labels).inc(exemplar=ex)
                    yield req

            async def _resp_gen():
                nonlocal code
                try:
                    async for resp in inner(_req_iter(), context):
                        if resp is not None:
                            self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(resp), exemplar=ex)
                        self.metrics.sent_msg_total.labels(*labels).inc(exemplar=ex)
                        yield resp
                except grpc.RpcError as e:
                    code = e.code() or grpc.StatusCode.UNKNOWN
                    raise
                except Exception:
                    code = grpc.StatusCode.UNKNOWN
                    raise

            try:
                async for item in _resp_gen():
                    yield item
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

# ------------------------------
# Sync interceptor
# ------------------------------

class SyncMetricsInterceptor(grpc.ServerInterceptor):
    def __init__(self, metrics: Metrics | None = None, cfg: MetricsConfig | None = None):
        self.metrics = metrics or Metrics(cfg or MetricsConfig())

    def intercept_service(self, continuation, handler_call_details: grpc.HandlerCallDetails):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_full_method(handler_call_details.method)
        grpc_type = _grpc_type_name(handler)
        tenant = _get_tenant_from_metadata(handler_call_details.invocation_metadata,
                                           tenant_keys=self.metrics.cfg.tenant_metadata_keys)

        # Deadline from details.timeout (seconds)
        try:
            timeout = float(handler_call_details.timeout) if handler_call_details.timeout is not None else None  # type: ignore[attr-defined]
        except Exception:
            timeout = None
        if timeout is not None:
            self.metrics.deadline_seconds.labels(service, method, grpc_type, tenant).observe(timeout, exemplar=self.metrics._ex())

        # Wrap based on type
        if handler.request_streaming and handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                service, {
                    method: grpc.stream_stream_rpc_method_handler(
                        self._wrap_sync_stream_stream(handler.stream_stream, service, method, grpc_type, tenant),
                        request_deserializer=handler.request_deserializer,
                        response_serializer=handler.response_serializer
                    )
                }
            )._method_handlers[method]  # type: ignore[attr-defined]
        if handler.request_streaming and not handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                service, {
                    method: grpc.stream_unary_rpc_method_handler(
                        self._wrap_sync_stream_unary(handler.stream_unary, service, method, grpc_type, tenant),
                        request_deserializer=handler.request_deserializer,
                        response_serializer=handler.response_serializer
                    )
                }
            )._method_handlers[method]  # type: ignore[attr-defined]
        if not handler.request_streaming and handler.response_streaming:
            return grpc.method_handlers_generic_handler(
                service, {
                    method: grpc.unary_stream_rpc_method_handler(
                        self._wrap_sync_unary_stream(handler.unary_stream, service, method, grpc_type, tenant),
                        request_deserializer=handler.request_deserializer,
                        response_serializer=handler.response_serializer
                    )
                }
            )._method_handlers[method]  # type: ignore[attr-defined]
        # unary-unary
        return grpc.method_handlers_generic_handler(
            service, {
                method: grpc.unary_unary_rpc_method_handler(
                    self._wrap_sync_unary_unary(handler.unary_unary, service, method, grpc_type, tenant),
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer
                )
            }
        )._method_handlers[method]  # type: ignore[attr-defined]

    # --- wrappers (sync) ---

    def _wrap_sync_unary_unary(self, inner, service, method, grpc_type, tenant):
        def _handler(request, context: grpc.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            if request is not None:
                self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(request), exemplar=ex)
            code = grpc.StatusCode.OK
            try:
                response = inner(request, context)
                if response is not None:
                    self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(response), exemplar=ex)
                return response
            except grpc.RpcError as e:
                code = e.code() or grpc.StatusCode.UNKNOWN
                raise
            except Exception:
                code = grpc.StatusCode.UNKNOWN
                raise
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_sync_unary_stream(self, inner, service, method, grpc_type, tenant):
        def _handler(request, context: grpc.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            if request is not None:
                self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(request), exemplar=ex)
            code = grpc.StatusCode.OK

            def _gen():
                nonlocal code
                try:
                    for resp in inner(request, context):
                        if resp is not None:
                            self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(resp), exemplar=ex)
                        self.metrics.sent_msg_total.labels(*labels).inc(exemplar=ex)
                        yield resp
                except grpc.RpcError as e:
                    code = e.code() or grpc.StatusCode.UNKNOWN
                    raise
                except Exception:
                    code = grpc.StatusCode.UNKNOWN
                    raise

            try:
                for item in _gen():
                    yield item
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_sync_stream_unary(self, inner, service, method, grpc_type, tenant):
        def _handler(request_iter, context: grpc.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            code = grpc.StatusCode.OK

            def _req_iter():
                for req in request_iter:
                    if req is not None:
                        self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(req), exemplar=ex)
                    self.metrics.recv_msg_total.labels(*labels).inc(exemplar=ex)
                    yield req

            try:
                response = inner(_req_iter(), context)
                if response is not None:
                    self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(response), exemplar=ex)
                return response
            except grpc.RpcError as e:
                code = e.code() or grpc.StatusCode.UNKNOWN
                raise
            except Exception:
                code = grpc.StatusCode.UNKNOWN
                raise
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

    def _wrap_sync_stream_stream(self, inner, service, method, grpc_type, tenant):
        def _handler(request_iter, context: grpc.ServicerContext):
            labels = (service, method, grpc_type, tenant)
            ex = self.metrics._ex()
            self.metrics.in_progress.labels(*labels).inc()
            start = _now()
            code = grpc.StatusCode.OK

            def _req_iter():
                for req in request_iter:
                    if req is not None:
                        self.metrics.request_bytes.labels(*labels).observe(_best_effort_size(req), exemplar=ex)
                    self.metrics.recv_msg_total.labels(*labels).inc(exemplar=ex)
                    yield req

            def _resp_gen():
                nonlocal code
                try:
                    for resp in inner(_req_iter(), context):
                        if resp is not None:
                            self.metrics.response_bytes.labels(*labels).observe(_best_effort_size(resp), exemplar=ex)
                        self.metrics.sent_msg_total.labels(*labels).inc(exemplar=ex)
                        yield resp
                except grpc.RpcError as e:
                    code = e.code() or grpc.StatusCode.UNKNOWN
                    raise
                except Exception:
                    code = grpc.StatusCode.UNKNOWN
                    raise

            try:
                for item in _resp_gen():
                    yield item
            finally:
                self.metrics.in_progress.labels(*labels).dec()
                dur = max(0.0, _now() - start)
                self.metrics.handling_seconds.labels(*labels).observe(dur, exemplar=ex)
                try:
                    code = context.code() or code
                except Exception:
                    pass
                self.metrics.requests_total.labels(service, method, grpc_type, _status_code_name(code), tenant).inc(exemplar=ex)
        return _handler

# ------------------------------
# Optional Prometheus HTTP exporter helper
# ------------------------------

def start_prometheus_http_server(port: int = 9095, addr: str = "0.0.0.0", registry: _t.Optional[CollectorRegistry] = None) -> None:
    """
    Запускает HTTP-эндпоинт для Prometheus (если prometheus_client установлен).
    Безопасность вынесите на уровень ingress/sidecar.
    """
    if not _PROM or start_http_server is None:  # pragma: no cover
        return
    start_http_server(port, addr=addr, registry=registry)

__all__ = [
    "MetricsConfig",
    "Metrics",
    "AioMetricsInterceptor",
    "SyncMetricsInterceptor",
    "start_prometheus_http_server",
]
