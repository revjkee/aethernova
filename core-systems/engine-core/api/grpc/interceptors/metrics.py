from __future__ import annotations

import os
import time
import typing as t
import contextvars
from dataclasses import dataclass

import grpc
from grpc import StatusCode
from grpc.aio import ServerInterceptor, ServicerContext

# ======== Опциональные бэкенды телеметрии (Prometheus / OpenTelemetry) ========

_ENABLE_PROM = os.getenv("METRICS_PROMETHEUS", "true").lower() == "true"
_ENABLE_OTEL = os.getenv("METRICS_OTEL", "false").lower() == "true"

# Конфигурация гистограмм
_LATENCY_BUCKETS = os.getenv(
    "METRICS_LATENCY_BUCKETS",
    # секунды: сверхширокие, подходят для p99 в сетях/ХД
    "0.001,0.002,0.005,0.01,0.02,0.05,0.1,0.2,0.5,1,2,5,10"
)
_SIZE_BUCKETS = os.getenv(
    "METRICS_SIZE_BUCKETS",
    # байты
    "0,128,256,512,1024,4096,16384,65536,262144,1048576,4194304"
)

def _parse_buckets(s: str) -> t.List[float]:
    out: t.List[float] = []
    for x in s.split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.append(float(x))
        except ValueError:
            continue
    out.sort()
    return out

LATENCY_BUCKETS = _parse_buckets(_LATENCY_BUCKETS)
SIZE_BUCKETS = _parse_buckets(_SIZE_BUCKETS)

# ======== Prometheus (если доступен) ========
_prom = None
if _ENABLE_PROM:
    try:
        from prometheus_client import Counter, Gauge, Histogram
        class _Prom:
            def __init__(self):
                common = dict(
                    labelnames=["service", "method", "grpc_type", "code"],
                    namespace="grpc",
                    subsystem="server",
                )
                self.requests = Counter(
                    "requests_total", "Total gRPC requests", ["service", "method", "grpc_type"],
                    namespace="grpc", subsystem="server"
                )
                self.in_flight = Gauge(
                    "in_flight", "In-flight gRPC requests", ["service", "method", "grpc_type"],
                    namespace="grpc", subsystem="server"
                )
                self.handling_seconds = Histogram(
                    "handling_seconds", "Server handling time (s)", ["service", "method", "grpc_type", "code"],
                    buckets=LATENCY_BUCKETS, namespace="grpc", subsystem="server"
                )
                self.req_bytes = Histogram(
                    "request_bytes", "Request size (bytes)", ["service", "method", "grpc_type"],
                    buckets=SIZE_BUCKETS, namespace="grpc", subsystem="server"
                )
                self.resp_bytes = Histogram(
                    "response_bytes", "Response size (bytes)", ["service", "method", "grpc_type", "code"],
                    buckets=SIZE_BUCKETS, namespace="grpc", subsystem="server"
                )
                self.stream_recv = Counter(
                    "stream_messages_received_total", "Streaming messages received", ["service", "method", "grpc_type"],
                    namespace="grpc", subsystem="server"
                )
                self.stream_sent = Counter(
                    "stream_messages_sent_total", "Streaming messages sent", ["service", "method", "grpc_type"],
                    namespace="grpc", subsystem="server"
                )
        _prom = _Prom()
    except Exception:
        _prom = None

# ======== OpenTelemetry (если доступен) ========
_otel = None
if _ENABLE_OTEL:
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.metrics import Observation
        class _Otel:
            def __init__(self):
                mp = metrics.get_meter_provider().get_meter("engine-core.grpc.server")
                self.m_requests = mp.create_counter(
                    "grpc.server.requests",
                    description="Total gRPC requests",
                    unit="{request}",
                )
                self.m_inflight = mp.create_up_down_counter(
                    "grpc.server.in_flight",
                    description="In-flight gRPC requests",
                    unit="{request}",
                )
                self.m_handling = mp.create_histogram(
                    "grpc.server.handling.seconds",
                    description="Server handling time",
                    unit="s",
                )
                self.m_req_bytes = mp.create_histogram(
                    "grpc.server.request.size",
                    description="Request message size",
                    unit="By",
                )
                self.m_resp_bytes = mp.create_histogram(
                    "grpc.server.response.size",
                    description="Response message size",
                    unit="By",
                )
                self.m_stream_recv = mp.create_counter(
                    "grpc.server.stream.messages.received",
                    description="Streaming messages received",
                    unit="{message}",
                )
                self.m_stream_sent = mp.create_counter(
                    "grpc.server.stream.messages.sent",
                    description="Streaming messages sent",
                    unit="{message}",
                )
                self.tracer = trace.get_tracer(__name__)
        _otel = _Otel()
    except Exception:
        _otel = None

# ======== Общие утилиты ========

def _split_method(full: str) -> tuple[str, str]:
    # "/package.Service/Method" -> ("package.Service", "Method")
    if not full or not full.startswith("/"):
        return "", ""
    p = full[1:].split("/", 1)
    if len(p) != 2:
        return "", ""
    return p[0], p[1]

def _grpc_type_name(handler: grpc.RpcMethodHandler) -> str:
    if handler.unary_unary:
        return "unary_unary"
    if handler.unary_stream:
        return "unary_stream"
    if handler.stream_unary:
        return "stream_unary"
    if handler.stream_stream:
        return "stream_stream"
    return "unknown"

def _status_code_name(code: StatusCode | int | None) -> str:
    try:
        if isinstance(code, StatusCode):
            return code.name
        if isinstance(code, int):
            return StatusCode(code).name
    except Exception:
        pass
    return "UNKNOWN"

def _size_of_message(msg: t.Any) -> int | None:
    # Избегаем копий: у protobuf message есть SerializeToString()
    try:
        if hasattr(msg, "SerializeToString"):
            return len(msg.SerializeToString(deterministic=True))
        # pydantic/dataclass — не считаем
        return None
    except Exception:
        return None

# Для корреляции с трассировкой в exemplars/attrs
trace_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id_ctx", default=None)

def _current_trace_id() -> str | None:
    # OpenTelemetry API (если доступен)
    try:
        from opentelemetry import trace as _tr
        span = _tr.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return None

# ======== Интерсептор метрик ========

@dataclass
class _Labels:
    service: str
    method: str
    grpc_type: str

class MetricsInterceptor(ServerInterceptor):
    """
    Интерсептор собирает метрики для всех типов RPC.
    Любые ошибки телеметрии игнорируются (fail-open).
    """

    def __init__(self) -> None:
        self._prom = _prom
        self._otel = _otel

    async def intercept_service(
        self,
        continuation: t.Callable[[grpc.HandlerCallDetails], t.Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        svc, mth = _split_method(handler_call_details.method)
        gtype = _grpc_type_name(handler)
        labels = _Labels(service=svc or "unknown", method=mth or "unknown", grpc_type=gtype)

        # Обёртка для каждого типа
        if handler.unary_unary:
            inner = handler.unary_unary
            async def uu(request, ctx: ServicerContext):
                return await self._measure_unary_unary(labels, inner, request, ctx)
            return grpc.unary_unary_rpc_method_handler(
                uu,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream
            async def us(request, ctx: ServicerContext):
                async for resp in self._measure_unary_stream(labels, inner, request, ctx):
                    yield resp
            return grpc.unary_stream_rpc_method_handler(
                us,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            inner = handler.stream_unary
            async def su(request_iter, ctx: ServicerContext):
                return await self._measure_stream_unary(labels, inner, request_iter, ctx)
            return grpc.stream_unary_rpc_method_handler(
                su,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            inner = handler.stream_stream
            async def ss(request_iter, ctx: ServicerContext):
                async for resp in self._measure_stream_stream(labels, inner, request_iter, ctx):
                    yield resp
            return grpc.stream_stream_rpc_method_handler(
                ss,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # fallback
        return handler

    # ======== Реализации измерений по типам RPC ========

    async def _measure_unary_unary(self, l: _Labels, inner, request, ctx: ServicerContext):
        req_sz = _size_of_message(request)
        self._on_start(l, req_size=req_sz)
        t0 = time.perf_counter_ns()
        code = StatusCode.OK
        try:
            resp = await inner(request, ctx)
            return resp
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        except Exception:
            code = StatusCode.UNKNOWN
            raise
        finally:
            dur_s = (time.perf_counter_ns() - t0) / 1e9
            resp_sz = None
            try:
                # Попытка оценить размер ответа (может быть None в случае исключения)
                if "resp" in locals():
                    resp_sz = _size_of_message(resp)
            except Exception:
                resp_sz = None
            self._on_finish(l, code, dur_s, resp_size=resp_sz)

    async def _measure_unary_stream(self, l: _Labels, inner, request, ctx: ServicerContext):
        req_sz = _size_of_message(request)
        self._on_start(l, req_size=req_sz, streaming=True)
        t0 = time.perf_counter_ns()
        code = StatusCode.OK
        sent = 0
        try:
            async for resp in inner(request, ctx):
                sent += 1
                self._on_stream_send(l)
                yield resp
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        except Exception:
            code = StatusCode.UNKNOWN
            raise
        finally:
            dur_s = (time.perf_counter_ns() - t0) / 1e9
            resp_sz = None
            try:
                if "resp" in locals():
                    resp_sz = _size_of_message(resp)
            except Exception:
                resp_sz = None
            self._on_finish(l, code, dur_s, resp_size=resp_sz)

    async def _measure_stream_unary(self, l: _Labels, inner, request_iter, ctx: ServicerContext):
        self._on_start(l, streaming=True)
        t0 = time.perf_counter_ns()
        code = StatusCode.OK
        # Оборачиваем итератор, чтобы считать входящие сообщения
        async def counting_iter():
            async for req in request_iter:
                self._on_stream_recv(l)
                yield req
        try:
            resp = await inner(counting_iter(), ctx)
            return resp
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        except Exception:
            code = StatusCode.UNKNOWN
            raise
        finally:
            dur_s = (time.perf_counter_ns() - t0) / 1e9
            resp_sz = None
            try:
                if "resp" in locals():
                    resp_sz = _size_of_message(resp)
            except Exception:
                resp_sz = None
            self._on_finish(l, code, dur_s, resp_size=resp_sz)

    async def _measure_stream_stream(self, l: _Labels, inner, request_iter, ctx: ServicerContext):
        self._on_start(l, streaming=True)
        t0 = time.perf_counter_ns()
        code = StatusCode.OK

        async def counting_iter():
            async for req in request_iter:
                self._on_stream_recv(l)
                yield req

        try:
            async for resp in inner(counting_iter(), ctx):
                self._on_stream_send(l)
                yield resp
        except grpc.RpcError as e:
            code = e.code() or StatusCode.UNKNOWN
            raise
        except Exception:
            code = StatusCode.UNKNOWN
            raise
        finally:
            dur_s = (time.perf_counter_ns() - t0) / 1e9
            resp_sz = None
            try:
                if "resp" in locals():
                    resp_sz = _size_of_message(resp)
            except Exception:
                resp_sz = None
            self._on_finish(l, code, dur_s, resp_size=resp_sz)

    # ======== Запись метрик ========

    def _on_start(self, l: _Labels, req_size: int | None = None, streaming: bool = False) -> None:
        trace_id = _current_trace_id()
        # Prometheus
        if self._prom:
            try:
                self._prom.requests.labels(l.service, l.method, l.grpc_type).inc()
                self._prom.in_flight.labels(l.service, l.method, l.grpc_type).inc()
                if req_size is not None:
                    self._prom.req_bytes.labels(l.service, l.method, l.grpc_type).observe(req_size)
                # streaming счётчики считаются на сообщениях
            except Exception:
                pass
        # OTEL
        if self._otel:
            try:
                attrs = {
                    "service": l.service,
                    "method": l.method,
                    "grpc.type": l.grpc_type,
                }
                self._otel.m_requests.add(1, attributes=attrs)
                self._otel.m_inflight.add(1, attributes=attrs)
                if req_size is not None:
                    self._otel.m_req_bytes.record(float(req_size), attributes=attrs)
            except Exception:
                pass
        # trace id в контекст (может пригодиться экспортёрам с exemplars)
        try:
            trace_id_ctx.set(trace_id)
        except Exception:
            pass

    def _on_stream_recv(self, l: _Labels) -> None:
        if self._prom:
            try:
                self._prom.stream_recv.labels(l.service, l.method, l.grpc_type).inc()
            except Exception:
                pass
        if self._otel:
            try:
                attrs = {"service": l.service, "method": l.method, "grpc.type": l.grpc_type}
                self._otel.m_stream_recv.add(1, attributes=attrs)
            except Exception:
                pass

    def _on_stream_send(self, l: _Labels) -> None:
        if self._prom:
            try:
                self._prom.stream_sent.labels(l.service, l.method, l.grpc_type).inc()
            except Exception:
                pass
        if self._otel:
            try:
                attrs = {"service": l.service, "method": l.method, "grpc.type": l.grpc_type}
                self._otel.m_stream_sent.add(1, attributes=attrs)
            except Exception:
                pass

    def _on_finish(self, l: _Labels, code: StatusCode, dur_s: float, resp_size: int | None = None) -> None:
        code_name = _status_code_name(code)
        if self._prom:
            try:
                self._prom.in_flight.labels(l.service, l.method, l.grpc_type).dec()
                self._prom.handling_seconds.labels(l.service, l.method, l.grpc_type, code_name).observe(dur_s)
                if resp_size is not None:
                    self._prom.resp_bytes.labels(l.service, l.method, l.grpc_type, code_name).observe(resp_size)
            except Exception:
                pass
        if self._otel:
            try:
                attrs = {
                    "service": l.service,
                    "method": l.method,
                    "grpc.type": l.grpc_type,
                    "grpc.code": code_name,
                }
                self._otel.m_inflight.add(-1, attributes={"service": l.service, "method": l.method, "grpc.type": l.grpc_type})
                self._otel.m_handling.record(dur_s, attributes=attrs)
                if resp_size is not None:
                    self._otel.m_resp_bytes.record(float(resp_size), attributes=attrs)
            except Exception:
                pass

# ======== Подключение к серверу ========
# from grpc.aio import server
# s = server(interceptors=[MetricsInterceptor()])
# ... add Servicers ...
# s.add_insecure_port("0.0.0.0:50051")  # или TLS
#
# Для Prometheus: запустите экспортер (например, prometheus_client.start_http_server(port))
# Для OpenTelemetry: настройте MeterProvider/Exporter (OTLP и т.д.)
