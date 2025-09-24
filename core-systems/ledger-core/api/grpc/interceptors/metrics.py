# ledger-core/api/grpc/interceptors/metrics.py
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, Iterator, Optional, Tuple, TypeVar

import grpc
from prometheus_client import Counter, Gauge, Histogram

# ===========================
# Конфиг/лейблы/бакеты
# ===========================

_DEFAULT_BUCKETS = (
    0.001, 0.0025, 0.005, 0.01,
    0.025, 0.05, 0.1, 0.25,
    0.5, 1.0, 2.5, 5.0, 10.0, 30.0
)

@dataclass(frozen=True)
class MetricsConfig:
    # Бакеты гистограммы латентности RPC в секундах
    latency_buckets: Tuple[float, ...] = _DEFAULT_BUCKETS
    # Включать детальный подсчёт байтов (возможен оверхед сериализации)
    count_bytes: bool = True
    # Префикс имён метрик
    prefix: str = "grpc_server"

# ===========================
# Регистрация метрик (singletons)
# ===========================

class _Registry:
    _initialized = False

    # Основные метрики
    RPC_LATENCY: Histogram
    RPC_STARTED: Counter
    RPC_HANDLED: Counter
    RPC_IN_FLIGHT: Gauge
    REQ_MESSAGES: Counter
    RESP_MESSAGES: Counter
    REQ_BYTES: Counter
    RESP_BYTES: Counter

    @classmethod
    def init(cls, cfg: MetricsConfig) -> None:
        if cls._initialized:
            return
        p = cfg.prefix

        cls.RPC_LATENCY = Histogram(
            f"{p}_handling_seconds",
            "gRPC server handling latency (seconds) per RPC",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
            buckets=cfg.latency_buckets,
        )
        cls.RPC_STARTED = Counter(
            f"{p}_started_total",
            "Total number of RPCs started on the server",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        cls.RPC_HANDLED = Counter(
            f"{p}_handled_total",
            "Total number of RPCs completed on the server, regardless of success or failure",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
        )
        cls.RPC_IN_FLIGHT = Gauge(
            f"{p}_in_flight",
            "Number of RPCs currently in-flight on the server",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        cls.REQ_MESSAGES = Counter(
            f"{p}_request_messages_total",
            "Total streaming/request messages received",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        cls.RESP_MESSAGES = Counter(
            f"{p}_response_messages_total",
            "Total streaming/response messages sent",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        cls.REQ_BYTES = Counter(
            f"{p}_request_bytes_total",
            "Total request payload bytes received",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        cls.RESP_BYTES = Counter(
            f"{p}_response_bytes_total",
            "Total response payload bytes sent",
            ["grpc_service", "grpc_method", "grpc_type"],
        )

        cls._initialized = True


# ===========================
# Вспомогательные утилиты
# ===========================

def _split_method(full_method: str) -> Tuple[str, str]:
    # формат: "/package.Service/Method"
    try:
        service, method = full_method.lstrip("/").split("/", 1)
        return service, method
    except ValueError:
        return "unknown", full_method or "unknown"

def _rpc_type(handler_call_details: grpc.HandlerCallDetails | Any, handler: Any) -> str:
    # Определяем тип RPC по хендлеру
    if hasattr(handler, "request_streaming") and hasattr(handler, "response_streaming"):
        rs, ss = handler.request_streaming, handler.response_streaming
    else:
        # aio server handler: has attributes as well
        rs = getattr(handler, "request_streaming", False)
        ss = getattr(handler, "response_streaming", False)

    if not rs and not ss:
        return "unary_unary"
    if not rs and ss:
        return "unary_stream"
    if rs and not ss:
        return "stream_unary"
    return "stream_stream"

def _code_from_exception(exc: BaseException) -> grpc.StatusCode:
    if isinstance(exc, grpc.RpcError):
        return exc.code() or grpc.StatusCode.UNKNOWN
    if isinstance(exc, asyncio.CancelledError):
        return grpc.StatusCode.CANCELLED
    return grpc.StatusCode.UNKNOWN

def _safe_len(obj: Any) -> int:
    try:
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return len(obj)
        # Пытаемся сериализовать в bytes, если proto сериализуемый
        if hasattr(obj, "ByteSize"):
            return int(obj.ByteSize())
        # Fallback: неточность возможна, но не бросаем
        return 0
    except Exception:
        return 0


# ===========================
# Sync server interceptor
# ===========================

_Handler = TypeVar("_Handler")

class PrometheusServerInterceptor(grpc.ServerInterceptor):
    """Sync gRPC серверный интерцептор Prometheus."""

    def __init__(self, cfg: Optional[MetricsConfig] = None) -> None:
        self.cfg = cfg or MetricsConfig()
        _Registry.init(self.cfg)

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], _Handler],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> _Handler:
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        service, method = _split_method(handler_call_details.method)
        rtype = _rpc_type(handler_call_details, handler)

        # Оборачиваем поведение для всех 4 типов RPC
        if rtype == "unary_unary":
            def unary_unary(req, ctx):
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    if self.cfg.count_bytes:
                        _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(req))
                    resp = handler.unary_unary(req, ctx)
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = code.name if isinstance(code, grpc.StatusCode) else str(code)
                    if ctx._state.code is not None:  # type: ignore[attr-defined]
                        code_s = ctx._state.code.name  # type: ignore[attr-defined]
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if rtype == "unary_stream":
            def unary_stream(req, ctx) -> Iterator[Any]:
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    if self.cfg.count_bytes:
                        _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(req))
                    for msg in handler.unary_stream(req, ctx):
                        _Registry.RESP_MESSAGES.labels(service, method, rtype).inc()
                        if self.cfg.count_bytes:
                            _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                        yield msg
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = ctx._state.code.name if ctx._state.code else code.name  # type: ignore[attr-defined]
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if rtype == "stream_unary":
            def stream_unary(req_iter, ctx):
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    # Оборачиваем итератор, чтобы считать сообщения/байты
                    def wrapped_iter():
                        for msg in req_iter:
                            _Registry.REQ_MESSAGES.labels(service, method, rtype).inc()
                            if self.cfg.count_bytes:
                                _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                            yield msg
                    resp = handler.stream_unary(wrapped_iter(), ctx)
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = ctx._state.code.name if ctx._state.code else code.name  # type: ignore[attr-defined]
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream_stream
        def stream_stream(req_iter, ctx):
            _Registry.RPC_STARTED.labels(service, method, rtype).inc()
            _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = grpc.StatusCode.OK
            try:
                def wrapped_iter():
                    for msg in req_iter:
                        _Registry.REQ_MESSAGES.labels(service, method, rtype).inc()
                        if self.cfg.count_bytes:
                            _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                        yield msg
                for resp in handler.stream_stream(wrapped_iter(), ctx):
                    _Registry.RESP_MESSAGES.labels(service, method, rtype).inc()
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    yield resp
            except BaseException as e:
                code = _code_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                code_s = ctx._state.code.name if ctx._state.code else code.name  # type: ignore[attr-defined]
                _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
        return grpc.stream_stream_rpc_method_handler(
            stream_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

# ===========================
# Async server interceptor (grpc.aio)
# ===========================

class AioPrometheusServerInterceptor(grpc.aio.ServerInterceptor):
    """Async gRPC серверный интерцептор Prometheus."""

    def __init__(self, cfg: Optional[MetricsConfig] = None) -> None:
        self.cfg = cfg or MetricsConfig(prefix="grpc_server")  # общий префикс
        _Registry.init(self.cfg)

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[Any]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> Any:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        service, method = _split_method(handler_call_details.method)
        rtype = _rpc_type(handler_call_details, handler)

        if rtype == "unary_unary":
            async def unary_unary(req, ctx):
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    if self.cfg.count_bytes:
                        _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(req))
                    resp = await handler.unary_unary(req, ctx)
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = (await ctx.code()).name if await ctx.code() else code.name  # type: ignore
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.aio.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if rtype == "unary_stream":
            async def unary_stream(req, ctx) -> AsyncIterator[Any]:
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    if self.cfg.count_bytes:
                        _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(req))
                    async for msg in handler.unary_stream(req, ctx):
                        _Registry.RESP_MESSAGES.labels(service, method, rtype).inc()
                        if self.cfg.count_bytes:
                            _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                        yield msg
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = (await ctx.code()).name if await ctx.code() else code.name  # type: ignore
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.aio.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if rtype == "stream_unary":
            async def stream_unary(req_iter, ctx):
                _Registry.RPC_STARTED.labels(service, method, rtype).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
                start = time.perf_counter()
                code = grpc.StatusCode.OK
                try:
                    async def wrapped():
                        async for msg in req_iter:
                            _Registry.REQ_MESSAGES.labels(service, method, rtype).inc()
                            if self.cfg.count_bytes:
                                _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                            yield msg
                    resp = await handler.stream_unary(wrapped(), ctx)
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    return resp
                except BaseException as e:
                    code = _code_from_exception(e)
                    raise
                finally:
                    elapsed = time.perf_counter() - start
                    code_s = (await ctx.code()).name if await ctx.code() else code.name  # type: ignore
                    _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                    _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                    _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
            return grpc.aio.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        async def stream_stream(req_iter, ctx):
            _Registry.RPC_STARTED.labels(service, method, rtype).inc()
            _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).inc()
            start = time.perf_counter()
            code = grpc.StatusCode.OK
            try:
                async def wrapped():
                    async for msg in req_iter:
                        _Registry.REQ_MESSAGES.labels(service, method, rtype).inc()
                        if self.cfg.count_bytes:
                            _Registry.REQ_BYTES.labels(service, method, rtype).inc(_safe_len(msg))
                        yield msg
                async for resp in handler.stream_stream(wrapped(), ctx):
                    _Registry.RESP_MESSAGES.labels(service, method, rtype).inc()
                    if self.cfg.count_bytes:
                        _Registry.RESP_BYTES.labels(service, method, rtype).inc(_safe_len(resp))
                    yield resp
            except BaseException as e:
                code = _code_from_exception(e)
                raise
            finally:
                elapsed = time.perf_counter() - start
                code_s = (await ctx.code()).name if await ctx.code() else code.name  # type: ignore
                _Registry.RPC_LATENCY.labels(service, method, rtype, code_s).observe(elapsed)
                _Registry.RPC_HANDLED.labels(service, method, rtype, code_s).inc()
                _Registry.RPC_IN_FLIGHT.labels(service, method, rtype).dec()
        return grpc.aio.stream_stream_rpc_method_handler(
            stream_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

# ===========================
# (Опционально) клиентский интерцептор
# ===========================

class PrometheusClientInterceptor(grpc.UnaryUnaryClientInterceptor,
                                  grpc.UnaryStreamClientInterceptor,
                                  grpc.StreamUnaryClientInterceptor,
                                  grpc.StreamStreamClientInterceptor):
    """gRPC клиентский интерцептор Prometheus (sync). Полезно для outbound‑зависимостей."""
    def __init__(self, prefix: str = "grpc_client", latency_buckets: Tuple[float, ...] = _DEFAULT_BUCKETS, count_bytes: bool = True) -> None:
        self.cfg = MetricsConfig(latency_buckets=latency_buckets, count_bytes=count_bytes, prefix=prefix)
        # Инициализируем отдельный набор клиентских метрик (с другим префиксом)
        _Registry.init(MetricsConfig())  # серверные уже доступны; клиент создаёт свои локальные через свои имена
        self._latency = Histogram(
            f"{prefix}_handling_seconds",
            "gRPC client handling latency (seconds) per RPC",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
            buckets=latency_buckets,
        )
        self._started = Counter(
            f"{prefix}_started_total",
            "Total number of RPCs started by the client",
            ["grpc_service", "grpc_method", "grpc_type"],
        )
        self._handled = Counter(
            f"{prefix}_handled_total",
            "Total number of RPCs completed by the client",
            ["grpc_service", "grpc_method", "grpc_type", "grpc_code"],
        )
        self._req_bytes = Counter(f"{prefix}_request_bytes_total", "Client request bytes", ["grpc_service", "grpc_method", "grpc_type"])
        self._resp_bytes = Counter(f"{prefix}_response_bytes_total", "Client response bytes", ["grpc_service", "grpc_method", "grpc_type"])
        self._count_bytes = count_bytes

    def _wrap(self, method, request_or_iterator, call_details, invoker, kind: str):
        service, meth = _split_method(call_details.method)
        self._started.labels(service, meth, kind).inc()
        start = time.perf_counter()
        code = grpc.StatusCode.OK
        try:
            if self._count_bytes and kind in ("unary_unary", "unary_stream"):
                self._req_bytes.labels(service, meth, kind).inc(_safe_len(request_or_iterator))
            resp = invoker(method, request_or_iterator, call_details)
            if self._count_bytes and kind == "unary_unary":
                try:
                    self._resp_bytes.labels(service, meth, kind).inc(_safe_len(resp.result()))  # type: ignore[attr-defined]
                except Exception:
                    pass
            return resp
        except BaseException as e:
            code = _code_from_exception(e)
            raise
        finally:
            elapsed = time.perf_counter() - start
            code_s = code.name
            self._latency.labels(service, meth, kind, code_s).observe(elapsed)
            self._handled.labels(service, meth, kind, code_s).inc()

    # Implement interfaces
    def intercept_unary_unary(self, continuation, client_call_details, request):
        return self._wrap(continuation, request, client_call_details, continuation, "unary_unary")

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return self._wrap(continuation, request, client_call_details, continuation, "unary_stream")

    def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
        return self._wrap(continuation, request_iterator, client_call_details, continuation, "stream_unary")

    def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
        return self._wrap(continuation, request_iterator, client_call_details, continuation, "stream_stream")


# ===========================
# Пояснение по использованию
# ===========================
# Server (sync):
#   server = grpc.server(futures.ThreadPoolExecutor())
#   server = grpc.server(..., interceptors=[PrometheusServerInterceptor()])
#
# Server (async):
#   server = grpc.aio.server(interceptors=[AioPrometheusServerInterceptor()])
#
# Prometheus экспорт:
#   from prometheus_client import start_http_server
#   start_http_server(9090)  # в отдельном процессе/потоке; ServiceMonitor опросит /metrics
#
# Client (опционально):
#   channel = grpc.intercept_channel(grpc.insecure_channel("..."), PrometheusClientInterceptor())
