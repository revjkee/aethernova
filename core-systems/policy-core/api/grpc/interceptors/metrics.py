# policy-core/api/grpc/interceptors/metrics.py
# Промышленная метрикация gRPC-сервера (sync и asyncio).
# Особенности:
# - Prometheus: rpc_started_total, rpc_handled_total{code}, rpc_latency_seconds,
#   rpc_inflight, rpc_msg_received_total, rpc_msg_sent_total,
#   rpc_req_size_bytes, rpc_resp_size_bytes
# - Корректная поддержка типов RPC: unary-unary, unary-stream, stream-unary, stream-stream
# - Безопасная обработка ошибок/исключений (grpc.RpcError и прочие)
# - Парсинг имени метода в метки service/method
# - Опциональная интеграция с OpenTelemetry (добавление атрибутов в текущий спан)
# - Конфиг через переменные окружения: GRPC_METRICS_NAMESPACE, *_BUCKETS, LOG_SAMPLE_RATE и т. п. (см. код)
# I cannot verify this.

from __future__ import annotations

import inspect
import os
import time
import typing as t

import grpc
from prometheus_client import Counter, Gauge, Histogram

try:
    import grpc.aio as grpc_aio  # type: ignore
except Exception:  # pragma: no cover
    grpc_aio = None  # type: ignore

try:
    from opentelemetry import trace as _otel_trace  # type: ignore
except Exception:  # pragma: no cover
    _otel_trace = None  # type: ignore


# ------------------------------ Конфиг ---------------------------------

def _float_list_env(name: str, default: list[float]) -> list[float]:
    raw = os.getenv(name, "")
    if not raw:
        return default
    out: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(float(part))
        except ValueError:
            continue
    return out or default


NAMESPACE = os.getenv("GRPC_METRICS_NAMESPACE", "policy_core")

# Бакеты по умолчанию (секунды)
DEFAULT_LATENCY_BUCKETS = _float_list_env(
    "GRPC_LATENCY_BUCKETS",
    [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0, 1.5, 2.5, 5.0, 10.0],
)
# Бакеты по размеру (байты)
DEFAULT_SIZE_BUCKETS = _float_list_env(
    "GRPC_SIZE_BUCKETS",
    [64, 128, 256, 512, 1_024, 2_048, 4_096, 8_192, 16_384, 32_768, 65_536, 131_072, 262_144, 524_288, 1_048_576],
)


# ------------------------------ Метрики --------------------------------

class GrpcMetrics:
    """Контейнер Prometheus-метрик с ленивой инициализацией."""

    def __init__(self, namespace: str = NAMESPACE):
        self.namespace = namespace
        self.rpc_started = Counter(
            "grpc_server_started_total",
            "Total number of RPCs started on the server.",
            ("service", "method"),
            namespace=namespace,
        )
        self.rpc_handled = Counter(
            "grpc_server_handled_total",
            "Total number of RPCs completed on the server, regardless of success or failure.",
            ("service", "method", "code"),
            namespace=namespace,
        )
        self.rpc_latency = Histogram(
            "grpc_server_handling_seconds",
            "Histogram of RPC handling latency (seconds) on the server.",
            ("service", "method"),
            buckets=DEFAULT_LATENCY_BUCKETS,
            namespace=namespace,
        )
        self.rpc_inflight = Gauge(
            "grpc_server_inflight",
            "Number of in-flight RPCs on the server.",
            ("service", "method"),
            namespace=namespace,
        )
        self.msg_recv = Counter(
            "grpc_server_msg_received_total",
            "Total number of RPC stream messages received on the server.",
            ("service", "method"),
            namespace=namespace,
        )
        self.msg_sent = Counter(
            "grpc_server_msg_sent_total",
            "Total number of RPC stream messages sent by the server.",
            ("service", "method"),
            namespace=namespace,
        )
        self.req_size = Histogram(
            "grpc_server_request_size_bytes",
            "Histogram of request message sizes.",
            ("service", "method"),
            buckets=DEFAULT_SIZE_BUCKETS,
            namespace=namespace,
        )
        self.resp_size = Histogram(
            "grpc_server_response_size_bytes",
            "Histogram of response message sizes.",
            ("service", "method"),
            buckets=DEFAULT_SIZE_BUCKETS,
            namespace=namespace,
        )

    # -------- вспомогательные методы --------

    @staticmethod
    def split_method(full_method: str) -> tuple[str, str]:
        # full_method: "/package.Service/Method"
        if not full_method or "/" not in full_method:
            return ("unknown", "unknown")
        try:
            _, sm = full_method.split("/", 1)
            service, method = sm.split("/", 1)
            return service, method
        except ValueError:
            return ("unknown", "unknown")

    @staticmethod
    def status_code_from_exc(exc: BaseException | None) -> str:
        if exc is None:
            return grpc.StatusCode.OK.name
        if isinstance(exc, grpc.RpcError):
            # code() может вернуть None для нестандартных ошибок; подменяем
            try:
                c = exc.code() or grpc.StatusCode.UNKNOWN
                return c.name
            except Exception:
                return grpc.StatusCode.UNKNOWN.name
        return grpc.StatusCode.UNKNOWN.name

    @staticmethod
    def protobuf_size(msg: t.Any) -> int:
        try:
            # Protobuf Python API
            if hasattr(msg, "ByteSize"):
                return int(msg.ByteSize())
            if hasattr(msg, "SerializeToString"):
                return len(msg.SerializeToString(deterministic=True))
        except Exception:
            pass
        # Fallback: пытаемся через bytes()
        try:
            return len(bytes(msg))
        except Exception:
            return 0

    @staticmethod
    def otel_set_attrs(service: str, method: str, code: str | None = None) -> None:
        if _otel_trace is None:
            return
        try:
            span = _otel_trace.get_current_span()
            if span and span.get_span_context().is_valid:
                span.set_attribute("rpc.system", "grpc")
                span.set_attribute("rpc.service", service)
                span.set_attribute("rpc.method", method)
                if code:
                    span.set_attribute("rpc.grpc.status_code", code)
        except Exception:
            pass


_METRICS = GrpcMetrics()  # по умолчанию используем один контейнер


# -------------------------- Sync interceptor ---------------------------

class PrometheusServerInterceptor(grpc.ServerInterceptor):
    """Серверный интерсептор для grpc.Server (sync)."""

    def __init__(self, metrics: GrpcMetrics | None = None) -> None:
        self.m = metrics or _METRICS

    def intercept_service(
        self,
        continuation: t.Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        service, method = self.m.split_method(handler_call_details.method)

        # Обёртки для каждого вида RPC
        if not handler.request_streaming and not handler.response_streaming:
            # unary-unary
            def unary_unary(req, ctx):
                return self._observed_unary_unary(handler, service, method, req, ctx)

            return grpc.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if not handler.request_streaming and handler.response_streaming:
            # unary-stream
            def unary_stream(req, ctx):
                return self._observed_unary_stream(handler, service, method, req, ctx)

            return grpc.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.request_streaming and not handler.response_streaming:
            # stream-unary
            def stream_unary(req_iter, ctx):
                return self._observed_stream_unary(handler, service, method, req_iter, ctx)

            return grpc.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # stream-stream
        def stream_stream(req_iter, ctx):
            return self._observed_stream_stream(handler, service, method, req_iter, ctx)

        return grpc.stream_stream_rpc_method_handler(
            stream_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    # ----------------- реализация наблюдения (sync) -----------------

    def _start(self, service: str, method: str) -> tuple[float, t.Callable[[], None]]:
        self.m.rpc_started.labels(service, method).inc()
        self.m.rpc_inflight.labels(service, method).inc()
        start = time.perf_counter()
        def done():
            self.m.rpc_inflight.labels(service, method).dec()
        return start, done

    def _finish(self, service: str, method: str, start: float, code: str) -> None:
        took = time.perf_counter() - start
        self.m.rpc_latency.labels(service, method).observe(took)
        self.m.rpc_handled.labels(service, method, code).inc()
        self.m.otel_set_attrs(service, method, code)

    def _observed_unary_unary(self, handler, service, method, request, context):
        start, done = self._start(service, method)
        exc: BaseException | None = None
        try:
            # размер запроса
            if request is not None:
                self.m.req_size.labels(service, method).observe(self.m.protobuf_size(request))
            resp = handler.unary_unary(request, context)
            if resp is not None:
                self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(resp))
            return resp
        except BaseException as e:
            exc = e
            raise
        finally:
            code = self.m.status_code_from_exc(exc)
            self._finish(service, method, start, code)
            done()

    def _observed_unary_stream(self, handler, service, method, request, context):
        start, done = self._start(service, method)
        exc: BaseException | None = None
        try:
            if request is not None:
                self.m.req_size.labels(service, method).observe(self.m.protobuf_size(request))
            resp_iter = handler.unary_stream(request, context)

            def gen():
                inner_exc: BaseException | None = None
                try:
                    for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
                except BaseException as e:
                    inner_exc = e
                    raise
                finally:
                    code = self.m.status_code_from_exc(inner_exc)
                    self._finish(service, method, start, code)
                    done()

            return gen()
        except BaseException as e:
            exc = e
            raise
        finally:
            if exc is not None:
                code = self.m.status_code_from_exc(exc)
                self._finish(service, method, start, code)
                done()

    def _observed_stream_unary(self, handler, service, method, request_iterator, context):
        start, done = self._start(service, method)

        def wrap_iter():
            inner_exc: BaseException | None = None
            try:
                for msg in request_iterator:
                    if msg is not None:
                        self.m.msg_recv.labels(service, method).inc()
                        self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                    yield msg
            except BaseException as e:
                inner_exc = e
                raise
            finally:
                # для входящего стрима код ещё неизвестен — финализируем в месте ответа
                if inner_exc is not None:
                    code = self.m.status_code_from_exc(inner_exc)
                    self._finish(service, method, start, code)
                    done()

        exc: BaseException | None = None
        try:
            resp = handler.stream_unary(wrap_iter(), context)
            if resp is not None:
                self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(resp))
            return resp
        except BaseException as e:
            exc = e
            raise
        finally:
            code = self.m.status_code_from_exc(exc)
            self._finish(service, method, start, code)
            done()

    def _observed_stream_stream(self, handler, service, method, request_iterator, context):
        start, done = self._start(service, method)

        def wrap_req_iter():
            try:
                for msg in request_iterator:
                    if msg is not None:
                        self.m.msg_recv.labels(service, method).inc()
                        self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                    yield msg
            except BaseException:
                raise  # финализируем в ответном генераторе

        exc_at_call: BaseException | None = None
        try:
            resp_iter = handler.stream_stream(wrap_req_iter(), context)

            def wrap_resp_iter():
                inner_exc: BaseException | None = None
                try:
                    for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
                except BaseException as e:
                    inner_exc = e
                    raise
                finally:
                    code = self.m.status_code_from_exc(inner_exc)
                    self._finish(service, method, start, code)
                    done()

            return wrap_resp_iter()
        except BaseException as e:
            exc_at_call = e
            raise
        finally:
            if exc_at_call is not None:
                code = self.m.status_code_from_exc(exc_at_call)
                self._finish(service, method, start, code)
                done()


# -------------------------- Async interceptor --------------------------

class AsyncPrometheusServerInterceptor(grpc_aio.ServerInterceptor if grpc_aio else object):  # type: ignore[misc]
    """Серверный интерсептор для grpc.aio.Server (asyncio)."""

    def __init__(self, metrics: GrpcMetrics | None = None) -> None:
        if grpc_aio is None:  # pragma: no cover
            raise RuntimeError("grpc.aio недоступен в окружении")
        self.m = metrics or _METRICS

    async def intercept_service(
        self,
        continuation: t.Callable[[grpc.HandlerCallDetails], t.Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler

        service, method = self.m.split_method(handler_call_details.method)

        # Определяем async/sync обработчики и оборачиваем соответствующим образом
        if not handler.request_streaming and not handler.response_streaming:
            async def unary_unary(request, context):
                return await self._observed_unary_unary(handler, service, method, request, context)

            return grpc_aio.unary_unary_rpc_method_handler(  # type: ignore[attr-defined]
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if not handler.request_streaming and handler.response_streaming:
            async def unary_stream(request, context):
                return self._observed_unary_stream(handler, service, method, request, context)

            return grpc_aio.unary_stream_rpc_method_handler(  # type: ignore[attr-defined]
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.request_streaming and not handler.response_streaming:
            async def stream_unary(request_iter, context):
                return await self._observed_stream_unary(handler, service, method, request_iter, context)

            return grpc_aio.stream_unary_rpc_method_handler(  # type: ignore[attr-defined]
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        async def stream_stream(request_iter, context):
            return self._observed_stream_stream(handler, service, method, request_iter, context)

        return grpc_aio.stream_stream_rpc_method_handler(  # type: ignore[attr-defined]
            stream_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    # ----------------- реализация наблюдения (async) -----------------

    def _start(self, service: str, method: str) -> tuple[float, t.Callable[[], None]]:
        self.m.rpc_started.labels(service, method).inc()
        self.m.rpc_inflight.labels(service, method).inc()
        start = time.perf_counter()
        def done():
            self.m.rpc_inflight.labels(service, method).dec()
        return start, done

    def _finish(self, service: str, method: str, start: float, code: str) -> None:
        took = time.perf_counter() - start
        self.m.rpc_latency.labels(service, method).observe(took)
        self.m.rpc_handled.labels(service, method, code).inc()
        self.m.otel_set_attrs(service, method, code)

    async def _observed_unary_unary(self, handler, service, method, request, context):
        start, done = self._start(service, method)
        exc: BaseException | None = None
        try:
            if request is not None:
                self.m.req_size.labels(service, method).observe(self.m.protobuf_size(request))

            # handler.unary_unary может быть sync/async
            if inspect.iscoroutinefunction(handler.unary_unary):
                resp = await handler.unary_unary(request, context)
            else:
                resp = handler.unary_unary(request, context)

            if resp is not None:
                self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(resp))
            return resp
        except BaseException as e:
            exc = e
            raise
        finally:
            code = self.m.status_code_from_exc(exc)
            self._finish(service, method, start, code)
            done()

    def _observed_unary_stream(self, handler, service, method, request, context):
        start, done = self._start(service, method)

        async def agen():
            inner_exc: BaseException | None = None
            try:
                if request is not None:
                    self.m.req_size.labels(service, method).observe(self.m.protobuf_size(request))

                resp_iter = handler.unary_stream(request, context)
                # resp_iter может быть async- или sync-итератором
                if inspect.isasyncgen(resp_iter):
                    async for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
                else:
                    for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
            except BaseException as e:
                inner_exc = e
                raise
            finally:
                code = self.m.status_code_from_exc(inner_exc)
                self._finish(service, method, start, code)
                done()

        return agen()

    async def _observed_stream_unary(self, handler, service, method, request_iter, context):
        start, done = self._start(service, method)

        async def wrap_req_iter():
            inner_exc: BaseException | None = None
            try:
                if inspect.isasyncgen(request_iter):
                    async for msg in request_iter:
                        if msg is not None:
                            self.m.msg_recv.labels(service, method).inc()
                            self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
                else:
                    for msg in request_iter:
                        if msg is not None:
                            self.m.msg_recv.labels(service, method).inc()
                            self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
            except BaseException as e:
                inner_exc = e
                raise
            finally:
                if inner_exc is not None:
                    code = self.m.status_code_from_exc(inner_exc)
                    self._finish(service, method, start, code)
                    done()

        exc: BaseException | None = None
        try:
            if inspect.iscoroutinefunction(handler.stream_unary):
                resp = await handler.stream_unary(wrap_req_iter(), context)
            else:
                resp = handler.stream_unary(wrap_req_iter(), context)

            if resp is not None:
                self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(resp))
            return resp
        except BaseException as e:
            exc = e
            raise
        finally:
            code = self.m.status_code_from_exc(exc)
            self._finish(service, method, start, code)
            done()

    def _observed_stream_stream(self, handler, service, method, request_iter, context):
        start, done = self._start(service, method)

        async def wrap_req_iter():
            if inspect.isasyncgen(request_iter):
                async for msg in request_iter:
                    if msg is not None:
                        self.m.msg_recv.labels(service, method).inc()
                        self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                    yield msg
            else:
                for msg in request_iter:
                    if msg is not None:
                        self.m.msg_recv.labels(service, method).inc()
                        self.m.req_size.labels(service, method).observe(self.m.protobuf_size(msg))
                    yield msg

        async def agen():
            inner_exc: BaseException | None = None
            try:
                resp_iter = handler.stream_stream(wrap_req_iter(), context)
                if inspect.isasyncgen(resp_iter):
                    async for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
                else:
                    for msg in resp_iter:
                        if msg is not None:
                            self.m.msg_sent.labels(service, method).inc()
                            self.m.resp_size.labels(service, method).observe(self.m.protobuf_size(msg))
                        yield msg
            except BaseException as e:
                inner_exc = e
                raise
            finally:
                code = self.m.status_code_from_exc(inner_exc)
                self._finish(service, method, start, code)
                done()

        return agen()


# ------------------------------ Вспомогательное ------------------------------

def server_interceptor(sync: bool | None = None, metrics: GrpcMetrics | None = None):
    """
    Возвращает подходящий серверный интерсептор:
      - sync=True  -> PrometheusServerInterceptor (grpc.Server)
      - sync=False -> AsyncPrometheusServerInterceptor (grpc.aio.Server)
      - None       -> пытаемся автоопределить по наличию grpc.aio
    """
    if sync is True:
        return PrometheusServerInterceptor(metrics)
    if sync is False:
        if grpc_aio is None:
            raise RuntimeError("grpc.aio недоступен, укажите sync=True")
        return AsyncPrometheusServerInterceptor(metrics)
    # авто
    return (AsyncPrometheusServerInterceptor(metrics) if grpc_aio else PrometheusServerInterceptor(metrics))


# ------------------------------ Пример подключения ------------------------------
# Sync:
#   interceptor = PrometheusServerInterceptor()
#   server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[interceptor])
#
# Async:
#   interceptor = AsyncPrometheusServerInterceptor()
#   server = grpc.aio.server(interceptors=[interceptor])
#
# Экспорт Prometheus (пример):
#   from prometheus_client import start_http_server
#   start_http_server(8000)  # /metrics на 0.0.0.0:8000
#
# Важно: метки service/method берутся из gRPC-path "/pkg.Svc/Method".
