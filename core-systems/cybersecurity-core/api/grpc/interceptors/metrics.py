# file: cybersecurity-core/api/grpc/interceptors/metrics.py
"""
gRPC Server Metrics Interceptor (sync + asyncio)

Функциональность:
- Метрики в стиле Prometheus:
  * grpc_server_started_total        (Counter)
  * grpc_server_handled_total        (Counter, с лейблом grpc_code)
  * grpc_server_handling_seconds     (Histogram)
  * grpc_server_msg_received_total   (Counter)
  * grpc_server_msg_sent_total       (Counter)
  * grpc_server_in_flight            (Gauge)
  Лейблы: grpc_type, grpc_service, grpc_method [, grpc_code]
- Поддержка всех типов RPC: unary_unary, unary_stream, stream_unary, stream_stream.
- Инициализация метрик идемпотентна (safe для многократного импорта).
- Никаких high-cardinality меток (корреляции/идентификаторы не используются в лейблах).
- Опциональные OpenTelemetry-метрики (если установлен opentelemetry).

Применение (Prometheus):
    from prometheus_client import start_http_server
    from cybersecurity_core.api.grpc.interceptors.metrics import (
        init_metrics, SyncPromMetricsInterceptor, AsyncPromMetricsInterceptor
    )

    # Инициализируем метрики один раз на старте приложения:
    init_metrics(namespace="aethernova", subsystem="grpc_server")

    # Запускаем эндпоинт экспорта метрик (если нужно) где-то снаружи:
    # start_http_server(9000)

    # Регистрируем интерцептор в gRPC сервере:
    # Sync:
    #   server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[SyncPromMetricsInterceptor()])
    # Async:
    #   server = grpc.aio.server(interceptors=[AsyncPromMetricsInterceptor()])

Зависимости: grpcio, prometheus_client (опционально opentelemetry-api/opentelemetry-sdk).
"""

from __future__ import annotations

import logging
import time
import types
from typing import Any, AsyncIterator, Callable, Iterator, Optional, Sequence, Tuple

import grpc

try:
    import grpc.aio as grpc_aio  # type: ignore
    _HAS_AIO = True
except Exception:  # pragma: no cover
    grpc_aio = None  # type: ignore
    _HAS_AIO = False

# Prometheus (обязателен)
from prometheus_client import Counter, Gauge, Histogram

# OpenTelemetry (опционально)
try:
    from opentelemetry import metrics as otel_metrics  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    otel_metrics = None  # type: ignore
    _HAS_OTEL = False

__all__ = [
    "init_metrics",
    "SyncPromMetricsInterceptor",
    "AsyncPromMetricsInterceptor",
]

logger = logging.getLogger("cybersecurity_core.grpc.metrics")

# --- Глобальные метрики (инициализируются один раз через init_metrics) ---

class _PromState:
    started: Optional[Counter] = None
    handled: Optional[Counter] = None
    handling_seconds: Optional[Histogram] = None
    msg_received: Optional[Counter] = None
    msg_sent: Optional[Counter] = None
    in_flight: Optional[Gauge] = None


class _OtelState:
    enabled: bool = False
    meter = None
    started = None
    handled = None
    handling_seconds = None
    msg_received = None
    msg_sent = None
    in_flight = None


_PROM = _PromState()
_OTEL = _OtelState()
_INITIALIZED = False


def init_metrics(
    *,
    namespace: str = "cybersec",
    subsystem: str = "grpc_server",
    buckets: Sequence[float] = (
        0.005, 0.01, 0.02, 0.05, 0.1,
        0.2, 0.5, 1.0, 2.0, 5.0,
        10.0, 30.0
    ),
    enable_otel: bool = True,
) -> None:
    """
    Инициализирует Prometheus и опциональные OpenTelemetry метрики. Идемпотентно.

    :param namespace: Префикс метрик (Prometheus namespace).
    :param subsystem: Подсистема (Prometheus subsystem).
    :param buckets:   Ведра гистограммы времени.
    :param enable_otel: Включать ли попытку регистрации метрик OTel (если пакет установлен).
    """
    global _INITIALIZED

    if _INITIALIZED:
        return

    # Prometheus метрики (соответствуют канону grpc_* метрик).
    _PROM.started = Counter(
        "started_total", "Total number of RPCs started on the server.",
        labelnames=("grpc_type", "grpc_service", "grpc_method"),
        namespace=namespace, subsystem=subsystem,
    )
    _PROM.handled = Counter(
        "handled_total", "Total number of RPCs completed on the server, regardless of success or failure.",
        labelnames=("grpc_type", "grpc_service", "grpc_method", "grpc_code"),
        namespace=namespace, subsystem=subsystem,
    )
    _PROM.handling_seconds = Histogram(
        "handling_seconds", "Histogram of response latency (seconds) of gRPC that had been application-level handled by the server.",
        labelnames=("grpc_type", "grpc_service", "grpc_method"),
        namespace=namespace, subsystem=subsystem,
        buckets=buckets,
    )
    _PROM.msg_received = Counter(
        "msg_received_total", "Total number of stream messages received from the client.",
        labelnames=("grpc_type", "grpc_service", "grpc_method"),
        namespace=namespace, subsystem=subsystem,
    )
    _PROM.msg_sent = Counter(
        "msg_sent_total", "Total number of stream messages sent by the server.",
        labelnames=("grpc_type", "grpc_service", "grpc_method"),
        namespace=namespace, subsystem=subsystem,
    )
    _PROM.in_flight = Gauge(
        "in_flight", "Number of in-flight RPCs on the server.",
        labelnames=("grpc_type", "grpc_service", "grpc_method"),
        namespace=namespace, subsystem=subsystem,
    )

    # Optional OpenTelemetry
    if enable_otel and _HAS_OTEL:
        try:
            _OTEL.meter = otel_metrics.get_meter_provider().get_meter("cybersecurity_core.grpc.metrics")
            _OTEL.started = _OTEL.meter.create_counter(
                name=f"{namespace}.{subsystem}.started",
                unit="1",
                description="Total number of RPCs started on the server.",
            )
            _OTEL.handled = _OTEL.meter.create_counter(
                name=f"{namespace}.{subsystem}.handled",
                unit="1",
                description="Total number of RPCs completed on the server.",
            )
            _OTEL.handling_seconds = _OTEL.meter.create_histogram(
                name=f"{namespace}.{subsystem}.handling_seconds",
                unit="s",
                description="Histogram of response latency (seconds).",
            )
            _OTEL.msg_received = _OTEL.meter.create_counter(
                name=f"{namespace}.{subsystem}.msg_received",
                unit="1",
                description="Total number of stream messages received from the client.",
            )
            _OTEL.msg_sent = _OTEL.meter.create_counter(
                name=f"{namespace}.{subsystem}.msg_sent",
                unit="1",
                description="Total number of stream messages sent by the server.",
            )
            _OTEL.in_flight = _OTEL.meter.create_up_down_counter(
                name=f"{namespace}.{subsystem}.in_flight",
                unit="1",
                description="Number of in-flight RPCs on the server.",
            )
            _OTEL.enabled = True
        except Exception:  # pragma: no cover
            logger.warning("OpenTelemetry metrics initialization failed; continuing without OTel.", exc_info=True)
            _OTEL.enabled = False

    _INITIALIZED = True


# --- Вспомогательные функции ---

def _split_method(full_method: str) -> Tuple[str, str]:
    """
    Разбивает имя метода вида '/package.Service/Method' на (service, method).
    """
    # gRPC Python гарантирует ведущий '/'
    try:
        _, svc, mtd = full_method.split("/", 2)
        return svc, mtd
    except Exception:
        return "unknown", full_method.lstrip("/")


def _labels(grpc_type: str, service: str, method: str) -> dict:
    return {"grpc_type": grpc_type, "grpc_service": service, "grpc_method": method}


def _inc_started(grpc_type: str, service: str, method: str) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.started.labels(**lab).inc()
    if _OTEL.enabled:
        _OTEL.started.add(1, attributes=lab)


def _inc_in_flight(grpc_type: str, service: str, method: str, delta: int) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.in_flight.labels(**lab).inc(delta)
    if _OTEL.enabled:
        _OTEL.in_flight.add(delta, attributes=lab)


def _observe_duration(grpc_type: str, service: str, method: str, seconds: float) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.handling_seconds.labels(**lab).observe(seconds)
    if _OTEL.enabled:
        _OTEL.handling_seconds.record(seconds, attributes=lab)


def _inc_msg_received(grpc_type: str, service: str, method: str, n: int = 1) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.msg_received.labels(**lab).inc(n)
    if _OTEL.enabled:
        _OTEL.msg_received.add(n, attributes=lab)


def _inc_msg_sent(grpc_type: str, service: str, method: str, n: int = 1) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.msg_sent.labels(**lab).inc(n)
    if _OTEL.enabled:
        _OTEL.msg_sent.add(n, attributes=lab)


def _inc_handled(grpc_type: str, service: str, method: str, code: grpc.StatusCode) -> None:
    lab = _labels(grpc_type, service, method)
    _PROM.handled.labels(**lab, grpc_code=code.name).inc()
    if _OTEL.enabled:
        _OTEL.handled.add(1, attributes={**lab, "grpc_code": code.name})


# --- Обёртки итераторов для подсчёта сообщений ---

def _wrap_request_iter(it: Iterator[Any], grpc_type: str, service: str, method: str) -> Iterator[Any]:
    for item in it:
        _inc_msg_received(grpc_type, service, method, 1)
        yield item


async def _wrap_request_aiter(it: AsyncIterator[Any], grpc_type: str, service: str, method: str) -> AsyncIterator[Any]:
    async for item in it:
        _inc_msg_received(grpc_type, service, method, 1)
        yield item


def _wrap_response_iter(it: Iterator[Any], grpc_type: str, service: str, method: str) -> Iterator[Any]:
    for item in it:
        _inc_msg_sent(grpc_type, service, method, 1)
        yield item


async def _wrap_response_aiter(it: AsyncIterator[Any], grpc_type: str, service: str, method: str) -> AsyncIterator[Any]:
    async for item in it:
        _inc_msg_sent(grpc_type, service, method, 1)
        yield item


# --- Sync interceptor ---

class SyncPromMetricsInterceptor(grpc.ServerInterceptor):
    """
    Промышленный Prometheus-интерцептор для sync gRPC сервера.
    """

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)

        # Оборачиваем каждый поддерживаемый тип обработчика
        if handler.unary_unary:
            fn = handler.unary_unary

            def wrapper(request, context):
                grpc_type = "unary_unary"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    # одна входящая + одна исходящая
                    _inc_msg_received(grpc_type, service, method, 1)
                    resp = fn(request, context)
                    _inc_msg_sent(grpc_type, service, method, 1)
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                    return resp
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            fn = handler.unary_stream

            def wrapper(request, context):
                grpc_type = "unary_stream"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    _inc_msg_received(grpc_type, service, method, 1)
                    resp_iter = fn(request, context)
                    return _wrap_response_iter(resp_iter, grpc_type, service, method)
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    # handled фиксируем только при полном прохождении итератора:
                    # сделаем это при потреблении через генератор (ниже).
                    duration = time.perf_counter() - started
                    _observe_duration(grpc_type, service, method, duration)
                    _inc_in_flight(grpc_type, service, method, -1)

            # Нам нужно зафиксировать handled после полной отправки — это сложнее,
            # но здесь считаем handled при возникновении RpcError/Exception в генераторе.
            def handler_unary_stream(request, context):
                grpc_type = "unary_stream"
                started = time.perf_counter()
                try:
                    for item in wrapper(request, context):
                        yield item
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)

            return grpc.unary_stream_rpc_method_handler(
                handler_unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            fn = handler.stream_unary

            def wrapper(request_iterator, context):
                grpc_type = "stream_unary"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    resp = fn(_wrap_request_iter(request_iterator, grpc_type, service, method), context)
                    _inc_msg_sent(grpc_type, service, method, 1)
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                    return resp
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc.stream_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            fn = handler.stream_stream

            def wrapper(request_iterator, context):
                grpc_type = "stream_stream"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    resp_iter = fn(_wrap_request_iter(request_iterator, grpc_type, service, method), context)
                    for item in _wrap_response_iter(resp_iter, grpc_type, service, method):
                        yield item
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc.stream_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Неподдержанные типы — возвращаем как есть
        return handler


# --- Async interceptor ---

class AsyncPromMetricsInterceptor(grpc_aio.ServerInterceptor):  # type: ignore[misc]
    """
    Промышленный Prometheus-интерцептор для asyncio gRPC сервера.
    Требует grpc.aio (grpcio 1.30+). Создавайте сервер с interceptors=[...].
    """

    async def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        service, method = _split_method(handler_call_details.method)

        if handler.unary_unary:
            fn = handler.unary_unary

            async def wrapper(request, context):
                grpc_type = "unary_unary"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    _inc_msg_received(grpc_type, service, method, 1)
                    resp = await fn(request, context)
                    _inc_msg_sent(grpc_type, service, method, 1)
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                    return resp
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc_aio.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            fn = handler.unary_stream

            async def wrapper(request, context):
                grpc_type = "unary_stream"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    _inc_msg_received(grpc_type, service, method, 1)
                    resp_aiter = await fn(request, context)
                    async for item in _wrap_response_aiter(resp_aiter, grpc_type, service, method):
                        yield item
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc_aio.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            fn = handler.stream_unary

            async def wrapper(request_aiter, context):
                grpc_type = "stream_unary"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    resp = await fn(_wrap_request_aiter(request_aiter, grpc_type, service, method), context)
                    _inc_msg_sent(grpc_type, service, method, 1)
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                    return resp
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc_aio.stream_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            fn = handler.stream_stream

            async def wrapper(request_aiter, context):
                grpc_type = "stream_stream"
                _inc_started(grpc_type, service, method)
                _inc_in_flight(grpc_type, service, method, +1)
                started = time.perf_counter()
                try:
                    resp_aiter = await fn(_wrap_request_aiter(request_aiter, grpc_type, service, method), context)
                    async for item in _wrap_response_aiter(resp_aiter, grpc_type, service, method):
                        yield item
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.OK)
                except grpc.RpcError as e:
                    _inc_handled(grpc_type, service, method, e.code() or grpc.StatusCode.UNKNOWN)
                    raise
                except Exception:
                    _inc_handled(grpc_type, service, method, grpc.StatusCode.UNKNOWN)
                    raise
                finally:
                    _observe_duration(grpc_type, service, method, time.perf_counter() - started)
                    _inc_in_flight(grpc_type, service, method, -1)

            return grpc_aio.stream_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler
