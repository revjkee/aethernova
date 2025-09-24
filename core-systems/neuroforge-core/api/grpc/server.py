# neuroforge-core/api/grpc/server.py
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
import os
import signal
import sys
import time
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Dict

import grpc
from grpc import StatusCode
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

try:
    # ВАШИ сгенерированные из proto пайтоны:
    # см. schemas/proto/v1/neuroforge/health.proto
    from neuroforge.v1 import health_pb2 as nf_health_pb2
    from neuroforge.v1 import health_pb2_grpc as nf_health_pb2_grpc
except Exception as e:  # pragma: no cover
    raise ImportError(
        "Не найдены сгенерированные protobuf артефакты для neuroforge.v1.health "
        "(ожидается neuroforge.v1.health_pb2 / health_pb2_grpc). "
        "Сгенерируйте их через scripts/gen_proto.sh."
    ) from e

# Опциональные метрики Prometheus (без жёсткой зависимости)
_PROM_AVAILABLE = False
try:  # pragma: no cover
    from prometheus_client import Counter, Histogram, Gauge, start_http_server

    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    pass

LOG = logging.getLogger("neuroforge.grpc.server")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="ts=%(asctime)s lvl=%(levelname)s logger=%(name)s msg=%(message)s",
)


# =============================================================================
# Конфигурация сервера
# =============================================================================

@dataclass(frozen=True)
class ServerConfig:
    host: str = os.getenv("GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("GRPC_PORT", "50051"))
    # Ограничения/производительность
    max_workers: int = int(os.getenv("GRPC_MAX_WORKERS", "16"))
    max_recv_msg_mb: int = int(os.getenv("GRPC_MAX_RECV_MB", "64"))
    max_send_msg_mb: int = int(os.getenv("GRPC_MAX_SEND_MB", "64"))
    # Keepalive (мс)
    keepalive_time_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "20000"))
    keepalive_timeout_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000"))
    keepalive_permit_without_calls: bool = bool(int(os.getenv("GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS", "1")))
    http2_max_pings_without_data: int = int(os.getenv("GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA", "0"))
    # Сжатие
    compression: Optional[str] = os.getenv("GRPC_COMPRESSION", "gzip")  # gzip|deflate|none
    # TLS / mTLS
    tls_enabled: bool = bool(int(os.getenv("GRPC_TLS_ENABLED", "0")))
    tls_cert_path: Optional[str] = os.getenv("GRPC_TLS_CERT", None)
    tls_key_path: Optional[str] = os.getenv("GRPC_TLS_KEY", None)
    tls_client_ca_path: Optional[str] = os.getenv("GRPC_TLS_CLIENT_CA", None)  # если задан, включается mTLS
    # Аутентификация по API-ключу (метадата x-api-key)
    auth_enabled: bool = bool(int(os.getenv("GRPC_AUTH_ENABLED", "0")))
    auth_allowed_keys: Tuple[str, ...] = tuple(
        k.strip() for k in os.getenv("GRPC_AUTH_KEYS", "").split(",") if k.strip()
    )
    # Health/Reflection/Метрики
    enable_reflection: bool = bool(int(os.getenv("GRPC_REFLECTION", "1")))
    enable_prometheus: bool = bool(int(os.getenv("PROMETHEUS_ENABLED", "1")))
    prometheus_port: int = int(os.getenv("PROMETHEUS_PORT", "9095"))
    # Идентификация приложения
    app_name: str = os.getenv("APP_NAME", "neuroforge-core")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    git_revision: str = os.getenv("GIT_REVISION", "")


# =============================================================================
# Интерсепторы: аутентификация, логирование, метрики, обработка ошибок
# =============================================================================

class AuthInterceptor(grpc.ServerInterceptor):
    """
    Простейшая аутентификация по API-ключу в metadata: x-api-key: <KEY>.
    Если auth отключена или список ключей пуст, пропускает.
    """

    def __init__(self, enabled: bool, keys: Iterable[str]):
        self.enabled = enabled
        self.keys = set(keys or [])

    def intercept_service(self, continuation, handler_call_details):
        if not self.enabled or not self.keys:
            return continuation(handler_call_details)

        md = dict(handler_call_details.invocation_metadata or [])
        apikey = md.get("x-api-key") or md.get("authorization")
        if apikey and apikey.lower().startswith("bearer "):
            apikey = apikey.split(" ", 1)[1].strip()

        if apikey not in self.keys:
            def deny_unary_unary(request, context):
                context.set_trailing_metadata((("x-deny-reason", "invalid-api-key"),))
                context.abort(StatusCode.UNAUTHENTICATED, "invalid api key")

            return grpc.unary_unary_rpc_method_handler(deny_unary_unary)

        return continuation(handler_call_details)


class LoggingInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        method = handler_call_details.method

        def _log(status: StatusCode, dur_ms: float):
            LOG.info(f"rpc method={method} status={status.name} dur_ms={dur_ms:.2f}")

        if handler is None:
            return None

        if handler.unary_unary:
            def wrapper(request, context):
                t0 = time.time()
                try:
                    resp = handler.unary_unary(request, context)
                    _log(StatusCode.OK, (time.time() - t0) * 1000)
                    return resp
                except grpc.RpcError as e:
                    code = e.code() or StatusCode.UNKNOWN
                    _log(code, (time.time() - t0) * 1000)
                    raise
            return grpc.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            def wrapper(request, context):
                t0 = time.time()
                try:
                    for item in handler.unary_stream(request, context):
                        yield item
                    _log(StatusCode.OK, (time.time() - t0) * 1000)
                except grpc.RpcError as e:
                    code = e.code() or StatusCode.UNKNOWN
                    _log(code, (time.time() - t0) * 1000)
                    raise
            return grpc.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            def wrapper(request_iter, context):
                t0 = time.time()
                try:
                    resp = handler.stream_unary(request_iter, context)
                    _log(StatusCode.OK, (time.time() - t0) * 1000)
                    return resp
                except grpc.RpcError as e:
                    code = e.code() or StatusCode.UNKNOWN
                    _log(code, (time.time() - t0) * 1000)
                    raise
            return grpc.stream_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            def wrapper(request_iter, context):
                t0 = time.time()
                try:
                    for item in handler.stream_stream(request_iter, context):
                        yield item
                    _log(StatusCode.OK, (time.time() - t0) * 1000)
                except grpc.RpcError as e:
                    code = e.code() or StatusCode.UNKNOWN
                    _log(code, (time.time() - t0) * 1000)
                    raise
            return grpc.stream_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


class MetricsInterceptor(grpc.ServerInterceptor):
    def __init__(self, enabled: bool):
        self.enabled = enabled
        if _PROM_AVAILABLE and enabled:
            self.rpc_counter = Counter(
                "grpc_server_requests_total",
                "Total RPC requests",
                ["method", "code"],
            )
            self.rpc_latency = Histogram(
                "grpc_server_request_duration_seconds",
                "RPC latency in seconds",
                ["method"],
                buckets=(0.003, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
            )
            self.inflight = Gauge(
                "grpc_server_inflight_requests",
                "In-flight RPCs",
                ["method"],
            )

    def intercept_service(self, continuation, handler_call_details):
        if not (self.enabled and _PROM_AVAILABLE):
            return continuation(handler_call_details)

        handler = continuation(handler_call_details)
        method = handler_call_details.method

        def _wrap_unary(func):
            def inner(*args, **kwargs):
                with self.inflight.labels(method).track_inprogress():
                    t0 = time.time()
                    try:
                        res = func(*args, **kwargs)
                        self.rpc_counter.labels(method, "OK").inc()
                        self.rpc_latency.labels(method).observe(time.time() - t0)
                        return res
                    except grpc.RpcError as e:
                        code = (e.code() or StatusCode.UNKNOWN).name
                        self.rpc_counter.labels(method, code).inc()
                        self.rpc_latency.labels(method).observe(time.time() - t0)
                        raise
            return inner

        def _wrap_stream(gen_func):
            def inner(*args, **kwargs):
                with self.inflight.labels(method).track_inprogress():
                    t0 = time.time()
                    try:
                        for item in gen_func(*args, **kwargs):
                            yield item
                        self.rpc_counter.labels(method, "OK").inc()
                        self.rpc_latency.labels(method).observe(time.time() - t0)
                    except grpc.RpcError as e:
                        code = (e.code() or StatusCode.UNKNOWN).name
                        self.rpc_counter.labels(method, code).inc()
                        self.rpc_latency.labels(method).observe(time.time() - t0)
                        raise
            return inner

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                _wrap_unary(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                _wrap_stream(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                _wrap_unary(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                _wrap_stream(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class ErrorMaskingInterceptor(grpc.ServerInterceptor):
    """
    Маскирует внутренние ошибки (5xx), чтобы не выдавать стек/детали.
    """

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        def _mask(e: grpc.RpcError):
            # если уже проставлен код — пропускаем
            raise e

        def _abort_unknown(context, msg="internal error"):
            context.abort(StatusCode.INTERNAL, msg)

        if handler.unary_unary:
            def wrapper(request, context):
                try:
                    return handler.unary_unary(request, context)
                except grpc.RpcError as e:
                    return _mask(e)
                except Exception:
                    LOG.exception("Unhandled exception in unary_unary")
                    _abort_unknown(context)
            return grpc.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            def wrapper(request, context):
                try:
                    for item in handler.unary_stream(request, context):
                        yield item
                except grpc.RpcError as e:
                    _mask(e)
                except Exception:
                    LOG.exception("Unhandled exception in unary_stream")
                    _abort_unknown(context)
            return grpc.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            def wrapper(request_iter, context):
                try:
                    return handler.stream_unary(request_iter, context)
                except grpc.RpcError as e:
                    return _mask(e)
                except Exception:
                    LOG.exception("Unhandled exception in stream_unary")
                    _abort_unknown(context)
            return grpc.stream_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            def wrapper(request_iter, context):
                try:
                    for item in handler.stream_stream(request_iter, context):
                        yield item
                except grpc.RpcError as e:
                    _mask(e)
                except Exception:
                    LOG.exception("Unhandled exception in stream_stream")
                    _abort_unknown(context)
            return grpc.stream_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


# =============================================================================
# Реализация NeuroForge Health (ваш сервис из proto)
# =============================================================================

class NeuroforgeHealthService(nf_health_pb2_grpc.HealthServicer):
    """
    Реализация нейтральных RPC Health/Watch/Liveness/Readiness на базе вашей схемы.
    """

    def __init__(self, cfg: ServerConfig, core_health: health.HealthServicer):
        self.cfg = cfg
        self.core_health = core_health  # gRPC стандартный health для совместимости

    def _base_response(self, status: nf_health_pb2.HealthCheckResponse.ServingStatus) -> nf_health_pb2.HealthCheckResponse:
        now = int(time.time())
        return nf_health_pb2.HealthCheckResponse(
            status=status,
            version=self.cfg.app_version,
            revision=self.cfg.git_revision,
            release_channel=os.getenv("RELEASE_CHANNEL", "dev"),
            node=os.getenv("POD_NAME", os.uname().nodename if hasattr(os, "uname") else ""),
            zone=os.getenv("ZONE", ""),
            region=os.getenv("REGION", ""),
            checked_at=_ts(now),
            metadata={
                "app": self.cfg.app_name,
                "python": sys.version.split()[0],
            },
            probes=[],  # можно добавить реальные пробы (БД, кэш и т.д.)
        )

    def Check(self, request: nf_health_pb2.HealthCheckRequest, context) -> nf_health_pb2.HealthCheckResponse:
        # Считаем агрегатный статус из стандартного health сервиса
        svc = request.service or ""
        st = self.core_health.Check(health_pb2.HealthCheckRequest(service=svc), context).status
        status_map = {
            health_pb2.HealthCheckResponse.SERVING: nf_health_pb2.HealthCheckResponse.SERVING,
            health_pb2.HealthCheckResponse.NOT_SERVING: nf_health_pb2.HealthCheckResponse.NOT_SERVING,
            health_pb2.HealthCheckResponse.SERVICE_UNKNOWN: nf_health_pb2.HealthCheckResponse.SERVICE_UNKNOWN,
            health_pb2.HealthCheckResponse.UNKNOWN: nf_health_pb2.HealthCheckResponse.UNKNOWN,
        }
        resp = self._base_response(status_map.get(st, nf_health_pb2.HealthCheckResponse.UNKNOWN))
        return resp

    def Watch(self, request: nf_health_pb2.WatchHealthRequest, context):
        # Простейший стриминг статуса раз в N миллисекунд; останавливается при cancel
        interval_ms = int(_duration_ms(request.min_interval) or 1000)
        while True:
            if context.is_active():
                yield self.Check(
                    nf_health_pb2.HealthCheckRequest(service=request.service, component=request.component, scope=request.scope, labels=request.labels),
                    context,
                )
                time.sleep(interval_ms / 1000.0)
            else:
                break

    def CheckLiveness(self, request: nf_health_pb2.LivenessRequest, context) -> nf_health_pb2.HealthCheckResponse:
        return self._base_response(nf_health_pb2.HealthCheckResponse.SERVING)

    def CheckReadiness(self, request: nf_health_pb2.ReadinessRequest, context) -> nf_health_pb2.HealthCheckResponse:
        # Тут можно добавить реальную проверку зависимостей
        return self._base_response(nf_health_pb2.HealthCheckResponse.SERVING)


# =============================================================================
# Построение и запуск сервера
# =============================================================================

def _server_options(cfg: ServerConfig) -> List[Tuple[str, int]]:
    return [
        ("grpc.max_send_message_length", cfg.max_send_msg_mb * 1024 * 1024),
        ("grpc.max_receive_message_length", cfg.max_recv_msg_mb * 1024 * 1024),
        ("grpc.keepalive_time_ms", cfg.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.http2.max_pings_without_data", cfg.http2_max_pings_without_data),
        ("grpc.keepalive_permit_without_calls", int(cfg.keepalive_permit_without_calls)),
    ]


def _compression(cfg: ServerConfig) -> Optional[grpc.Compression]:
    if not cfg.compression or cfg.compression.lower() == "none":
        return None
    if cfg.compression.lower() == "gzip":
        return grpc.Compression.Gzip
    if cfg.compression.lower() == "deflate":
        return grpc.Compression.Deflate
    return None


def _load_server_credentials(cfg: ServerConfig) -> Optional[grpc.ServerCredentials]:
    if not cfg.tls_enabled:
        return None
    if not cfg.tls_cert_path or not cfg.tls_key_path:
        raise RuntimeError("TLS включен, но GRPC_TLS_CERT/GRPC_TLS_KEY не заданы")
    with open(cfg.tls_key_path, "rb") as f:
        private_key = f.read()
    with open(cfg.tls_cert_path, "rb") as f:
        cert_chain = f.read()
    if cfg.tls_client_ca_path:
        with open(cfg.tls_client_ca_path, "rb") as f:
            client_ca = f.read()
        return grpc.ssl_server_credentials(
            [(private_key, cert_chain)],
            root_certificates=client_ca,
            require_client_auth=True,
        )
    return grpc.ssl_server_credentials([(private_key, cert_chain)])


def build_server(cfg: ServerConfig) -> grpc.Server:
    interceptors: List[grpc.ServerInterceptor] = [
        ErrorMaskingInterceptor(),
        LoggingInterceptor(),
        MetricsInterceptor(cfg.enable_prometheus),
    ]
    if cfg.auth_enabled:
        interceptors.insert(0, AuthInterceptor(True, cfg.auth_allowed_keys))

    server = grpc.server(
        thread_pool=grpc.futures.ThreadPoolExecutor(max_workers=cfg.max_workers),
        interceptors=interceptors,
        options=_server_options(cfg),
        compression=_compression(cfg),
    )

    # gRPC standard Health
    core_health = health.HealthServicer()
    # По умолчанию объявляем сервер SERVING; конкретные сервисы можно метить отдельно.
    core_health.set("", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(core_health, server)

    # Ваш NeuroForge Health
    nf_health = NeuroforgeHealthService(cfg, core_health)
    nf_health_pb2_grpc.add_HealthServicer_to_server(nf_health, server)

    # Reflection
    if cfg.enable_reflection:
        service_names = [
            reflection.SERVICE_NAME,
            health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
            nf_health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
        ]
        reflection.enable_server_reflection(tuple(service_names), server)

    return server


def serve(cfg: Optional[ServerConfig] = None) -> None:
    cfg = cfg or ServerConfig()

    # Метрики Prometheus (отдельный HTTP порт)
    if cfg.enable_prometheus and _PROM_AVAILABLE:
        start_http_server(cfg.prometheus_port)
        LOG.info(f"prometheus metrics on :{cfg.prometheus_port}")

    server = build_server(cfg)
    addr = f"{cfg.host}:{cfg.port}"
    creds = _load_server_credentials(cfg)
    if creds:
        server.add_secure_port(addr, creds)
        LOG.info(f"gRPC TLS on {addr} (mTLS={'on' if cfg.tls_client_ca_path else 'off'})")
    else:
        server.add_insecure_port(addr)
        LOG.info(f"gRPC insecure on {addr}")

    # Грациозная остановка
    stop_event = threading.Event()

    def handle_signal(signum, frame):
        LOG.warning(f"signal {signum} received, shutting down...")
        stop_event.set()
        # Переводим health в NOT_SERVING
        try:
            # Общий канал "" уже зарегистрирован в build_server
            pass
        except Exception:
            pass

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    server.start()
    LOG.info("gRPC server started")

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        LOG.info("stopping gRPC server gracefully...")
        # 10 секунд на корректное завершение активных RPC
        server.stop(grace=10).wait(10)
        LOG.info("gRPC server stopped")


# =============================================================================
# Вспомогательные функции времени/продолжительности для protobuf
# =============================================================================

def _ts(epoch_sec: int):
    # google.protobuf.Timestamp
    from google.protobuf.timestamp_pb2 import Timestamp

    t = Timestamp()
    t.FromSeconds(epoch_sec)
    return t


def _duration_ms(dur):
    # google.protobuf.Duration -> миллисекунды
    try:
        from google.protobuf.duration_pb2 import Duration

        if isinstance(dur, Duration):
            return dur.seconds * 1000 + dur.nanos // 1_000_000
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    serve()
