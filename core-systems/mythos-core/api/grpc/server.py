# -*- coding: utf-8 -*-
"""
mythos-core/api/grpc/server.py

Промышленный gRPC сервер (grpc.aio) с поддержкой:
- TLS/mTLS (по окружению)
- Health Checking (grpc.health.v1)
- Reflection
- Перехватчики: аутентификация (JWT/MTLS-хук), наблюдаемость (логирование + метрики)
- Prometheus метрики (опционально)
- Корреляция запросов (x-request-id) и возврат в trailing metadata
- Keepalive/лимиты/компрессия
- Graceful shutdown по SIGTERM/SIGINT

Зависимости:
  grpcio>=1.57, grpcio-health-checking, grpcio-reflection
  prometheus_client (опционально, для метрик)

Лицензия: proprietary (Aethernova / Mythos Core)
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Sequence, Tuple

import grpc
from grpc import aio

# Инфраструктурные сервисы (опционально доступны в окружении)
try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc  # type: ignore
except Exception:  # pragma: no cover
    health = None
    health_pb2 = None
    health_pb2_grpc = None

try:
    from grpc_reflection.v1alpha import reflection  # type: ignore
except Exception:  # pragma: no cover
    reflection = None

# Метрики Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None
    start_http_server = None


# -----------------------------------------------------------------------------
# Конфигурация
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class ServerConfig:
    host: str = os.getenv("MYTHOS_GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("MYTHOS_GRPC_PORT", "8081"))

    max_concurrent_rpcs: int = int(os.getenv("MYTHOS_GRPC_MAX_CONCURRENT_RPCS", "1000"))
    max_message_length: int = int(os.getenv("MYTHOS_GRPC_MAX_MESSAGE_LENGTH", str(40 * 1024 * 1024)))  # 40 MiB
    enable_reflection: bool = os.getenv("MYTHOS_GRPC_REFLECTION", "1") in ("1", "true", "yes")
    enable_health: bool = os.getenv("MYTHOS_GRPC_HEALTH", "1") in ("1", "true", "yes")
    enable_metrics: bool = os.getenv("MYTHOS_METRICS_ENABLED", "1") in ("1", "true", "yes")
    metrics_port: Optional[int] = int(os.getenv("MYTHOS_METRICS_PORT", "0")) or None

    tls_cert_file: Optional[str] = os.getenv("MYTHOS_GRPC_TLS_CERT_FILE") or None
    tls_key_file: Optional[str] = os.getenv("MYTHOS_GRPC_TLS_KEY_FILE") or None
    tls_ca_file: Optional[str] = os.getenv("MYTHOS_GRPC_TLS_CA_FILE") or None
    require_client_cert: bool = os.getenv("MYTHOS_GRPC_REQUIRE_CLIENT_CERT", "0") in ("1", "true", "yes")

    # Keepalive (значения подобраны консервативно)
    ka_time_ms: int = int(os.getenv("MYTHOS_GRPC_KA_TIME_MS", "20000"))
    ka_timeout_ms: int = int(os.getenv("MYTHOS_GRPC_KA_TIMEOUT_MS", "10000"))
    ka_permit_wo_calls: bool = os.getenv("MYTHOS_GRPC_KA_PERMIT_WO_CALLS", "1") in ("1", "true", "yes")

    # Компрессия (gzip) — опционально
    compression: Optional[str] = os.getenv("MYTHOS_GRPC_COMPRESSION", "gzip") or None

    # Явный список имён сервисов для health/reflection (добавьте ваши)
    service_names_csv: str = os.getenv("MYTHOS_GRPC_SERVICE_NAMES", "").strip()


# -----------------------------------------------------------------------------
# Метрики и логирование
# -----------------------------------------------------------------------------

def setup_logging() -> None:
    level = os.getenv("MYTHOS_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt="%(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers[:] = [handler]


class Observability:
    """Обёртка для метрик Prometheus + вспомогательные методы логирования."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and Counter is not None and Histogram is not None
        if self.enabled:
            # Кардинальность меток ограничена методом и кодом ответа
            self.rpc_started = Counter(
                "grpc_server_started_total", "Started RPCs", ["grpc_method"]
            )
            self.rpc_handled = Counter(
                "grpc_server_handled_total", "Handled RPCs", ["grpc_method", "grpc_code"]
            )
            self.rpc_latency = Histogram(
                "grpc_server_handling_seconds",
                "RPC latency (seconds)",
                ["grpc_method"],
                buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
            )
            self.inflight = Gauge(
                "grpc_server_inflight_requests", "Inflight RPCs", ["grpc_method"]
            )

    def start_metrics_http(self, port: Optional[int]) -> None:
        if self.enabled and start_http_server and port:
            start_http_server(port)


# -----------------------------------------------------------------------------
# Перехватчики
# -----------------------------------------------------------------------------

class ObservabilityInterceptor(aio.ServerInterceptor):
    """Единый перехватчик: корреляция, логирование, метрики, trailing metadata."""

    def __init__(self, obs: Observability) -> None:
        self.obs = obs

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:

        method = handler_call_details.method or "unknown"
        handler = await continuation(handler_call_details)

        # Оборачиваем все четыре вида RPC
        if handler.unary_unary:
            inner = handler.unary_unary

            async def unary_unary_wrapper(request, context: aio.ServicerContext):
                started = time.perf_counter()
                rid = _ensure_request_id(context)
                _metrics_started(self.obs, method)
                with _inflight(self.obs, method):
                    try:
                        resp = await inner(request, context)
                        await _set_trailing_request_id(context, rid)
                        code = context.code() or grpc.StatusCode.OK
                        _metrics_finished(self.obs, method, code, started)
                        _log_success(method, rid, code)
                        return resp
                    except Exception as ex:  # noqa: BLE001
                        code = _abort_with(context, ex)
                        await _set_trailing_request_id(context, rid)
                        _metrics_finished(self.obs, method, code, started)
                        _log_error(method, rid, code, ex)
                        raise

            return grpc.unary_unary_rpc_method_handler(
                unary_unary_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            async def unary_stream_wrapper(request, context: aio.ServicerContext):
                started = time.perf_counter()
                rid = _ensure_request_id(context)
                _metrics_started(self.obs, method)
                with _inflight(self.obs, method):
                    try:
                        async for item in inner(request, context):
                            yield item
                        await _set_trailing_request_id(context, rid)
                        code = context.code() or grpc.StatusCode.OK
                        _metrics_finished(self.obs, method, code, started)
                        _log_success(method, rid, code)
                    except Exception as ex:  # noqa: BLE001
                        code = _abort_with(context, ex)
                        await _set_trailing_request_id(context, rid)
                        _metrics_finished(self.obs, method, code, started)
                        _log_error(method, rid, code, ex)
                        raise

            return grpc.unary_stream_rpc_method_handler(
                unary_stream_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            inner = handler.stream_unary

            async def stream_unary_wrapper(request_iterator, context: aio.ServicerContext):
                started = time.perf_counter()
                rid = _ensure_request_id(context)
                _metrics_started(self.obs, method)
                with _inflight(self.obs, method):
                    try:
                        resp = await inner(request_iterator, context)
                        await _set_trailing_request_id(context, rid)
                        code = context.code() or grpc.StatusCode.OK
                        _metrics_finished(self.obs, method, code, started)
                        _log_success(method, rid, code)
                        return resp
                    except Exception as ex:  # noqa: BLE001
                        code = _abort_with(context, ex)
                        await _set_trailing_request_id(context, rid)
                        _metrics_finished(self.obs, method, code, started)
                        _log_error(method, rid, code, ex)
                        raise

            return grpc.stream_unary_rpc_method_handler(
                stream_unary_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            inner = handler.stream_stream

            async def stream_stream_wrapper(request_iterator, context: aio.ServicerContext):
                started = time.perf_counter()
                rid = _ensure_request_id(context)
                _metrics_started(self.obs, method)
                with _inflight(self.obs, method):
                    try:
                        async for item in inner(request_iterator, context):
                            yield item
                        await _set_trailing_request_id(context, rid)
                        code = context.code() or grpc.StatusCode.OK
                        _metrics_finished(self.obs, method, code, started)
                        _log_success(method, rid, code)
                    except Exception as ex:  # noqa: BLE001
                        code = _abort_with(context, ex)
                        await _set_trailing_request_id(context, rid)
                        _metrics_finished(self.obs, method, code, started)
                        _log_error(method, rid, code, ex)
                        raise

            return grpc.stream_stream_rpc_method_handler(
                stream_stream_wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler  # на случай неизвестного типа

class AuthInterceptor(aio.ServerInterceptor):
    """
    Перехватчик аутентификации:
    - При наличии мандата в metadata 'authorization: Bearer <token>' вызывает колбэк проверки
    - При mTLS может проверять subject из контекста (peer identity) — хук оставлен для интеграции
    """

    def __init__(self, validator: Optional[Callable[[str], bool]] = None) -> None:
        self.validator = validator

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        method = handler_call_details.method

        async def ensure_auth(context: aio.ServicerContext) -> None:
            if not self.validator:
                return
            md = dict(context.invocation_metadata())
            token = md.get("authorization") or md.get("Authorization")
            if token and token.lower().startswith("bearer "):
                jwt = token[7:].strip()
                if self.validator(jwt):
                    return
            # Можно также сверять SPIFFE/Subject при mTLS (context.peer())
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "unauthenticated")

        # Оборачивание по типам
        if handler.unary_unary:
            inner = handler.unary_unary

            async def uuw(req, ctx):
                await ensure_auth(ctx)
                return await inner(req, ctx)

            return grpc.unary_unary_rpc_method_handler(
                uuw, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            async def usw(req, ctx):
                await ensure_auth(ctx)
                async for item in inner(req, ctx):
                    yield item

            return grpc.unary_stream_rpc_method_handler(
                usw, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer
            )

        if handler.stream_unary:
            inner = handler.stream_unary

            async def suw(req_it, ctx):
                await ensure_auth(ctx)
                return await inner(req_it, ctx)

            return grpc.stream_unary_rpc_method_handler(
                suw, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer
            )

        if handler.stream_stream:
            inner = handler.stream_stream

            async def ssw(req_it, ctx):
                await ensure_auth(ctx)
                async for item in inner(req_it, ctx):
                    yield item

            return grpc.stream_stream_rpc_method_handler(
                ssw, request_deserializer=handler.request_deserializer, response_serializer=handler.response_serializer
            )

        return handler


# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

def _ensure_request_id(context: aio.ServicerContext) -> str:
    md = dict(context.invocation_metadata())
    rid = md.get("x-request-id") or str(uuid.uuid4())
    context.set_trailing_metadata((("x-request-id", rid),))
    return rid

async def _set_trailing_request_id(context: aio.ServicerContext, rid: str) -> None:
    # gRPC Python добавляет trailing метаданные один раз; аккуратно дополняем
    context.set_trailing_metadata((("x-request-id", rid),))

def _metrics_started(obs: Observability, method: str) -> None:
    if obs.enabled:
        obs.rpc_started.labels(method).inc()

def _metrics_finished(obs: Observability, method: str, code: grpc.StatusCode, started: float) -> None:
    if obs.enabled:
        obs.rpc_handled.labels(method, code.name).inc()
        obs.rpc_latency.labels(method).observe(max(0.0, time.perf_counter() - started))

class _inflight:
    def __init__(self, obs: Observability, method: str) -> None:
        self.obs = obs
        self.method = method
    def __enter__(self):
        if self.obs.enabled:
            self.obs.inflight.labels(self.method).inc()
    def __exit__(self, exc_type, exc, tb):
        if self.obs.enabled:
            self.obs.inflight.labels(self.method).dec()

def _log_success(method: str, request_id: str, code: grpc.StatusCode) -> None:
    logging.info(
        '{"event":"rpc","method":"%s","code":"%s","request_id":"%s"}',
        method, code.name, request_id
    )

def _log_error(method: str, request_id: str, code: grpc.StatusCode, ex: Exception) -> None:
    logging.error(
        '{"event":"rpc_error","method":"%s","code":"%s","request_id":"%s","error":"%s"}',
        method, code.name, request_id, str(ex).replace('"', '\\"')
    )

def _abort_with(context: aio.ServicerContext, ex: Exception) -> grpc.StatusCode:
    if isinstance(ex, grpc.RpcError):
        return ex.code() or grpc.StatusCode.UNKNOWN
    # Мягкое сопоставление распространённых исключений
    if isinstance(ex, asyncio.CancelledError):
        context.abort(grpc.StatusCode.CANCELLED, "cancelled")
    context.abort(grpc.StatusCode.INTERNAL, "internal")
    return grpc.StatusCode.INTERNAL  # недостижимо


def _server_options(cfg: ServerConfig) -> Sequence[Tuple[str, Any]]:
    opts: list[Tuple[str, Any]] = [
        ("grpc.max_receive_message_length", cfg.max_message_length),
        ("grpc.max_send_message_length", cfg.max_message_length),
        ("grpc.keepalive_time_ms", cfg.ka_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.ka_timeout_ms),
        ("grpc.keepalive_permit_without_calls", int(cfg.ka_permit_wo_calls)),
        ("grpc.http2.min_time_between_pings_ms", 10000),
        ("grpc.http2.max_pings_without_data", 0),
    ]
    if cfg.compression and cfg.compression.lower() == "gzip":
        opts.append(("grpc.default_compression_algorithm", grpc.Compression.Gzip))
    return opts


def _build_credentials(cfg: ServerConfig) -> Optional[grpc.ServerCredentials]:
    if not cfg.tls_cert_file or not cfg.tls_key_file:
        return None
    with open(cfg.tls_cert_file, "rb") as f:
        cert = f.read()
    with open(cfg.tls_key_file, "rb") as f:
        key = f.read()
    ca = None
    if cfg.tls_ca_file and os.path.exists(cfg.tls_ca_file):
        with open(cfg.tls_ca_file, "rb") as f:
            ca = f.read()
    return grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(key, cert)],
        root_certificates=ca,
        require_client_auth=bool(ca and cfg.require_client_cert),
    )


# -----------------------------------------------------------------------------
# Регистрация сервисов
# -----------------------------------------------------------------------------

def _register_infrastructure_services(
    server: aio.Server,
    cfg: ServerConfig,
) -> Tuple[Optional[Any], Sequence[str]]:
    svc_names: list[str] = []

    # Health
    health_svc = None
    if cfg.enable_health and health and health_pb2_grpc:
        health_svc = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_svc, server)
        svc_names.append(health.SERVICE_NAME)

    # Reflection
    if cfg.enable_reflection and reflection:
        # Перечень сервисов для рефлексии: health + ваши
        base = [reflection.SERVICE_NAME]
        if health_svc:
            base.append(health.SERVICE_NAME)
        extra = [s.strip() for s in cfg.service_names_csv.split(",") if s.strip()]
        reflection.enable_server_reflection(base + extra, server)

    return health_svc, tuple(svc_names)


def _set_health_status_ready(health_svc: Any, cfg: ServerConfig) -> None:
    if not health_svc or not health_pb2:
        return
    # Общий статус процесса
    health_svc.set("", health_pb2.HealthCheckResponse.SERVING)
    # Явно заявленные сервисы (если указаны)
    for name in [s.strip() for s in cfg.service_names_csv.split(",") if s.strip()]:
        health_svc.set(name, health_pb2.HealthCheckResponse.SERVING)


def _set_health_status_not_serving(health_svc: Any, cfg: ServerConfig) -> None:
    if not health_svc or not health_pb2:
        return
    health_svc.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
    for name in [s.strip() for s in cfg.service_names_csv.split(",") if s.strip()]:
        health_svc.set(name, health_pb2.HealthCheckResponse.NOT_SERVING)


def _register_business_services(server: aio.Server) -> Sequence[str]:
    """
    Подключите здесь ваши gRPC-сервисы.

    Пример:
        from mythos_core.schemas.proto.v1.my_service_pb2_grpc import add_MyServiceServicer_to_server
        from mythos_core.api.grpc.impl.my_service import MyService

        add_MyServiceServicer_to_server(MyService(), server)
        return ("mythos.v1.MyService",)

    Сейчас возвращаем пустой список, чтобы файл был самодостаточен.
    """
    return ()


# -----------------------------------------------------------------------------
# main: запуск сервера
# -----------------------------------------------------------------------------

async def serve() -> None:
    setup_logging()
    cfg = ServerConfig()

    obs = Observability(cfg.enable_metrics)
    obs.start_metrics_http(cfg.metrics_port)

    interceptors: list[aio.ServerInterceptor] = [
        ObservabilityInterceptor(obs),
        AuthInterceptor(_env_jwt_validator()),
    ]

    server = aio.server(
        interceptors=interceptors,
        options=_server_options(cfg),
        maximum_concurrent_rpcs=cfg.max_concurrent_rpcs,
        compression=(grpc.Compression.Gzip if (cfg.compression or "").lower() == "gzip" else None),
    )

    # Регистрация бизнес-сервисов
    business_services = _register_business_services(server)

    # Инфраструктура: health/reflection
    health_svc, infra_services = _register_infrastructure_services(server, cfg)

    # Порты и TLS
    creds = _build_credentials(cfg)
    bind_target = f"{cfg.host}:{cfg.port}"
    if creds:
        port = server.add_secure_port(bind_target, creds)
    else:
        port = server.add_insecure_port(bind_target)
    if port != cfg.port:
        logging.warning('{"event":"bind_warning","requested":%d,"bound":%d}', cfg.port, port)

    # Старт
    await server.start()
    _set_health_status_ready(health_svc, cfg)

    logging.info(
        '{"event":"grpc_server_started","bind":"%s","tls":%s,"services":%s}',
        bind_target,
        bool(creds),
        list(business_services) + list(infra_services),
    )

    # Грациозное завершение по сигналам
    stop_event = asyncio.Event()

    def _signal_handler(sig: int, _frame=None) -> None:
        logging.info('{"event":"signal","sig":"%s"}', signal.Signals(sig).name)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _signal_handler, s)
        except NotImplementedError:  # Windows
            signal.signal(s, _signal_handler)

    # Ожидаем сигнал
    await stop_event.wait()
    _set_health_status_not_serving(health_svc, cfg)

    # Аккуратная остановка
    await server.stop(grace=10.0)
    logging.info('{"event":"grpc_server_stopped"}')

def _env_jwt_validator() -> Optional[Callable[[str], bool]]:
    """
    Пример заглушки валидатора JWT из окружения:
    - Если переменная MYTHOS_JWT_AUDIENCE задана, здесь можно интегрировать pyjwt/jwk
    - По умолчанию возвращаем None (валидация отключена)
    """
    aud = os.getenv("MYTHOS_JWT_AUDIENCE")
    if not aud:
        return None

    def _validate(token: str) -> bool:
        # ВНИМАНИЕ: Здесь должна быть реальная проверка подписи и claims.
        # Оставлено намеренно как заглушка (возвращает False для пустых и True иначе).
        return bool(token.strip())

    return _validate


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
