# -*- coding: utf-8 -*-
"""
Industrial gRPC Server (async, v1)

Особенности:
- grpc.aio (полностью асинхронный сервер)
- TLS / mTLS (по конфигу)
- Health Checking (grpc_health) с авто-менеджментом статуса
- Reflection (grpc_reflection) для отладки и клиента без .proto
- Корреляция запросов (x-request-id), логирование, метаданные
- Идемпотентность (по метадате idempotency-key) через кэш ответов
- Rate limiting per-method (token-bucket, настраиваемый)
- Централизованный перехват исключений и маппинг в gRPC Status
- Тонкая настройка keepalive, потоки, размеры сообщений
- Graceful shutdown по сигналам SIGINT/SIGTERM
- Точки расширения: register_services(server), middleware interceptors, hooks

Замените заглушки Auth/JWT на реальные (issuer/aud/exp/kid) и IdempotencyStore на Redis/Memcached в продакшене.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import ssl
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import grpc
from grpc import aio

# Optional: Health & Reflection (необязательные зависимости; сервер работает и без них)
try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc  # type: ignore
    HAS_HEALTH = True
except Exception:
    HAS_HEALTH = False

try:
    from grpc_reflection.v1alpha import reflection  # type: ignore
    HAS_REFLECTION = True
except Exception:
    HAS_REFLECTION = False


# -----------------------------------------------------------------------------
# Логирование
# -----------------------------------------------------------------------------

logger = logging.getLogger("engine_core.grpc.server")
if not logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# Конфигурация
# -----------------------------------------------------------------------------

@dataclass
class TLSConfig:
    cert_chain_path: Optional[str] = None
    private_key_path: Optional[str] = None
    client_ca_path: Optional[str] = None  # при указании включится mTLS (require client cert)

    def build_credentials(self) -> Optional[grpc.ServerCredentials]:
        if not self.cert_chain_path or not self.private_key_path:
            return None
        with open(self.private_key_path, "rb") as f:
            private_key = f.read()
        with open(self.cert_chain_path, "rb") as f:
            cert_chain = f.read()
        if self.client_ca_path:
            with open(self.client_ca_path, "rb") as f:
                root_ca = f.read()
            return grpc.ssl_server_credentials(
                [(private_key, cert_chain)],
                root_certificates=root_ca,
                require_client_auth=True,
            )
        return grpc.ssl_server_credentials([(private_key, cert_chain)])


@dataclass
class RateLimitRule:
    rate: int = 100  # tokens per window
    per_seconds: int = 60  # window seconds


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 7000
    # gRPC channel/server options
    max_concurrent_streams: int = 1024
    max_send_message_length: int = 32 * 1024 * 1024
    max_receive_message_length: int = 32 * 1024 * 1024
    keepalive_time_ms: int = 30_000
    keepalive_timeout_ms: int = 10_000
    keepalive_permit_without_calls: int = 1
    http2_max_pings_without_data: int = 0
    http2_min_time_between_pings_ms: int = 10_000
    http2_min_ping_interval_without_data_ms: int = 10_000

    # TLS/mTLS
    tls: TLSConfig = field(default_factory=TLSConfig)

    # Rate limits per full method name (e.g. "/pkg.Service/Method"), fallback_rule applies if not found
    rate_limits: Dict[str, RateLimitRule] = field(default_factory=dict)
    fallback_rate_limit: RateLimitRule = field(default_factory=lambda: RateLimitRule(rate=300, per_seconds=60))

    # Идемпотентность: TTL кэша ответа
    idempotency_ttl_seconds: int = 900

    # Health/Reflection
    enable_health: bool = True
    enable_reflection: bool = True

    # Сервисные имена для health/reflect (автодобавление при регистрации)
    registered_service_names: List[str] = field(default_factory=list)

    def bind_address(self) -> str:
        return f"{self.host}:{self.port}"

    def grpc_server_options(self) -> List[Tuple[str, Any]]:
        return [
            ("grpc.max_send_message_length", self.max_send_message_length),
            ("grpc.max_receive_message_length", self.max_receive_message_length),
            ("grpc.http2.max_pings_without_data", self.http2_max_pings_without_data),
            ("grpc.keepalive_time_ms", self.keepalive_time_ms),
            ("grpc.keepalive_timeout_ms", self.keepalive_timeout_ms),
            ("grpc.keepalive_permit_without_calls", self.keepalive_permit_without_calls),
            ("grpc.http2.min_time_between_pings_ms", self.http2_min_time_between_pings_ms),
            ("grpc.http2.min_ping_interval_without_data_ms", self.http2_min_ping_interval_without_data_ms),
            ("grpc.max_concurrent_streams", self.max_concurrent_streams),
        ]


# -----------------------------------------------------------------------------
# Вспомогательные структуры
# -----------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class TokenBucket:
    def __init__(self, rate: int, per_seconds: int):
        self.capacity = max(1, rate)
        self.tokens = self.capacity
        self.per_seconds = max(1, per_seconds)
        self.updated_at = time.time()

    def consume(self, amount: int = 1) -> Tuple[bool, int, int]:
        now = time.time()
        elapsed = now - self.updated_at
        refill = int((elapsed / self.per_seconds) * self.capacity)
        if refill > 0:
            self.tokens = min(self.capacity, self.tokens + refill)
            self.updated_at = now
        if self.tokens >= amount:
            self.tokens -= amount
            reset_in = self.per_seconds - int((now - self.updated_at))
            return True, self.tokens, max(0, reset_in)
        reset_in = self.per_seconds - int((now - self.updated_at))
        return False, self.tokens, max(0, reset_in)


class IdempotencyStore:
    """In-memory идемпотентный кэш ответов. Замените на Redis/Memcached в проде."""
    def __init__(self, ttl_seconds: int):
        self._ttl = ttl_seconds
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if not item:
            return None
        ts, value = item
        if time.time() - ts > self._ttl:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time(), value)


# -----------------------------------------------------------------------------
# Interceptors (Auth, RateLimit, Idempotency, Logging, Exception)
# -----------------------------------------------------------------------------

class AuthInterceptor(aio.ServerInterceptor):
    """
    Заглушка авторизации: извлекает user из JWT (метадата "authorization: Bearer ...").
    Замените на проверку ключей/issuer/audience/exp/kid.
    """

    async def intercept_service(self, continuation, handler_call_details):
        metadata = dict(handler_call_details.invocation_metadata or [])
        auth = metadata.get("authorization") or metadata.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            context = grpc.ServicerContext  # type: ignore
            # Нельзя напрямую останавливать здесь без контекста; проверка в хендлере wrapper ниже:
            # Мы завернем хендлер, чтобы вернуть UNAUTHENTICATED до вызова business-логики.
        handler = await continuation(handler_call_details)

        async def aborting_unary_unary(request, context):
            md = dict(context.invocation_metadata())
            token = md.get("authorization") or md.get("Authorization")
            if not token or not token.lower().startswith("bearer "):
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Missing or invalid Bearer token")
            return await handler.unary_unary(request, context)

        async def aborting_unary_stream(request, context):
            md = dict(context.invocation_metadata())
            token = md.get("authorization") or md.get("Authorization")
            if not token or not token.lower().startswith("bearer "):
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Missing or invalid Bearer token")
            async for resp in handler.unary_stream(request, context):
                yield resp

        # Поддержка только наиболее частых паттернов (unary-unary / unary-stream).
        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(
                aborting_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(
                aborting_unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class RateLimitInterceptor(aio.ServerInterceptor):
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self._buckets: Dict[str, TokenBucket] = {}

    def _bucket_for(self, method: str) -> TokenBucket:
        rule = self.cfg.rate_limits.get(method, self.cfg.fallback_rate_limit)
        key = f"{method}:{rule.rate}/{rule.per_seconds}"
        b = self._buckets.get(key)
        if not b:
            b = TokenBucket(rule.rate, rule.per_seconds)
            self._buckets[key] = b
        return b

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        method = handler_call_details.method

        async def limited_unary_unary(request, context):
            ok, remaining, reset = self._bucket_for(method).consume(1)
            if not ok:
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
            # Проставим трейлинг-метаданные с лимитом
            context.set_trailing_metadata((
                ("x-rate-limit", str(self.cfg.rate_limits.get(method, self.cfg.fallback_rate_limit).rate)),
                ("x-rate-remaining", str(max(0, remaining))),
                ("x-rate-reset", str(reset)),
            ))
            return await handler.unary_unary(request, context)

        async def limited_unary_stream(request, context):
            ok, remaining, reset = self._bucket_for(method).consume(1)
            if not ok:
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
            context.set_trailing_metadata((
                ("x-rate-limit", str(self.cfg.rate_limits.get(method, self.cfg.fallback_rate_limit).rate)),
                ("x-rate-remaining", str(max(0, remaining))),
                ("x-rate-reset", str(reset)),
            ))
            async for resp in handler.unary_stream(request, context):
                yield resp

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(
                limited_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(
                limited_unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class IdempotencyInterceptor(aio.ServerInterceptor):
    """
    Идемпотентность на основе gRPC метадаты "idempotency-key".
    Для unary-unary: кэшируем сериализованный ответ.
    """
    def __init__(self, ttl_seconds: int):
        self.store = IdempotencyStore(ttl_seconds)

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def idem_unary_unary(request, context):
            md = dict(context.invocation_metadata())
            key = md.get("idempotency-key")
            if key:
                cached = self.store.get(key)
                if cached is not None:
                    # Возвращаем уже сериализованный proto-ответ
                    return cached
            resp = await handler.unary_unary(request, context)
            if key:
                self.store.set(key, resp)
            return resp

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(
                idem_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class LoggingInterceptor(aio.ServerInterceptor):
    """
    Корреляция x-request-id (из метадаты или генерируется), логирование начала/окончания вызова,
    дедлайны и размеры сообщений (по возможности).
    """

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        method = handler_call_details.method

        async def log_unary_unary(request, context):
            md = dict(context.invocation_metadata())
            req_id = md.get("x-request-id") or str(uuid.uuid4())
            start = time.time()
            deadline = context.time_remaining() if context.time_remaining() is not None else None
            logger.info("gRPC start",
                        extra={"method": method, "request_id": req_id, "deadline_s": deadline})
            try:
                resp = await handler.unary_unary(request, context)
                dur = int((time.time() - start) * 1000)
                context.set_trailing_metadata((("x-request-id", req_id),))
                logger.info("gRPC finish",
                            extra={"method": method, "request_id": req_id, "duration_ms": dur})
                return resp
            except grpc.RpcError as e:
                dur = int((time.time() - start) * 1000)
                logger.warning("gRPC rpc_error",
                               extra={"method": method, "request_id": req_id, "duration_ms": dur, "code": str(e.code())})
                raise
            except Exception:
                dur = int((time.time() - start) * 1000)
                logger.exception("gRPC unhandled",
                                 extra={"method": method, "request_id": req_id, "duration_ms": dur})
                raise

        async def log_unary_stream(request, context):
            md = dict(context.invocation_metadata())
            req_id = md.get("x-request-id") or str(uuid.uuid4())
            start = time.time()
            deadline = context.time_remaining() if context.time_remaining() is not None else None
            logger.info("gRPC start",
                        extra={"method": method, "request_id": req_id, "deadline_s": deadline})
            try:
                async for resp in handler.unary_stream(request, context):
                    yield resp
                dur = int((time.time() - start) * 1000)
                context.set_trailing_metadata((("x-request-id", req_id),))
                logger.info("gRPC finish",
                            extra={"method": method, "request_id": req_id, "duration_ms": dur})
            except grpc.RpcError as e:
                dur = int((time.time() - start) * 1000)
                logger.warning("gRPC rpc_error",
                               extra={"method": method, "request_id": req_id, "duration_ms": dur, "code": str(e.code())})
                raise
            except Exception:
                dur = int((time.time() - start) * 1000)
                logger.exception("gRPC unhandled",
                                 extra={"method": method, "request_id": req_id})
                raise

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(
                log_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(
                log_unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class ExceptionMappingInterceptor(aio.ServerInterceptor):
    """
    Централизованное преобразование непойманных исключений в INTERNAL с безопасным сообщением.
    """

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def safe_unary_unary(request, context):
            try:
                return await handler.unary_unary(request, context)
            except grpc.RpcError:
                raise
            except asyncio.CancelledError:
                await context.abort(grpc.StatusCode.CANCELLED, "Request cancelled")
            except Exception:
                logger.exception("Unhandled business exception")
                await context.abort(grpc.StatusCode.INTERNAL, "Internal Server Error")

        async def safe_unary_stream(request, context):
            try:
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except grpc.RpcError:
                raise
            except asyncio.CancelledError:
                await context.abort(grpc.StatusCode.CANCELLED, "Request cancelled")
            except Exception:
                logger.exception("Unhandled business exception")
                await context.abort(grpc.StatusCode.INTERNAL, "Internal Server Error")

        if handler.unary_unary:
            return grpc.aio.unary_unary_rpc_method_handler(
                safe_unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.aio.unary_stream_rpc_method_handler(
                safe_unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


# -----------------------------------------------------------------------------
# Регистрация сервисов (передайте сюда свои register_* функции)
# -----------------------------------------------------------------------------

ServiceRegistrar = Callable[[aio.Server, ServerConfig], None]

async def _register_health(server: aio.Server, cfg: ServerConfig) -> Optional[str]:
    if not (cfg.enable_health and HAS_HEALTH):
        return None
    health_servicer = health.HealthServicer()
    # По умолчанию статус SERVING для всего сервера, имена сервисов будут добавляться по мере регистрации
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    # Сохраним в объект server для управления статусом в рантайме
    setattr(server, "_health_servicer", health_servicer)
    return health.SERVICE_NAME  # "grpc.health.v1.Health"

def set_service_health(server: aio.Server, service_name: str, serving: bool) -> None:
    """
    Вспомогательная функция для ваших регистраций: отмечайте сервис служащим/нет.
    """
    servicer = getattr(server, "_health_servicer", None)
    if not servicer:
        return
    status = health_pb2.HealthCheckResponse.SERVING if serving else health_pb2.HealthCheckResponse.NOT_SERVING
    servicer.set(service_name, status)


async def _enable_reflection(server: aio.Server, cfg: ServerConfig) -> Optional[str]:
    if not (cfg.enable_reflection and HAS_REFLECTION):
        return None
    # Reflection требует список имен сервисов; health/reflection добавим автоматически
    names = list(cfg.registered_service_names)
    if cfg.enable_health and HAS_HEALTH:
        names.append(health.SERVICE_NAME)
    names.append(reflection.SERVICE_NAME)
    reflection.enable_server_reflection(tuple(names), server)
    return reflection.SERVICE_NAME


# -----------------------------------------------------------------------------
# Сборка и запуск сервера
# -----------------------------------------------------------------------------

def _build_server(cfg: ServerConfig, registrars: Iterable[ServiceRegistrar]) -> aio.Server:
    # Interceptors порядок: Exceptions -> Auth -> RateLimit -> Idempotency -> Logging
    interceptors: List[aio.ServerInterceptor] = [
        ExceptionMappingInterceptor(),
        AuthInterceptor(),
        RateLimitInterceptor(cfg),
        IdempotencyInterceptor(cfg.idempotency_ttl_seconds),
        LoggingInterceptor(),
    ]

    server = aio.server(
        options=cfg.grpc_server_options(),
        interceptors=interceptors,
        maximum_concurrent_rpcs=cfg.max_concurrent_streams,
    )

    # Register services
    for reg in registrars:
        reg(server, cfg)

    return server


async def serve(
    cfg: ServerConfig,
    registrars: Iterable[ServiceRegistrar],
    *,
    on_started: Optional[Callable[[ServerConfig], Awaitable[None]]] = None,
    on_stopping: Optional[Callable[[ServerConfig], Awaitable[None]]] = None,
) -> None:
    server = _build_server(cfg, registrars)

    # Health & Reflection
    health_name = await _register_health(server, cfg)
    if health_name:
        cfg.registered_service_names.append(health_name)

    refl_name = await _enable_reflection(server, cfg)
    if refl_name and refl_name not in cfg.registered_service_names:
        cfg.registered_service_names.append(refl_name)

    address = cfg.bind_address()
    creds = cfg.tls.build_credentials()
    if creds:
        server.add_secure_port(address, creds)
        logger.info("gRPC server bound (TLS)", extra={"address": address, "mtls": bool(cfg.tls.client_ca_path)})
    else:
        server.add_insecure_port(address)
        logger.warning("gRPC server bound (PLAINTEXT)", extra={"address": address})

    # Если есть health, переведем общее имя сервера в SERVING
    if HAS_HEALTH and cfg.enable_health:
        set_service_health(server, "", True)  # "" означает весь сервер

    await server.start()
    logger.info("gRPC server started", extra={"address": address})

    if on_started:
        await on_started(cfg)

    # Graceful shutdown по сигналам
    stop_event = asyncio.Event()

    def _signal_handler(sig):
        logger.info("Received signal", extra={"signal": sig})
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler, sig.name)
        except NotImplementedError:
            # Windows
            signal.signal(sig, lambda *_: _signal_handler(sig.name))

    await stop_event.wait()

    # Перед остановкой — отметить как NOT_SERVING
    if HAS_HEALTH and cfg.enable_health:
        set_service_health(server, "", False)
        for name in cfg.registered_service_names:
            set_service_health(server, name, False)

    if on_stopping:
        await on_stopping(cfg)

    # Даем 10 секунд на завершение активных запросов
    await server.stop(grace=10)
    logger.info("gRPC server stopped", extra={"address": address})


# -----------------------------------------------------------------------------
# Пример регистратора: Noop Ping Service (для smoke‑тестов)
# Замените/удалите в проде, здесь — как образец подключения сервиса.
# -----------------------------------------------------------------------------

# Простейшая Proto‑less реализация невозможна; ожидается сгенерированный код из .proto.
# Для полноты примера покажем схему подключения: предполагается сгенерированный
# модуль mypkg.ping_pb2_grpc с классом add_PingServiceServicer_to_server и Servicer.

class _ExamplePingServicer:  # pragma: no cover - демонстрационный каркас
    # Ожидаются методы: async def Ping(self, request, context): ...
    pass


def register_example_ping(server: aio.Server, cfg: ServerConfig) -> None:
    """
    Подключение вашего сервиса должно выглядеть аналогично:
    from mypkg import ping_pb2_grpc
    ping_pb2_grpc.add_PingServiceServicer_to_server(MyPingServicer(), server)
    cfg.registered_service_names.append(ping_pb2_grpc.DESCRIPTOR.services_by_name["PingService"].full_name)
    set_service_health(server, "mypkg.PingService", True)
    """
    # Заглушка: не регистрируем, лишь показываем паттерн.
    return


# -----------------------------------------------------------------------------
# Точка входа (опционально). Включите при самостоятельном запуске модуля.
# -----------------------------------------------------------------------------

async def _on_started(cfg: ServerConfig) -> None:
    logger.info("on_started hook", extra={"time": now_utc().isoformat()})

async def _on_stopping(cfg: ServerConfig) -> None:
    logger.info("on_stopping hook", extra={"time": now_utc().isoformat()})

def _config_from_env() -> ServerConfig:
    def getenv_int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)))
        except Exception:
            return default

    cfg = ServerConfig(
        host=os.getenv("GRPC_HOST", "0.0.0.0"),
        port=getenv_int("GRPC_PORT", 7000),
        keepalive_time_ms=getenv_int("GRPC_KEEPALIVE_TIME_MS", 30000),
        keepalive_timeout_ms=getenv_int("GRPC_KEEPALIVE_TIMEOUT_MS", 10000),
        idempotency_ttl_seconds=getenv_int("GRPC_IDEMPOTENCY_TTL_S", 900),
    )
    # TLS envs (опционально)
    cert = os.getenv("GRPC_TLS_CERT")
    key = os.getenv("GRPC_TLS_KEY")
    ca = os.getenv("GRPC_TLS_CLIENT_CA")
    if cert and key:
        cfg.tls.cert_chain_path = cert
        cfg.tls.private_key_path = key
    if ca:
        cfg.tls.client_ca_path = ca

    # Пример настройки пер-метод лимитов
    # cfg.rate_limits["/mypkg.PingService/Ping"] = RateLimitRule(rate=50, per_seconds=10)

    return cfg

if __name__ == "__main__":
    cfg = _config_from_env()
    registrars: List[ServiceRegistrar] = [
        register_example_ping,  # Замените на ваши register_* функции
    ]
    asyncio.run(serve(cfg, registrars, on_started=_on_started, on_stopping=_on_stopping))
