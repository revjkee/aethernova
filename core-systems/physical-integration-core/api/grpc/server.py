# physical-integration-core/api/grpc/server.py
# Промышленный gRPC-сервер на asyncio с TLS/mTLS, health, reflection, метриками и перехватчиками.
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import ssl
import time
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import grpc
from grpc import StatusCode
from grpc.aio import ServerInterceptor
from grpc_health.v1 import health, health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import jwt  # PyJWT
from jwt import PyJWKClient

# ======== Конфигурация через переменные окружения ========
APP_NAME = os.getenv("APP_NAME", "physical-integration-core")
APP_VERSION = os.getenv("APP_VERSION", "0.0.0")
ENVIRONMENT = os.getenv("ENV", "prod")
REGION = os.getenv("REGION")

GRPC_HOST = os.getenv("GRPC_HOST", "0.0.0.0")
GRPC_PORT = int(os.getenv("GRPC_PORT", "9091"))
GRPC_MAX_RECV_MB = int(os.getenv("GRPC_MAX_RECV_MB", "64"))
GRPC_MAX_SEND_MB = int(os.getenv("GRPC_MAX_SEND_MB", "64"))

KEEPALIVE_TIME_MS = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "20000"))
KEEPALIVE_TIMEOUT_MS = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000"))
KEEPALIVE_PERMIT_WITHOUT_CALLS = int(os.getenv("GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS", "1"))
MAX_CONCURRENT_STREAMS = int(os.getenv("GRPC_MAX_CONCURRENT_STREAMS", "1024"))

TLS_ENABLED = os.getenv("TLS_ENABLED", "false").lower() == "true"
MTLS_ENABLED = os.getenv("MTLS_ENABLED", "false").lower() == "true"
TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "")
TLS_KEY_FILE = os.getenv("TLS_KEY_FILE", "")
TLS_CA_FILE = os.getenv("TLS_CA_FILE", "")

# Аутентификация JWT/JWKS
AUTH_PROVIDER = os.getenv("AUTH_PROVIDER", "none")  # none|jwt
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "")
AUTH_AUDIENCE = os.getenv("AUTH_AUDIENCE", "")
AUTH_ISSUER = os.getenv("AUTH_ISSUER", "")
AUTH_BEARER_HEADER = os.getenv("AUTH_BEARER_HEADER", "authorization")

# Rate limiting / concurrency
CONCURRENCY_LIMIT = int(os.getenv("GRPC_CONCURRENCY_LIMIT", "0"))  # 0 = без лимита
RATE_LIMIT_QPS = float(os.getenv("GRPC_RATE_LIMIT_QPS", "0"))  # 0 = off
RATE_LIMIT_BURST = int(os.getenv("GRPC_RATE_LIMIT_BURST", "0"))  # 0 = off

# Prometheus metrics
METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() == "true"
METRICS_PORT = int(os.getenv("METRICS_PORT", "9090"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("grpc-server")


# ======== Prometheus метрики ========
RPC_REQ = Counter(
    "grpc_server_requests_total",
    "Total gRPC requests",
    ["service", "method", "code"],
)
RPC_LATENCY = Histogram(
    "grpc_server_request_duration_seconds",
    "gRPC request latency",
    ["service", "method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
RPC_INFLIGHT = Gauge(
    "grpc_server_inflight_requests",
    "In-flight gRPC requests",
    ["service", "method"],
)


def _split_full_method(full_method: str) -> Tuple[str, str]:
    # full_method: "/package.Service/Method"
    try:
        _, sm = full_method.split("/", 1)
        service, method = sm.split("/", 1)
        return service, method
    except Exception:
        return "unknown", "unknown"


# ======== Перехватчик логирования ========
class LoggingInterceptor(ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        service, method = _split_full_method(handler_call_details.method)

        if handler is None:
            return handler

        async def unary_unary(request, context):
            start = time.perf_counter()
            RPC_INFLIGHT.labels(service, method).inc()
            peer = context.peer()
            try:
                response = await handler.unary_unary(request, context)
                code = context.code() or StatusCode.OK
                return response
            except grpc.RpcError as e:
                code = e.code() or StatusCode.UNKNOWN
                raise
            except Exception:
                code = StatusCode.INTERNAL
                logger.exception("Unhandled error in %s/%s", service, method)
                await context.abort(StatusCode.INTERNAL, "internal error")
            finally:
                elapsed = time.perf_counter() - start
                RPC_LATENCY.labels(service, method).observe(elapsed)
                RPC_REQ.labels(service, method, code.name).inc()
                RPC_INFLIGHT.labels(service, method).dec()
                logger.debug(
                    "rpc %s/%s peer=%s code=%s dur=%.3f",
                    service,
                    method,
                    peer,
                    code.name if isinstance(code, StatusCode) else code,
                    elapsed,
                )

        async def unary_stream(request, context):
            start = time.perf_counter()
            RPC_INFLIGHT.labels(service, method).inc()
            peer = context.peer()
            code = StatusCode.OK
            try:
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except grpc.RpcError as e:
                code = e.code() or StatusCode.UNKNOWN
                raise
            except Exception:
                code = StatusCode.INTERNAL
                logger.exception("Unhandled stream error in %s/%s", service, method)
                await context.abort(StatusCode.INTERNAL, "internal error")
            finally:
                elapsed = time.perf_counter() - start
                RPC_LATENCY.labels(service, method).observe(elapsed)
                RPC_REQ.labels(service, method, code.name).inc()
                RPC_INFLIGHT.labels(service, method).dec()
                logger.debug(
                    "rpc-stream %s/%s peer=%s code=%s dur=%.3f",
                    service,
                    method,
                    peer,
                    code.name if isinstance(code, StatusCode) else code,
                    elapsed,
                )

        return grpc.aio.rpc_method_handler(
            unary_unary=unary_unary if handler.unary_unary else None,
            unary_stream=unary_stream if handler.unary_stream else None,
            request_streaming=handler.request_streaming,
            response_streaming=handler.response_streaming,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


# ======== Перехватчик аутентификации (JWT/JWKS) ========
class JwtAuthInterceptor(ServerInterceptor):
    def __init__(self, provider: str, jwks_url: str, audience: str, issuer: str, header: str = "authorization"):
        self.provider = provider
        self.header = header.lower()
        self.audience = audience
        self.issuer = issuer
        self._jwks_client: Optional[PyJWKClient] = PyJWKClient(jwks_url) if (provider == "jwt" and jwks_url) else None

    async def intercept_service(self, continuation, handler_call_details):
        if self.provider == "none":
            return await continuation(handler_call_details)

        # Получаем Bearer токен из метаданных
        metadata = dict(handler_call_details.invocation_metadata or [])
        token = None
        for k, v in metadata.items():
            if k.lower() == self.header:
                if v.lower().startswith("bearer "):
                    token = v[7:].strip()
                else:
                    token = v.strip()
                break

        handler = await continuation(handler_call_details)
        service, method = _split_full_method(handler_call_details.method)

        async def abort_unauth(context, msg="unauthenticated"):
            await context.abort(StatusCode.UNAUTHENTICATED, msg)

        async def unary_unary(request, context):
            if not token:
                return await abort_unauth(context, "missing bearer token")
            try:
                claims = self._decode_jwt(token)
                context.set_trailing_metadata((("x-auth-sub", str(claims.get("sub", ""))),))
                return await handler.unary_unary(request, context)
            except Exception as e:
                logger.debug("JWT validation failed for %s/%s: %s", service, method, e)
                return await abort_unauth(context, "invalid token")

        async def unary_stream(request, context):
            if not token:
                return await abort_unauth(context, "missing bearer token")
            try:
                claims = self._decode_jwt(token)
                context.set_trailing_metadata((("x-auth-sub", str(claims.get("sub", ""))),))
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except Exception as e:
                logger.debug("JWT validation failed for %s/%s: %s", service, method, e)
                await abort_unauth(context, "invalid token")

        return grpc.aio.rpc_method_handler(
            unary_unary=unary_unary if handler.unary_unary else None,
            unary_stream=unary_stream if handler.unary_stream else None,
            request_streaming=handler.request_streaming,
            response_streaming=handler.response_streaming,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        if self.provider != "jwt" or not self._jwks_client:
            raise ValueError("JWT provider not configured")
        signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"],
            audience=self.audience if self.audience else None,
            issuer=self.issuer if self.issuer else None,
            options={"verify_aud": bool(self.audience), "verify_signature": True, "require": []},
        )
        return claims


# ======== Перехватчик rate-limit / concurrency ========
class ThrottleInterceptor(ServerInterceptor):
    def __init__(self, concurrency_limit: int = 0, qps: float = 0.0, burst: int = 0):
        self.sem = asyncio.Semaphore(concurrency_limit) if concurrency_limit > 0 else None
        self.qps = qps
        self.burst = max(burst, 1) if qps > 0 else 0
        self._tokens = self.burst
        self._last = time.perf_counter()

    def _allow(self) -> bool:
        if self.qps <= 0:
            return True
        now = time.perf_counter()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.burst, self._tokens + elapsed * self.qps)
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)

        async def unary_unary(request, context):
            if self.sem:
                async with self.sem:
                    if not self._allow():
                        await context.abort(StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                    return await handler.unary_unary(request, context)
            else:
                if not self._allow():
                    await context.abort(StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                return await handler.unary_unary(request, context)

        async def unary_stream(request, context):
            if self.sem:
                async with self.sem:
                    if not self._allow():
                        await context.abort(StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                    async for resp in handler.unary_stream(request, context):
                        yield resp
            else:
                if not self._allow():
                    await context.abort(StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                async for resp in handler.unary_stream(request, context):
                    yield resp

        return grpc.aio.rpc_method_handler(
            unary_unary=unary_unary if handler.unary_unary else None,
            unary_stream=unary_stream if handler.unary_stream else None,
            request_streaming=handler.request_streaming,
            response_streaming=handler.response_streaming,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


# ======== TLS/mTLS контекст ========
def build_server_credentials() -> Optional[grpc.ServerCredentials]:
    if not TLS_ENABLED:
        return None
    if not (TLS_CERT_FILE and TLS_KEY_FILE):
        raise RuntimeError("TLS enabled but TLS_CERT_FILE/TLS_KEY_FILE not set")

    with open(TLS_KEY_FILE, "rb") as f:
        private_key = f.read()
    with open(TLS_CERT_FILE, "rb") as f:
        cert_chain = f.read()

    if MTLS_ENABLED:
        if not TLS_CA_FILE:
            raise RuntimeError("mTLS enabled but TLS_CA_FILE not set")
        with open(TLS_CA_FILE, "rb") as f:
            root_certs = f.read()
        return grpc.ssl_server_credentials(
            [(private_key, cert_chain)],
            root_certificates=root_certs,
            require_client_auth=True,
        )
    else:
        return grpc.ssl_server_credentials([(private_key, cert_chain)])


# ======== Регистрация пользовательских сервисов ========
def register_services(server: grpc.aio.Server) -> Tuple[str, ...]:
    """
    Здесь регистрируйте ваши gRPC‑сервисы.
    Пример:
        from physical.schemas.proto.v1.physical import event_pb2_grpc
        event_pb2_grpc.add_PhysicalIntegrationServiceServicer_to_server(MyServicer(), server)
        service_names += (event_pb2_grpc.DESCRIPTOR.services_by_name["PhysicalIntegrationService"].full_name,)
    """
    service_names: Tuple[str, ...] = tuple()
    # Health сервис добавим ниже отдельно
    return service_names


# ======== Основной запуск сервера ========
async def serve() -> None:
    interceptors = [
        LoggingInterceptor(),
        JwtAuthInterceptor(AUTH_PROVIDER, AUTH_JWKS_URL, AUTH_AUDIENCE, AUTH_ISSUER, AUTH_BEARER_HEADER),
        ThrottleInterceptor(CONCURRENCY_LIMIT, RATE_LIMIT_QPS, RATE_LIMIT_BURST),
    ]

    options = [
        ("grpc.keepalive_time_ms", KEEPALIVE_TIME_MS),
        ("grpc.keepalive_timeout_ms", KEEPALIVE_TIMEOUT_MS),
        ("grpc.keepalive_permit_without_calls", KEEPALIVE_PERMIT_WITHOUT_CALLS),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.max_concurrent_streams", MAX_CONCURRENT_STREAMS),
        ("grpc.max_receive_message_length", GRPC_MAX_RECV_MB * 1024 * 1024),
        ("grpc.max_send_message_length", GRPC_MAX_SEND_MB * 1024 * 1024),
    ]

    server = grpc.aio.server(interceptors=interceptors, options=options)

    # Health
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Ваши сервисы
    svc_names = list(register_services(server))

    # Reflection (включаем health + ваши сервисы)
    service_names = [
        reflection.SERVICE_NAME,
        health.SERVICE_NAME,
        *svc_names,
    ]
    reflection.enable_server(server)

    # Адрес и креденшелы
    address = f"{GRPC_HOST}:{GRPC_PORT}"
    credentials = build_server_credentials()
    if credentials:
        server.add_secure_port(address, credentials)
        logger.info("gRPC listening (TLS%s) on %s", " mTLS" if MTLS_ENABLED else "", address)
    else:
        server.add_insecure_port(address)
        logger.info("gRPC listening (insecure) on %s", address)

    # Prometheus metrics HTTP
    if METRICS_ENABLED:
        start_http_server(METRICS_PORT)
        logger.info("Prometheus metrics on :%d /metrics", METRICS_PORT)

    # Health: готовность/живость
    for name in service_names:
        health_servicer.set(name, health_pb2_grpc.health_pb2.HealthCheckResponse.SERVING)
    health_servicer.set("", health_pb2_grpc.health_pb2.HealthCheckResponse.SERVING)

    # Запуск
    await server.start()

    # Graceful shutdown по сигналам
    shutdown_event = asyncio.Event()

    def _handle_sig(*_):
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            # Windows
            signal.signal(sig, lambda *_: _handle_sig())

    logger.info("Service=%s version=%s env=%s region=%s", APP_NAME, APP_VERSION, ENVIRONMENT, REGION)

    await shutdown_event.wait()
    logger.info("Shutting down gRPC server...")

    # Health: переводим в NOT_SERVING
    for name in service_names:
        health_servicer.set(name, health_pb2_grpc.health_pb2.HealthCheckResponse.NOT_SERVING)
    health_servicer.set("", health_pb2_grpc.health_pb2.HealthCheckResponse.NOT_SERVING)

    await server.stop(grace=10.0)
    logger.info("Server stopped")


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
