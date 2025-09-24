# -*- coding: utf-8 -*-
"""
DataFabric gRPC server (asyncio, grpc.aio)

Функции:
- Async gRPC сервер с TLS/mTLS (опционально).
- HealthChecking + Server Reflection.
- Interceptors: логирование, аутентификация (Bearer/API-Key), квоты/лимиты.
- Ограничения: max message size, keepalive, concurrency, timeouts.
- Метрики: лёгкие крючки (можно связать с Prometheus отдельно).
- Graceful shutdown по сигналам SIGTERM/SIGINT с дедлайнами.
- Регистрация сервисов (пример: IngestService, DatasetCatalogService).

ENV (значения по умолчанию в []):
  GRPC_HOST=[0.0.0.0]
  GRPC_PORT=[50051]
  GRPC_MAX_RECV_MB=[32]
  GRPC_MAX_SEND_MB=[32]
  GRPC_CONCURRENCY=[0]               # 0 = без ограничений
  GRPC_KEEPALIVE_MS=[20000]
  GRPC_KEEPALIVE_TIMEOUT_MS=[20000]
  GRPC_PERMIT_WITHOUT_STREAM=[true]
  GRPC_TLS_CERT_FILE=[]
  GRPC_TLS_KEY_FILE=[]
  GRPC_TLS_CA_FILE=[]                # при указании включает mTLS (request client cert)
  AUTH_BEARER_REQUIRED=[false]
  AUTH_API_KEY=[]                    # допустимый API Key (один, для простоты)
  RATE_LIMIT_QPS=[0]                # 0 = выкл, иначе глобальный лимит запросов/сек
  RATE_LIMIT_BURST=[0]              # добор к QPS
  LOG_LEVEL=[INFO]
  SHUTDOWN_GRACE_SEC=[15]
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import signal
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence, Tuple

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

# ==== Импортируйте сгенерированные gRPC модули ваших сервисов ====
# Пример (замените пакет/имена на ваши):
# from datafabric_core.schemas.proto.v1.data import ingest_pb2_grpc
# from datafabric_core.schemas.proto.v1.stream.catalog import datasets_pb2_grpc
# Для демонстрации ниже предусмотрены заглушки регистрации.

# ========================= Утилиты конфигурации ===============================

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)

# ============================== Метрики (крючки) ==============================

class Metrics:
    def inc(self, name: str, **labels: Any) -> None:
        # Реализуйте интеграцию с вашей системой метрик
        pass
    def observe(self, name: str, value: float, **labels: Any) -> None:
        pass

metrics = Metrics()

# ============================== Interceptors ==================================

class LoggingInterceptor(aio.ServerInterceptor):
    def __init__(self, logger: logging.Logger) -> None:
        self.log = logger

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        start = time.perf_counter()
        peer = handler_call_details.invocation_metadata
        md = {m.key.lower(): m.value for m in (peer or [])}
        ctx = {"method": method, "authority": md.get(":authority", ""), "ua": md.get("user-agent", "")}
        self.log.debug("grpc.request.start %s", ctx)
        try:
            handler = await continuation(handler_call_details)
            if handler is None:
                return None
            # Оборачиваем unary-unary и unary-stream — stream-* по аналогии при необходимости
            if handler.unary_unary:
                inner = handler.unary_unary

                async def _uu(request, servicer_context):
                    try:
                        response = await inner(request, servicer_context)
                        return response
                    finally:
                        dur = (time.perf_counter() - start) * 1000.0
                        self.log.info("grpc.request.end method=%s code=%s dur_ms=%.1f",
                                      method, servicer_context.code(), dur)
                        metrics.observe("grpc_request_ms", dur, method=method, code=str(servicer_context.code()))
            else:
                # Для краткости оборачиваем только unary_unary; расширьте при необходимости
                return handler
            return grpc.aio.unary_unary_rpc_method_handler(
                _uu,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        except Exception as e:
            self.log.exception("grpc.interceptor.error method=%s err=%s", method, e)
            raise

class AuthInterceptor(aio.ServerInterceptor):
    def __init__(self, require_bearer: bool, api_key: Optional[str]) -> None:
        self.require_bearer = require_bearer
        self.api_key = api_key

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        md = {m.key.lower(): m.value for m in (handler_call_details.invocation_metadata or [])}
        # API-Key
        if self.api_key and md.get("x-api-key") == self.api_key:
            return await continuation(handler_call_details)
        # Bearer (поверхностная проверка заголовка; полную верификацию делайте в сервисе/прокси)
        auth = md.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return await continuation(handler_call_details)
        if self.require_bearer:
            # Отвергаем с UNAUTHENTICATED
            async def unauth(request, context: aio.ServicerContext):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing or invalid credentials")
            # Возвращаем заглушку‑хэндлер, который всегда падает
            return grpc.aio.unary_unary_rpc_method_handler(
                unauth,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x,
            )
        return await continuation(handler_call_details)

class RateLimitInterceptor(aio.ServerInterceptor):
    def __init__(self, qps: int, burst: int) -> None:
        self.enabled = qps > 0
        self.qps = float(max(1, qps)) if self.enabled else 0.0
        self.capacity = float(max(1, qps + max(0, burst))) if self.enabled else 0.0
        self.tokens = self.capacity
        self.ts = time.monotonic()
        self._lock = asyncio.Lock()

    async def intercept_service(self, continuation, handler_call_details):
        if not self.enabled:
            return await continuation(handler_call_details)

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.ts
            if elapsed > 0:
                refill = elapsed * self.qps
                self.tokens = min(self.capacity, self.tokens + refill)
                self.ts = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return await continuation(handler_call_details)
        # Лимит исчерпан
        async def rate_limited(request, context: aio.ServicerContext):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limited")
        return grpc.aio.unary_unary_rpc_method_handler(
            rate_limited,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        )

# ============================== TLS/mTLS =======================================

def build_server_credentials() -> Optional[grpc.ServerCredentials]:
    cert_file = _env_str("GRPC_TLS_CERT_FILE", "")
    key_file = _env_str("GRPC_TLS_KEY_FILE", "")
    ca_file = _env_str("GRPC_TLS_CA_FILE", "")
    if not cert_file or not key_file:
        return None
    with open(cert_file, "rb") as f:
        cert_chain = f.read()
    with open(key_file, "rb") as f:
        private_key = f.read()
    root_certs = None
    require_client_auth = False
    if ca_file:
        with open(ca_file, "rb") as f:
            root_certs = f.read()
        require_client_auth = True
    creds = grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=root_certs,
        require_client_auth=require_client_auth,
    )
    return creds

# ============================== Регистрация сервисов ===========================

def register_services(server: aio.Server, health_svc: health.HealthServicer) -> Sequence[str]:
    """
    Зарегистрируйте реальные сервисы здесь.
    Верните список полных имён для включения в reflection.
    """
    service_names = [
        health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
    ]

    # Пример регистрации:
    # ingest_pb2_grpc.add_IngestServiceServicer_to_server(IngestServicerImpl(), server)
    # service_names.append(ingest_pb2_grpc.IngestService.__name__)
    #
    # datasets_pb2_grpc.add_DatasetCatalogServiceServicer_to_server(CatalogServicerImpl(), server)
    # service_names.append(datasets_pb2_grpc.DatasetCatalogService.__name__)

    # Сигналы для health
    health_svc.set("", health_pb2.HealthCheckResponse.SERVING)  # агрегированный статус
    # health_svc.set("datafabric.v1.data.IngestService", health_pb2.HealthCheckResponse.SERVING)

    return service_names

# ============================== Создание сервера ===============================

@dataclass
class ServerConfig:
    host: str
    port: int
    max_recv_mb: int
    max_send_mb: int
    concurrency: int
    keepalive_ms: int
    keepalive_timeout_ms: int
    permit_without_stream: bool
    shutdown_grace_sec: int
    tls_creds: Optional[grpc.ServerCredentials]
    require_bearer: bool
    api_key: Optional[str]
    rate_qps: int
    rate_burst: int

def load_config() -> ServerConfig:
    return ServerConfig(
        host=_env_str("GRPC_HOST", "0.0.0.0"),
        port=_env_int("GRPC_PORT", 50051),
        max_recv_mb=_env_int("GRPC_MAX_RECV_MB", 32),
        max_send_mb=_env_int("GRPC_MAX_SEND_MB", 32),
        concurrency=_env_int("GRPC_CONCURRENCY", 0),
        keepalive_ms=_env_int("GRPC_KEEPALIVE_MS", 20000),
        keepalive_timeout_ms=_env_int("GRPC_KEEPALIVE_TIMEOUT_MS", 20000),
        permit_without_stream=_env_bool("GRPC_PERMIT_WITHOUT_STREAM", True),
        shutdown_grace_sec=_env_int("SHUTDOWN_GRACE_SEC", 15),
        tls_creds=build_server_credentials(),
        require_bearer=_env_bool("AUTH_BEARER_REQUIRED", False),
        api_key=_env_str("AUTH_API_KEY", "") or None,
        rate_qps=_env_int("RATE_LIMIT_QPS", 0),
        rate_burst=_env_int("RATE_LIMIT_BURST", 0),
    )

async def create_server(cfg: ServerConfig, logger: logging.Logger) -> aio.Server:
    # Параметры канала
    options = [
        ("grpc.max_receive_message_length", cfg.max_recv_mb * 1024 * 1024),
        ("grpc.max_send_message_length", cfg.max_send_mb * 1024 * 1024),
        ("grpc.keepalive_time_ms", cfg.keepalive_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.keepalive_permit_without_calls", 1 if cfg.permit_without_stream else 0),
    ]

    interceptors = [
        LoggingInterceptor(logger),
        AuthInterceptor(cfg.require_bearer, cfg.api_key),
        RateLimitInterceptor(cfg.rate_qps, cfg.rate_burst),
    ]

    server = aio.server(
        options=options,
        interceptors=interceptors,
        maximum_concurrent_rpcs=cfg.concurrency if cfg.concurrency > 0 else None,
    )

    # Health & Reflection
    health_svc = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_svc, server)

    # Регистрация бизнес‑сервисов
    svc_names = register_services(server, health_svc)

    # Reflection (включая health и reflection сам по себе)
    service_names = list(svc_names) + [
        reflection.SERVICE_NAME,
    ]
    reflection.enable_server_reflection(service_names, server)

    # Bind address
    bind_addr = f"{cfg.host}:{cfg.port}"
    if cfg.tls_creds:
        server.add_secure_port(bind_addr, cfg.tls_creds)
        logger.info("gRPC listening (TLS) on %s", bind_addr)
    else:
        server.add_insecure_port(bind_addr)
        logger.warning("gRPC listening (INSECURE) on %s", bind_addr)

    return server, health_svc

# ============================== Запуск/Остановка ==============================

async def _serve() -> int:
    log_level = _env_str("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    logger = logging.getLogger("datafabric.grpc")

    cfg = load_config()
    server, health_svc = await create_server(cfg, logger)

    # Управление сигналами
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler(sig: signal.Signals):
        logger.warning("signal received: %s", sig.name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, functools.partial(_signal_handler, sig))
        except NotImplementedError:
            # Windows
            pass

    await server.start()
    logger.info("server started")
    metrics.inc("grpc_server_started")

    # Ожидание сигнала
    await stop_event.wait()
    logger.info("server shutdown initiated")

    # Health: NOT_SERVING, чтобы балансеры перестали слать трафик
    try:
        health_svc.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
    except Exception:
        pass

    # Мягкая остановка
    grace = max(1, cfg.shutdown_grace_sec)
    await server.stop(grace)
    logger.info("server stopped (grace=%ss)", grace)
    metrics.inc("grpc_server_stopped")
    return 0

def main() -> None:
    # На случай запуска из WSGI/entrypoint
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
