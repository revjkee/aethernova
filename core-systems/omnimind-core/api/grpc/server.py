# ops/api/grpc/server.py
"""
OmniMind Core — gRPC AIO Server (production grade)

Особенности:
- AsyncIO gRPC (grpc.aio), готов к высоконагруженным сервисам.
- Безопасность: TLS/mTLS (по env), проверяемые cipher suites.
- Наблюдаемость: health-check, reflection, Prometheus метрики (опц.), OpenTelemetry (опц.).
- Устойчивость: корректное завершение по SIGTERM/SIGINT с grace-period.
- Производительность: настраиваемые keepalive/flow-control/max-message-size.
- Качество: структурные логи JSON, перехватчики (логирование, аутентификация, rate limit).

Зависимости (рекомендуемые версии):
  grpcio>=1.60, grpcio-health-checking>=1.60, grpcio-reflection>=1.60
  prometheus_client>=0.16 (опционально), redis>=4.2 (опционально),
  opentelemetry-sdk>=1.24, opentelemetry-instrumentation-grpc>=0.45 (опционально)

Запуск:
  PYTHONPATH=. OMNIMIND_GRPC_PORT=8443 OMNIMIND_GRPC_TLS_CERT=/etc/tls/tls.crt \
  OMNIMIND_GRPC_TLS_KEY=/etc/tls/tls.key python -m ops.api.grpc.server
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import grpc
from grpc import aio

# --- Optional components (fail-soft) ---
try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
    _HAS_HEALTH = True
except Exception:
    _HAS_HEALTH = False

try:
    from grpc_reflection.v1alpha import reflection
    _HAS_REFLECTION = True
except Exception:
    _HAS_REFLECTION = False

try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server  # type: ignore
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

try:
    # OpenTelemetry (server auto-instrumentation is optional)
    from opentelemetry.instrumentation.grpc import GrpcAioInstrumentorServer  # type: ignore
    from opentelemetry import trace  # noqa
    _HAS_OTEL = True
except Exception:
    _HAS_OTEL = False

# --------------------------------------------------------------------------------------
# Конфигурация из окружения
# --------------------------------------------------------------------------------------

def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default)

def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

GRPC_HOST         = env_str("OMNIMIND_GRPC_HOST", "0.0.0.0")
GRPC_PORT         = env_int("OMNIMIND_GRPC_PORT", 8443)
GRPC_WORKERS_HINT = env_int("OMNIMIND_GRPC_CONCURRENCY", 0)  # 0=auto
MAX_RECV_MB       = env_int("OMNIMIND_GRPC_MAX_RECV_MB", 64)
MAX_SEND_MB       = env_int("OMNIMIND_GRPC_MAX_SEND_MB", 64)

# TLS/mTLS
TLS_CERT_FILE     = env_str("OMNIMIND_GRPC_TLS_CERT", "")
TLS_KEY_FILE      = env_str("OMNIMIND_GRPC_TLS_KEY", "")
TLS_CLIENT_CA     = env_str("OMNIMIND_GRPC_CLIENT_CA", "")  # если задан — включается mTLS
TLS_REQUIRE_CLIENT_AUTH = env_bool("OMNIMIND_GRPC_REQUIRE_CLIENT_AUTH", bool(TLS_CLIENT_CA))

# Keepalive / transport tuning
KEEPALIVE_TIME_MS             = env_int("OMNIMIND_GRPC_KEEPALIVE_TIME_MS", 30_000)
KEEPALIVE_TIMEOUT_MS          = env_int("OMNIMIND_GRPC_KEEPALIVE_TIMEOUT_MS", 10_000)
KEEPALIVE_PERMIT_NO_CALLS     = env_int("OMNIMIND_GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS", 1)
MAX_PINGS_WITHOUT_DATA        = env_int("OMNIMIND_GRPC_MAX_PINGS_WITHOUT_DATA", 0)
MIN_TIME_BETWEEN_PINGS_MS     = env_int("OMNIMIND_GRPC_MIN_TIME_BETWEEN_PINGS_MS", 10_000)
MIN_PING_INTERVAL_NO_DATA_MS  = env_int("OMNIMIND_GRPC_MIN_PING_INTERVAL_NO_DATA_MS", 10_000)
MAX_CONNECTION_IDLE_MS        = env_int("OMNIMIND_GRPC_MAX_CONNECTION_IDLE_MS", 300_000)

# Auth / Rate limit
AUTH_BEARER_TOKEN  = env_str("OMNIMIND_GRPC_AUTH_TOKEN", "")
RL_ENABLE          = env_bool("OMNIMIND_RL_ENABLE", True)
RL_CAPACITY        = env_int("OMNIMIND_RL_CAPACITY", 200)        # токенов в бакете
RL_REFILL_RPS      = float(env_str("OMNIMIND_RL_REFILL_RPS", "3.5"))  # пополнение в секунду
RL_WINDOW_HINT_SEC = env_int("OMNIMIND_RL_WINDOW_SEC", 60)
RL_SOFT            = env_bool("OMNIMIND_RL_SOFT", False)         # только маркировка, без 429
ALLOW_CIDRS        = [s for s in env_str("OMNIMIND_RL_ALLOW_CIDRS", "").split(",") if s]
DENY_CIDRS         = [s for s in env_str("OMNIMIND_RL_DENY_CIDRS", "").split(",") if s]

# Metrics / Health
METRICS_ENABLE     = env_bool("OMNIMIND_METRICS_ENABLE", True)
METRICS_PORT       = env_int("OMNIMIND_METRICS_PORT", 9090)
HEALTH_DEFAULT     = env_str("OMNIMIND_HEALTH_SERVING_STATUS", "SERVING")

# OTel
OTEL_ENABLE        = env_bool("OMNIMIND_OTEL_ENABLE", False)

# Логирование
LOG_LEVEL          = env_str("OMNIMIND_LOG_LEVEL", "INFO")

# --------------------------------------------------------------------------------------
# Логирование (структурное JSON)
# --------------------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Добавим кастомные поля (если заданы в record.__dict__)
        for k in ("method", "peer", "code", "dur_ms", "trace_id", "span_id"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        return json.dumps(payload, ensure_ascii=False)

def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.handlers[:] = [h]

log = logging.getLogger("grpc.server")

# --------------------------------------------------------------------------------------
# Перехватчики: аутентификация, логирование, rate limit
# --------------------------------------------------------------------------------------

def _peer_ip(peer: str) -> str:
    # peer looks like: "ipv4:127.0.0.1:54321" or "ipv6:[::1]:54321"
    try:
        if peer.startswith("ipv4:"):
            return peer.split(":")[1]
        if peer.startswith("ipv6:"):
            p = peer.split(":", 1)[1]
            return p.split("]:")[0].strip("[]")
    except Exception:
        pass
    return "0.0.0.0"

class AuthInterceptor(aio.ServerInterceptor):
    def __init__(self, bearer_token: str) -> None:
        self.token = bearer_token

    async def intercept_service(self, continuation, handler_call_details):
        if not self.token:
            return await continuation(handler_call_details)

        md = {}
        if handler_call_details.invocation_metadata:
            for kv in handler_call_details.invocation_metadata:
                md[kv.key.lower()] = kv.value

        auth = md.get("authorization", "")
        if auth.lower().startswith("bearer "):
            got = auth.split(" ", 1)[1]
        else:
            got = auth

        if got != self.token:
            async def deny(request, context):
                context.set_trailing_metadata((("www-authenticate", "Bearer"),))
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid token")
            method = await continuation(handler_call_details)
            # Вернем handler, который при вызове сделает abort
            return aio.unary_unary_rpc_method_handler(deny)

        return await continuation(handler_call_details)

@dataclass
class _Bucket:
    tokens: float
    ts_ms: int

class RateLimitInterceptor(aio.ServerInterceptor):
    """
    Простой in-memory token bucket (per process). Для распределенного лимита используйте
    отдельный сервис/Redis и замените реализацию.
    """
    def __init__(self,
                 capacity: int,
                 refill_rps: float,
                 window_hint_sec: int,
                 allow_cidrs: Sequence[str],
                 deny_cidrs: Sequence[str],
                 soft: bool) -> None:
        self.capacity = max(1, int(capacity))
        self.refill_rps = float(refill_rps)
        self.window = max(1, int(window_hint_sec))
        self.soft = soft
        self.allow = [ip_network(x, strict=False) for x in allow_cidrs]
        self.deny = [ip_network(x, strict=False) for x in deny_cidrs]
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

        if _HAS_PROM:
            self.m_block = Counter("omnimind_grpc_rl_block_total", "gRPC RL blocks", ["method"])
            self.m_allow = Counter("omnimind_grpc_rl_allow_total", "gRPC RL allows", ["method"])

    def _ip_allowed(self, ip: str) -> bool:
        try:
            ip_obj = ip_address(ip)
        except Exception:
            return False
        if any(ip_obj in n for n in self.deny):
            return False
        if any(ip_obj in n for n in self.allow):
            return True
        return None  # type: ignore

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method or ""
        peer = handler_call_details.peer or ""
        key = f"{method}|{_peer_ip(peer)}"

        # Быстрые списки
        ip = _peer_ip(peer)
        allowed_by_cidr = self._ip_allowed(ip)
        if allowed_by_cidr is True:
            return await continuation(handler_call_details)
        if allowed_by_cidr is False and not self.soft:
            async def deny(request, context):
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit (cidr policy)")
            return aio.unary_unary_rpc_method_handler(deny)

        now_ms = int(time.time() * 1000)
        async with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=self.capacity, ts_ms=now_ms)
            else:
                elapsed = max(0, now_ms - b.ts_ms) / 1000.0
                b.tokens = min(self.capacity, b.tokens + elapsed * self.refill_rps)
                b.ts_ms = now_ms

            if b.tokens >= 1.0:
                b.tokens -= 1.0
                self._buckets[key] = b
                if _HAS_PROM:
                    self.m_allow.labels(method=method).inc()
                return await continuation(handler_call_details)

            # Не хватает токенов
            self._buckets[key] = b
            retry_after = (1.0 - b.tokens) / max(self.refill_rps, 1e-6)

        if self.soft:
            # Пропускаем, но обозначаем состояние через trailing-metadata
            async def soft_wrapper(request, context):
                context.set_trailing_metadata((
                    ("x-ratelimit-soft", "1"),
                    ("retry-after", f"{int(retry_after)}"),
                ))
                return await (await continuation(handler_call_details)).unary_unary(request, context)
            return aio.unary_unary_rpc_method_handler(soft_wrapper)

        if _HAS_PROM:
            self.m_block.labels(method=method).inc()

        async def deny(request, context):
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
        return aio.unary_unary_rpc_method_handler(deny)

class LoggingInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method or ""
        peer = handler_call_details.peer or ""
        md = {kv.key.lower(): kv.value for kv in (handler_call_details.invocation_metadata or [])}
        req_id = md.get("x-request-id") or md.get("request-id") or ""
        t0 = time.perf_counter()
        handler = await continuation(handler_call_details)

        async def _unary_unary(request, context):
            code = grpc.StatusCode.OK
            try:
                resp = await handler.unary_unary(request, context)
                return resp
            except aio.AioRpcError as e:
                code = e.code()
                raise
            finally:
                dur_ms = int((time.perf_counter() - t0) * 1000)
                log.info("grpc request",
                         extra={"method": method, "peer": peer, "code": code.name, "dur_ms": dur_ms,
                                "trace_id": md.get("traceparent", ""), "span_id": ""})

        # Поддержка unary-unary; при необходимости добавьте stream-обработчики аналогично
        if handler.unary_unary:
            return aio.unary_unary_rpc_method_handler(
                _unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler

# --------------------------------------------------------------------------------------
# Регистрация gRPC-сервисов
# --------------------------------------------------------------------------------------

def register_services(server: aio.Server, health_srv: Optional["health.HealthServicer"]) -> List[str]:
    """
    Зарегистрируйте здесь свои сервисы. Пример показан для условного TaskService,
    сгенерированного из omnimind/core/v1/task.proto.
    """
    registered: List[str] = []

    # Пример: TaskService
    try:
        # from omnimind.core.v1 import task_service_pb2_grpc
        # task_service_pb2_grpc.add_TaskServiceServicer_to_server(YourTaskServicerImpl(), server)
        # registered.append("omnimind.core.v1.TaskService")
        pass
    except Exception as e:
        log.warning("TaskService not registered: %s", e)

    # Health — регистрируем последним, после основных сервисов
    if _HAS_HEALTH and health_srv is not None:
        health_pb2_grpc.add_HealthServicer_to_server(health_srv, server)
        registered.append("grpc.health.v1.Health")

    return registered

# --------------------------------------------------------------------------------------
# TLS/mTLS
# --------------------------------------------------------------------------------------

def build_server_credentials() -> Optional[grpc.ServerCredentials]:
    if not TLS_CERT_FILE or not TLS_KEY_FILE:
        return None
    with open(TLS_CERT_FILE, "rb") as f:
        cert = f.read()
    with open(TLS_KEY_FILE, "rb") as f:
        key = f.read()
    root_cert = None
    require_client = TLS_REQUIRE_CLIENT_AUTH and bool(TLS_CLIENT_CA)
    if TLS_CLIENT_CA:
        with open(TLS_CLIENT_CA, "rb") as f:
            root_cert = f.read()
    creds = grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=root_cert,
        require_client_auth=require_client,
    )
    return creds

# --------------------------------------------------------------------------------------
# Инициализация Prometheus/OTel
# --------------------------------------------------------------------------------------

def start_metrics_if_enabled() -> None:
    if METRICS_ENABLE and _HAS_PROM:
        start_http_server(METRICS_PORT)
        log.info("Prometheus metrics started", extra={"method": "metrics", "peer": f"0.0.0.0:{METRICS_PORT}"})
    elif METRICS_ENABLE and not _HAS_PROM:
        log.warning("Prometheus disabled: prometheus_client not installed")

def instrument_otel_if_enabled() -> None:
    if OTEL_ENABLE and _HAS_OTEL:
        try:
            GrpcAioInstrumentorServer().instrument()
            log.info("OpenTelemetry gRPC instrumentation enabled")
        except Exception as e:
            log.warning("OpenTelemetry instrumentation failed: %s", e)
    elif OTEL_ENABLE:
        log.warning("OpenTelemetry requested but not available")

# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

async def serve() -> None:
    setup_logging()
    start_metrics_if_enabled()
    instrument_otel_if_enabled()

    options = (
        ("grpc.keepalive_time_ms", KEEPALIVE_TIME_MS),
        ("grpc.keepalive_timeout_ms", KEEPALIVE_TIMEOUT_MS),
        ("grpc.keepalive_permit_without_calls", KEEPALIVE_PERMIT_NO_CALLS),
        ("grpc.http2.max_pings_without_data", MAX_PINGS_WITHOUT_DATA),
        ("grpc.http2.min_time_between_pings_ms", MIN_TIME_BETWEEN_PINGS_MS),
        ("grpc.http2.min_ping_interval_without_data_ms", MIN_PING_INTERVAL_NO_DATA_MS),
        ("grpc.max_connection_idle_ms", MAX_CONNECTION_IDLE_MS),
        ("grpc.max_receive_message_length", MAX_RECV_MB * 1024 * 1024),
        ("grpc.max_send_message_length", MAX_SEND_MB * 1024 * 1024),
    )

    interceptors: List[aio.ServerInterceptor] = [LoggingInterceptor()]

    if AUTH_BEARER_TOKEN:
        interceptors.append(AuthInterceptor(AUTH_BEARER_TOKEN))

    if RL_ENABLE:
        interceptors.append(
            RateLimitInterceptor(
                capacity=RL_CAPACITY,
                refill_rps=RL_REFILL_RPS,
                window_hint_sec=RL_WINDOW_HINT_SEC,
                allow_cidrs=ALLOW_CIDRS,
                deny_cidrs=DENY_CIDRS,
                soft=RL_SOFT,
            )
        )

    server = aio.server(
        options=options,
        interceptors=interceptors,
        maximum_concurrent_rpcs=GRPC_WORKERS_HINT if GRPC_WORKERS_HINT > 0 else None,
    )

    # Health
    health_srv = None
    if _HAS_HEALTH:
        health_srv = health.HealthServicer()
        # Статус по умолчанию — SERVING
        serving_status = {
            "SERVING": health_pb2.HealthCheckResponse.SERVING,
            "NOT_SERVING": health_pb2.HealthCheckResponse.NOT_SERVING,
            "SERVICE_UNKNOWN": health_pb2.HealthCheckResponse.SERVICE_UNKNOWN,
        }.get(HEALTH_DEFAULT.upper(), health_pb2.HealthCheckResponse.SERVING)
        health_srv.set("", serving_status)

    # Регистрация сервисов
    registered = register_services(server, health_srv)

    # Reflection
    if _HAS_REFLECTION:
        services_for_reflection = list(reflection.SERVICE_NAMES)
        # Добавим имена зарегистрированных сервисов (если есть)
        services_for_reflection.extend(registered)
        reflection.enable_server_reflection(services_for_reflection, server)

    # Порты
    creds = build_server_credentials()
    bind_addr = f"{GRPC_HOST}:{GRPC_PORT}"
    if creds:
        server.add_secure_port(bind_addr, creds)
        log.info("gRPC secure server listening", extra={"peer": bind_addr, "method": "bind", "code": "OK"})
    else:
        server.add_insecure_port(bind_addr)
        log.warning("gRPC insecure server listening (no TLS)", extra={"peer": bind_addr, "method": "bind", "code": "OK"})

    # Старт
    await server.start()

    # Хэндлеры сигналов для graceful shutdown
    should_stop = asyncio.Event()

    def _signal_handler(sig_name: str):
        log.info("signal received", extra={"method": "signal", "code": sig_name})
        should_stop.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(s, _signal_handler, s.name)
        except NotImplementedError:
            # Windows
            pass

    # Ожидание остановки
    await should_stop.wait()

    # Перед остановкой отмечаем health NOT_SERVING
    if _HAS_HEALTH and health_srv is not None:
        try:
            health_srv.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        except Exception:
            pass

    GRACE = env_int("OMNIMIND_GRPC_SHUTDOWN_GRACE_SEC", 20)
    log.info("stopping grpc server", extra={"method": "shutdown", "code": "BEGIN"})
    await server.stop(GRACE)
    await server.wait_for_termination(timeout=GRACE)
    log.info("grpc server stopped", extra={"method": "shutdown", "code": "DONE"})

# Точка входа
if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
