# zero-trust-core/api/grpc/server.py
# -*- coding: utf-8 -*-
"""
Промышленный gRPC сервер (grpc.aio) для Zero-Trust Core.

Возможности:
- TLS/mTLS (server cert, опциональная проверка клиентского сертификата).
- Health Checking (grpc_health.v1) и Reflection.
- Перехватчики: аутентификация (JWT через security.tokens.jwt, если доступен),
  rate limiting (Redis Lua; fallback — in-memory), структурированные логи.
- RateLimit метаданные (ratelimit-limit|remaining|reset) и корректный статус RESOURCE_EXHAUSTED.
- Сжатие (gzip), лимиты на размер сообщений, keepalive/connection age.
- Плагинная регистрация пользовательских сервисов по списку модулей из ENV.
- Graceful shutdown по SIGINT/SIGTERM, тайм-аут на завершение.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import os
import signal
import ssl
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2_grpc

# Опциональные зависимости
_HAS_REDIS = False
try:  # pragma: no cover
    from redis.asyncio import Redis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    _HAS_REDIS = False

_HAS_JWT_SVC = False
try:  # pragma: no cover
    # Не обязателен. Если доступен — используем для проверки JWT.
    from security.tokens.jwt import JwtService, JwtConfig, ValidationPolicy, TokenInvalid  # type: ignore
    _HAS_JWT_SVC = True
except Exception:  # pragma: no cover
    _HAS_JWT_SVC = False


# -----------------------------------------------------------------------------
# Конфигурация
# -----------------------------------------------------------------------------

@dataclass
class ServerConfig:
    host: str = os.getenv("ZT_GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("ZT_GRPC_PORT", "8443"))

    # TLS/mTLS
    tls_cert_path: Optional[str] = os.getenv("TLS_SERVER_CERT")
    tls_key_path: Optional[str] = os.getenv("TLS_SERVER_KEY")
    tls_ca_path: Optional[str] = os.getenv("TLS_CA_CERT")
    require_client_cert: bool = os.getenv("TLS_REQUIRE_CLIENT_CERT", "false").lower() == "true"

    # gRPC опции
    max_recv_mb: int = int(os.getenv("GRPC_MAX_RECV_MB", "32"))
    max_send_mb: int = int(os.getenv("GRPC_MAX_SEND_MB", "32"))
    enable_reflection: bool = os.getenv("GRPC_REFLECTION", "true").lower() == "true"

    # Keepalive / Connection management
    keepalive_time_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "20000"))         # каждые 20s
    keepalive_timeout_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000"))   # 20s
    max_connection_age_ms: int = int(os.getenv("GRPC_MAX_CONNECTION_AGE_MS", "120000"))     # 2m
    max_connection_age_grace_ms: int = int(os.getenv("GRPC_MAX_CONNECTION_AGE_GRACE_MS", "30000"))  # 30s

    # Аутентификация
    auth_mode: str = os.getenv("AUTH_MODE", "none")  # none|jwt
    jwt_issuer: Optional[str] = os.getenv("JWT_ISSUER") or None
    jwt_audience: Optional[str] = os.getenv("JWT_AUDIENCE") or None
    jwt_allowed_algs: List[str] = os.getenv("JWT_ALLOWED_ALGS", "RS256,ES256,EdDSA").split(",")
    jwt_jwks_url: Optional[str] = os.getenv("JWT_JWKS_URL") or None
    jwt_require_sub: bool = os.getenv("JWT_REQUIRE_SUB", "false").lower() == "true"
    jwt_leeway_sec: int = int(os.getenv("JWT_LEEWAY_SEC", "60"))
    jwt_max_age_sec: Optional[int] = int(os.getenv("JWT_MAX_AGE_SEC")) if os.getenv("JWT_MAX_AGE_SEC") else None

    # Rate limiting
    rl_enabled: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    rl_algorithm: str = os.getenv("RATE_LIMIT_ALGORITHM", "token_bucket")  # token_bucket|sliding_window
    rl_limit: int = int(os.getenv("RATE_LIMIT_LIMIT", "300"))
    rl_window_sec: int = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
    rl_burst: Optional[int] = int(os.getenv("RATE_LIMIT_BURST")) if os.getenv("RATE_LIMIT_BURST") else None
    rl_key_type: str = os.getenv("RATE_LIMIT_KEY", "peer")  # peer|jwt_sub|method|peer_jwt
    rl_redis_url: str = os.getenv("RATE_LIMIT_REDIS_URL", "redis://127.0.0.1:6379/0")
    rl_retry_after_sec: int = int(os.getenv("RATE_LIMIT_RETRY_AFTER_SEC", "60"))
    rl_shadow_on_backend_error: bool = os.getenv("RATE_LIMIT_SHADOW_ON_BACKEND_ERROR", "true").lower() == "true"

    # Плагины сервисов (через запятую): pkg.module:factory
    # factory: Callable[[aio.Server], Awaitable[None] | None] регистрирует сервисы в сервер.
    service_plugins: List[str] = [s.strip() for s in os.getenv("ZT_GRPC_SERVICE_PLUGINS", "").split(",") if s.strip()]

    # Логи
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()


CFG = ServerConfig()


# -----------------------------------------------------------------------------
# Вспомогательные утилиты
# -----------------------------------------------------------------------------

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def request_id_from_metadata(md: Iterable[Tuple[str, str]] | None) -> str:
    rid = None
    if md:
        for k, v in md:
            if k.lower() == "x-request-id" and v:
                rid = v
                break
    if not rid:
        rid = b64u(sha256(f"{time.time_ns()}".encode()).digest()[:12])
    return rid

def peer_ip_from_peer(peer: str) -> str:
    # peer формат: "ipv4:127.0.0.1:12345" или "ipv6:[::1]:12345"
    if not peer:
        return "unknown"
    try:
        ptype, rest = peer.split(":", 1)
        if ptype.startswith("ipv"):
            last_colon = rest.rfind(":")
            host = rest[:last_colon]
            return host.strip("[]")
    except Exception:
        pass
    return "unknown"


# -----------------------------------------------------------------------------
# Rate Limiting (Redis Lua или In-memory)
# -----------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, cfg: ServerConfig, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.redis: Optional["Redis"] = None
        self._tb_sha: Optional[str] = None
        self._inmem_buckets: Dict[str, Tuple[float, float, int]] = {}
        # bucket state: (tokens, last_ts_ms, capacity)

    async def start(self) -> None:
        if _HAS_REDIS and self.cfg.rl_enabled:
            try:
                self.redis = Redis.from_url(self.cfg.rl_redis_url, encoding="utf-8", decode_responses=False)  # type: ignore
                await self.redis.ping()
                self._tb_sha = await self.redis.script_load(_TOKEN_BUCKET_LUA)
                self.logger.info("RateLimiter: Redis backend enabled")
            except Exception as e:
                self.logger.warning("RateLimiter: Redis unavailable (%s); falling back to memory", e)
                self.redis = None

    async def stop(self) -> None:
        if self.redis:
            try:
                await self.redis.close()  # type: ignore
            except Exception:
                pass

    async def acquire(self, key: str, now_ms: int) -> Tuple[bool, int, int, int, str]:
        """
        Возвращает (allowed, limit, remaining, reset_ms, reason)
        """
        limit = self.cfg.rl_limit
        capacity = self.cfg.rl_burst if self.cfg.rl_burst is not None else limit
        window_ms = max(self.cfg.rl_window_sec * 1000, 1)
        refill = float(capacity) / float(window_ms)

        # Redis путь
        if self.redis:
            try:
                args = [now_ms, refill, int(capacity), 1]
                res = await self.redis.evalsha(self._tb_sha, 1, self._redis_key(key), *args)  # type: ignore
                allowed, remaining, reset_in_ms = int(res[0]), int(res[1]), int(res[2])
                return bool(allowed), limit, max(0, remaining), max(0, reset_in_ms), "ok" if allowed else "over_limit"
            except Exception as e:
                self.logger.exception("RateLimiter Redis error: %s", e)
                # мягкая деградация
                if self.cfg.rl_shadow_on_backend_error:
                    return True, limit, limit, window_ms, "backend_error"
                return True, limit, limit, window_ms, "backend_error"

        # In-memory token bucket
        state = self._inmem_buckets.get(key)
        if state is None:
            tokens = float(capacity)
            self._inmem_buckets[key] = (tokens, now_ms, capacity)
            state = self._inmem_buckets[key]
        tokens, ts, cap = state
        delta = max(0, now_ms - ts)
        tokens = min(float(cap), tokens + delta * refill)
        allowed = False
        if tokens >= 1.0:
            tokens -= 1.0
            allowed = True
        remaining = int(tokens)
        reset_ms = int(max(0.0, (cap - tokens) / refill))
        self._inmem_buckets[key] = (tokens, now_ms, cap)
        return allowed, limit, max(0, remaining), reset_ms, "ok" if allowed else "over_limit"

    def _redis_key(self, raw: str) -> str:
        return f"zt:rl:{sha256(raw.encode()).hexdigest()}"


_TOKEN_BUCKET_LUA = """
-- KEYS[1] = bucket key
-- ARGV: now_ms, refill_rate_per_ms, capacity, cost
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  ts = now
else
  local delta = math.max(now - ts, 0)
  tokens = math.min(capacity, tokens + delta * rate)
  ts = now
end

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', ts)
local ttl = math.ceil((capacity / rate) / 1000) + 5
redis.call('EXPIRE', key, ttl)

local remaining = math.floor(tokens)
local reset_ms = math.floor((capacity - tokens) / rate)
return {allowed, remaining, reset_ms}
"""


# -----------------------------------------------------------------------------
# Перехватчики: логирование, аутентификация, rate limit
# -----------------------------------------------------------------------------

class AccessLogInterceptor(aio.ServerInterceptor):
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        method = handler_call_details.method

        async def unary_unary(request, context):
            start = time.time()
            md = tuple((k, v) for k, v in context.invocation_metadata())
            rid = request_id_from_metadata(md)
            peer = context.peer()
            err = None
            try:
                context.set_trailing_metadata((("x-request-id", rid),))
                resp = await handler.unary_unary(request, context)
                return resp
            except Exception as e:
                err = e
                raise
            finally:
                dur = time.time() - start
                self.logger.info(json.dumps({
                    "ts": time.time(),
                    "lvl": "INFO",
                    "msg": "grpc_access",
                    "rid": rid,
                    "method": method,
                    "peer": peer,
                    "peer_ip": peer_ip_from_peer(peer),
                    "duration_ms": int(dur * 1000),
                    "error": str(err) if err else None
                }, separators=(",", ":"), ensure_ascii=False))

        async def unary_stream(request, context):
            start = time.time()
            md = tuple((k, v) for k, v in context.invocation_metadata())
            rid = request_id_from_metadata(md)
            peer = context.peer()
            context.set_trailing_metadata((("x-request-id", rid),))
            async for resp in handler.unary_stream(request, context):
                yield resp
            dur = time.time() - start
            self.logger.info(json.dumps({
                "ts": time.time(), "lvl": "INFO", "msg": "grpc_access",
                "rid": rid, "method": method, "peer": peer,
                "peer_ip": peer_ip_from_peer(peer), "duration_ms": int(dur*1000)
            }, separators=(",", ":"), ensure_ascii=False))

        return aio.unary_unary_rpc_method_handler(unary_unary) if handler.unary_unary \
            else aio.unary_stream_rpc_method_handler(unary_stream) if handler.unary_stream \
            else handler


class AuthInterceptor(aio.ServerInterceptor):
    """
    AUTH_MODE=none — пропускаем.
    AUTH_MODE=jwt  — требуем Bearer JWT в metadata["authorization"]; валидация JwtService (если доступен).
    """
    def __init__(self, cfg: ServerConfig, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.jwt_svc: Optional["JwtService"] = None
        if _HAS_JWT_SVC and self.cfg.auth_mode == "jwt":
            self.jwt_svc = JwtService(  # type: ignore
                keystore=None,
                config=JwtConfig(
                    allowed_algs=set(self.cfg.jwt_allowed_algs),
                    default_issuer=self.cfg.jwt_issuer or "",
                    default_audience=self.cfg.jwt_audience or "",
                    jwks_url=self.cfg.jwt_jwks_url,
                    jwks_cache_ttl_sec=300,
                    require_jwt_typ=True,
                    forbid_zip=True,
                    forbid_crit=True,
                ),
            )

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        async def unary_unary(request, context):
            if self.cfg.auth_mode == "jwt":
                auth = _auth_header_from_md(context.invocation_metadata())
                if not auth or not auth.lower().startswith("bearer "):
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
                token = auth.split(" ", 1)[1].strip()
                if not self.jwt_svc:
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "jwt service unavailable")
                try:
                    pol = ValidationPolicy(
                        issuer=self.cfg.jwt_issuer or "",
                        audience=self.cfg.jwt_audience or "",
                        leeway=self.cfg.jwt_leeway_sec,
                        max_age=self.cfg.jwt_max_age_sec,
                        require_sub=self.cfg.jwt_require_sub,
                    )
                    claims = self.jwt_svc.verify(token, policy=pol)  # type: ignore
                    # Прокинем sub/iss/aud в context (trailing metadata)
                    context.set_trailing_metadata((
                        ("x-auth-sub", str(claims.get("sub", ""))),
                        ("x-auth-iss", str(claims.get("iss", ""))),
                        ("x-auth-aud", str(claims.get("aud", ""))),
                    ))
                except Exception as e:
                    self.logger.info("JWT denied: %s", e)
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid token")
            return await handler.unary_unary(request, context)

        async def unary_stream(request, context):
            if self.cfg.auth_mode == "jwt":
                auth = _auth_header_from_md(context.invocation_metadata())
                if not auth or not auth.lower().startswith("bearer "):
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
                token = auth.split(" ", 1)[1].strip()
                if not self.jwt_svc:
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "jwt service unavailable")
                try:
                    pol = ValidationPolicy(
                        issuer=self.cfg.jwt_issuer or "",
                        audience=self.cfg.jwt_audience or "",
                        leeway=self.cfg.jwt_leeway_sec,
                        max_age=self.cfg.jwt_max_age_sec,
                        require_sub=self.cfg.jwt_require_sub,
                    )
                    self.jwt_svc.verify(token, policy=pol)  # type: ignore
                except Exception as e:
                    self.logger.info("JWT denied: %s", e)
                    await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid token")
            async for resp in handler.unary_stream(request, context):
                yield resp

        return aio.unary_unary_rpc_method_handler(unary_unary) if handler.unary_unary \
            else aio.unary_stream_rpc_method_handler(unary_stream) if handler.unary_stream \
            else handler


def _auth_header_from_md(md: Iterable[Tuple[str, str]] | None) -> Optional[str]:
    if not md:
        return None
    for k, v in md:
        if k.lower() == "authorization":
            return v
    return None


class RateLimitInterceptor(aio.ServerInterceptor):
    def __init__(self, cfg: ServerConfig, limiter: RateLimiter, logger: logging.Logger):
        self.cfg = cfg
        self.limiter = limiter
        self.logger = logger

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None or not self.cfg.rl_enabled:
            return handler

        method = handler_call_details.method

        async def unary_unary(request, context):
            key = await self._key_for_call(method, context)
            now_ms = int(time.time() * 1000)
            allowed, limit, remaining, reset_in_ms, reason = await self.limiter.acquire(key, now_ms)
            # Метаданные RateLimit
            context.set_trailing_metadata((
                ("ratelimit-limit", str(limit)),
                ("ratelimit-remaining", str(remaining)),
                ("ratelimit-reset", str(int(reset_in_ms / 1000))),
            ))
            if not allowed and reason == "over_limit":
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
            return await handler.unary_unary(request, context)

        async def unary_stream(request, context):
            key = await self._key_for_call(method, context)
            now_ms = int(time.time() * 1000)
            allowed, limit, remaining, reset_in_ms, reason = await self.limiter.acquire(key, now_ms)
            context.set_trailing_metadata((
                ("ratelimit-limit", str(limit)),
                ("ratelimit-remaining", str(remaining)),
                ("ratelimit-reset", str(int(reset_in_ms / 1000))),
            ))
            if not allowed and reason == "over_limit":
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
            async for resp in handler.unary_stream(request, context):
                yield resp

        return aio.unary_unary_rpc_method_handler(unary_unary) if handler.unary_unary \
            else aio.unary_stream_rpc_method_handler(unary_stream) if handler.unary_stream \
            else handler

    async def _key_for_call(self, method: str, context: aio.ServicerContext) -> str:
        peer = peer_ip_from_peer(context.peer())
        md = context.invocation_metadata()
        sub = "anon"
        auth = _auth_header_from_md(md)
        if auth and auth.lower().startswith("bearer "):
            parts = auth.split(" ", 1)[1].split(".")
            if len(parts) == 3:
                try:
                    payload = json.loads(_b64url_decode(parts[1]) or "{}")
                    if isinstance(payload.get("sub"), str) and payload["sub"]:
                        sub = payload["sub"]
                except Exception:
                    pass
        if self.cfg.rl_key_type == "peer":
            raw = f"{peer}"
        elif self.cfg.rl_key_type == "jwt_sub":
            raw = f"{sub}"
        elif self.cfg.rl_key_type == "method":
            raw = f"{method}"
        elif self.cfg.rl_key_type == "peer_jwt":
            raw = f"{peer}|{sub}"
        else:
            raw = f"{peer}"
        return sha256(f"{method}:{raw}".encode()).hexdigest()


def _b64url_decode(s: str) -> bytes:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return b""


# -----------------------------------------------------------------------------
# Инициализация и запуск сервера
# -----------------------------------------------------------------------------

def _server_credentials(cfg: ServerConfig) -> Optional[grpc.ServerCredentials]:
    if not cfg.tls_cert_path or not cfg.tls_key_path:
        return None
    with open(cfg.tls_cert_path, "rb") as f:
        cert = f.read()
    with open(cfg.tls_key_path, "rb") as f:
        key = f.read()
    root = None
    if cfg.tls_ca_path:
        with open(cfg.tls_ca_path, "rb") as f:
            root = f.read()
    return grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=root,
        require_client_auth=cfg.require_client_cert,
    )

async def register_plugins(server: aio.Server, plugins: List[str], logger: logging.Logger) -> None:
    """
    Поддержка плагинов: ZT_GRPC_SERVICE_PLUGINS="pkg.module:factory,other.mod:init"
    factory(server) должен зарегистрировать свои сервисы.
    """
    for spec in plugins:
        try:
            mod_name, func_name = spec.split(":")
            mod = importlib.import_module(mod_name)
            factory: Callable[[aio.Server], Any] = getattr(mod, func_name)
            res = factory(server)
            if asyncio.iscoroutine(res):
                await res
            logger.info("Service plugin registered: %s", spec)
        except Exception as e:
            logger.error("Failed to register plugin %s: %s", spec, e)

def _grpc_options(cfg: ServerConfig) -> List[Tuple[str, Any]]:
    return [
        ("grpc.max_receive_message_length", cfg.max_recv_mb * 1024 * 1024),
        ("grpc.max_send_message_length", cfg.max_send_mb * 1024 * 1024),
        ("grpc.keepalive_time_ms", cfg.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.max_connection_age_ms", cfg.max_connection_age_ms),
        ("grpc.max_connection_age_grace_ms", cfg.max_connection_age_grace_ms),
        ("grpc.enable_retries", 1),
    ]

async def serve() -> None:
    # Логи
    logging.basicConfig(level=getattr(logging, CFG.log_level, logging.INFO))
    logger = logging.getLogger("zt.grpc.server")

    # Перехватчики
    limiter = RateLimiter(CFG, logger)
    await limiter.start()

    interceptors: List[aio.ServerInterceptor] = [
        AccessLogInterceptor(logger),
        RateLimitInterceptor(CFG, limiter, logger),
        AuthInterceptor(CFG, logger),
    ]

    server = aio.server(
        interceptors=interceptors,
        options=_grpc_options(CFG),
        compression=grpc.Compression.Gzip,
    )

    # Health
    health_svc = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_svc, server)

    # Reflection
    if CFG.enable_reflection:
        try:
            from grpc_reflection.v1alpha import reflection  # type: ignore
            service_names = (
                health.SERVICE_NAME,
                reflection.SERVICE_NAME,
            )
            reflection.enable_server_reflection(service_names, server)
        except Exception as e:
            logger.warning("Reflection disabled: %s", e)

    # Плагины сервисов
    await register_plugins(server, CFG.service_plugins, logger)

    # TLS / Insecure bind
    addr = f"{CFG.host}:{CFG.port}"
    creds = _server_credentials(CFG)
    if creds:
        server.add_secure_port(addr, creds)
        logger.info("gRPC listening (TLS): %s", addr)
    else:
        server.add_insecure_port(addr)
        logger.warning("gRPC listening (INSECURE): %s", addr)

    await server.start()

    # Health status
    health_svc.set("", health_pb2_grpc.health_pb2.HealthCheckResponse.SERVING)  # type: ignore

    # Graceful shutdown
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    await stop_event.wait()
    logger.info("Shutting down gRPC server...")
    await server.stop(grace=None)  # мягко: завершить активные RPC
    await limiter.stop()
    logger.info("Server stopped")

def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
