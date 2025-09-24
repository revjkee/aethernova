# cybersecurity-core/api/grpc/server.py
# Industrial-grade async gRPC server for cybersecurity-core.
# Features:
# - TLS/mTLS (optional) via env or function args
# - Structured JSON access logging with request correlation ID (x-request-id)
# - Safe metadata redaction (authorization, x-api-key, cookies)
# - Auth interceptor (Bearer JWT via PyJWT if available, API-Key), pluggable policy
# - Rate limiting (token bucket per method and per peer)
# - Prometheus metrics (optional) and /metrics side HTTP server
# - gRPC Health Checking service
# - Reflection (optional)
# - Robust server/options: keepalive, message size limits, gzip compression
# - Graceful shutdown on SIGINT/SIGTERM
#
# Python: 3.10+
# Requires: grpcio>=1.56, grpcio-health-checking, (optional) prometheus_client, PyJWT
from __future__ import annotations

import asyncio
import contextvars
import hmac
import json
import logging
import os
import signal
import sys
import time
import uuid
from hashlib import sha256
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Sequence, Tuple, Union

import grpc
from grpc import aio

try:  # Health service
    from grpc_health.v1 import health, health_pb2_grpc
    _HEALTH_AVAILABLE = True
except Exception:  # pragma: no cover
    _HEALTH_AVAILABLE = False

try:  # Reflection
    from grpc_reflection.v1alpha import reflection
    _REFLECTION_AVAILABLE = True
except Exception:  # pragma: no cover
    _REFLECTION_AVAILABLE = False

try:  # Metrics (optional)
    from prometheus_client import Counter, Histogram, Gauge, start_http_server  # type: ignore
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

try:  # JWT (optional)
    import jwt  # type: ignore
    _JWT_AVAILABLE = True
except Exception:  # pragma: no cover
    _JWT_AVAILABLE = False


# =========================
# Context & Logging utils
# =========================

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("grpc_request_id", default="")

REDACTED = "******"
REDACT_METADATA = {"authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie"}

def get_request_id() -> str:
    return _request_id_ctx.get()

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        try:
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return f'{payload["ts"]} {payload["level"]} {payload["logger"]} {payload["msg"]}'

def _configure_logger(name: str = "cybersec.grpc") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.propagate = False
    return lg

LOGGER = _configure_logger()

def _redact_metadata(md: Sequence[Tuple[str, str]] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not md:
        return out
    for k, v in md:
        kl = k.lower()
        out[kl] = REDACTED if kl in REDACT_METADATA else v
    return out

def _status_name(code: grpc.StatusCode | None) -> str | None:
    return code.name if code else None


# =========================
# Prometheus metrics (opt)
# =========================

if _PROM_AVAILABLE:
    RPC_STARTED = Counter(
        "grpc_server_rpc_started_total",
        "Total number of RPCs started on the server.",
        ["grpc_service", "grpc_method"],
    )
    RPC_HANDLED = Counter(
        "grpc_server_rpc_handled_total",
        "Total number of RPCs completed on the server, regardless of success or failure.",
        ["grpc_service", "grpc_method", "grpc_code"],
    )
    RPC_LATENCY = Histogram(
        "grpc_server_handling_seconds",
        "Histogram of response latency (seconds) for gRPC that had been application-level handled by the server.",
        ["grpc_service", "grpc_method"],
        buckets=(0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
    RPC_INFLIGHT = Gauge(
        "grpc_server_in_flight",
        "Current in-flight RPCs.",
        ["grpc_service", "grpc_method"],
    )
else:  # pragma: no cover
    RPC_STARTED = RPC_HANDLED = RPC_LATENCY = RPC_INFLIGHT = None


# =========================
# Token bucket rate limiter
# =========================

class _TokenBucket:
    __slots__ = ("rate", "capacity", "tokens", "updated")

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    def consume(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


# =========================
# Auth policy
# =========================

class AuthError(Exception):
    pass

class AuthPolicy:
    """
    Pluggable auth policy:
      - verify_api_key(api_key: str) -> bool
      - verify_jwt(token: str) -> dict (claims)  OR raises AuthError
    """
    def __init__(
        self,
        *,
        api_keys: Optional[set[str]] = None,
        jwt_secret: Optional[str] = None,
        jwt_audience: Optional[str] = None,
        jwt_issuer: Optional[str] = None,
        jwt_algorithms: Sequence[str] = ("HS256",),
        constant_time_api_key: bool = True,
    ) -> None:
        self.api_keys = api_keys or set()
        self.jwt_secret = jwt_secret
        self.jwt_audience = jwt_audience
        self.jwt_issuer = jwt_issuer
        self.jwt_algorithms = tuple(jwt_algorithms)
        self.constant_time_api_key = constant_time_api_key

    def verify_api_key(self, api_key: str) -> bool:
        if not self.api_keys:
            return False
        if self.constant_time_api_key:
            for k in self.api_keys:
                if hmac.compare_digest(k, api_key):
                    return True
            return False
        return api_key in self.api_keys

    def verify_jwt(self, token: str) -> dict:
        if not self.jwt_secret:
            raise AuthError("JWT secret is not configured")
        if _JWT_AVAILABLE:
            try:
                claims = jwt.decode(
                    token,
                    self.jwt_secret,
                    algorithms=list(self.jwt_algorithms),
                    audience=self.jwt_audience,
                    issuer=self.jwt_issuer,
                )
                return dict(claims)
            except Exception as e:  # pragma: no cover
                raise AuthError(f"JWT validation error: {e}") from e
        else:
            # Minimal HS256 check without PyJWT (no exp/nbf/aud checks)
            try:
                header_b64, payload_b64, signature_b64 = token.split(".")
            except ValueError as e:  # pragma: no cover
                raise AuthError("Malformed JWT") from e
            signing_input = f"{header_b64}.{payload_b64}".encode()
            import base64
            def b64url_decode(x: str) -> bytes:
                pad = "=" * (-len(x) % 4)
                return base64.urlsafe_b64decode(x + pad)
            expected_sig = hmac.new(self.jwt_secret.encode(), signing_input, sha256).digest()
            if not hmac.compare_digest(expected_sig, b64url_decode(signature_b64)):
                raise AuthError("Invalid JWT signature")
            try:
                payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
            except Exception as e:  # pragma: no cover
                raise AuthError("Invalid JWT payload") from e
            return payload


# =========================
# Interceptors
# =========================

class AccessLogInterceptor(aio.ServerInterceptor):
    def __init__(self, logger: logging.Logger = LOGGER, sample_rate: float = 1.0) -> None:
        self.logger = logger
        self.sample_rate = max(0.0, min(1.0, sample_rate))

    async def intercept_service(self, continuation, handler_call_details):
        method_full = handler_call_details.method or ""
        service, method = _split_method(method_full)
        metadata = list(handler_call_details.invocation_metadata or [])
        req_id = _extract_request_id(metadata) or str(uuid.uuid4())
        token = _request_id_ctx.set(req_id)
        started = time.monotonic()

        if RPC_INFLIGHT is not None:
            RPC_INFLIGHT.labels(service, method).inc()
        if RPC_STARTED is not None:
            RPC_STARTED.labels(service, method).inc()

        handler = await continuation(handler_call_details)

        def _log(event: str, *, code: grpc.StatusCode | None = None, peer: str | None = None, extra: dict | None = None):
            payload = {
                "event": event,
                "request_id": req_id,
                "grpc_service": service,
                "grpc_method": method,
                "peer": peer,
                "code": _status_name(code),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "metadata": _redact_metadata(metadata),
                "sampled": self._sample(),
            }
            if extra:
                payload.update(extra)
            self.logger.info("grpc.access", extra={"extra": payload})

        # Wrap unary-unary
        if handler and handler.unary_unary:
            inner = handler.unary_unary

            async def wrapper(request, context):
                peer = context.peer()
                try:
                    response = await inner(request, context)
                    code = context.code() or grpc.StatusCode.OK
                    _log("rpc_complete", code=code, peer=peer)
                    return response
                except grpc.RpcError as e:
                    _log("rpc_error", code=e.code(), peer=peer, extra={"details": e.details()})
                    raise
                except Exception as e:
                    _log("rpc_exception", code=grpc.StatusCode.INTERNAL, peer=peer, extra={"error": repr(e)})
                    raise
                finally:
                    if RPC_INFLIGHT is not None:
                        RPC_INFLIGHT.labels(service, method).dec()
                    if RPC_HANDLED is not None:
                        code = context.code() or grpc.StatusCode.OK
                        RPC_HANDLED.labels(service, method, code.name).inc()
                    if RPC_LATENCY is not None:
                        RPC_LATENCY.labels(service, method).observe(time.monotonic() - started)

            return aio.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Wrap unary-stream
        if handler and handler.unary_stream:
            inner = handler.unary_stream

            async def wrapper(request, context):
                peer = context.peer()
                try:
                    async for resp in inner(request, context):
                        yield resp
                except grpc.RpcError as e:
                    self.logger.info("grpc.access", extra={"extra": {
                        "event": "rpc_error",
                        "request_id": req_id,
                        "grpc_service": service,
                        "grpc_method": method,
                        "peer": peer,
                        "code": _status_name(e.code()),
                        "details": e.details(),
                        "metadata": _redact_metadata(metadata),
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    }})
                    raise
                except Exception as e:
                    self.logger.info("grpc.access", extra={"extra": {
                        "event": "rpc_exception",
                        "request_id": req_id,
                        "grpc_service": service,
                        "grpc_method": method,
                        "peer": peer,
                        "code": "INTERNAL",
                        "error": repr(e),
                        "metadata": _redact_metadata(metadata),
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    }})
                    raise
                finally:
                    if RPC_INFLIGHT is not None:
                        RPC_INFLIGHT.labels(service, method).dec()
                    if RPC_HANDLED is not None:
                        code = aio.ServicerContext.code(context) if hasattr(aio.ServicerContext, "code") else (context.code() or grpc.StatusCode.OK)  # type: ignore
                        RPC_HANDLED.labels(service, method, (code.name if code else "OK")).inc()
                    if RPC_LATENCY is not None:
                        RPC_LATENCY.labels(service, method).observe(time.monotonic() - started)

            return aio.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # For stream types not explicitly wrapped, return original handler
        # (you can extend to stream_unary/stream_stream similarly if needed).
        return handler

    def _sample(self) -> bool:
        if self.sample_rate >= 1.0:
            return True
        if self.sample_rate <= 0.0:
            return False
        import random
        return random.random() < self.sample_rate


class AuthInterceptor(aio.ServerInterceptor):
    """
    Supports:
      - "authorization": "Bearer <jwt>" OR "ApiKey <key>" OR raw key
      - "x-api-key": "<key>"
    """
    def __init__(self, policy: AuthPolicy) -> None:
        self.policy = policy

    async def intercept_service(self, continuation, handler_call_details):
        md = list(handler_call_details.invocation_metadata or [])
        api_key, bearer = _extract_keys(md)
        try:
            if bearer:
                claims = self.policy.verify_jwt(bearer)
                # Optionally attach claims to context via contextvars (simple stash)
                _grpc_claims_ctx.set(claims)  # type: ignore
            elif api_key:
                if not self.policy.verify_api_key(api_key):
                    raise AuthError("Invalid API key")
            else:
                raise AuthError("Missing credentials")
        except AuthError as e:
            # Short-circuit with UNAUTHENTICATED
            async def unauthenticated_behavior(request, context):
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, str(e))
            return aio.unary_unary_rpc_method_handler(unauthenticated_behavior)
        return await continuation(handler_call_details)

_grpc_claims_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("grpc_claims", default={})

def get_claims() -> dict:
    return _grpc_claims_ctx.get()


class RateLimitInterceptor(aio.ServerInterceptor):
    """
    Token bucket per (peer, method) with global defaults.
    """
    def __init__(self, rate_per_sec: float = 50.0, burst: float = 100.0) -> None:
        self.rate = float(rate_per_sec)
        self.burst = float(burst)
        self._buckets: dict[Tuple[str, str], _TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def intercept_service(self, continuation, handler_call_details):
        method_full = handler_call_details.method or ""
        service, method = _split_method(method_full)
        handler = await continuation(handler_call_details)
        if not handler:
            return handler

        # Wrap only unary_unary & unary_stream for performance
        if handler.unary_unary:
            inner = handler.unary_unary

            async def wrapper(request, context):
                peer = context.peer()
                if not await self._allow(peer, f"{service}/{method}"):
                    await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                return await inner(request, context)

            return aio.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            async def wrapper(request, context):
                peer = context.peer()
                if not await self._allow(peer, f"{service}/{method}"):
                    await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")
                async for resp in inner(request, context):
                    yield resp

            return aio.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler

    async def _allow(self, peer: str, method: str) -> bool:
        key = (peer, method)
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self.rate, self.burst)
                self._buckets[key] = bucket
            return bucket.consume(1.0)


class ExceptionMappingInterceptor(aio.ServerInterceptor):
    """
    Converts unexpected exceptions into INTERNAL without leaking internals.
    """
    def __init__(self, logger: logging.Logger = LOGGER) -> None:
        self.logger = logger

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if not handler:
            return handler

        if handler.unary_unary:
            inner = handler.unary_unary

            async def wrapper(request, context):
                try:
                    return await inner(request, context)
                except grpc.RpcError:
                    raise
                except Exception as e:
                    req_id = get_request_id()
                    self.logger.error("grpc.exception", extra={"extra": {
                        "event": "uncaught_exception",
                        "request_id": req_id,
                        "method": handler_call_details.method,
                        "error": repr(e),
                    }})
                    await context.abort(grpc.StatusCode.INTERNAL, "internal server error")

            return aio.unary_unary_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            inner = handler.unary_stream

            async def wrapper(request, context):
                try:
                    async for resp in inner(request, context):
                        yield resp
                except grpc.RpcError:
                    raise
                except Exception as e:
                    req_id = get_request_id()
                    self.logger.error("grpc.exception", extra={"extra": {
                        "event": "uncaught_exception",
                        "request_id": req_id,
                        "method": handler_call_details.method,
                        "error": repr(e),
                    }})
                    await context.abort(grpc.StatusCode.INTERNAL, "internal server error")

            return aio.unary_stream_rpc_method_handler(
                wrapper,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


# =========================
# TLS/mTLS helpers
# =========================

def _build_server_credentials(
    *,
    cert_chain_pem: Optional[bytes],
    private_key_pem: Optional[bytes],
    root_ca_pem: Optional[bytes],
    require_client_auth: bool,
) -> Optional[grpc.ServerCredentials]:
    if not cert_chain_pem or not private_key_pem:
        return None
    if require_client_auth:
        return grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=[(private_key_pem, cert_chain_pem)],
            root_certificates=root_ca_pem or None,
            require_client_auth=True,
        )
    else:
        return grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=[(private_key_pem, cert_chain_pem)],
            root_certificates=None,
            require_client_auth=False,
        )


# =========================
# Public server API
# =========================

class ServerConfig:
    def __init__(
        self,
        *,
        bind: str = os.getenv("GRPC_BIND", "0.0.0.0:50051"),
        max_send_mb: int = int(os.getenv("GRPC_MAX_SEND_MB", "16")),
        max_recv_mb: int = int(os.getenv("GRPC_MAX_RECV_MB", "16")),
        max_concurrent_rpcs: int = int(os.getenv("GRPC_MAX_CONCURRENCY", "1024")),
        enable_reflection: bool = os.getenv("GRPC_REFLECTION", "1") == "1",
        enable_health: bool = os.getenv("GRPC_HEALTH", "1") == "1",
        enable_metrics: bool = os.getenv("GRPC_METRICS", "1") == "1",
        metrics_port: Optional[int] = int(os.getenv("METRICS_PORT", "8000")),
        keepalive_time_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "60000")),
        keepalive_timeout_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000")),
        keepalive_permit_wo_calls: int = int(os.getenv("GRPC_KEEPALIVE_PERMIT_WO_CALLS", "1")),
        http2_max_pings_without_data: int = int(os.getenv("GRPC_HTTP2_MAX_PINGS_WO_DATA", "0")),
        compression: Optional[grpc.Compression] = grpc.Compression.Gzip,
        # TLS
        tls_cert_path: Optional[str] = os.getenv("GRPC_TLS_CERT"),
        tls_key_path: Optional[str] = os.getenv("GRPC_TLS_KEY"),
        tls_ca_path: Optional[str] = os.getenv("GRPC_TLS_CA"),
        tls_require_client_auth: bool = os.getenv("GRPC_MTLS", "0") == "1",
        # Auth & RL
        auth_api_keys: Optional[set[str]] = {k.strip() for k in os.getenv("GRPC_API_KEYS", "").split(",") if k.strip()},
        jwt_secret: Optional[str] = os.getenv("GRPC_JWT_SECRET"),
        jwt_aud: Optional[str] = os.getenv("GRPC_JWT_AUD"),
        jwt_iss: Optional[str] = os.getenv("GRPC_JWT_ISS"),
        rl_rate: float = float(os.getenv("GRPC_RL_RATE", "50")),
        rl_burst: float = float(os.getenv("GRPC_RL_BURST", "100")),
        access_log_sample: float = float(os.getenv("GRPC_ACCESSLOG_SAMPLE", "1.0")),
    ) -> None:
        self.bind = bind
        self.max_send_mb = max_send_mb
        self.max_recv_mb = max_recv_mb
        self.max_concurrent_rpcs = max_concurrent_rpcs
        self.enable_reflection = enable_reflection
        self.enable_health = enable_health
        self.enable_metrics = enable_metrics
        self.metrics_port = metrics_port
        self.keepalive_time_ms = keepalive_time_ms
        self.keepalive_timeout_ms = keepalive_timeout_ms
        self.keepalive_permit_wo_calls = keepalive_permit_wo_calls
        self.http2_max_pings_without_data = http2_max_pings_without_data
        self.compression = compression
        self.tls_cert_path = tls_cert_path
        self.tls_key_path = tls_key_path
        self.tls_ca_path = tls_ca_path
        self.tls_require_client_auth = tls_require_client_auth
        self.auth_api_keys = auth_api_keys or set()
        self.jwt_secret = jwt_secret
        self.jwt_aud = jwt_aud
        self.jwt_iss = jwt_iss
        self.rl_rate = rl_rate
        self.rl_burst = rl_burst
        self.access_log_sample = access_log_sample


async def serve(
    register_services: Callable[[aio.Server], None],
    *,
    cfg: Optional[ServerConfig] = None,
    extra_interceptors: Optional[list[aio.ServerInterceptor]] = None,
) -> None:
    """
    Start the gRPC server with provided service registration callback.

    register_services(server): must add_*_servicer_to_server(...) for all services.
    """
    cfg = cfg or ServerConfig()

    # Metrics side server
    if cfg.enable_metrics and _PROM_AVAILABLE and cfg.metrics_port:
        start_http_server(cfg.metrics_port)

    # Interceptors (order matters)
    interceptors: list[aio.ServerInterceptor] = [
        AccessLogInterceptor(LOGGER, sample_rate=cfg.access_log_sample),
        ExceptionMappingInterceptor(LOGGER),
        RateLimitInterceptor(cfg.rl_rate, cfg.rl_burst),
    ]
    # Auth (enabled if configured)
    if cfg.auth_api_keys or cfg.jwt_secret:
        policy = AuthPolicy(
            api_keys=cfg.auth_api_keys,
            jwt_secret=cfg.jwt_secret,
            jwt_audience=cfg.jwt_aud,
            jwt_issuer=cfg.jwt_iss,
        )
        interceptors.insert(1, AuthInterceptor(policy))

    if extra_interceptors:
        interceptors.extend(extra_interceptors)

    # Server options
    options = (
        ("grpc.max_send_message_length", cfg.max_send_mb * 1024 * 1024),
        ("grpc.max_receive_message_length", cfg.max_recv_mb * 1024 * 1024),
        ("grpc.keepalive_time_ms", cfg.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.keepalive_permit_without_calls", cfg.keepalive_permit_wo_calls),
        ("grpc.http2.max_pings_without_data", cfg.http2_max_pings_without_data),
    )

    server = aio.server(
        interceptors=interceptors,
        options=options,
        maximum_concurrent_rpcs=cfg.max_concurrent_rpcs,
        compression=cfg.compression,
    )

    # Health service
    service_names_for_reflection: list[str] = []
    if _HEALTH_AVAILABLE and cfg.enable_health:
        health_servicer = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
        service_names_for_reflection.append(health.SERVICE_NAME)

    # Register application services
    register_services(server)
    service_names_for_reflection.extend(_list_registered_service_names(server))

    # Reflection
    if _REFLECTION_AVAILABLE and cfg.enable_reflection and service_names_for_reflection:
        reflection.enable_server_reflection(service_names_for_reflection, server)

    # TLS/mTLS
    creds = None
    if cfg.tls_cert_path and cfg.tls_key_path:
        cert = _read_bytes(cfg.tls_cert_path)
        key = _read_bytes(cfg.tls_key_path)
        ca = _read_bytes(cfg.tls_ca_path) if cfg.tls_ca_path else None
        creds = _build_server_credentials(
            cert_chain_pem=cert,
            private_key_pem=key,
            root_ca_pem=ca,
            require_client_auth=cfg.tls_require_client_auth,
        )

    # Bind
    if creds:
        addy = server.add_secure_port(cfg.bind, creds)
    else:
        addy = server.add_insecure_port(cfg.bind)
    if addy == 0:
        raise RuntimeError(f"Failed to bind gRPC on {cfg.bind}")

    # Start
    await server.start()
    LOGGER.info("grpc.server.started", extra={"extra": {
        "bind": cfg.bind,
        "secure": bool(creds),
        "mtls": bool(creds and cfg.tls_require_client_auth),
        "services": service_names_for_reflection,
        "pid": os.getpid(),
    }})

    # Graceful shutdown
    stop_event = asyncio.Event()

    def _handle_signal(signame: str):
        LOGGER.info("grpc.server.signal", extra={"extra": {"signal": signame}})
        stop_event.set()

    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _handle_signal, s.name)
        except NotImplementedError:  # pragma: no cover
            signal.signal(s, lambda *_: _handle_signal(s.name))

    await stop_event.wait()
    await server.stop(grace=None)  # allow inflight to finish
    LOGGER.info("grpc.server.stopped", extra={"extra": {"bind": cfg.bind}})


# =========================
# Helpers
# =========================

def _split_method(full: str) -> Tuple[str, str]:
    # "/package.Service/Method" -> ("package.Service", "Method")
    try:
        _, rest = full.split("/", 1)
        svc, meth = rest.split("/", 1)
        return svc, meth
    except Exception:
        return "", full or ""

def _extract_request_id(md: Sequence[Tuple[str, str]] | None) -> Optional[str]:
    if not md:
        return None
    for k, v in md:
        if k.lower() in ("x-request-id", "request-id"):
            return v
    return None

def _extract_keys(md: Sequence[Tuple[str, str]] | None) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns: (api_key, bearer_jwt)
    """
    api_key = None
    bearer = None
    if not md:
        return api_key, bearer
    for k, v in md:
        kl = k.lower()
        if kl == "x-api-key":
            api_key = v
        elif kl == "authorization":
            val = v.strip()
            if val.lower().startswith("bearer "):
                bearer = val[7:].strip()
            elif val.lower().startswith("apikey "):
                api_key = val[7:].strip()
            else:
                # treat as raw api key
                api_key = val
    return api_key, bearer

def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def _list_registered_service_names(server: aio.Server) -> list[str]:
    # Reflection needs full service names; aio.Server has _state with generic_handlers
    names: list[str] = []
    try:
        for h in server._state.generic_handlers:  # type: ignore[attr-defined]
            if hasattr(h, "service_name"):
                names.append(h.service_name())
            elif hasattr(h, "_method_handlers"):
                # Fallback
                pass
    except Exception:
        pass
    # Add reflection service name itself when enabled by reflection.enable_server_reflection
    if _REFLECTION_AVAILABLE:
        names.append(reflection.SERVICE_NAME)
    # Deduplicate
    return sorted(set(filter(None, names)))


# =========================
# CLI entry (optional)
# =========================

async def _noop_register(server: aio.Server) -> None:
    # Placeholder if run standalone; real services must be registered by caller.
    pass

def main() -> None:
    """
    Standalone run with env configuration.
    """
    cfg = ServerConfig()
    asyncio.run(serve(_noop_register, cfg=cfg))

if __name__ == "__main__":
    main()
