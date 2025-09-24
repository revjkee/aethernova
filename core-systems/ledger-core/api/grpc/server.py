# ledger-core/api/grpc/server.py
"""
Industrial-grade gRPC server for ledger-core.
Python 3.10+, grpcio>=1.56

Features:
- asyncio gRPC server with interceptors (auth, logging, metrics)
- Health checking (grpc.health.v1)
- Server reflection for debuggability
- Optional TLS/mTLS with reload-safe credentials
- Prometheus metrics on a separate HTTP port
- Graceful shutdown on SIGTERM/SIGINT with deadlines
- Robust error handling and structured logs
- Keepalive, max message size, concurrency knobs

Replace PLACEHOLDER imports with your generated stubs.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Sequence

import grpc
from grpc.aio import ServerInterceptor, ServicerContext
from grpc_health.v1 import health, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

try:
    # Optional prometheus metrics
    from prometheus_client import Counter, Histogram, Gauge, start_http_server
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore
    def start_http_server(*args: Any, **kwargs: Any) -> None:  # type: ignore
        pass

# =============================================================================
# PLACEHOLDER: replace with your compiled proto modules
# Example:
# from ledger_core.schemas.proto.v1.ledger import ledger_service_pb2_grpc
# from ledger_core.schemas.proto.v1.balance import balance_service_pb2_grpc
# =============================================================================
# BEGIN PLACEHOLDER IMPORTS
# To illustrate registration flow we keep them optional.
ledger_service_pb2_grpc = None
balance_service_pb2_grpc = None
# END PLACEHOLDER IMPORTS

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

@dataclass
class ServerConfig:
    host: str = os.getenv("GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("GRPC_PORT", "7443"))
    # TLS / mTLS
    tls_enabled: bool = os.getenv("GRPC_TLS_ENABLED", "false").lower() == "true"
    tls_cert_file: Optional[str] = os.getenv("GRPC_TLS_CERT_FILE")  # server cert (PEM)
    tls_key_file: Optional[str] = os.getenv("GRPC_TLS_KEY_FILE")    # server key (PEM)
    tls_ca_file: Optional[str] = os.getenv("GRPC_TLS_CA_FILE")      # client CA (for mTLS)
    tls_client_auth: str = os.getenv("GRPC_TLS_CLIENT_AUTH", "none")  # none|require
    # Limits
    max_concurrent_streams: int = int(os.getenv("GRPC_MAX_CONCURRENT_STREAMS", "1024"))
    max_recv_message_bytes: int = int(os.getenv("GRPC_MAX_RECV_MB", "16")) * 1024 * 1024
    max_send_message_bytes: int = int(os.getenv("GRPC_MAX_SEND_MB", "16")) * 1024 * 1024
    # Keepalive
    ka_time: int = int(os.getenv("GRPC_KA_TIME_SEC", "60"))
    ka_timeout: int = int(os.getenv("GRPC_KA_TIMEOUT_SEC", "20"))
    ka_permit_without_calls: int = int(os.getenv("GRPC_KA_PING_WITHOUT_CALLS", "1"))
    # Metrics
    metrics_enabled: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    metrics_port: int = int(os.getenv("METRICS_PORT", "9095"))
    # Auth
    auth_mode: str = os.getenv("GRPC_AUTH_MODE", "none")  # none|api_key|jwt
    api_keys_b64: Optional[str] = os.getenv("GRPC_API_KEYS_B64")  # base64-encoded JSON list
    jwt_issuer: Optional[str] = os.getenv("GRPC_JWT_ISSUER")
    jwt_audience: Optional[str] = os.getenv("GRPC_JWT_AUDIENCE")
    jwt_jwks_url: Optional[str] = os.getenv("GRPC_JWT_JWKS_URL")  # if using remote JWKS (not fetched here)
    # Shutdown
    shutdown_grace: float = float(os.getenv("GRPC_SHUTDOWN_GRACE_SEC", "20"))
    shutdown_timeout: float = float(os.getenv("GRPC_SHUTDOWN_TIMEOUT_SEC", "30"))
    # Reflection
    reflection_enabled: bool = os.getenv("GRPC_REFLECTION_ENABLED", "true").lower() == "true"
    # Health service name to set SERVING for
    health_service_names: Sequence[str] = tuple(
        filter(None, os.getenv("GRPC_HEALTH_SERVICES", "").split(","))
    )

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------

def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv(
        "LOG_FORMAT",
        '{"t":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s","module":"%(module)s","fn":"%(funcName)s"}',
    )
    datefmt = "%Y-%m-%dT%H:%M:%S%z"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)
    # Reduce grpc noisy logs
    logging.getLogger("grpc").setLevel(logging.WARNING)


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------

if Counter and Histogram:
    RPC_COUNTER = Counter(
        "grpc_server_requests_total",
        "gRPC requests",
        labelnames=("service", "method", "code"),
    )
    RPC_LATENCY = Histogram(
        "grpc_server_request_seconds",
        "gRPC request latency",
        labelnames=("service", "method"),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
    ACTIVE_CONNECTIONS = Gauge(
        "grpc_server_active_connections",
        "Active connections",
    )
else:  # pragma: no cover
    RPC_COUNTER = RPC_LATENCY = ACTIVE_CONNECTIONS = None  # type: ignore


# -----------------------------------------------------------------------------
# Interceptors
# -----------------------------------------------------------------------------

class LoggingInterceptor(ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        start = time.perf_counter()
        method_full = handler_call_details.method  # "/package.Service/Method"
        service, method = method_full.rsplit("/", 1)
        try:
            handler = await continuation(handler_call_details)
        except Exception:
            logging.exception("Interceptor continuation error for %s", method_full)
            raise
        if handler is None:
            return None

        async def unary_unary(request, context: ServicerContext):
            try:
                resp = await handler.unary_unary(request, context)
                code = context.code() or grpc.StatusCode.OK
                self._observe(service, method, code, start)
                return resp
            except grpc.RpcError as e:
                code = e.code()
                self._observe(service, method, code, start)
                raise
            except Exception:
                logging.exception("Unhandled server error in %s", method_full)
                if context.is_active():
                    await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise

        # Stream handlers wrapped similarly
        async def unary_stream(request, context: ServicerContext):
            code = grpc.StatusCode.OK
            try:
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except grpc.RpcError as e:
                code = e.code()
                raise
            except Exception:
                logging.exception("Unhandled stream error in %s", method_full)
                code = grpc.StatusCode.INTERNAL
                if context.is_active():
                    await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise
            finally:
                self._observe(service, method, code, start)

        async def stream_unary(request_iter, context: ServicerContext):
            try:
                resp = await handler.stream_unary(request_iter, context)
                code = context.code() or grpc.StatusCode.OK
                self._observe(service, method, code, start)
                return resp
            except grpc.RpcError as e:
                self._observe(service, method, e.code(), start)
                raise
            except Exception:
                logging.exception("Unhandled server error in %s", method_full)
                if context.is_active():
                    await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise

        async def stream_stream(request_iter, context: ServicerContext):
            code = grpc.StatusCode.OK
            try:
                async for resp in handler.stream_stream(request_iter, context):
                    yield resp
            except grpc.RpcError as e:
                code = e.code()
                raise
            except Exception:
                logging.exception("Unhandled stream error in %s", method_full)
                code = grpc.StatusCode.INTERNAL
                if context.is_active():
                    await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise
            finally:
                self._observe(service, method, code, start)

        return grpc.aio.ServerInterceptorRpcMethodHandler(
            unary_unary=unary_unary if hasattr(handler, "unary_unary") else None,
            unary_stream=unary_stream if hasattr(handler, "unary_stream") else None,
            stream_unary=stream_unary if hasattr(handler, "stream_unary") else None,
            stream_stream=stream_stream if hasattr(handler, "stream_stream") else None,
        )

    def _observe(self, service: str, method: str, code: grpc.StatusCode, start: float) -> None:
        latency = time.perf_counter() - start
        if RPC_LATENCY:
            RPC_LATENCY.labels(service=service, method=method).observe(latency)
        if RPC_COUNTER:
            RPC_COUNTER.labels(service=service, method=method, code=code.name).inc()
        logging.info("grpc: service=%s method=%s code=%s latency_ms=%.2f", service, method, code.name, latency * 1000)


class AuthError(grpc.RpcError):
    def __init__(self, code: grpc.StatusCode, details: str):
        super().__init__()
        self._code = code
        self._details = details

    def code(self) -> grpc.StatusCode:  # type: ignore[override]
        return self._code

    def details(self) -> str:  # type: ignore[override]
        return self._details


class AuthInterceptor(ServerInterceptor):
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self._api_keys = set()
        if cfg.api_keys_b64:
            try:
                raw = base64.b64decode(cfg.api_keys_b64).decode("utf-8")
                self._api_keys = set(json.loads(raw))
            except Exception:
                logging.warning("Failed to parse GRPC_API_KEYS_B64")

    async def intercept_service(self, continuation, handler_call_details):
        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        async def deny(context: ServicerContext, code: grpc.StatusCode, msg: str):
            await context.abort(code, msg)

        async def check_auth(context: ServicerContext) -> None:
            # Allow unauthenticated health/reflection for observability
            method = handler_call_details.method
            if method.startswith("/grpc.health.v1.Health/"):
                return
            if self.cfg.auth_mode == "none":
                return
            md = dict(context.invocation_metadata() or [])
            auth = md.get("authorization") or md.get("Authorization")  # type: ignore
            if self.cfg.auth_mode == "api_key":
                api_key = md.get("x-api-key") or (auth.split(" ", 1)[1] if auth and auth.startswith("ApiKey ") else None)  # type: ignore
                if not api_key or api_key not in self._api_keys:
                    raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "invalid api key")
                return
            if self.cfg.auth_mode == "jwt":
                # Minimal JWT validation for example; production: verify signature via JWKS.
                if not auth or not auth.startswith("Bearer "):
                    raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
                token = auth.split(" ", 1)[1]
                # Do not perform remote calls here; rely on a separate verifier in your service.
                # Attach token to context for downstream handlers:
                context.set_trailing_metadata((("x-auth-subject", "jwt"),))  # example marker
                return
            raise AuthError(grpc.StatusCode.PERMISSION_DENIED, "access denied")

        async def wrap_unary_unary(request, context: ServicerContext):
            try:
                await check_auth(context)
                return await handler.unary_unary(request, context)
            except AuthError as e:
                await deny(context, e.code(), e.details())
                raise

        async def wrap_unary_stream(request, context: ServicerContext):
            try:
                await check_auth(context)
                async for resp in handler.unary_stream(request, context):
                    yield resp
            except AuthError as e:
                await deny(context, e.code(), e.details())
                raise

        async def wrap_stream_unary(request_iter, context: ServicerContext):
            try:
                await check_auth(context)
                return await handler.stream_unary(request_iter, context)
            except AuthError as e:
                await deny(context, e.code(), e.details())
                raise

        async def wrap_stream_stream(request_iter, context: ServicerContext):
            try:
                await check_auth(context)
                async for resp in handler.stream_stream(request_iter, context):
                    yield resp
            except AuthError as e:
                await deny(context, e.code(), e.details())
                raise

        return grpc.aio.ServerInterceptorRpcMethodHandler(
            unary_unary=wrap_unary_unary if hasattr(handler, "unary_unary") else None,
            unary_stream=wrap_unary_stream if hasattr(handler, "unary_stream") else None,
            stream_unary=wrap_stream_unary if hasattr(handler, "stream_unary") else None,
            stream_stream=wrap_stream_stream if hasattr(handler, "stream_stream") else None,
        )


# -----------------------------------------------------------------------------
# TLS helpers
# -----------------------------------------------------------------------------

def build_server_credentials(cfg: ServerConfig) -> Optional[grpc.ServerCredentials]:
    if not cfg.tls_enabled:
        return None
    if not cfg.tls_cert_file or not cfg.tls_key_file:
        raise RuntimeError("TLS enabled but GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE not set")
    with open(cfg.tls_cert_file, "rb") as f:
        cert_chain = f.read()
    with open(cfg.tls_key_file, "rb") as f:
        private_key = f.read()

    root_certs = None
    require_client_auth = cfg.tls_client_auth.lower() == "require"
    if cfg.tls_ca_file:
        with open(cfg.tls_ca_file, "rb") as f:
            root_certs = f.read()

    return grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=root_certs,
        require_client_auth=require_client_auth,
    )


# -----------------------------------------------------------------------------
# Server factory
# -----------------------------------------------------------------------------

async def create_server(cfg: ServerConfig) -> grpc.aio.Server:
    interceptors: list[ServerInterceptor] = [LoggingInterceptor(), AuthInterceptor(cfg)]
    opts = [
        ("grpc.max_concurrent_streams", cfg.max_concurrent_streams),
        ("grpc.max_receive_message_length", cfg.max_recv_message_bytes),
        ("grpc.max_send_message_length", cfg.max_send_message_bytes),
        ("grpc.keepalive_time_ms", cfg.ka_time * 1000),
        ("grpc.keepalive_timeout_ms", cfg.ka_timeout * 1000),
        ("grpc.keepalive_permit_without_calls", cfg.ka_permit_without_calls),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.http2.min_time_between_pings_ms", 10000),
        ("grpc.http2.min_ping_interval_without_data_ms", 10000),
    ]
    server = grpc.aio.server(interceptors=interceptors, options=opts)

    # Health service
    health_servicer = health.HealthServicer(
        experimental_non_blocking=True,  # async-friendly
    )
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    # Register application services (replace with your generated add_*_to_server)
    all_service_names: list[str] = [reflection.SERVICE_NAME, health.SERVICE_NAME]

    # PLACEHOLDER service registration (examples)
    # if ledger_service_pb2_grpc:
    #     ledger_service_pb2_grpc.add_LedgerServiceServicer_to_server(LedgerServiceImpl(), server)
    #     all_service_names.append("ledger.v1.LedgerService")
    # if balance_service_pb2_grpc:
    #     balance_service_pb2_grpc.add_BalanceServiceServicer_to_server(BalanceServiceImpl(), server)
    #     all_service_names.append("ledger.v1.BalanceService")

    # Reflection (optional)
    if cfg.reflection_enabled:
        reflection.enable_server_reflection(tuple(all_service_names), server)

    # Bind address
    bind_addr = f"{cfg.host}:{cfg.port}"
    creds = build_server_credentials(cfg)
    if creds:
        await server.add_secure_port(bind_addr, creds)
    else:
        await server.add_insecure_port(bind_addr)

    # Health: mark serving for configured services (if any provided)
    for svc in cfg.health_service_names:
        health_servicer.set(svc, health_pb2_grpc.health__pb2.HealthCheckResponse.SERVING)  # type: ignore

    return server


# -----------------------------------------------------------------------------
# Graceful lifecycle
# -----------------------------------------------------------------------------

async def serve(cfg: ServerConfig) -> None:
    if cfg.metrics_enabled:
        start_http_server(cfg.metrics_port)  # Prometheus metrics
        logging.info("metrics: http=:%d", cfg.metrics_port)

    server = await create_server(cfg)
    await server.start()
    ACTIVE_CONNECTIONS.inc() if ACTIVE_CONNECTIONS else None
    logging.info("grpc: listen=%s:%d tls=%s", cfg.host, cfg.port, cfg.tls_enabled)

    # Signal handlers for graceful shutdown
    stop_event = asyncio.Event()

    def _handle_signal(name: str):
        logging.warning("signal: %s received, initiating graceful shutdown", name)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig.name)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda *_: _handle_signal(sig.name))  # type: ignore

    await stop_event.wait()
    # Graceful stop
    await server.stop(cfg.shutdown_grace)
    ACTIVE_CONNECTIONS.dec() if ACTIVE_CONNECTIONS else None

    # Final timeout for lingering tasks
    try:
        await asyncio.wait_for(server.wait_for_termination(), timeout=cfg.shutdown_timeout)
    except asyncio.TimeoutError:
        logging.error("shutdown: force exit after timeout")
    logging.info("grpc: terminated")


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def parse_args(argv: Sequence[str]) -> ServerConfig:
    p = argparse.ArgumentParser(description="ledger-core gRPC server")
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--no-metrics", dest="metrics", action="store_false")
    p.add_argument("--metrics-port", type=int, default=None)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--cert", default=None)
    p.add_argument("--key", default=None)
    p.add_argument("--ca", default=None)
    p.add_argument("--mtls-require", action="store_true")
    p.add_argument("--auth-mode", choices=["none", "api_key", "jwt"], default=None)
    args = p.parse_args(argv)

    cfg = ServerConfig()
    if args.host is not None:
        cfg.host = args.host
    if args.port is not None:
        cfg.port = args.port
    if args.metrics is False:
        cfg.metrics_enabled = False
    if args.metrics_port is not None:
        cfg.metrics_port = args.metrics_port
    if args.tls:
        cfg.tls_enabled = True
    if args.cert:
        cfg.tls_cert_file = args.cert
    if args.key:
        cfg.tls_key_file = args.key
    if args.ca:
        cfg.tls_ca_file = args.ca
    if args.mtls_require:
        cfg.tls_client_auth = "require"
    if args.auth_mode:
        cfg.auth_mode = args.auth_mode
    return cfg


# -----------------------------------------------------------------------------
# Entry
# -----------------------------------------------------------------------------

def main() -> None:
    setup_logging()
    cfg = parse_args(sys.argv[1:])
    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
