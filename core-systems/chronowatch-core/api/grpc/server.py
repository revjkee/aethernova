# chronowatch-core/api/grpc/server.py
# Industrial-grade gRPC server for ChronoWatch Core (Python 3.11+)
# Features: TLS, health, reflection, auth (API key / JWT), logging, error normalization,
# keepalive tuning, graceful shutdown, optional Prometheus metrics.

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import json
import logging
import os
import signal
import sys
import time
import traceback
from typing import Any, Awaitable, Callable, Iterable, Optional, Sequence, Tuple

import grpc
from grpc import StatusCode
from grpc.aio import ServerInterceptor, ServicerContext, Server, AioRpcError

# Optional features
try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
    HAS_HEALTH = True
except Exception:  # pragma: no cover
    HAS_HEALTH = False
    health = health_pb2 = health_pb2_grpc = None  # type: ignore

try:
    from grpc_reflection.v1alpha import reflection
    HAS_REFLECTION = True
except Exception:  # pragma: no cover
    HAS_REFLECTION = False
    reflection = None  # type: ignore

try:
    import uvloop  # type: ignore
    HAS_UVLOOP = True
except Exception:  # pragma: no cover
    HAS_UVLOOP = False

try:
    import jwt  # PyJWT
    HAS_JWT = True
except Exception:  # pragma: no cover
    HAS_JWT = False

try:
    # Prometheus telemetry is optional
    from prometheus_client import Counter, Histogram, start_http_server  # type: ignore
    HAS_PROM = True
except Exception:  # pragma: no cover
    HAS_PROM = False

# ------------------------------------------------------------------------------
# Correlation context
# ------------------------------------------------------------------------------
correlation_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("corr_id", default=None)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
@dataclasses.dataclass(slots=True)
class GrpcConfig:
    host: str = os.getenv("GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("GRPC_PORT", "50051"))
    max_send_message_bytes: int = int(os.getenv("GRPC_MAX_SEND_BYTES", str(50 * 1024 * 1024)))
    max_receive_message_bytes: int = int(os.getenv("GRPC_MAX_RECV_BYTES", str(50 * 1024 * 1024)))
    max_concurrent_rpcs: Optional[int] = None  # reserved (grpc.aio manages concurrency with ThreadPool)
    compression: Optional[grpc.Compression] = grpc.Compression.Gzip if os.getenv("GRPC_GZIP", "true").lower() == "true" else None

    # Keepalive / HTTP2 tuning (values in ms)
    keepalive_time_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "60000"))
    keepalive_timeout_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000"))
    keepalive_permit_without_calls: int = int(os.getenv("GRPC_KEEPALIVE_PERMIT_WITHOUT_CALLS", "1"))
    http2_max_pings_without_data: int = int(os.getenv("GRPC_HTTP2_MAX_PINGS_WITHOUT_DATA", "0"))
    http2_min_recv_ping_interval_without_data_ms: int = int(os.getenv("GRPC_HTTP2_MIN_RECV_PING_INTERVAL_MS", "10000"))
    http2_max_ping_strikes: int = int(os.getenv("GRPC_HTTP2_MAX_PING_STRIKES", "2"))

    # TLS
    tls_enabled: bool = os.getenv("GRPC_TLS_ENABLED", "false").lower() == "true"
    tls_cert_file: str = os.getenv("GRPC_TLS_CERT_FILE", "")
    tls_key_file: str = os.getenv("GRPC_TLS_KEY_FILE", "")
    tls_client_ca_file: Optional[str] = os.getenv("GRPC_TLS_CLIENT_CA_FILE", "") or None  # mTLS if provided

    # Auth
    api_key: Optional[str] = os.getenv("GRPC_API_KEY")  # static API key
    jwt_secret: Optional[str] = os.getenv("GRPC_JWT_SECRET")  # HS256 secret
    jwt_issuer: Optional[str] = os.getenv("GRPC_JWT_ISSUER") or None
    jwt_audience: Optional[str] = os.getenv("GRPC_JWT_AUDIENCE") or None
    allow_insecure_no_auth: bool = os.getenv("GRPC_ALLOW_INSECURE_NO_AUTH", "false").lower() == "true"

    # Health & Reflection
    enable_health: bool = os.getenv("GRPC_ENABLE_HEALTH", "true").lower() == "true"
    enable_reflection: bool = os.getenv("GRPC_ENABLE_REFLECTION", "true").lower() == "true"

    # Metrics
    enable_metrics: bool = os.getenv("GRPC_ENABLE_METRICS", "false").lower() == "true"
    metrics_port: int = int(os.getenv("METRICS_PORT", "9095"))

    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def bind(self) -> str:
        return f"{self.host}:{self.port}"


# ------------------------------------------------------------------------------
# Metrics (optional)
# ------------------------------------------------------------------------------
if HAS_PROM:
    RPC_REQUESTS = Counter(
        "grpc_requests_total",
        "Total number of gRPC requests",
        ["method", "code"],
    )
    RPC_LATENCY = Histogram(
        "grpc_request_duration_seconds",
        "Latency of gRPC requests",
        ["method"],
        buckets=(
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
            0.5, 1.0, 2.5, 5.0, 10.0
        ),
    )
else:
    RPC_REQUESTS = None
    RPC_LATENCY = None


# ------------------------------------------------------------------------------
# Interceptors
# ------------------------------------------------------------------------------
class ErrorNormalizerInterceptor(ServerInterceptor):
    """Convert uncaught exceptions to proper gRPC status codes."""

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)

        if handler is None:
            return handler  # pragma: no cover

        async def unary_unary(request, context: ServicerContext):
            try:
                return await handler.unary_unary(request, context)  # type: ignore[attr-defined]
            except AioRpcError:
                raise
            except asyncio.CancelledError:
                await context.abort(StatusCode.CANCELLED, "Request cancelled")
            except Exception as exc:  # pragma: no cover
                logging.getLogger("grpc.error").error("Unhandled exception: %s", exc, exc_info=True)
                await context.abort(StatusCode.INTERNAL, "Internal server error")

        async def unary_stream(request, context: ServicerContext):
            try:
                async for resp in handler.unary_stream(request, context):  # type: ignore[attr-defined]
                    yield resp
            except AioRpcError:
                raise
            except asyncio.CancelledError:
                await context.abort(StatusCode.CANCELLED, "Request cancelled")
            except Exception as exc:  # pragma: no cover
                logging.getLogger("grpc.error").error("Unhandled exception: %s", exc, exc_info=True)
                await context.abort(StatusCode.INTERNAL, "Internal server error")

        # For simplicity, we wrap most common paths; others fall back to original handler
        return grpc.aio.RpcMethodHandler(
            unary_unary=unary_unary if getattr(handler, "unary_unary", None) else None,
            unary_stream=unary_stream if getattr(handler, "unary_stream", None) else None,
            stream_unary=getattr(handler, "stream_unary", None),
            stream_stream=getattr(handler, "stream_stream", None),
        )


class LoggingInterceptor(ServerInterceptor):
    """Structured logging + correlation id + metrics."""

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        method = handler_call_details.method

        handler = await continuation(handler_call_details)
        if handler is None:
            return handler  # pragma: no cover

        async def unary_unary(request, context: ServicerContext):
            start = time.perf_counter()
            corr_id = _extract_correlation_id(context)
            token = correlation_id_ctx.set(corr_id)
            try:
                result = await handler.unary_unary(request, context)  # type: ignore[attr-defined]
                code = context.code() or StatusCode.OK
                _observe_metrics(method, code, start)
                _log_access(method, code, start, corr_id, context)
                return result
            finally:
                correlation_id_ctx.reset(token)

        async def unary_stream(request, context: ServicerContext):
            start = time.perf_counter()
            corr_id = _extract_correlation_id(context)
            token = correlation_id_ctx.set(corr_id)
            try:
                async for resp in handler.unary_stream(request, context):  # type: ignore[attr-defined]
                    yield resp
                code = context.code() or StatusCode.OK
                _observe_metrics(method, code, start)
                _log_access(method, code, start, corr_id, context)
            finally:
                correlation_id_ctx.reset(token)

        return grpc.aio.RpcMethodHandler(
            unary_unary=unary_unary if getattr(handler, "unary_unary", None) else None,
            unary_stream=unary_stream if getattr(handler, "unary_stream", None) else None,
            stream_unary=getattr(handler, "stream_unary", None),
            stream_stream=getattr(handler, "stream_stream", None),
        )


class AuthInterceptor(ServerInterceptor):
    """Simple API key / JWT authorization interceptor."""

    def __init__(self, cfg: GrpcConfig):
        self.cfg = cfg

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        handler = await continuation(handler_call_details)
        if handler is None:
            return handler  # pragma: no cover

        async def unary_unary(request, context: ServicerContext):
            await self._authorize(context)
            return await handler.unary_unary(request, context)  # type: ignore[attr-defined]

        async def unary_stream(request, context: ServicerContext):
            await self._authorize(context)
            async for resp in handler.unary_stream(request, context):  # type: ignore[attr-defined]
                yield resp

        return grpc.aio.RpcMethodHandler(
            unary_unary=unary_unary if getattr(handler, "unary_unary", None) else None,
            unary_stream=unary_stream if getattr(handler, "unary_stream", None) else None,
            stream_unary=getattr(handler, "stream_unary", None),
            stream_stream=getattr(handler, "stream_stream", None),
        )

    async def _authorize(self, context: ServicerContext) -> None:
        if self.cfg.allow_insecure_no_auth and not (self.cfg.api_key or self.cfg.jwt_secret):
            return  # explicitly allowed for dev/test

        md = dict(context.invocation_metadata())
        # 1) API Key
        key = md.get("x-api-key") or md.get("authorization")
        if key and key.startswith("ApiKey "):
            candidate = key.split(" ", 1)[1].strip()
            if self.cfg.api_key and candidate == self.cfg.api_key:
                return
            await context.abort(StatusCode.UNAUTHENTICATED, "Invalid API key")

        # 2) JWT Bearer
        if HAS_JWT and (auth := md.get("authorization")) and auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
            try:
                decoded = jwt.decode(
                    token,
                    self.cfg.jwt_secret,
                    algorithms=["HS256"],
                    issuer=self.cfg.jwt_issuer if self.cfg.jwt_issuer else None,
                    audience=self.cfg.jwt_audience if self.cfg.jwt_audience else None,
                    options={
                        "verify_signature": bool(self.cfg.jwt_secret),
                        "verify_iss": bool(self.cfg.jwt_issuer),
                        "verify_aud": bool(self.cfg.jwt_audience),
                    },
                )
                # Optionally, check scopes/claims here
                return
            except Exception:
                await context.abort(StatusCode.UNAUTHENTICATED, "Invalid JWT")

        # 3) No credentials
        await context.abort(StatusCode.UNAUTHENTICATED, "Missing credentials")


# ------------------------------------------------------------------------------
# Server builder and registration
# ------------------------------------------------------------------------------
def build_server(cfg: GrpcConfig) -> Server:
    options = [
        ("grpc.max_send_message_length", cfg.max_send_message_bytes),
        ("grpc.max_receive_message_length", cfg.max_receive_message_bytes),
        ("grpc.keepalive_time_ms", cfg.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.keepalive_permit_without_calls", cfg.keepalive_permit_without_calls),
        ("grpc.http2.max_pings_without_data", cfg.http2_max_pings_without_data),
        ("grpc.http2.min_time_between_pings_ms", cfg.keepalive_time_ms),
        ("grpc.http2.min_ping_interval_without_data_ms", cfg.http2_min_recv_ping_interval_without_data_ms),
        ("grpc.http2.max_ping_strikes", cfg.http2_max_ping_strikes),
    ]

    interceptors: list[ServerInterceptor] = [
        ErrorNormalizerInterceptor(),
        LoggingInterceptor(),
        AuthInterceptor(cfg),
    ]

    server = grpc.aio.server(
        options=options,
        interceptors=interceptors,
        compression=cfg.compression,
    )
    return server


async def register_builtins(server: Server, service_names: list[str]) -> Optional[health.HealthServicer]:
    """Register health and reflection; return health servicer for status updates."""
    h: Optional[health.HealthServicer] = None
    if HAS_HEALTH:
        h = health.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(h, server)
        service_names.append(health_pb2.DESCRIPTOR.services_by_name["Health"].full_name)

    if HAS_REFLECTION:
        # Include reflection service name and already registered services
        service_names.append(reflection.SERVICE_NAME)  # type: ignore[attr-defined]
        reflection.enable_server_reflection(service_names, server)  # type: ignore[attr-defined]

    return h


def try_register_project_services(server: Server, service_names: list[str]) -> None:
    """
    Attempt to import and register ChronoWatch gRPC services.
    Keep server operational even if services are not yet generated.
    """
    # Example registration pattern:
    # from chronowatch_core.api.grpc.v1 import metrics_pb2_grpc, metrics_service
    # metrics_pb2_grpc.add_MetricsServiceServicer_to_server(metrics_service.MetricsServicer(), server)
    try:
        from importlib import import_module

        candidates = [
            ("chronowatch_core.api.grpc.v1.metrics_pb2_grpc", "MetricsService"),
            ("chronowatch_core.api.grpc.v1.ingest_pb2_grpc", "IngestService"),
        ]
        for mod_name, svc_name in candidates:
            try:
                mod = import_module(mod_name)
            except Exception:
                continue
            # add_*Servicer_to_server naming convention
            adders = [getattr(mod, name) for name in dir(mod) if name.startswith("add_") and name.endswith("_to_server")]
            for adder in adders:
                try:
                    # We need a corresponding implementation object; try to find default
                    impl_module_name = mod_name.replace("_pb2_grpc", "_service")
                    impl_module = import_module(impl_module_name)
                    # Guess classname: MetricsServicer / IngestServicer
                    impl_candidates = [getattr(impl_module, n) for n in dir(impl_module) if n.endswith("Servicer")]
                    if not impl_candidates:
                        continue
                    impl = impl_candidates[0]()  # instantiate default
                    adder(impl, server)
                except Exception:
                    continue

            # Append fully-qualified service names for reflection, if pb2 is importable
            try:
                pb2_name = mod_name.replace("_pb2_grpc", "_pb2")
                pb2 = import_module(pb2_name)
                if hasattr(pb2, "DESCRIPTOR"):
                    for svc in pb2.DESCRIPTOR.services_by_name.values():
                        service_names.append(svc.full_name)
            except Exception:
                pass
    except Exception:
        # Any unexpected error during dynamic loading shouldn't prevent server startup
        logging.getLogger("grpc.server").warning("Dynamic service registration failed", exc_info=True)


def _server_credentials(cfg: GrpcConfig) -> Optional[grpc.ServerCredentials]:
    if not cfg.tls_enabled:
        return None
    if not (cfg.tls_cert_file and cfg.tls_key_file):
        raise RuntimeError("TLS enabled but GRPC_TLS_CERT_FILE/GRPC_TLS_KEY_FILE not provided")
    with open(cfg.tls_cert_file, "rb") as f:
        cert_chain = f.read()
    with open(cfg.tls_key_file, "rb") as f:
        private_key = f.read()
    if cfg.tls_client_ca_file:
        with open(cfg.tls_client_ca_file, "rb") as f:
            ca = f.read()
        return grpc.ssl_server_credentials(
            [(private_key, cert_chain)],
            root_certificates=ca,
            require_client_auth=True,
        )
    return grpc.ssl_server_credentials([(private_key, cert_chain)])


# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s corr=%(corr)s | %(message)s",
    )

    # Inject correlation id into log records
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.corr = correlation_id_ctx.get() or "-"
        return record

    logging.setLogRecordFactory(record_factory)


def _extract_correlation_id(context: ServicerContext) -> str:
    md = dict(context.invocation_metadata())
    return md.get("x-correlation-id") or md.get("x-request-id") or "-"


def _observe_metrics(method: str, code: StatusCode, start: float) -> None:
    if not HAS_PROM:
        return
    try:
        RPC_REQUESTS.labels(method=method, code=code.name).inc()  # type: ignore[union-attr]
        RPC_LATENCY.labels(method=method).observe(time.perf_counter() - start)  # type: ignore[union-attr]
    except Exception:  # pragma: no cover
        pass


def _log_access(method: str, code: StatusCode, start: float, corr_id: str, context: ServicerContext) -> None:
    duration = time.perf_counter() - start
    peer = context.peer() if hasattr(context, "peer") else "-"
    logging.getLogger("grpc.access").info(
        "method=%s code=%s duration=%.6fs peer=%s",
        method, code.name if code else "-", duration, peer
    )


async def _graceful_serve(server: Server, cfg: GrpcConfig, health_srv: Optional[Any]) -> None:
    creds = _server_credentials(cfg)
    if creds:
        server.add_secure_port(cfg.bind, creds)
    else:
        server.add_insecure_port(cfg.bind)

    await server.start()

    # Health: mark as SERVING
    if HAS_HEALTH and cfg.enable_health and health_srv:
        health_srv.set_status("", health_pb2.HealthCheckResponse.SERVING)
        # If you have named services, you can set per-service status too.

    logging.getLogger("grpc.server").info("gRPC server started on %s (TLS=%s)", cfg.bind, cfg.tls_enabled)

    # Handle signals for graceful shutdown
    stop_event = asyncio.Event()

    def _handle_signal(signame: str):
        logging.getLogger("grpc.server").warning("Received %s, initiating graceful shutdown", signame)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig.name)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda s, f: _handle_signal(sig.name))  # type: ignore[arg-type]

    await stop_event.wait()

    # Health: mark as NOT_SERVING
    if HAS_HEALTH and cfg.enable_health and health_srv:
        health_srv.set_status("", health_pb2.HealthCheckResponse.NOT_SERVING)

    # Allow in-flight RPCs to finish
    await server.stop(grace=None)  # immediately stop accepting new calls, drain existing
    logging.getLogger("grpc.server").info("gRPC server stopped")


# ------------------------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------------------------
async def main() -> None:
    cfg = GrpcConfig()
    if HAS_UVLOOP:
        uvloop.install()  # pragma: no cover

    setup_logging(cfg.log_level)

    if cfg.enable_metrics and HAS_PROM:
        start_http_server(cfg.metrics_port)
        logging.getLogger("grpc.server").info("Prometheus metrics on :%d", cfg.metrics_port)

    server = build_server(cfg)

    # Register built-in services
    service_names: list[str] = []
    health_srv = None
    if cfg.enable_health or cfg.enable_reflection:
        health_srv = await register_builtins(server, service_names)

    # Register project services (best-effort)
    try_register_project_services(server, service_names)

    await _graceful_serve(server, cfg, health_srv)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
