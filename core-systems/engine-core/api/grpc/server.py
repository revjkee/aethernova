# engine-core/api/grpc/server.py
"""
Industrial-grade asyncio gRPC server for engine-core.

Features:
- grpc.aio pure-async server
- TLS/mTLS (optional via env)
- Health checking (grpc_health.v1)
- Server reflection (optional)
- Structured logging with context-rich metadata
- Interceptors: auth, validation, logging, exception->status, tracing
- Prometheus metrics (optional, with exporter)
- OpenTelemetry tracing (optional)
- Large message support, keepalive tuning
- Graceful shutdown on SIGTERM/SIGINT
- Pluggable service registration
- Config via environment variables

Runtime deps (optional guarded imports):
  grpcio>=1.59
  grpcio-health-checking
  grpcio-reflection
  prometheus-client
  opentelemetry-api, opentelemetry-sdk, opentelemetry-instrumentation-grpc
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import ssl
import sys
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

import grpc
from grpc.aio import Server, ServerInterceptor, ServicerContext
from grpc import StatusCode

# -------- Optional packages (guarded) --------
try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
except Exception:  # pragma: no cover
    health = None
    health_pb2 = None
    health_pb2_grpc = None

try:
    from grpc_reflection.v1alpha import reflection
except Exception:  # pragma: no cover
    reflection = None

try:
    from prometheus_client import Counter, Histogram, start_http_server
except Exception:  # pragma: no cover
    Counter = Histogram = start_http_server = None

try:
    from opentelemetry import trace
    from opentelemetry.trace import Tracer
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.grpc import aio_client_interceptors, aio_server_interceptor
except Exception:  # pragma: no cover
    trace = None
    Tracer = TracerProvider = BatchSpanProcessor = ConsoleSpanExporter = None
    aio_client_interceptors = aio_server_interceptor = None

# -------- Logging setup --------
_LOGGER = logging.getLogger("engine_core.grpc")
logging.basicConfig(
    level=os.getenv("GRPC_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)

# -------- Config --------

def _env_bool(key: str, default: bool = False) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.lower() in {"1", "true", "yes", "on"}

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except Exception:
        return default

@dataclass
class GRPCConfig:
    host: str = os.getenv("GRPC_HOST", "0.0.0.0")
    port: int = _env_int("GRPC_PORT", 7000)

    max_receive_message_length: int = _env_int("GRPC_MAX_RECV_MB", 64) * 1024 * 1024
    max_send_message_length: int = _env_int("GRPC_MAX_SEND_MB", 64) * 1024 * 1024

    keepalive_time_ms: int = _env_int("GRPC_KEEPALIVE_TIME_MS", 20_000)
    keepalive_timeout_ms: int = _env_int("GRPC_KEEPALIVE_TIMEOUT_MS", 10_000)
    keepalive_permit_wo_calls: int = _env_int("GRPC_KEEPALIVE_PERMIT_WO_CALLS", 1)

    enable_tls: bool = _env_bool("GRPC_ENABLE_TLS", False)
    enable_mtls: bool = _env_bool("GRPC_ENABLE_MTLS", False)
    tls_cert_file: Optional[str] = os.getenv("GRPC_TLS_CERT_FILE")
    tls_key_file: Optional[str] = os.getenv("GRPC_TLS_KEY_FILE")
    tls_ca_file: Optional[str] = os.getenv("GRPC_TLS_CA_FILE")  # for mTLS

    enable_reflection: bool = _env_bool("GRPC_ENABLE_REFLECTION", True)
    enable_health: bool = _env_bool("GRPC_ENABLE_HEALTH", True)

    enable_metrics: bool = _env_bool("GRPC_ENABLE_METRICS", True)
    metrics_port: int = _env_int("GRPC_METRICS_PORT", 9100)

    enable_otel: bool = _env_bool("GRPC_ENABLE_OTEL", False)
    otel_console_exporter: bool = _env_bool("GRPC_OTEL_CONSOLE_EXPORTER", False)

    auth_header: str = os.getenv("GRPC_AUTH_HEADER", "authorization")
    # simple shared token auth for perimeter; replace with proper IAM/JWT provider as needed
    auth_token: Optional[str] = os.getenv("GRPC_AUTH_TOKEN")

    graceful_timeout_s: int = _env_int("GRPC_GRACEFUL_TIMEOUT_S", 20)

    # Services to register: list of callables(register_to_server)
    # Each item should be a callable: (server: grpc.aio.Server) -> Iterable[str]  (returns fully-qualified service names)
    service_registrars: List[Callable[[Server], Iterable[str]]] = field(default_factory=list)


# -------- Metrics --------

class Metrics:
    def __init__(self, enabled: bool, port: int) -> None:
        self.enabled = enabled and Counter is not None and Histogram is not None
        self.port = port
        if self.enabled:
            # Create metrics
            self.rpc_counter = Counter(
                "grpc_server_requests_total",
                "Total number of gRPC requests",
                ["method", "code"],
            )
            self.rpc_latency = Histogram(
                "grpc_server_request_duration_seconds",
                "Duration of gRPC requests",
                ["method"],
                buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            )
            self._exporter_started = False
        else:
            self.rpc_counter = None
