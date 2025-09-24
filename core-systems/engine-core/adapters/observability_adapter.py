# engine-core/engine/adapters/observability_adapter.py
"""
Industrial-grade Observability Adapter for engine-core.

Capabilities:
- Structured JSON logging with trace/span/request ids
- OpenTelemetry tracing integration (via engine.telemetry.tracing)
- Prometheus metrics: Counter/Gauge/Histogram/Summary + ASGI /metrics
- Safe fallbacks when optional deps are missing (no-op mode)
- Convenience decorators/context managers for spans and timings
- Graceful shutdown to flush tracing exporters

Env (defaults in brackets):
  ENGINE_OBS_SERVICE_NAME       [engine-core]
  ENGINE_OBS_SERVICE_VERSION    [0.0.0]
  ENGINE_OBS_DEPLOY_ENV         [dev]
  ENGINE_OBS_LOG_LEVEL          [INFO]      # DEBUG|INFO|WARNING|ERROR
  ENGINE_OBS_LOG_JSON           [true]
  ENGINE_OBS_PROM_ENABLED       [true]
  ENGINE_OBS_PROM_NAMESPACE     [engine]
  ENGINE_OBS_PROM_PATH          [/metrics]
  ENGINE_OBS_TRACING_ENABLED    [true]

Dependencies (optional):
  - prometheus-client (metrics; ASGI endpoint)
  - opentelemetry-* (tracing)
"""

from __future__ import annotations

import atexit
import contextvars
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

# ---------- Optional deps (soft imports) ----------
try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        Summary,
        CONTENT_TYPE_LATEST,
        generate_latest,
        multiprocess,  # noqa
    )
    from prometheus_client import make_asgi_app as _prom_make_asgi_app  # type: ignore
    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False
    CollectorRegistry = object  # type: ignore
    Counter = Gauge = Histogram = Summary = object  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"
    def generate_latest(*_a, **_k):  # type: ignore
        return b""
    _prom_make_asgi_app = None  # type: ignore

try:
    from opentelemetry import trace as ot_trace  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False
    ot_trace = None  # type: ignore

# Local tracing integration (safe to import even if OTel absent per our tracing.py)
try:
    from engine.telemetry import tracing as eng_tracing
except Exception:
    eng_tracing = None  # type: ignore

# ---------- Context keys ----------
_ctx_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)

# ---------- Utilities ----------
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return default if v is None or v.strip() == "" else v

def _env_level(name: str, default: str) -> int:
    lvl = _env_str(name, default).upper()
    return getattr(logging, lvl, logging.INFO)

# ---------- JSON Log Formatter ----------
class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, version: str, env: str):
        super().__init__()
        self.service = service
        self.version = version
        self.env = env

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "service": self.service,
            "service_version": self.version,
            "env": self.env,
            "msg": record.getMessage(),
        }
        # Request id
        req_id = _ctx_request_id.get()
        if req_id:
            base["request_id"] = req_id

        # Trace/span ids
        if _OTEL_AVAILABLE:
            span = ot_trace.get_current_span()  # type: ignore
            ctx = getattr(span, "get_span_context", lambda: None)()
            if ctx and getattr(ctx, "is_valid", lambda: False)():
                trace_id = getattr(ctx, "trace_id", 0)
                span_id = getattr(ctx, "span_id", 0)
                base["trace_id"] = f"{trace_id:032x}"
                base["span_id"] = f"{span_id:016x}"

        # Extra / exception
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            base["stack_info"] = self.formatStack(record.stack_info)

        # Attach any extra dict-like fields
        for k in ("extra",):
            val = getattr(record, k, None)
            if isinstance(val, dict):
                base.update(val)

        try:
            return json.dumps(base, ensure_ascii=False)
        except Exception:
            # Fallback to minimal line
            return f'{{"ts":"{base["ts"]}","level":"{base["level"]}","msg":{json.dumps(base["msg"])}}}'

# ---------- Config ----------
@dataclass(frozen=True)
class ObservabilityConfig:
    service_name: str = field(default_factory=lambda: _env_str("ENGINE_OBS_SERVICE_NAME", "engine-core"))
    service_version: str = field(default_factory=lambda: _env_str("ENGINE_OBS_SERVICE_VERSION", "0.0.0"))
    deploy_env: str = field(default_factory=lambda: _env_str("ENGINE_OBS_DEPLOY_ENV", "dev"))
    log_level: int = field(default_factory=lambda: _env_level("ENGINE_OBS_LOG_LEVEL", "INFO"))
    log_json: bool = field(default_factory=lambda: _env_bool("ENGINE_OBS_LOG_JSON", True))
    prom_enabled: bool = field(default_factory=lambda: _env_bool("ENGINE_OBS_PROM_ENABLED", True))
    prom_namespace: str = field(default_factory=lambda: _env_str("ENGINE_OBS_PROM_NAMESPACE", "engine"))
    prom_path: str = field(default_factory=lambda: _env_str("ENGINE_OBS_PROM_PATH", "/metrics"))
    tracing_enabled: bool = field(default_factory=lambda: _env_bool("ENGINE_OBS_TRACING_ENABLED", True))

# ---------- Adapter ----------
class ObservabilityAdapter:
    """
    Unified adapter for logging, tracing, and metrics.
    Safe to use even when optional deps are missing (no-op mode).
    """

    def __init__(self, config: ObservabilityConfig | None = None) -> None:
        self.cfg = config or ObservabilityConfig()
        self._logger_configured = False
        self._registry = None  # type: Optional[CollectorRegistry]
        self._metrics_cache: Dict[Tuple[str, str], Any] = {}
        self._metrics_app = None
        self._shutdown_registered = False

    # ---- Setup / Shutdown ----
    def setup(self) -> None:
        self._setup_logging()
        self._setup_tracing()
        self._setup_metrics()
        if not self._shutdown_registered:
            atexit.register(self.shutdown)
            self._shutdown_registered = True
        logging.getLogger(__name__).info(
            "Observability initialized",
            extra={"extra": {"service": self.cfg.service_name, "env": self.cfg.deploy_env}}
        )

    def shutdown(self) -> None:
        # Flush tracing exporters if available
        if self.cfg.tracing_enabled and eng_tracing:
            try:
                eng_tracing.shutdown_tracing()
            except Exception:
                pass

    # ---- Logging ----
    def _setup_logging(self) -> None:
        if self._logger_configured:
            return
        root = logging.getLogger()
        # Avoid double handlers
        for h in list(root.handlers):
            root.removeHandler(h)

        handler = logging.StreamHandler(sys.stdout)
        if self.cfg.log_json:
            formatter = JsonFormatter(
                service=self.cfg.service_name,
                version=self.cfg.service_version,
                env=self.cfg.deploy_env,
            )
        else:
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        handler.setFormatter(formatter)
        root.addHandler(handler)
        root.setLevel(self.cfg.log_level)
        self._logger_configured = True

    def set_request_id(self, request_id: Optional[str]) -> None:
        _ctx_request_id.set(request_id)

    def get_request_id(self) -> Optional[str]:
        return _ctx_request_id.get()

    # ---- Tracing ----
    def _setup_tracing(self) -> None:
        if not self.cfg.tracing_enabled:
            logging.getLogger(__name__).info("Tracing disabled by config")
            return
        if not eng_tracing:
            logging.getLogger(__name__).warning("Tracing module not available; skipping")
            return
        try:
            # Rely on env‑driven config inside engine.telemetry.tracing
            eng_tracing.setup_tracing()
        except Exception:
            logging.getLogger(__name__).exception("Failed to initialize tracing")

    def trace_span(self, name: Optional[str] = None, **span_kw) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator to trace sync/async functions via engine.telemetry.tracing.trace.
        """
        if eng_tracing and hasattr(eng_tracing, "trace"):
            return eng_tracing.trace(name, **span_kw)  # type: ignore

        # No-op decorator
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn
        return deco

    # ---- Metrics ----
    def _setup_metrics(self) -> None:
        if not self.cfg.prom_enabled:
            logging.getLogger(__name__).info("Prometheus metrics disabled by config")
            return
        if not _PROM_AVAILABLE:
            logging.getLogger(__name__).warning("prometheus-client not installed; metrics disabled")
            return

        # Use custom registry (safe for uWSGI/gunicorn)
        registry = CollectorRegistry()
        # If using multiprocess mode (prometheus_multiproc_dir), merge collectors
        try:
            if "prometheus_multiproc_dir" in os.environ:
                multiprocess.MultiProcessCollector(registry)  # type: ignore
        except Exception:
            logging.getLogger(__name__).warning("Failed to enable multiprocess collector")

        self._registry = registry

        # Build ASGI metrics app
        if _prom_make_asgi_app:
            self._metrics_app = _prom_make_asgi_app(registry=self._registry)  # type: ignore

        # Default builtin metrics
        self.counter(
            name="startup_total",
            documentation="Service startup counter",
        ).inc()

    # -- Metric factories with cache keys (type,name) --
    def counter(self, name: str, documentation: str, labelnames: Iterable[str] = ()) -> Any:
        if not _PROM_AVAILABLE or not self._registry:
            return _NoopMetric()
        key = ("counter", name, tuple(labelnames))
        if key not in self._metrics_cache:
            self._metrics_cache[key] = Counter(
                f"{self.cfg.prom_namespace}_{name}",
                documentation,
                labelnames=tuple(labelnames),
                registry=self._registry,
            )
        return self._metrics_cache[key]

    def gauge(self, name: str, documentation: str, labelnames: Iterable[str] = ()) -> Any:
        if not _PROM_AVAILABLE or not self._registry:
            return _NoopMetric()
        key = ("gauge", name, tuple(labelnames))
        if key not in self._metrics_cache:
            self._metrics_cache[key] = Gauge(
                f"{self.cfg.prom_namespace}_{name}",
                documentation,
                labelnames=tuple(labelnames),
                registry=self._registry,
            )
        return self._metrics_cache[key]

    def histogram(self, name: str, documentation: str, labelnames: Iterable[str] = (), buckets: Optional[Iterable[float]] = None) -> Any:
        if not _PROM_AVAILABLE or not self._registry:
            return _NoopMetric()
        key = ("histogram", name, tuple(labelnames), tuple(buckets) if buckets else None)
        if key not in self._metrics_cache:
            self._metrics_cache[key] = Histogram(
                f"{self.cfg.prom_namespace}_{name}",
                documentation,
                labelnames=tuple(labelnames),
                buckets=tuple(buckets) if buckets else Histogram.DEFAULT_BUCKETS,
                registry=self._registry,
            )
        return self._metrics_cache[key]

    def summary(self, name: str, documentation: str, labelnames: Iterable[str] = ()) -> Any:
        if not _PROM_AVAILABLE or not self._registry:
            return _NoopMetric()
        key = ("summary", name, tuple(labelnames))
        if key not in self._metrics_cache:
            self._metrics_cache[key] = Summary(
                f"{self.cfg.prom_namespace}_{name}",
                documentation,
                labelnames=tuple(labelnames),
                registry=self._registry,
            )
        return self._metrics_cache[key]

    # ---- Timers ----
    def timer(self, metric: Any, **labels) -> "_TimerCtx":
        """
        Context manager to time a block and observe duration in seconds
        for Histogram/Summary; no-op otherwise.
        """
        return _TimerCtx(metric, labels)

    # ---- ASGI hooks ----
    @property
    def metrics_asgi_app(self):
        """
        Returns ASGI app for /metrics if prometheus-client is available, else None.
        """
        return self._metrics_app

    def install_fastapi(self, app) -> None:
        """
        Optional: mount /metrics and add simple middleware to set request_id.
        """
        # Mount metrics endpoint
        if self._metrics_app and hasattr(app, "mount"):
            app.mount(self.cfg.prom_path, self._metrics_app)

        # Minimal middleware to set request_id from headers or generate one
        try:
            import uuid
            from starlette.middleware.base import BaseHTTPMiddleware

            class _ReqIdMW(BaseHTTPMiddleware):
                async def dispatch(_self, request, call_next):
                    rid = request.headers.get("x-request-id") or uuid.uuid4().hex
                    self.set_request_id(rid)
                    # attach to response
                    response = await call_next(request)
                    response.headers["x-request-id"] = rid
                    return response

            app.add_middleware(_ReqIdMW)
        except Exception:
            logging.getLogger(__name__).warning("FastAPI/Starlette not available; request-id middleware not installed")

    # ---- Logging helpers ----
    def log_debug(self, msg: str, **fields) -> None:
        logging.getLogger("engine").debug(msg, extra={"extra": fields} if fields else None)

    def log_info(self, msg: str, **fields) -> None:
        logging.getLogger("engine").info(msg, extra={"extra": fields} if fields else None)

    def log_warning(self, msg: str, **fields) -> None:
        logging.getLogger("engine").warning(msg, extra={"extra": fields} if fields else None)

    def log_error(self, msg: str, **fields) -> None:
        logging.getLogger("engine").error(msg, extra={"extra": fields} if fields else None)

    def log_exception(self, msg: str, **fields) -> None:
        logging.getLogger("engine").exception(msg, extra={"extra": fields} if fields else None)

# ---------- No-op metric & timer ----------
class _NoopMetric:
    def labels(self, **_labels):
        return self
    def inc(self, *_a, **_k): pass
    def dec(self, *_a, **_k): pass
    def set(self, *_a, **_k): pass
    def observe(self, *_a, **_k): pass
    def time(self): return _TimerCtx(self, {})

class _TimerCtx:
    def __init__(self, metric: Any, labels: Dict[str, Any]) -> None:
        self.metric = metric
        self.labels = labels
        self._t0 = None

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        dur = max(0.0, time.perf_counter() - (self._t0 or time.perf_counter()))
        try:
            # For Histogram/Summary with labels()
            if hasattr(self.metric, "labels"):
                m = self.metric.labels(**self.labels) if self.labels else self.metric
            else:
                m = self.metric
            if hasattr(m, "observe"):
                m.observe(dur)
        except Exception:
            pass
        # do not suppress exceptions
        return False

# ---------- Singleton convenience ----------
_obs_singleton: Optional[ObservabilityAdapter] = None

def get_observability() -> ObservabilityAdapter:
    global _obs_singleton
    if _obs_singleton is None:
        _obs_singleton = ObservabilityAdapter()
        _obs_singleton.setup()
    return _obs_singleton

# ---------- Example usage (comments only) ----------
# obs = get_observability()
# req_counter = obs.counter("http_requests_total", "Total HTTP requests", labelnames=("method","code"))
# latency = obs.histogram("http_request_duration_seconds", "Request latency", labelnames=("method","route"))
#
# from engine.telemetry.tracing import SPANKIND_SERVER
# @obs.trace_span("http.handler", kind=SPANKIND_SERVER, attributes={"component":"api"})
# async def handler(request):
#     with obs.timer(latency, method=request.method, route=request.url.path):
#         ...
#
# obs.log_info("server started", port=8080)
