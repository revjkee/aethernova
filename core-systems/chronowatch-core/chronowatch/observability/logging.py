"""
Chronowatch Observability: structured logging for production.

Features:
- JSON formatter with stable schema: ts, level, logger, message, event, fields, service, version,
  correlation_id, trace_id, span_id, pid, thread, file, line, function.
- Context propagation using contextvars for correlation_id, tenant_id, user_id.
- Optional OpenTelemetry trace/span correlation if opentelemetry is present.
- Secret redaction (configurable keys and patterns), safe JSON serialization.
- Non-blocking logging via QueueHandler + QueueListener to avoid IO stalls.
- Sampling and rate limiting filters to prevent log storms.
- Structured logger adapter: logger.event("name", **fields) with deterministic JSON.
- Friendly integration with Uvicorn/Gunicorn standard loggers.

Only stdlib required. OpenTelemetry is optional.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
import time
import traceback
import types
import typing as t
from dataclasses import dataclass, field

# Optional OpenTelemetry
try:  # pragma: no cover
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# ----------------------------
# Context variables
# ----------------------------
correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("cw_correlation_id", default=None)
tenant_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("cw_tenant_id", default=None)
user_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("cw_user_id", default=None)

# ----------------------------
# Defaults and helpers
# ----------------------------
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info", "exc_text",
    "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName", "processName",
    "process", "asctime",
}

def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="milliseconds")

def _safe_repr(obj: t.Any) -> t.Any:
    try:
        json.dumps(obj)  # fast path
        return obj
    except Exception:
        try:
            return repr(obj)
        except Exception:
            return f"<unserializable type={type(obj).__name__}>"

def _walk_and_redact(value: t.Any, redact_keys: list[re.Pattern], redact_patterns: list[re.Pattern], depth: int = 0) -> t.Any:
    if depth > 6:
        return _safe_repr(value)
    if isinstance(value, dict):
        out: dict[str, t.Any] = {}
        for k, v in value.items():
            if any(p.search(str(k)) for p in redact_keys):
                out[str(k)] = "***"
            else:
                out[str(k)] = _walk_and_redact(v, redact_keys, redact_patterns, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [ _walk_and_redact(v, redact_keys, redact_patterns, depth + 1) for v in value ]
    if isinstance(value, str):
        s = value
        for p in redact_patterns:
            s = p.sub("***", s)
        return s
    return _safe_repr(value)

def _current_trace_ids() -> tuple[str | None, str | None]:
    if not _HAS_OTEL:
        return None, None
    try:  # pragma: no cover
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return None, None
        # trace_id and span_id as hex
        return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
    except Exception:
        return None, None

# ----------------------------
# Config
# ----------------------------
@dataclass
class LogConfig:
    service: str = field(default_factory=lambda: os.getenv("CHRONOWATCH_SERVICE", "chronowatch-core"))
    version: str = field(default_factory=lambda: os.getenv("CHRONOWATCH_VERSION", "dev"))
    level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    json: bool = field(default_factory=lambda: os.getenv("LOG_JSON", "1") not in ("0", "false", "False"))
    include_stack: bool = field(default_factory=lambda: os.getenv("LOG_STACK", "0") in ("1", "true", "True"))
    redact_keys: list[str] = field(default_factory=lambda: [
        "password", "secret", "token", "authorization", "api_key", "apiKey", "x-api-key", "set-cookie"
    ])
    redact_patterns: list[str] = field(default_factory=lambda: [
        r"(?i)password\s*=\s*[^&\s]+",
        r"(?i)token\s*=\s*[^&\s]+",
        r"(?i)api[_-]?key\s*=\s*[^&\s]+",
        r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\._\-]+"
    ])
    stdout: bool = True
    file_path: str | None = None              # optional rotating file
    file_max_bytes: int = 50 * 1024 * 1024
    file_backup_count: int = 5
    queue_size: int = 10000
    sample_debug: float = 0.0                 # 0..1, sample rate for DEBUG
    rate_limit_per_key: float = 50.0          # events per second allowed per key
    rate_burst_per_key: float = 100.0

# ----------------------------
# Filters
# ----------------------------
class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        record.correlation_id = correlation_id_var.get()
        record.tenant_id = tenant_id_var.get()
        record.user_id = user_id_var.get()
        trace_id, span_id = _current_trace_ids()
        record.trace_id = trace_id
        record.span_id = span_id
        return True

class SamplingFilter(logging.Filter):
    def __init__(self, rate_debug: float) -> None:
        super().__init__()
        self.rate_debug = max(0.0, min(1.0, rate_debug))

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno <= logging.DEBUG and self.rate_debug < 1.0:
            # simple reservoir: sample by hash of message
            try:
                key = f"{record.name}:{record.getMessage()}"
            except Exception:
                key = f"{record.name}:{record.msg}"
            h = hash(key)
            # convert to [0,1)
            val = (h & 0xFFFFFFFF) / 0x100000000
            return val < self.rate_debug
        return True

class RateLimitFilter(logging.Filter):
    """Token bucket per (logger, message template) key."""
    def __init__(self, rate: float, burst: float) -> None:
        super().__init__()
        self.rate = float(rate)
        self.burst = float(burst)
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def filter(self, record: logging.LogRecord) -> bool:
        key = f"{record.name}:{record.levelno}:{record.msg}"
        now = time.perf_counter()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.burst, now))
            # refill
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allow = tokens >= 1.0
            tokens = tokens - 1.0 if allow else tokens
            self._buckets[key] = (tokens, now)
        if not allow:
            # mark suppressed; formatter may include this
            record.suppressed = True  # type: ignore[attr-defined]
        else:
            record.suppressed = False  # type: ignore[attr-defined]
        return allow

# ----------------------------
# Formatter
# ----------------------------
class JSONFormatter(logging.Formatter):
    def __init__(self, config: LogConfig) -> None:
        super().__init__()
        self.config = config
        self._redact_key_patterns = [re.compile(pat) for pat in config.redact_keys]
        self._redact_value_patterns = [re.compile(pat) for pat in config.redact_patterns]

    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, t.Any] = {
            "ts": _utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "service": self.config.service,
            "version": self.config.version,
            "message": _safe_message(record),
            "pid": record.process,
            "thread": record.threadName,
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
            "correlation_id": getattr(record, "correlation_id", None),
            "tenant_id": getattr(record, "tenant_id", None),
            "user_id": getattr(record, "user_id", None),
            "trace_id": getattr(record, "trace_id", None),
            "span_id": getattr(record, "span_id", None),
            "suppressed": getattr(record, "suppressed", False),
        }

        # enrich with event and fields if provided via StructuredAdapter
        event = getattr(record, "event", None)
        if event:
            base["event"] = str(event)
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            base["fields"] = fields

        # capture extras that are not reserved
        extras = {}
        for k, v in record.__dict__.items():
            if k not in _RESERVED and k not in ("event", "fields", "correlation_id", "tenant_id", "user_id", "trace_id", "span_id", "suppressed"):
                extras[k] = v
        if extras:
            base["extra"] = extras

        # exception info
        if record.exc_info:
            etype, evalue, etb = record.exc_info
            base["exception"] = {
                "type": getattr(etype, "__name__", str(etype)),
                "message": str(evalue),
                "stacktrace": "".join(traceback.format_exception(etype, evalue, etb)) if self.config.include_stack else None,
            }

        # redact and serialize
        redacted = _walk_and_redact(base, self._redact_key_patterns, self._redact_value_patterns)
        try:
            return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            # last resort: no redaction, but safe repr of values
            safe = {k: _safe_repr(v) for k, v in redacted.items()}
            return json.dumps(safe, separators=(",", ":"), ensure_ascii=False)

def _safe_message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception:
        return str(record.msg)

# ----------------------------
# Structured adapter
# ----------------------------
class StructuredAdapter(logging.LoggerAdapter):
    """
    Logger adapter that accepts event name and structured fields:

        log = get_logger(__name__)
        log.event("user.login", user_id="u1", method="password")

        log.info("plain message", extra={"event": "info.note", "fields": {"k": "v"}})

    All values must be JSON serializable or will be repr()-ed.
    """
    def process(self, msg, kwargs):
        return msg, kwargs

    def event(self, name: str, /, **fields: t.Any) -> None:
        extra = kwargs_extra(kwargs=None)
        extra["event"] = name
        extra["fields"] = {k: _safe_repr(v) for k, v in (fields or {}).items()}
        self.logger.info("", extra=extra)

def kwargs_extra(kwargs: dict | None) -> dict:
    extra = (kwargs or {}).get("extra") if kwargs else None
    return {} if not isinstance(extra, dict) else extra

# ----------------------------
# Setup
# ----------------------------
class _Queueing:
    def __init__(self, config: LogConfig, formatter: logging.Formatter) -> None:
        self.queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=config.queue_size)
        self.handler = logging.handlers.QueueHandler(self.queue)
        self.listener_handlers: list[logging.Handler] = []

        if config.stdout:
            sh = logging.StreamHandler(stream=sys.stdout)
            sh.setFormatter(formatter)
            self.listener_handlers.append(sh)

        if config.file_path:
            fh = logging.handlers.RotatingFileHandler(
                filename=config.file_path,
                maxBytes=config.file_max_bytes,
                backupCount=config.file_backup_count,
                encoding="utf-8",
                delay=True,
            )
            fh.setFormatter(formatter)
            self.listener_handlers.append(fh)

        self.listener = logging.handlers.QueueListener(self.queue, *self.listener_handlers, respect_handler_level=True)

    def start(self) -> None:
        self.listener.start()

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.listener.stop()

def configure_logging(config: LogConfig | None = None) -> logging.Logger:
    """
    Initialize root logger and common library loggers.
    """
    cfg = config or LogConfig()
    root = logging.getLogger()
    root.setLevel(_parse_level(cfg.level))
    # clear handlers before reconfiguring
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter = JSONFormatter(cfg)
    q = _Queueing(cfg, formatter)
    q.handler.addFilter(ContextFilter())
    q.handler.addFilter(SamplingFilter(cfg.sample_debug))
    q.handler.addFilter(RateLimitFilter(cfg.rate_limit_per_key, cfg.rate_burst_per_key))
    root.addHandler(q.handler)
    q.start()

    # tone down noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # store listener for graceful shutdown
    root._cw_listener = q  # type: ignore[attr-defined]

    # Return a structured adapter for module __name__ if desired
    return get_logger("chronowatch")

def shutdown_logging() -> None:
    root = logging.getLogger()
    q = getattr(root, "_cw_listener", None)
    if isinstance(q, _Queueing):
        q.stop()

def _parse_level(name: str) -> int:
    return getattr(logging, str(name).upper(), logging.INFO)

def get_logger(name: str | None = None) -> StructuredAdapter:
    logger = logging.getLogger(name or "chronowatch")
    return StructuredAdapter(logger, extra={})

# ----------------------------
# Correlation helpers
# ----------------------------
@contextlib.contextmanager
def bind_correlation_id(correlation_id: str | None = None):
    """
    Bind correlation_id to current context. Generates one if not provided.
    """
    token = correlation_id_var.set(correlation_id or _gen_correlation_id())
    try:
        yield
    finally:
        correlation_id_var.reset(token)

def _gen_correlation_id() -> str:
    # compact, sortable-ish: yyyymmddThhmmssZ-rand
    ts = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    rand = os.urandom(6).hex()
    return f"{ts}-{rand}"

@contextlib.contextmanager
def bind_user_context(*, tenant_id: str | None = None, user_id: str | None = None):
    t_token = tenant_id_var.set(tenant_id) if tenant_id is not None else None
    u_token = user_id_var.set(user_id) if user_id is not None else None
    try:
        yield
    finally:
        if t_token is not None:
            tenant_id_var.reset(t_token)
        if u_token is not None:
            user_id_var.reset(u_token)

# ----------------------------
# Decorators
# ----------------------------
def log_exceptions(logger: StructuredAdapter | logging.Logger | None = None, *, rethrow: bool = True):
    """
    Decorator: log uncaught exceptions with context. Keeps function signature.
    """
    log = logger or get_logger(__name__)

    def decorator(fn):
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception:
                log = get_logger(getattr(fn, "__module__", __name__))
                log.logger.exception("Unhandled exception", extra={"event": "error.unhandled"})
                if rethrow:
                    raise
                return None
        return wrapper
    return decorator

# ----------------------------
# Uvicorn integration helpers (optional)
# ----------------------------
def patch_uvicorn_loggers() -> None:
    """
    Map uvicorn access/error logs into our JSON schema by attaching ContextFilter.
    Call after configure_logging().
    """
    ctx = ContextFilter()
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(name).addFilter(ctx)

# ----------------------------
# Example minimal bootstrap (not executed)
# ----------------------------
if __name__ == "__main__":  # pragma: no cover
    log = configure_logging()
    with bind_correlation_id():
        log.event("service.start", pid=os.getpid())
        log.logger.info("hello world", extra={"event": "demo.note", "fields": {"x": 1}})
        try:
            1 / 0
        except ZeroDivisionError:
            log.logger.exception("division error", extra={"event": "error.div_zero"})
    shutdown_logging()
