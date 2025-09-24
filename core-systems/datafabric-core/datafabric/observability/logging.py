# datafabric/datafabric/observability/logging.py
# Industrial-grade structured logging for DataFabric.
# - JSON logs with UTC timestamps and RFC3339/ISO8601 format
# - Queue-based non-blocking logging (QueueHandler/QueueListener)
# - Timed rotation + optional stdout JSON handler
# - Context propagation via contextvars (trace_id, span_id, request_id, tenant, user_id)
# - Safe redaction of PII by configurable patterns
# - Rate limiting filter to suppress floods
# - Healthcheck noise filter
# - Multiprocess-friendly (fork-safe) with a singleton listener
# - Hot-reload by environment variables on next get_logger() call
# - Minimal external deps: stdlib only

from __future__ import annotations

import json
import logging
import logging.config
import logging.handlers
import os
import queue
import re
import signal
import sys
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, Iterable, Optional, Tuple

# ===========
# Context Vars
# ===========
_ctx_trace_id: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)
_ctx_span_id: ContextVar[Optional[str]] = ContextVar("span_id", default=None)
_ctx_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_ctx_tenant: ContextVar[Optional[str]] = ContextVar("tenant", default=None)
_ctx_user_id: ContextVar[Optional[str]] = ContextVar("user_id", default=None)
_ctx_extra: ContextVar[Dict[str, Any]] = ContextVar("extra_ctx", default={})

# ===========
# Defaults via ENV
# ===========
def _env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else (default if default is not None else "")

LOG_LEVEL = _env("DF_LOG_LEVEL", "INFO").upper()
LOG_JSON = _env("DF_LOG_JSON", "1") in ("1", "true", "TRUE", "yes", "YES")
LOG_TO_STDOUT = _env("DF_LOG_STDOUT", "1") in ("1", "true", "TRUE", "yes", "YES")
LOG_FILE = _env("DF_LOG_FILE", "")
LOG_DIR = _env("DF_LOG_DIR", "logs")
LOG_FILE_BASENAME = _env("DF_LOG_FILE_BASENAME", "datafabric")
LOG_ROTATION_WHEN = _env("DF_LOG_ROTATION_WHEN", "D")  # S, M, H, D, W0..W6, midnight
LOG_ROTATION_INTERVAL = int(_env("DF_LOG_ROTATION_INTERVAL", "1"))
LOG_ROTATION_BACKUP = int(_env("DF_LOG_ROTATION_BACKUP", "14"))
LOG_QUEUE_SIZE = int(_env("DF_LOG_QUEUE_SIZE", "100000"))
LOG_INCLUDE_PID = _env("DF_LOG_INCLUDE_PID", "1") in ("1", "true", "TRUE", "yes", "YES")
LOG_REDACT_ENABLE = _env("DF_LOG_REDACT", "1") in ("1", "true", "TRUE", "yes", "YES")
LOG_RATE_LIMIT_ENABLE = _env("DF_LOG_RATE_LIMIT", "1") in ("1", "true", "TRUE", "yes", "YES")
LOG_RATE_LIMIT_WINDOW_SEC = float(_env("DF_LOG_RATE_LIMIT_WINDOW_SEC", "5.0"))
LOG_RATE_LIMIT_MAX_RECORDS = int(_env("DF_LOG_RATE_LIMIT_MAX_RECORDS", "200"))
LOG_HEALTHCHECK_FILTER = _env("DF_LOG_HEALTHCHECK_FILTER", "1") in ("1","true","TRUE","yes","YES")
LOG_HEALTHCHECK_PATTERNS = _env("DF_LOG_HEALTHCHECK_PATTERNS", "/health,/ready,/live")
LOG_SERVICE_NAME = _env("DF_SERVICE_NAME", "datafabric-core")
LOG_NODE = _env("DF_NODE", os.uname().nodename if hasattr(os, "uname") else "unknown")
LOG_APP_ENV = _env("DF_ENV", _env("ENV", "prod"))

# Redaction patterns (configurable via env, comma-separated key=value regex)
# Example:
# DF_LOG_REDACT_PATTERNS="email=\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b,card=\b(?:\d[ -]*?){13,16}\b"
_raw_redact_patterns = _env(
    "DF_LOG_REDACT_PATTERNS",
    "email=\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b,"
    "card=\\b(?:\\d[ -]*?){13,16}\\b,"
    "ssn=\\b\\d{3}-\\d{2}-\\d{4}\\b,"
    "phone=\\b\\+?\\d[\\d\\-() ]{7,}\\b"
)

def _parse_redact_patterns(spec: str) -> Dict[str, re.Pattern]:
    patterns: Dict[str, re.Pattern] = {}
    for part in filter(None, [p.strip() for p in spec.split(",")]):
        if "=" not in part:
            continue
        key, regex = part.split("=", 1)
        try:
            patterns[key.strip()] = re.compile(regex.strip(), re.IGNORECASE | re.MULTILINE)
        except re.error:
            # Skip invalid pattern
            continue
    return patterns

REDACT_PATTERNS = _parse_redact_patterns(_raw_redact_patterns)

# ====================
# Structured JSON Format
# ====================
class JsonFormatter(logging.Formatter):
    def __init__(self, *, static_fields: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.static = static_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        # Base event
        event: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": LOG_SERVICE_NAME,
            "env": LOG_APP_ENV,
            "node": LOG_NODE,
            "msg": record.getMessage(),
        }
        if LOG_INCLUDE_PID:
            event["pid"] = record.process
            event["tid"] = record.thread

        # Context
        event["trace_id"] = getattr(record, "trace_id", None) or _ctx_trace_id.get()
        event["span_id"] = getattr(record, "span_id", None) or _ctx_span_id.get()
        event["request_id"] = getattr(record, "request_id", None) or _ctx_request_id.get()
        event["tenant"] = getattr(record, "tenant", None) or _ctx_tenant.get()
        event["user_id"] = getattr(record, "user_id", None) or _ctx_user_id.get()

        # Extra fields from LoggerAdapter or context
        extra_ctx = dict(_ctx_extra.get() or {})
        for k in ("trace_id","span_id","request_id","tenant","user_id"):
            extra_ctx.pop(k, None)
        # Merge adapter extras on record if present
        if hasattr(record, "__dict__"):
            for k, v in record.__dict__.items():
                if k not in event and k not in ("args","msg","message","exc_info","exc_text","stack_info","stacklevel","pathname","filename","module","lineno","funcName","created","msecs","relativeCreated","levelno","name","process","processName","thread","threadName"):
                    extra_ctx.setdefault(k, v)

        if extra_ctx:
            event["extra"] = extra_ctx

        # Exception and stack
        if record.exc_info:
            event["exc_type"] = getattr(record.exc_info[0], "__name__", str(record.exc_info[0]))
            event["exc_message"] = str(record.exc_info[1])
            event["exc"] = self.formatException(record.exc_info)

        # Static fields
        if self.static:
            event.update(self.static)

        # Redaction (best-effort)
        if LOG_REDACT_ENABLE:
            event = RedactFilter.apply_redaction(event)

        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))

# ====================
# Filters
# ====================
class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Propagate contextvars into record for formatters that read record attributes
        for k, var in (
            ("trace_id", _ctx_trace_id),
            ("span_id", _ctx_span_id),
            ("request_id", _ctx_request_id),
            ("tenant", _ctx_tenant),
            ("user_id", _ctx_user_id),
        ):
            val = var.get()
            if val is not None and not hasattr(record, k):
                setattr(record, k, val)
        return True

class HealthcheckFilter(logging.Filter):
    def __init__(self, patterns: Iterable[str]):
        super().__init__("HealthcheckFilter")
        # compile list of simple substrings or regex with prefix r/
        self._compiled: Tuple[Tuple[str, Optional[re.Pattern]], ...] = tuple(
            (p, re.compile(p[2:]) if p.startswith("r/") else None) for p in patterns
        )

    def filter(self, record: logging.LogRecord) -> bool:
        if not LOG_HEALTHCHECK_FILTER:
            return True
        text = f"{record.getMessage()} {getattr(record, 'path', '')}"
        for raw, cre in self._compiled:
            if cre:
                if cre.search(text):
                    return False
            else:
                if raw and raw in text:
                    return False
        return True

class RateLimitFilter(logging.Filter):
    """
    Token-bucket-like limiter per (logger_name, level) pair.
    """
    _lock = threading.Lock()
    _state: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def __init__(self, window_sec: float, max_records: int):
        super().__init__("RateLimitFilter")
        self.window = window_sec
        self.max = max_records

    def filter(self, record: logging.LogRecord) -> bool:
        if not LOG_RATE_LIMIT_ENABLE or self.max <= 0:
            return True
        key = (record.name, record.levelno)
        now = time.monotonic()
        with self._lock:
            s = self._state.get(key)
            if not s or now - s["start"] > self.window:
                self._state[key] = {"start": now, "count": 1}
                return True
            if s["count"] < self.max:
                s["count"] += 1
                return True
            # Drop and once per window notify the first drop
            if s["count"] == self.max:
                s["count"] += 1
                # emit one warning about suppression via root logger to avoid recursion
                logging.getLogger("logging.ratelimit").warning(
                    "Rate limit reached for logger=%s level=%s; further records suppressed for %.2fs",
                    record.name, logging.getLevelName(record.levelno), self.window
                )
            else:
                s["count"] += 1
            return False

class RedactFilter(logging.Filter):
    MASK = "«REDACTED»"

    @classmethod
    def _redact_str(cls, text: str) -> str:
        if not text:
            return text
        for pat in REDACT_PATTERNS.values():
            text = pat.sub(cls.MASK, text)
        return text

    @classmethod
    def apply_redaction(cls, payload: Any) -> Any:
        try:
            if isinstance(payload, str):
                return cls._redact_str(payload)
            if isinstance(payload, dict):
                return {k: cls.apply_redaction(v) for k, v in payload.items()}
            if isinstance(payload, (list, tuple)):
                t = [cls.apply_redaction(v) for v in payload]
                return type(payload)(t) if not isinstance(payload, list) else t
            if isinstance(payload, (int, float, bool)) or payload is None:
                return payload
            # Fallback: stringifying unknown types
            return cls._redact_str(str(payload))
        except Exception:
            return payload

    def filter(self, record: logging.LogRecord) -> bool:
        if not LOG_REDACT_ENABLE:
            return True
        # Redact the message and known extra fields eagerly to avoid leaks in non-JSON formatters
        record.msg = self.apply_redaction(record.getMessage())
        if hasattr(record, "__dict__"):
            for k, v in list(record.__dict__.items()):
                if k in ("args","msg","message","exc_info","exc_text","stack_info","stacklevel"):
                    continue
                record.__dict__[k] = self.apply_redaction(v)
        return True

# ====================
# Queue Listener (singleton)
# ====================
class _SingletonQueueListener:
    _instance: Optional["_SingletonQueueListener"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.q: "queue.Queue[logging.LogRecord]" = queue.Queue(maxsize=LOG_QUEUE_SIZE)
        self.listener: Optional[logging.handlers.QueueListener] = None
        self.handlers: Tuple[logging.Handler, ...] = tuple()
        self.started = False

    @classmethod
    def instance(cls) -> "_SingletonQueueListener":
        with cls._lock:
            if not cls._instance:
                cls._instance = cls()
            return cls._instance

    def configure(self, handlers: Iterable[logging.Handler]) -> None:
        self.handlers = tuple(handlers)

    def start(self) -> None:
        if self.started:
            return
        self.listener = logging.handlers.QueueListener(self.q, *self.handlers, respect_handler_level=True)
        self.listener.start()
        self.started = True
        # Graceful shutdown on SIGTERM/SIGINT
        def _shutdown(*_a):
            try:
                self.stop()
            finally:
                # Let the process exit naturally after handlers flush
                pass
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

    def stop(self) -> None:
        if not self.started:
            return
        try:
            self.listener.stop()
        finally:
            self.started = False

# ====================
# Logger Adapter with bind/unbind context
# ====================
class BoundLogger(logging.LoggerAdapter):
    def __init__(self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None):
        super().__init__(logger, extra or {})

    def process(self, msg, kwargs):
        # merge adapter extras with kwargs["extra"]
        extra = dict(self.extra)
        supplied = kwargs.get("extra") or {}
        if supplied:
            extra.update(supplied)
        kwargs["extra"] = extra
        return msg, kwargs

    def bind(self, **fields) -> "BoundLogger":
        merged = dict(self.extra)
        merged.update(fields)
        return BoundLogger(self.logger, merged)

    def unbind(self, *keys: str) -> "BoundLogger":
        merged = dict(self.extra)
        for k in keys:
            merged.pop(k, None)
        return BoundLogger(self.logger, merged)

# ====================
# Public API
# ====================
@dataclass
class LoggingConfig:
    level: str = LOG_LEVEL
    json: bool = LOG_JSON
    to_stdout: bool = LOG_TO_STDOUT
    file_path: str = LOG_FILE  # if empty, assemble from LOG_DIR/LOG_FILE_BASENAME
    rotation_when: str = LOG_ROTATION_WHEN
    rotation_interval: int = LOG_ROTATION_INTERVAL
    rotation_backup: int = LOG_ROTATION_BACKUP
    include_pid: bool = LOG_INCLUDE_PID
    rate_limit_enable: bool = LOG_RATE_LIMIT_ENABLE
    rate_limit_window_sec: float = LOG_RATE_LIMIT_WINDOW_SEC
    rate_limit_max_records: int = LOG_RATE_LIMIT_MAX_RECORDS
    healthcheck_filter: bool = LOG_HEALTHCHECK_FILTER
    healthcheck_patterns: Tuple[str, ...] = field(default_factory=lambda: tuple(p.strip() for p in LOG_HEALTHCHECK_PATTERNS.split(",") if p.strip()))
    redact_enable: bool = LOG_REDACT_ENABLE
    service_name: str = LOG_SERVICE_NAME
    node: str = LOG_NODE
    app_env: str = LOG_APP_ENV

# Cache key for hot-reload semantics: if env changes, process restarts or next call can rebuild
def _config_signature(cfg: LoggingConfig) -> Tuple:
    return (
        cfg.level, cfg.json, cfg.to_stdout, cfg.file_path, cfg.rotation_when,
        cfg.rotation_interval, cfg.rotation_backup, cfg.include_pid,
        cfg.rate_limit_enable, cfg.rate_limit_window_sec, cfg.rate_limit_max_records,
        cfg.healthcheck_filter, cfg.healthcheck_patterns, cfg.redact_enable,
        cfg.service_name, cfg.node, cfg.app_env
    )

_last_sig: Optional[Tuple] = None
_last_handlers_key: Optional[str] = None

def _build_handlers(cfg: LoggingConfig) -> Tuple[logging.Handler, ...]:
    handlers: list[logging.Handler] = []
    static_fields = {"service": cfg.service_name, "env": cfg.app_env, "node": cfg.node}

    # Console handler
    if cfg.to_stdout:
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setLevel(cfg.level)
        if cfg.json:
            ch.setFormatter(JsonFormatter(static_fields=static_fields))
        else:
            fmt = "%(asctime)s %(levelname)s %(name)s | %(message)s [trace=%(trace_id)s req=%(request_id)s]"
            ch.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S%z"))
        handlers.append(ch)

    # File handler
    path = cfg.file_path
    if not path:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, f"{LOG_FILE_BASENAME}.log")

    if path:
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=path,
            when=cfg.rotation_when,
            interval=cfg.rotation_interval,
            backupCount=cfg.rotation_backup,
            encoding="utf-8",
            delay=True,
            utc=True
        )
        fh.setLevel(cfg.level)
        if cfg.json:
            fh.setFormatter(JsonFormatter(static_fields=static_fields))
        else:
            fmt = "%(asctime)s %(levelname)s %(name)s | %(message)s [trace=%(trace_id)s req=%(request_id)s]"
            fh.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S%z"))
        handlers.append(fh)

    return tuple(handlers)

def _ensure_listener(cfg: LoggingConfig) -> logging.Handler:
    """
    Returns a QueueHandler attached to a singleton QueueListener with configured downstream handlers.
    """
    global _last_sig, _last_handlers_key
    listener = _SingletonQueueListener.instance()

    sig = _config_signature(cfg)
    rebuild = sig != _last_sig

    # Multi-process safety: handlers can't be shared across forks reliably;
    # use a key to rebuild if pid changed or config changed.
    pid_key = f"{os.getpid()}:{hash(sig)}"
    if _last_handlers_key != pid_key:
        rebuild = True

    if rebuild:
        handlers = _build_handlers(cfg)
        # Common filters on sinks
        common_filters: Tuple[logging.Filter, ...] = (
            ContextFilter(),
            RedactFilter(),
            HealthcheckFilter(cfg.healthcheck_patterns),
            RateLimitFilter(cfg.rate_limit_window_sec, cfg.rate_limit_max_records),
        )
        for h in handlers:
            for f in common_filters:
                h.addFilter(f)

        listener.configure(handlers)
        listener.start()
        _last_sig = sig
        _last_handlers_key = pid_key

    # Producer side handler
    qh = logging.handlers.QueueHandler(listener.q)
    qh.setLevel(cfg.level)
    # Keep only cheap producer-side filters (no heavy regex)
    qh.addFilter(ContextFilter())
    return qh

@lru_cache(maxsize=128)
def _logger_core(name: str, cfg: LoggingConfig) -> BoundLogger:
    qh = _ensure_listener(cfg)
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, cfg.level, logging.INFO))

    # Avoid duplicate handlers if called multiple times
    # Keep only our QueueHandler
    to_remove = [h for h in logger.handlers if not isinstance(h, logging.handlers.QueueHandler)]
    for h in to_remove:
        logger.removeHandler(h)

    if not any(isinstance(h, logging.handlers.QueueHandler) for h in logger.handlers):
        logger.addHandler(qh)
        logger.propagate = False

    return BoundLogger(logger)

def get_logger(name: str, cfg: Optional[LoggingConfig] = None) -> BoundLogger:
    """
    Public factory for a bound structured logger.
    Hot-reloads if env-based config changed since the last call.
    """
    cfg = cfg or LoggingConfig()
    # Bust cache if signature changed
    core_key = (name, _config_signature(cfg))
    # lru_cache is on function with (name, cfg) identity; create a derived key by serializing
    # Workaround: use a local memo that includes the signature
    return _logger_core.__wrapped__(name, cfg) if core_key != (name, _last_sig) else _logger_core(name, cfg)

# ===========
# Context helpers
# ===========
def set_trace_id(value: Optional[str]) -> None:
    _ctx_trace_id.set(value)

def set_span_id(value: Optional[str]) -> None:
    _ctx_span_id.set(value)

def set_request_id(value: Optional[str]) -> None:
    _ctx_request_id.set(value)

def set_tenant(value: Optional[str]) -> None:
    _ctx_tenant.set(value)

def set_user_id(value: Optional[str]) -> None:
    _ctx_user_id.set(value)

def set_extra(**fields: Any) -> None:
    current = dict(_ctx_extra.get() or {})
    current.update(fields)
    _ctx_extra.set(current)

def clear_extra(*keys: str) -> None:
    current = dict(_ctx_extra.get() or {})
    if not keys:
        _ctx_extra.set({})
        return
    for k in keys:
        current.pop(k, None)
    _ctx_extra.set(current)

@contextmanager
def log_context(**fields: Any):
    """
    Context manager to temporarily bind context fields into contextvars.
    """
    prev = {
        "trace_id": _ctx_trace_id.get(),
        "span_id": _ctx_span_id.get(),
        "request_id": _ctx_request_id.get(),
        "tenant": _ctx_tenant.get(),
        "user_id": _ctx_user_id.get(),
        "extra": dict(_ctx_extra.get() or {}),
    }
    try:
        for k, v in fields.items():
            if k == "trace_id":
                set_trace_id(v)
            elif k == "span_id":
                set_span_id(v)
            elif k == "request_id":
                set_request_id(v)
            elif k == "tenant":
                set_tenant(v)
            elif k == "user_id":
                set_user_id(v)
            else:
                set_extra(**{k: v})
        yield
    finally:
        set_trace_id(prev["trace_id"])
        set_span_id(prev["span_id"])
        set_request_id(prev["request_id"])
        set_tenant(prev["tenant"])
        set_user_id(prev["user_id"])
        _ctx_extra.set(prev["extra"])

# ===========
# Convenience API
# ===========
def configure_basic(level: str = LOG_LEVEL) -> None:
    """
    Minimal setup for early bootstrap (e.g., pre-fork). Logs go to stdout with JSON.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level, logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    h.setLevel(getattr(logging, level, logging.INFO))
    h.setFormatter(JsonFormatter(static_fields={"service": LOG_SERVICE_NAME, "env": LOG_APP_ENV, "node": LOG_NODE}))
    h.addFilter(ContextFilter())
    if LOG_REDACT_ENABLE:
        h.addFilter(RedactFilter())
    if LOG_HEALTHCHECK_FILTER:
        h.addFilter(HealthcheckFilter(tuple(LOG_HEALTHCHECK_PATTERNS.split(","))))
    if LOG_RATE_LIMIT_ENABLE:
        h.addFilter(RateLimitFilter(LOG_RATE_LIMIT_WINDOW_SEC, LOG_RATE_LIMIT_MAX_RECORDS))
    root.addHandler(h)

def shutdown() -> None:
    """
    Flush and stop the queue listener.
    """
    _SingletonQueueListener.instance().stop()
    logging.shutdown()

# ===========
# Self-test (optional)
# ===========
if __name__ == "__main__":
    # Simple smoke test demonstrating structured output and redaction
    os.environ.setdefault("DF_LOG_JSON", "1")
    os.environ.setdefault("DF_LOG_STDOUT", "1")
    log = get_logger("datafabric.demo")

    with log_context(trace_id="trace-123", request_id="req-456", tenant="org-1", user_id="u-42", feature="init"):
        log.info("Service %s started", LOG_SERVICE_NAME, extra={"email": "user@example.com", "card": "4111 1111 1111 1111"})
        try:
            1 / 0
        except ZeroDivisionError:
            log.exception("Failure in bootstrap")

        # Rate limit demo
        for i in range(0, 300):
            log.debug("debug burst %s", i)

    shutdown()
