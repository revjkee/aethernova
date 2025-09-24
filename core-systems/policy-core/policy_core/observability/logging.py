# policy_core/observability/logging.py
# Industrial-grade structured logging for policy-core
# Python 3.11+

from __future__ import annotations

import json
import logging
import os
import queue
import re
import sys
import time
import uuid
import atexit
import traceback
import contextvars
from dataclasses import is_dataclass, asdict
from datetime import datetime, timezone
from logging.handlers import QueueHandler, QueueListener, TimedRotatingFileHandler
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple

# -------- Optional: OpenTelemetry (auto-detected) --------
try:
    from opentelemetry import trace as otel_trace  # type: ignore
    _OTEL_OK = True
except Exception:
    _OTEL_OK = False

__all__ = [
    "setup_logging",
    "get_logger",
    "bind",
    "unbind",
    "use_context",
    "set_correlation_id",
    "new_correlation_id",
]

# =========================
# Environment config
# =========================

ENV = {
    "SERVICE_NAME": os.getenv("LOG_SERVICE_NAME", "policy-core"),
    "LEVEL": os.getenv("LOG_LEVEL", "INFO").upper(),
    "FORMAT": os.getenv("LOG_FORMAT", "json").lower(),  # json|text (json by default)
    "UTC": os.getenv("LOG_UTC", "true").lower() == "true",
    "INCLUDE_CALLSITE": os.getenv("LOG_INCLUDE_CALLSITE", "false").lower() == "true",
    "FILE_PATH": os.getenv("LOG_FILE_PATH", ""),  # e.g. ./logs/policy-core.log
    "FILE_ROTATION_WHEN": os.getenv("LOG_FILE_ROTATION_WHEN", "D"),  # S, M, H, D, W0-6, midnight, etc.
    "FILE_ROTATION_INTERVAL": int(os.getenv("LOG_FILE_ROTATION_INTERVAL", "1")),
    "FILE_RETENTION_COUNT": int(os.getenv("LOG_FILE_RETENTION_COUNT", "14")),
    "QUEUED": os.getenv("LOG_QUEUED", "true").lower() == "true",
    "QUEUE_SIZE": int(os.getenv("LOG_QUEUE_SIZE", "65536")),
    "SAMPLING": os.getenv("LOG_SAMPLING", ""),  # e.g. "INFO=0.2,DEBUG=0.05" or "WINDOW=10;RATE=100"
    "REDACT": os.getenv("LOG_REDACT", "true").lower() == "true",
    "MAX_FIELD_LEN": int(os.getenv("LOG_MAX_FIELD_LEN", "4096")),
    "MAX_MSG_LEN": int(os.getenv("LOG_MAX_MSG_LEN", "2048")),
    "STRUCT_VERSION": int(os.getenv("LOG_STRUCT_VERSION", "1")),
}

_LEVEL_MAP = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}

# =========================
# Context handling (contextvars)
# =========================

_LOG_CONTEXT: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("policy_log_context", default={})

def _ctx_get() -> Dict[str, Any]:
    return dict(_LOG_CONTEXT.get())

def bind(**fields: Any) -> None:
    ctx = _ctx_get()
    ctx.update(fields)
    _LOG_CONTEXT.set(ctx)

def unbind(*keys: str) -> None:
    ctx = _ctx_get()
    for k in keys:
        ctx.pop(k, None)
    _LOG_CONTEXT.set(ctx)

class _UseContext:
    def __init__(self, **fields: Any) -> None:
        self._token: Optional[contextvars.Token] = None
        self._fields = fields

    def __enter__(self):
        current = _ctx_get()
        merged = {**current, **self._fields}
        self._token = _LOG_CONTEXT.set(merged)

    def __exit__(self, exc_type, exc, tb):
        if self._token is not None:
            _LOG_CONTEXT.reset(self._token)

def use_context(**fields: Any) -> _UseContext:
    return _UseContext(**fields)

def set_correlation_id(value: str) -> None:
    bind(correlation_id=value)

def new_correlation_id() -> str:
    cid = str(uuid.uuid4())
    set_correlation_id(cid)
    return cid

# =========================
# Redaction & safe serialization
# =========================

_SECRET_PATTERNS = [
    r"(?i)password",
    r"(?i)passwd",
    r"(?i)secret",
    r"(?i)api[_\-]?key",
    r"(?i)authorization",
    r"(?i)bearer\s+[a-z0-9\.\-\_]+",
    r"(?i)token",
    r"(?i)set-cookie",
    r"(?i)cookie",
    r"(?i)private[_\-]?key",
]

_REDACT_RE = re.compile("|".join(_SECRET_PATTERNS))

def _redact_text(s: str) -> str:
    if not ENV["REDACT"] or not s:
        return s
    return _REDACT_RE.sub("[REDACTED]", s)

def _safe_primitive(v: Any, max_len: int) -> Any:
    # Ensure JSON-serializable primitives with truncation
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        s = v
    else:
        # Dataclasses / pydantic / mapping
        if is_dataclass(v):
            try:
                v = asdict(v)
            except Exception:
                v = repr(v)
        elif hasattr(v, "model_dump"):
            try:
                v = v.model_dump()
            except Exception:
                v = repr(v)
        elif hasattr(v, "dict"):
            try:
                v = v.dict()
            except Exception:
                v = repr(v)
        # Convert non-primitive to string (limit size)
        if not isinstance(v, (dict, list, tuple, set, str)):
            s = repr(v)
        else:
            s = v  # will be processed below

    if isinstance(s, str):
        s = _redact_text(s)
        if len(s) > max_len:
            return s[:max_len] + "...(truncated)"
        return s
    if isinstance(s, (list, tuple, set)):
        return [_safe_primitive(i, max_len) for i in list(s)[:1000]]
    if isinstance(s, dict):
        out: Dict[str, Any] = {}
        for k, val in list(s.items())[:1000]:
            key = str(k)[:128]
            out[key] = _safe_primitive(val, max_len)
        return out
    # Fallback
    s = str(s)
    s = _redact_text(s)
    if len(s) > max_len:
        return s[:max_len] + "...(truncated)"
    return s

# =========================
# Sampling filter
# =========================

class SamplerFilter(logging.Filter):
    """
    Supports:
      - Probability per-level: LOG_SAMPLING="INFO=0.2,DEBUG=0.05"
      - Windowed token bucket: LOG_SAMPLING="WINDOW=10;RATE=100" (per logger+level)
    """
    def __init__(self, spec: str):
        super().__init__()
        self._prob_levels: Dict[int, float] = {}
        self._window: Optional[int] = None
        self._rate: Optional[int] = None
        self._buckets: Dict[Tuple[str, int], Tuple[int, float]] = {}  # key -> (tokens, window_start)
        if not spec:
            return
        if "WINDOW=" in spec and "RATE=" in spec:
            parts = dict(p.split("=", 1) for p in spec.split(";") if "=" in p)
            self._window = int(parts.get("WINDOW", "10"))
            self._rate = int(parts.get("RATE", "100"))
        else:
            for kv in spec.split(","):
                if not kv.strip():
                    continue
                lvl, prob = kv.split("=", 1)
                lvl = lvl.strip().upper()
                prob = float(prob.strip())
                levelno = _LEVEL_MAP.get(lvl, None)
                if levelno is not None:
                    self._prob_levels[levelno] = max(0.0, min(1.0, prob))

    def filter(self, record: logging.LogRecord) -> bool:
        # Per-level probability
        if self._prob_levels:
            p = self._prob_levels.get(record.levelno, 1.0)
            if p >= 1.0:
                return True
            # LCG-based cheap RNG tied to time+hash(record)
            h = hash((record.name, record.levelno, int(time.time() * 10)))
            return (h % 10000) / 10000.0 < p
        # Token bucket per logger+level
        if self._window and self._rate is not None:
            key = (record.name, record.levelno)
            tokens, start_ts = self._buckets.get(key, (0, time.time()))
            now = time.time()
            if now - start_ts >= self._window:
                tokens, start_ts = 0, now
            if tokens < self._rate:
                self._buckets[key] = (tokens + 1, start_ts)
                return True
            return False
        return True

# =========================
# Redaction filter
# =========================

class RedactorFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_text(record.msg)
            # Extra structured fields may be in record.__dict__['extra']
            extra = getattr(record, "extra", None)
            if isinstance(extra, dict):
                for k, v in list(extra.items()):
                    extra[k] = _safe_primitive(v, ENV["MAX_FIELD_LEN"])
            # Also sanitize arbitrary attributes
            for k, v in list(record.__dict__.items()):
                if k in ("msg", "args", "exc_info", "exc_text", "stack_info"):
                    continue
                if isinstance(v, str):
                    record.__dict__[k] = _redact_text(v)
        except Exception:
            # Redaction must never break logging
            pass
        return True

# =========================
# JSON Formatter
# =========================

_STD_KEYS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
    "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName", "process",
}

class JsonFormatter(logging.Formatter):
    def __init__(self, include_callsite: bool = False, use_utc: bool = True):
        super().__init__()
        self.include_callsite = include_callsite
        self.use_utc = use_utc

    def format(self, record: logging.LogRecord) -> str:
        try:
            ts = datetime.fromtimestamp(record.created, tz=timezone.utc if self.use_utc else None).isoformat()
            base: Dict[str, Any] = {
                "ts": ts,
                "v": ENV["STRUCT_VERSION"],
                "service": ENV["SERVICE_NAME"],
                "level": record.levelname,
                "logger": record.name,
                "message": self._format_message(record),
            }

            # Context
            base.update(_ctx_get())

            # OTel
            if _OTEL_OK:
                span = otel_trace.get_current_span()
                ctx = span.get_span_context() if span else None
                if ctx and ctx.is_valid:
                    base["trace_id"] = "{:032x}".format(ctx.trace_id)
                    base["span_id"] = "{:016x}".format(ctx.span_id)

            # Extras (record.extra set by our wrapper)
            if isinstance(getattr(record, "extra", None), dict):
                for k, v in record.extra.items():
                    if k not in base:
                        base[k] = _safe_primitive(v, ENV["MAX_FIELD_LEN"])

            # Include non-standard attributes as extra
            for k, v in record.__dict__.items():
                if k in _STD_KEYS or k == "extra":
                    continue
                # Avoid huge duplication
                if k not in base:
                    base[k] = _safe_primitive(v, ENV["MAX_FIELD_LEN"])

            # Exception
            if record.exc_info:
                exc_type, exc_val, exc_tb = record.exc_info
                base["error"] = {
                    "type": getattr(exc_type, "__name__", str(exc_type)),
                    "message": _safe_primitive(str(exc_val), ENV["MAX_FIELD_LEN"]),
                    "stack": self._format_stack(exc_tb),
                }

            # Callsite
            if self.include_callsite:
                base["callsite"] = {
                    "file": record.pathname,
                    "line": record.lineno,
                    "func": record.funcName,
                }

            return json.dumps(base, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            # As a last resort, fallback to default text formatting to avoid losing logs
            return super().format(record)

    def _format_message(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if len(msg) > ENV["MAX_MSG_LEN"]:
            msg = msg[:ENV["MAX_MSG_LEN"]] + "...(truncated)"
        return _redact_text(msg)

    def _format_stack(self, tb) -> str:
        try:
            return "".join(traceback.format_tb(tb))[-ENV["MAX_FIELD_LEN"]:]
        except Exception:
            return "unavailable"

# =========================
# Logger wrapper (structured)
# =========================

class StructuredLogger:
    def __init__(self, logger: logging.Logger):
        self._log = logger

    def debug(self, msg: str, **fields: Any) -> None:
        self._log.debug(msg, extra={"extra": fields} if fields else None)

    def info(self, msg: str, **fields: Any) -> None:
        self._log.info(msg, extra={"extra": fields} if fields else None)

    def warning(self, msg: str, **fields: Any) -> None:
        self._log.warning(msg, extra={"extra": fields} if fields else None)

    def error(self, msg: str, **fields: Any) -> None:
        self._log.error(msg, extra={"extra": fields} if fields else None)

    def exception(self, msg: str, **fields: Any) -> None:
        self._log.exception(msg, extra={"extra": fields} if fields else None)

    def critical(self, msg: str, **fields: Any) -> None:
        self._log.critical(msg, extra={"extra": fields} if fields else None)

def get_logger(name: Optional[str] = None) -> StructuredLogger:
    return StructuredLogger(logging.getLogger(name or ENV["SERVICE_NAME"]))

# =========================
# Setup & Handlers
# =========================

_listener_ref: Optional[QueueListener] = None

def _build_stream_handler(fmt: logging.Formatter, filters: Iterable[logging.Filter]) -> logging.Handler:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(fmt)
    for f in filters:
        h.addFilter(f)
    return h

def _build_file_handler(fmt: logging.Formatter, filters: Iterable[logging.Filter]) -> Optional[logging.Handler]:
    if not ENV["FILE_PATH"]:
        return None
    os.makedirs(os.path.dirname(ENV["FILE_PATH"]), exist_ok=True)
    fh = TimedRotatingFileHandler(
        filename=ENV["FILE_PATH"],
        when=ENV["FILE_ROTATION_WHEN"],
        interval=ENV["FILE_ROTATION_INTERVAL"],
        backupCount=ENV["FILE_RETENTION_COUNT"],
        encoding="utf-8",
        utc=ENV["UTC"],
    )
    fh.setFormatter(fmt)
    for f in filters:
        fh.addFilter(f)
    return fh

def _configure_root_handlers(handlers: Iterable[logging.Handler]) -> Tuple[logging.Logger, Iterable[logging.Handler]]:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(_LEVEL_MAP.get(ENV["LEVEL"], logging.INFO))

    if ENV["QUEUED"]:
        q: "queue.Queue[logging.LogRecord]" = queue.Queue(maxsize=ENV["QUEUE_SIZE"])
        qh = QueueHandler(q)
        root.addHandler(qh)
        global _listener_ref
        _listener_ref = QueueListener(q, *handlers, respect_handler_level=False)
        _listener_ref.start()

        def _stop():
            try:
                if _listener_ref:
                    _listener_ref.stop()
            except Exception:
                pass

        atexit.register(_stop)
        return root, [qh]
    else:
        for h in handlers:
            root.addHandler(h)
        return root, handlers

def setup_logging() -> None:
    """
    Initialize logging once. Safe to call multiple times.
    """
    # Formatter
    if ENV["FORMAT"] == "text":
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    else:
        fmt = JsonFormatter(include_callsite=ENV["INCLUDE_CALLSITE"], use_utc=ENV["UTC"])

    # Filters
    sampling = SamplerFilter(ENV["SAMPLING"])
    redactor = RedactorFilter()
    filters: Tuple[logging.Filter, ...] = (sampling, redactor)

    # Handlers
    stream_h = _build_stream_handler(fmt, filters)
    file_h = _build_file_handler(fmt, filters)
    handlers = [stream_h] + ([file_h] if file_h else [])

    # Root config
    root, _ = _configure_root_handlers(handlers)

    # Third-party noisy loggers tune
    for noisy in ("uvicorn", "uvicorn.access", "uvicorn.error", "asyncio", "aiokafka", "botocore"):
        logging.getLogger(noisy).setLevel(_LEVEL_MAP.get(ENV["LEVEL"], logging.INFO))

    # Confirm initialization
    StructuredLogger(root).info(
        "logging initialized",
        service=ENV["SERVICE_NAME"],
        level=ENV["LEVEL"],
        format=ENV["FORMAT"],
        utc=ENV["UTC"],
        queued=ENV["QUEUED"],
        file=ENV["FILE_PATH"] or None,
        sampling=ENV["SAMPLING"] or None,
        struct_version=ENV["STRUCT_VERSION"],
    )

# =========================
# Minimal self-check
# =========================

if __name__ == "__main__":
    setup_logging()
    log = get_logger("policy-core.demo")
    new_correlation_id()
    bind(tenant="acme", user="alice", component="observability")

    log.info("hello, world", health="ok", temp_c=21.5)
    try:
        raise ValueError("boom: password=supersecret token=abc123")
    except Exception:
        log.exception("caught exception", action="demo")
    log.debug("debug details", payload={"api_key": "XYZ", "nested": {"authorization": "Bearer SECRET"}})
