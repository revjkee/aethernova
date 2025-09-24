# -*- coding: utf-8 -*-
"""
Industrial logging setup for AVM Core.

Features:
- JSON/text logging with consistent fields and RFC3339/UTC timestamps with millis
- Context via contextvars: request_id, correlation_id, user_id, session_id, tenant, operation, client_ip
- OpenTelemetry trace context enrichment (if opentelemetry is available)
- Secret redaction (keys and inline patterns)
- Per-level sampling filter and custom TRACE (level 5)
- File rotation (size- or time-based), console, optional Syslog, optional Sentry
- Environment-driven configuration with safe defaults
- Idempotent setup and helper API: setup_logging(), get_logger(), set_context(), clear_context()

No hard dependency on non-stdlib packages. Optional integrations are enabled if libraries are installed:
- sentry_sdk for Sentry DSN
- opentelemetry-api for trace context (logs still go to std handlers)

(c) core-systems/security-core
"""
from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import logging.config
import logging.handlers
import os
import random
import re
import socket
import sys
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

__all__ = [
    "setup_logging",
    "get_logger",
    "set_context",
    "clear_context",
    "TRACE",
]

# -----------------------------
# Constants and defaults
# -----------------------------
TRACE = 5
if not hasattr(logging, "TRACE"):
    logging.addLevelName(TRACE, "TRACE")

def _logger_trace(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)

logging.Logger.trace = _logger_trace  # type: ignore[attr-defined]

SERVICE_NAME = os.getenv("SERVICE_NAME", "security-core")
DEFAULT_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
DEFAULT_FORMAT = os.getenv("LOG_FORMAT", "json").lower()  # json|text
DEFAULT_COLOR = os.getenv("LOG_COLOR", "auto").lower()  # true|false|auto
DEFAULT_FILE = os.getenv("LOG_FILE", "").strip()
DEFAULT_FILE_MAX_BYTES = int(os.getenv("LOG_FILE_MAX_BYTES", str(50 * 1024 * 1024)))  # 50MB
DEFAULT_FILE_BACKUP_COUNT = int(os.getenv("LOG_FILE_BACKUP_COUNT", "10"))
DEFAULT_FILE_WHEN = os.getenv("LOG_FILE_WHEN", "").lower()  # "", 'midnight', 'H', 'D', etc.
DEFAULT_FILE_INTERVAL = int(os.getenv("LOG_FILE_INTERVAL", "1"))

SYSLOG_ADDR = os.getenv("LOG_SYSLOG_ADDRESS", "").strip()  # "/dev/log" or "host:514"
SYSLOG_FACILITY = os.getenv("LOG_SYSLOG_FACILITY", "user").lower()

SENTRY_DSN = os.getenv("LOG_SENTRY_DSN", "").strip()
SENTRY_ENV = os.getenv("LOG_SENTRY_ENV", os.getenv("ENVIRONMENT", "prod"))
SENTRY_LEVEL = os.getenv("LOG_SENTRY_LEVEL", "ERROR").upper()

SAMPLE_RATES = {
    logging.DEBUG: float(os.getenv("LOG_SAMPLE_DEBUG_RATE", "1.0")),
    logging.INFO: float(os.getenv("LOG_SAMPLE_INFO_RATE", "1.0")),
    TRACE: float(os.getenv("LOG_SAMPLE_TRACE_RATE", "1.0")),
}
SUPPRESS_LOGGERS = [s.strip() for s in os.getenv("LOG_SUPPRESS_LOGGERS", "").split(",") if s.strip()]

# -----------------------------
# Context variables
# -----------------------------
_cv_request_id = contextvars.ContextVar("request_id", default=None)
_cv_correlation_id = contextvars.ContextVar("correlation_id", default=None)
_cv_user_id = contextvars.ContextVar("user_id", default=None)
_cv_session_id = contextvars.ContextVar("session_id", default=None)
_cv_tenant = contextvars.ContextVar("tenant", default=None)
_cv_operation = contextvars.ContextVar("operation", default=None)
_cv_client_ip = contextvars.ContextVar("client_ip", default=None)

def set_context(
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    tenant: Optional[str] = None,
    operation: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> None:
    """Set correlation context for subsequent log records (per task/coroutine)."""
    if request_id is not None:
        _cv_request_id.set(request_id)
    if correlation_id is not None:
        _cv_correlation_id.set(correlation_id)
    if user_id is not None:
        _cv_user_id.set(user_id)
    if session_id is not None:
        _cv_session_id.set(session_id)
    if tenant is not None:
        _cv_tenant.set(tenant)
    if operation is not None:
        _cv_operation.set(operation)
    if client_ip is not None:
        _cv_client_ip.set(client_ip)

def clear_context() -> None:
    """Clear correlation context."""
    for var in (
        _cv_request_id,
        _cv_correlation_id,
        _cv_user_id,
        _cv_session_id,
        _cv_tenant,
        _cv_operation,
        _cv_client_ip,
    ):
        try:
            var.set(None)  # overwrite in current context
        except Exception:
            pass

# -----------------------------
# Helpers
# -----------------------------
_STD_ATTRS = frozenset(
    [
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "asctime",
    ]
)

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|authorization|token|client[_-]?secret|set-cookie)"
)
_SECRET_VALUE_INLINE_RE = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*([^\s'\";]+)"
)

def _now_rfc3339() -> str:
    dt = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    # Example: 2025-08-19T12:34:56.789Z
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

def _extract_trace_ctx() -> Dict[str, Any]:
    """Return OpenTelemetry trace context if available."""
    try:
        from opentelemetry import trace as _trace  # type: ignore
        span = _trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return {}
        # Trace/span IDs as 32/16 hex
        trace_id = "{:032x}".format(ctx.trace_id)
        span_id = "{:016x}".format(ctx.span_id)
        sampled = bool(getattr(ctx.trace_flags, "sampled", False) or (ctx.trace_flags & 0x01))
        # W3C traceparent: version 00
        traceparent = f"00-{trace_id}-{span_id}-{'01' if sampled else '00'}"
        return {"trace_id": trace_id, "span_id": span_id, "trace_sampled": sampled, "traceparent": traceparent}
    except Exception:
        return {}

def _clean_extras(record: logging.LogRecord) -> Dict[str, Any]:
    extras = {k: v for k, v in record.__dict__.items() if k not in _STD_ATTRS}
    # Avoid unserializable values in JSON
    def _safe(obj):
        try:
            json.dumps(obj)
            return obj
        except Exception:
            return repr(obj)
    return {k: _safe(v) for k, v in extras.items()}

def _redact_value(v: Any) -> Any:
    if isinstance(v, str):
        if _SECRET_KEY_RE.search(v):
            return "***"
        # Redact inline patterns like "password=..." in messages
        return _SECRET_VALUE_INLINE_RE.sub(lambda m: f"{m.group(1)}=***", v)
    if isinstance(v, Mapping):
        return {k: ("***" if _SECRET_KEY_RE.search(str(k)) else _redact_value(val)) for k, val in v.items()}
    if isinstance(v, (list, tuple, set)):
        t = type(v)
        return t(_redact_value(x) for x in v)
    return v

# -----------------------------
# Filters
# -----------------------------
class RedactionFilter(logging.Filter):
    """Redact secrets in message and extra fields."""
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = _redact_value(record.msg)
            # redact args too (for %-formatting)
            if record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(_redact_value(a) for a in record.args)
                elif isinstance(record.args, dict):
                    record.args = {k: _redact_value(v) for k, v in record.args.items()}
            # redact extras stored in record.__dict__
            for k in list(record.__dict__.keys()):
                if k in _STD_ATTRS:
                    continue
                record.__dict__[k] = _redact_value(record.__dict__[k])
        except Exception:
            pass
        return True

class SamplingFilter(logging.Filter):
    """Sample records by level using random rate in [0..1]."""
    def __init__(self, rates: Mapping[int, float]) -> None:
        super().__init__()
        self.rates = rates

    def filter(self, record: logging.LogRecord) -> bool:
        rate = self.rates.get(record.levelno, 1.0)
        if rate >= 1.0:
            return True
        # Never sample WARNING+ by default
        if record.levelno >= logging.WARNING:
            return True
        return random.random() < max(0.0, min(rate, 1.0))

# -----------------------------
# Formatters
# -----------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": _now_rfc3339(),
            "level": record.levelname,
            "logger": record.name,
            "service": SERVICE_NAME,
            "host": _hostname(),
            "pid": record.process,
            "message": record.getMessage(),
        }
        # Context
        ctx = {
            "request_id": _cv_request_id.get(),
            "correlation_id": _cv_correlation_id.get(),
            "user_id": _cv_user_id.get(),
            "session_id": _cv_session_id.get(),
            "tenant": _cv_tenant.get(),
            "operation": _cv_operation.get(),
            "client_ip": _cv_client_ip.get(),
        }
        base.update({k: v for k, v in ctx.items() if v})

        # Trace context
        base.update(_extract_trace_ctx())

        # Extras
        extras = _clean_extras(record)
        if extras:
            base["extra"] = extras

        # Location for WARNING+
        if record.levelno >= logging.WARNING:
            base["src"] = {
                "file": record.pathname,
                "line": record.lineno,
                "func": record.funcName,
            }

        # Exception
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)

        return json.dumps(base, ensure_ascii=False)

class TextFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "TRACE": "\033[37m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET": "\033[0m",
    }

    def __init__(self, color: str = "auto"):
        super().__init__()
        self.color_mode = color

    def _use_color(self) -> bool:
        if self.color_mode == "true":
            return True
        if self.color_mode == "false":
            return False
        # auto
        return sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        ts = _now_rfc3339()
        level = record.levelname
        parts = [f"{ts} {SERVICE_NAME} {level:<8} {record.name}: {record.getMessage()}"]
        # Context short
        ctx = []
        for key, var in [
            ("rid", _cv_request_id),
            ("cid", _cv_correlation_id),
            ("uid", _cv_user_id),
            ("ten", _cv_tenant),
        ]:
            val = var.get()
            if val:
                ctx.append(f"{key}={val}")
        tc = _extract_trace_ctx()
        if tc.get("trace_id"):
            ctx.append(f"trace={tc['trace_id']}/{tc.get('span_id','')}")
        if ctx:
            parts.append("[" + " ".join(ctx) + "]")
        if record.exc_info:
            parts.append("\n" + self.formatException(record.exc_info))

        line = " ".join(parts)
        if self._use_color():
            c = self.COLORS.get(level, "")
            r = self.COLORS["RESET"]
            return f"{c}{line}{r}"
        return line

# -----------------------------
# Handlers builders
# -----------------------------
def _build_console_handler() -> Dict[str, Any]:
    fmt = "json" if DEFAULT_FORMAT == "json" else "text"
    formatter = "json" if fmt == "json" else "text"
    return {
        "class": "logging.StreamHandler",
        "level": DEFAULT_LEVEL,
        "formatter": formatter,
        "stream": "ext://sys.stdout",
        "filters": ["redact", "sample"],
    }

def _build_file_handler() -> Optional[Dict[str, Any]]:
    if not DEFAULT_FILE:
        return None
    base = {
        "level": DEFAULT_LEVEL,
        "formatter": "json" if DEFAULT_FORMAT == "json" else "text",
        "filters": ["redact", "sample"],
    }
    if DEFAULT_FILE_WHEN:
        # Timed rotation
        return {
            **base,
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": DEFAULT_FILE,
            "when": DEFAULT_FILE_WHEN,
            "interval": DEFAULT_FILE_INTERVAL,
            "backupCount": DEFAULT_FILE_BACKUP_COUNT,
            "encoding": "utf-8",
            "utc": True,
        }
    return {
        **base,
        "class": "logging.handlers.RotatingFileHandler",
        "filename": DEFAULT_FILE,
        "maxBytes": DEFAULT_FILE_MAX_BYTES,
        "backupCount": DEFAULT_FILE_BACKUP_COUNT,
        "encoding": "utf-8",
    }

def _build_syslog_handler() -> Optional[Dict[str, Any]]:
    if not SYSLOG_ADDR:
        return None
    address: Any
    if "/" in SYSLOG_ADDR:
        address = SYSLOG_ADDR
    else:
        host, _, port = SYSLOG_ADDR.partition(":")
        address = (host, int(port or "514"))
    facility = getattr(logging.handlers.SysLogHandler, SYSLOG_FACILITY.upper(), logging.handlers.SysLogHandler.USER)
    return {
        "class": "logging.handlers.SysLogHandler",
        "level": DEFAULT_LEVEL,
        "address": address,
        "facility": facility,
        "formatter": "json",  # syslog лучше отправлять как JSON
        "filters": ["redact", "sample"],
    }

def _init_sentry_if_configured(root_logger: logging.Logger) -> None:
    if not SENTRY_DSN:
        return
    try:
        import sentry_sdk  # type: ignore
        from sentry_sdk.integrations.logging import LoggingIntegration  # type: ignore

        sentry_logging = LoggingIntegration(
            level=getattr(logging, SENTRY_LEVEL, logging.ERROR),
            event_level=getattr(logging, SENTRY_LEVEL, logging.ERROR),
        )
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            environment=SENTRY_ENV,
            enable_tracing=False,
            integrations=[sentry_logging],
            send_default_pii=False,
        )
        root_logger.info("Sentry logging initialized", extra={"sentry_env": SENTRY_ENV})
    except Exception as e:
        root_logger.warning("Failed to initialize Sentry: %s", e)

# -----------------------------
# Public setup
# -----------------------------
_configured = False

def setup_logging(extra_handlers: Optional[Iterable[Dict[str, Any]]] = None, level: Optional[str] = None) -> None:
    """Configure root logging. Safe to call multiple times."""
    global _configured
    if _configured:
        return

    level_str = (level or DEFAULT_LEVEL).upper()
    if level_str == "TRACE":
        root_level = TRACE
    else:
        root_level = getattr(logging, level_str, logging.INFO)

    handlers_cfg: Dict[str, Dict[str, Any]] = {
        "console": _build_console_handler(),
    }

    file_h = _build_file_handler()
    if file_h:
        handlers_cfg["file"] = file_h

    syslog_h = _build_syslog_handler()
    if syslog_h:
        handlers_cfg["syslog"] = syslog_h

    # Formatters
    formatters_cfg: Dict[str, Dict[str, Any]] = {
        "json": {
            "()": JSONFormatter,
        },
        "text": {
            "()": TextFormatter,
            "color": DEFAULT_COLOR,
        },
    }

    # Filters
    filters_cfg: Dict[str, Dict[str, Any]] = {
        "redact": {"()": RedactionFilter},
        "sample": {"()": SamplingFilter, "rates": SAMPLE_RATES},
    }

    # Root handlers list
    root_handlers = ["console"]
    if "file" in handlers_cfg:
        root_handlers.append("file")
    if "syslog" in handlers_cfg:
        root_handlers.append("syslog")

    # Allow adding custom handlers from code
    if extra_handlers:
        for idx, h in enumerate(extra_handlers, start=1):
            name = f"extra_{idx}"
            handlers_cfg[name] = h
            root_handlers.append(name)

    config_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters_cfg,
        "filters": filters_cfg,
        "handlers": handlers_cfg,
        "root": {
            "level": root_level,
            "handlers": root_handlers,
        },
    }

    logging.config.dictConfig(config_dict)

    # Optional: suppress noisy third-party loggers
    for lname in SUPPRESS_LOGGERS:
        try:
            logging.getLogger(lname).setLevel(logging.WARNING)
        except Exception:
            pass

    # Sentry init (non-fatal if missing)
    _init_sentry_if_configured(logging.getLogger())

    _configured = True

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Helper to obtain a logger with TRACE support."""
    logger = logging.getLogger(name or SERVICE_NAME)
    return logger

# -----------------------------
# Usage example (not executed)
# -----------------------------
if __name__ == "__main__":
    # Example usage
    setup_logging()
    log = get_logger(__name__)
    set_context(request_id="req-123", correlation_id="corr-abc", user_id="u42", tenant="acme")
    log.trace("Boot trace with details: %s", {"debug_info": "init"})  # custom level
    log.debug("Debug event with secret=%s", "topsecret")
    log.info("Service started on %s", _hostname(), extra={"port": 8080})
    try:
        1 / 0
    except ZeroDivisionError:
        log.exception("Unhandled exception")
