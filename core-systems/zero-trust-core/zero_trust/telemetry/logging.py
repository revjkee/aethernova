# File: zero-trust-core/zero_trust/telemetry/logging.py
# Industrial-grade logging for Zero Trust core telemetry.
# Features:
# - Structured JSON logs with RFC3339 timestamps
# - Context propagation via contextvars (trace_id, request_id, user_id, tenant_id, session_id)
# - Security AUDIT level and convenience APIs
# - Sensitive data redaction (PII/secrets/tokens/passwords)
# - Tamper-evident integrity chain (HMAC/sha256) per-process
# - Async, non-blocking logging via QueueHandler/QueueListener
# - File rotation (time/size), Syslog, Stdout
# - Dynamic configuration via env vars; runtime level override
# - Minimal dependencies (stdlib only)

from __future__ import annotations

import json
import logging
import logging.handlers as _handlers
import os
import socket
import sys
import threading
import queue
import time
import uuid
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
import contextvars

# -------------------------
# Configuration dataclass
# -------------------------

@dataclass
class LoggingConfig:
    service_name: str = field(default_factory=lambda: os.getenv("ZTC_SERVICE", "zero-trust-core"))
    service_component: str = field(default_factory=lambda: os.getenv("ZTC_COMPONENT", "telemetry"))
    service_version: str = field(default_factory=lambda: os.getenv("ZTC_VERSION", "0.1.0"))
    environment: str = field(default_factory=lambda: os.getenv("ZTC_ENV", "dev"))

    level: str = field(default_factory=lambda: os.getenv("ZTC_LOG_LEVEL", "INFO"))
    json_output: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_JSON", "1") not in ("0", "false", "False"))
    include_integrity_chain: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_INTEGRITY", "1") not in ("0", "false", "False"))
    redact_sensitive: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_REDACT", "1") not in ("0", "false", "False"))
    debug_sample_rate: float = field(default_factory=lambda: float(os.getenv("ZTC_DEBUG_SAMPLE_RATE", "1.0")))  # 0..1

    stdout_enabled: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_STDOUT", "1") not in ("0", "false", "False"))
    file_enabled: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_FILE", "0") not in ("0", "false", "False"))
    file_path: str = field(default_factory=lambda: os.getenv("ZTC_LOG_FILE_PATH", "./logs/ztc.log"))
    file_rotate_when: str = field(default_factory=lambda: os.getenv("ZTC_LOG_FILE_ROTATE_WHEN", "midnight"))  # 'S','M','H','D','midnight','W0'-'W6'
    file_rotate_interval: int = field(default_factory=lambda: int(os.getenv("ZTC_LOG_FILE_ROTATE_INTERVAL", "1")))
    file_backup_count: int = field(default_factory=lambda: int(os.getenv("ZTC_LOG_FILE_BACKUP_COUNT", "14")))
    file_max_bytes: int = field(default_factory=lambda: int(os.getenv("ZTC_LOG_FILE_MAX_BYTES", "0")))  # if >0 use size-based

    syslog_enabled: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_SYSLOG", "0") not in ("0", "false", "False"))
    syslog_address: str = field(default_factory=lambda: os.getenv("ZTC_LOG_SYSLOG_ADDR", "/dev/log" if sys.platform != "win32" else "localhost:514"))
    syslog_facility: str = field(default_factory=lambda: os.getenv("ZTC_LOG_SYSLOG_FACILITY", "local0"))

    queue_size: int = field(default_factory=lambda: int(os.getenv("ZTC_LOG_QUEUE_SIZE", "65536")))
    propagate: bool = field(default_factory=lambda: os.getenv("ZTC_LOG_PROPAGATE", "0") not in ("0", "false", "False"))

    # Integrity chain
    integrity_secret_env: str = field(default_factory=lambda: os.getenv("ZTC_LOG_INTEGRITY_SECRET_ENV", "ZTC_SIGNING_KEY"))

# -------------------------
# Custom levels
# -------------------------

AUDIT_LEVEL = 25
if not hasattr(logging, "AUDIT"):
    logging.addLevelName(AUDIT_LEVEL, "AUDIT")

def _audit(self, msg, *args, **kwargs):
    if self.isEnabledFor(AUDIT_LEVEL):
        self._log(AUDIT_LEVEL, msg, args, **kwargs)

logging.Logger.audit = _audit  # type: ignore

# -------------------------
# Context management
# -------------------------

_ctx_trace_id = contextvars.ContextVar("trace_id", default=None)
_ctx_span_id = contextvars.ContextVar("span_id", default=None)
_ctx_request_id = contextvars.ContextVar("request_id", default=None)
_ctx_session_id = contextvars.ContextVar("session_id", default=None)
_ctx_user_id = contextvars.ContextVar("user_id", default=None)
_ctx_tenant_id = contextvars.ContextVar("tenant_id", default=None)
_ctx_extra = contextvars.ContextVar("extra_ctx", default={})

def set_context(
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    **extra: Any,
):
    if trace_id is not None: _ctx_trace_id.set(trace_id)
    if span_id is not None: _ctx_span_id.set(span_id)
    if request_id is not None: _ctx_request_id.set(request_id)
    if session_id is not None: _ctx_session_id.set(session_id)
    if user_id is not None: _ctx_user_id.set(user_id)
    if tenant_id is not None: _ctx_tenant_id.set(tenant_id)
    if extra: _ctx_extra.set({**_ctx_extra.get(), **extra})

class LogContext:
    def __init__(self, **kv: Any):
        self._tokens: List[Tuple[contextvars.ContextVar, Any]] = []
        self._kv = kv
    def __enter__(self):
        mapping = {
            "trace_id": _ctx_trace_id, "span_id": _ctx_span_id, "request_id": _ctx_request_id,
            "session_id": _ctx_session_id, "user_id": _ctx_user_id, "tenant_id": _ctx_tenant_id
        }
        for k, v in self._kv.items():
            if k in mapping:
                self._tokens.append((mapping[k], mapping[k].set(v)))
            else:
                # Put into extra context
                cur = _ctx_extra.get()
                cur2 = {**cur, k: v}
                self._tokens.append((_ctx_extra, _ctx_extra.set(cur2)))
        return self
    def __exit__(self, exc_type, exc, tb):
        for var, tok in reversed(self._tokens):
            var.reset(tok)

# -------------------------
# Redaction filter
# -------------------------

class PIIRedactorFilter(logging.Filter):
    _REPLACEMENT = "[REDACTED]"
    def __init__(self, enable: bool = True, fields: Optional[Iterable[str]] = None):
        super().__init__()
        self.enable = enable
        self.fields = set(fields or {"password", "passwd", "secret", "token", "api_key", "authorization", "auth", "cookie", "set-cookie"})
        # Patterns (keep conservative to avoid over-redaction)
        self._patterns = [
            (re.compile(r'(?i)\b(pass(word)?|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*([^\s,;]+)'), r'\1: ' + self._REPLACEMENT),
            (re.compile(r'(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9\.\-\=_]+)'), "Authorization: Bearer " + self._REPLACEMENT),
            (re.compile(r'(?i)\b(set-)?cookie\b\s*[:=]\s*([^\s,;]+)'), r'Cookie: ' + self._REPLACEMENT),
            (re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'), self._REPLACEMENT),
            (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), self._REPLACEMENT),  # IPv4
            (re.compile(r'\b(0x)?[A-Fa-f0-9]{32,}\b'), self._REPLACEMENT),    # hex-like secrets
            (re.compile(r'\b[A-Za-z0-9_\-]{24,}\b'), self._REPLACEMENT),      # generic tokens
            (re.compile(r'\b(\d{4}[-\s]?){3}\d{4}\b'), self._REPLACEMENT),    # CC-like
        ]

    def _sanitize(self, s: str) -> str:
        if not self.enable or not s:
            return s
        out = s
        for pattern, repl in self._patterns:
            out = pattern.sub(repl, out)
        return out

    def filter(self, record: logging.LogRecord) -> bool:
        if not self.enable:
            return True
        # Sanitize message and args
        if isinstance(record.msg, str):
            record.msg = self._sanitize(record.msg)
        if record.args:
            try:
                if isinstance(record.args, dict):
                    record.args = {k: (self._sanitize(v) if isinstance(v, str) else v) for k, v in record.args.items()}
                else:
                    record.args = tuple(self._sanitize(a) if isinstance(a, str) else a for a in record.args)
            except Exception:
                pass
        # Sanitize extra-serializable attributes if present
        for key in list(record.__dict__.keys()):
            if key.lower() in self.fields and isinstance(record.__dict__[key], str):
                record.__dict__[key] = self._REPLACEMENT
        return True

# -------------------------
# Integrity chain filter
# -------------------------

class IntegrityChainFilter(logging.Filter):
    def __init__(self, enabled: bool, secret: Optional[bytes]):
        super().__init__()
        self.enabled = enabled
        self.secret = secret
        self._lock = threading.Lock()
        self._prev: bytes = b""
    def _compute(self, payload: bytes) -> str:
        digest_input = self._prev + payload
        if self.secret:
            d = hmac.new(self.secret, digest_input, hashlib.sha256).hexdigest()
        else:
            d = hashlib.sha256(digest_input).hexdigest()
        self._prev = bytes.fromhex(d)
        return d
    def filter(self, record: logging.LogRecord) -> bool:
        if not self.enabled:
            return True
        # Build a stable payload: logger name + level + created + message
        try:
            base = f"{record.name}|{record.levelno}|{int(record.created*1e9)}|{record.getMessage()}".encode("utf-8", "replace")
        except Exception:
            base = f"{record.name}|{record.levelno}|{int(record.created*1e9)}".encode("utf-8", "replace")
        with self._lock:
            record.integrity = self._compute(base)
        return True

# -------------------------
# Sampling filter (for DEBUG)
# -------------------------

class DebugSamplingFilter(logging.Filter):
    def __init__(self, rate: float):
        super().__init__()
        self.rate = max(0.0, min(1.0, rate))
        self._counter = 0
    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.DEBUG or self.rate >= 1.0:
            return True
        self._counter += 1
        return (self._counter % int(max(1, round(1.0 / max(self.rate, 1e-6))))) == 0

# -------------------------
# Context/metadata injection
# -------------------------

class ContextEnricher(logging.Filter):
    def __init__(self, cfg: LoggingConfig):
        super().__init__()
        self.cfg = cfg
        self.host = socket.gethostname()
        self.pid = os.getpid()
    def filter(self, record: logging.LogRecord) -> bool:
        record.service = self.cfg.service_name
        record.component = self.cfg.service_component
        record.version = self.cfg.service_version
        record.environment = self.cfg.environment
        record.host = self.host
        record.pid = self.pid
        record.trace_id = _ctx_trace_id.get() or None
        record.span_id = _ctx_span_id.get() or None
        record.request_id = _ctx_request_id.get() or None
        record.session_id = _ctx_session_id.get() or None
        record.user_id = _ctx_user_id.get() or None
        record.tenant_id = _ctx_tenant_id.get() or None
        extra = _ctx_extra.get() or {}
        for k, v in extra.items():
            # Avoid overriding core fields
            if not hasattr(record, k):
                setattr(record, k, v)
        return True

# -------------------------
# JSON formatter
# -------------------------

class RFC3339JSONFormatter(logging.Formatter):
    def __init__(self, default_level: str = "INFO"):
        super().__init__()
        self.default_level = default_level
    @staticmethod
    def _ts(epoch: float) -> str:
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        # RFC3339 with 'Z'
        return dt.isoformat().replace("+00:00", "Z")
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": self._ts(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": getattr(record, "service", None),
            "component": getattr(record, "component", None),
            "version": getattr(record, "version", None),
            "environment": getattr(record, "environment", None),
            "host": getattr(record, "host", None),
            "pid": getattr(record, "pid", None),
            "trace_id": getattr(record, "trace_id", None),
            "span_id": getattr(record, "span_id", None),
            "request_id": getattr(record, "request_id", None),
            "session_id": getattr(record, "session_id", None),
            "user_id": getattr(record, "user_id", None),
            "tenant_id": getattr(record, "tenant_id", None),
        }
        # Integrity, if present
        if hasattr(record, "integrity"):
            base["integrity"] = getattr(record, "integrity")
        # Include non-core extras
        reserved = set(base.keys()) | {"msg", "args", "exc_info", "exc_text", "stack_info", "lineno", "pathname", "filename", "module", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName", "processName", "process", "stacklevel"}
        for k, v in record.__dict__.items():
            if k not in reserved and not k.startswith("_"):
                # Only JSON-serializable basics
                if isinstance(v, (str, int, float, bool)) or v is None:
                    base[k] = v
                else:
                    base[k] = repr(v)
        # Exception formatting
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))

# -------------------------
# Plain text formatter (fallback)
# -------------------------

class PlainFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("{asctime} | {levelname:<8} | {name} | {message}", style="{", datefmt="%Y-%m-%dT%H:%M:%S%z")
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")

# -------------------------
# Builder
# -------------------------

class _Manager:
    def __init__(self, cfg: LoggingConfig, root_logger: logging.Logger, queue_listener: Optional[_handlers.QueueListener]):
        self.cfg = cfg
        self.root_logger = root_logger
        self.queue_listener = queue_listener
    def shutdown(self):
        try:
            if self.queue_listener:
                self.queue_listener.stop()
        finally:
            logging.shutdown()

_manager_singleton: Optional[_Manager] = None
_singleton_lock = threading.Lock()

def _level_from_str(s: str) -> int:
    s = (s or "").upper()
    return getattr(logging, s, logging.INFO)

def setup_logging(cfg: Optional[LoggingConfig] = None) -> _Manager:
    global _manager_singleton
    with _singleton_lock:
        if _manager_singleton:
            return _manager_singleton

        cfg = cfg or LoggingConfig()

        root = logging.getLogger()
        root.setLevel(_level_from_str(cfg.level))
        root.propagate = cfg.propagate

        # Common filters
        context_filter = ContextEnricher(cfg)
        redactor = PIIRedactorFilter(enable=cfg.redact_sensitive)
        secret = os.getenv(cfg.integrity_secret_env, "").encode("utf-8") if cfg.include_integrity_chain and os.getenv(cfg.integrity_secret_env) else None
        integrity = IntegrityChainFilter(enabled=cfg.include_integrity_chain, secret=secret)
        sampler = DebugSamplingFilter(rate=cfg.debug_sample_rate)

        # Formatters
        json_fmt = RFC3339JSONFormatter()
        plain_fmt = PlainFormatter()

        # Handlers (sync, wrapped by QueueHandler)
        sync_handlers: List[logging.Handler] = []

        if cfg.stdout_enabled:
            h = logging.StreamHandler(stream=sys.stdout)
            h.setLevel(_level_from_str(cfg.level))
            h.addFilter(context_filter)
            h.addFilter(redactor)
            h.addFilter(integrity)
            h.addFilter(sampler)
            h.setFormatter(json_fmt if cfg.json_output else plain_fmt)
            sync_handlers.append(h)

        if cfg.file_enabled:
            os.makedirs(os.path.dirname(cfg.file_path), exist_ok=True)
            if cfg.file_max_bytes and cfg.file_max_bytes > 0:
                f = _handlers.RotatingFileHandler(cfg.file_path, maxBytes=cfg.file_max_bytes, backupCount=cfg.file_backup_count, encoding="utf-8")
            else:
                f = _handlers.TimedRotatingFileHandler(cfg.file_path, when=cfg.file_rotate_when, interval=cfg.file_rotate_interval, backupCount=cfg.file_backup_count, encoding="utf-8", utc=True)
            f.setLevel(_level_from_str(cfg.level))
            f.addFilter(context_filter)
            f.addFilter(redactor)
            f.addFilter(integrity)
            f.addFilter(sampler)
            f.setFormatter(json_fmt if cfg.json_output else plain_fmt)
            sync_handlers.append(f)

        if cfg.syslog_enabled:
            addr = cfg.syslog_address
            facility = getattr(_handlers.SysLogHandler, f"LOG_{cfg.syslog_facility.upper()}", _handlers.SysLogHandler.LOG_LOCAL0)
            if ":" in addr and not os.path.exists(addr):
                host, port = addr.split(":", 1)
                s = _handlers.SysLogHandler(address=(host, int(port)), facility=facility)
            else:
                s = _handlers.SysLogHandler(address=addr, facility=facility)
            s.setLevel(_level_from_str(cfg.level))
            s.addFilter(context_filter)
            s.addFilter(redactor)
            s.addFilter(integrity)
            s.addFilter(sampler)
            s.setFormatter(json_fmt if cfg.json_output else plain_fmt)
            sync_handlers.append(s)

        # Async queue
        log_queue: "queue.Queue[logging.LogRecord]" = queue.Queue(maxsize=cfg.queue_size)
        qh = _handlers.QueueHandler(log_queue)
        qh.setLevel(_level_from_str(cfg.level))
        root.handlers.clear()
        root.addHandler(qh)

        ql = _handlers.QueueListener(log_queue, *sync_handlers, respect_handler_level=True)
        ql.daemon = True
        ql.start()

        _manager_singleton = _Manager(cfg, root, ql)
        return _manager_singleton

def get_logger(name: Optional[str] = None) -> logging.Logger:
    if _manager_singleton is None:
        setup_logging()
    return logging.getLogger(name if name else __name__)

# -------------------------
# Convenience APIs
# -------------------------

def audit_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """
    Emit a security/audit event with stable field names.
    Example fields: action, subject, object, status, reason, ip, user_agent
    """
    logger.audit(event, extra=fields)

def gen_trace_ids() -> Tuple[str, str]:
    trace = uuid.uuid4().hex
    span = uuid.uuid4().hex[:16]
    return trace, span

def with_trace(logger: logging.Logger, msg: str, **fields: Any) -> None:
    if not _ctx_trace_id.get():
        trace, span = gen_trace_ids()
        set_context(trace_id=trace, span_id=span)
    logger.info(msg, extra=fields)

# Initialize on import (safe defaults). Can be overridden if caller invokes setup_logging with custom cfg.
try:
    if os.getenv("ZTC_AUTO_INIT", "1") not in ("0", "false", "False"):
        setup_logging()
except Exception as _e:
    # Last-resort fallback to basicConfig to not lose logs
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger(__name__).warning("Fallback basic logging due to init error: %s", _e)
