# neuroforge-core/neuroforge/observability/logging.py
# Industrial-grade logging module for NeuroForge.
# Features:
# - Structured JSON logs with safe serialization
# - Context propagation via contextvars (request_id, correlation_id, user_id, session_id)
# - OpenTelemetry trace/span injection if available
# - PII redaction (emails, phones, cards, secrets) for message and extra
# - Sampling, de-duplication, rate-limiting, and "log_once"
# - Rotating file handlers with gzip compression
# - Audit logger with separate sinks
# - Dynamic level updates, extra sinks (console/file/syslog)
# - No mandatory external deps; OTel is optional

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import io
import json
import logging
import logging.handlers
import os
import queue
import random
import re
import socket
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple
import contextvars

# ---------------------------
# Context variables
# ---------------------------

_ctx_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)
_ctx_request_id:     contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
_ctx_user_id:        contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_id", default=None)
_ctx_session_id:     contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("session_id", default=None)
_ctx_tenant:         contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant", default=None)
_ctx_extra:          contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("extra_ctx", default={})

# ---------------------------
# Optional OpenTelemetry
# ---------------------------

def _get_otel_context() -> Tuple[Optional[str], Optional[str]]:
    try:
        # Lazy import to avoid hard dependency
        from opentelemetry.trace import get_current_span
        span = get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            trace_id = f"{ctx.trace_id:032x}"
            span_id = f"{ctx.span_id:016x}"
            return trace_id, span_id
    except Exception:
        pass
    return None, None

# ---------------------------
# Configuration dataclasses
# ---------------------------

@dataclass
class FileHandlerOptions:
    path: str
    max_bytes: int = 50 * 1024 * 1024  # 50MB
    backup_count: int = 10
    compress: bool = True
    encoding: str = "utf-8"
    delay: bool = True

@dataclass
class ConsoleHandlerOptions:
    enable: bool = True
    json: bool = True
    use_color: bool = False
    stream: str = "stderr"  # "stdout" or "stderr"

@dataclass
class SyslogHandlerOptions:
    enable: bool = False
    address: Tuple[str, int] = ("localhost", 514)
    facility: int = logging.handlers.SysLogHandler.LOG_USER
    socktype: int = socket.SOCK_DGRAM

@dataclass
class SamplingConfig:
    # Probability per level [0..1]; e.g., {"DEBUG": 0.1, "INFO": 1.0}
    per_level_probability: Dict[str, float] = field(default_factory=lambda: {"DEBUG": 0.1, "INFO": 1.0, "WARNING": 1.0, "ERROR": 1.0, "CRITICAL": 1.0})

@dataclass
class DedupConfig:
    # Collapse identical messages within a time window (seconds)
    window_seconds: float = 2.0
    max_keys: int = 10000

@dataclass
class RateLimitConfig:
    # Token bucket per unique message key
    capacity: int = 10
    refill_per_sec: float = 5.0  # tokens replenished per second
    max_keys: int = 10000

@dataclass
class RedactConfig:
    # Predefined patterns; custom can be appended
    email: bool = True
    phone: bool = True
    card: bool = True
    secrets: bool = True
    custom_patterns: List[str] = field(default_factory=list)
    replacement: str = "[REDACTED]"

@dataclass
class AuditConfig:
    enabled: bool = True
    file: Optional[FileHandlerOptions] = None  # If set, audit logs go here
    logger_name: str = "neuroforge.audit"
    level: str = "INFO"

@dataclass
class LoggingConfig:
    level: str = "INFO"
    json: bool = True
    service: str = "neuroforge"
    environment: str = os.getenv("ENVIRONMENT", "dev")
    version: str = os.getenv("SERVICE_VERSION", "0.0.1")
    hostname: str = socket.gethostname()
    console: ConsoleHandlerOptions = field(default_factory=ConsoleHandlerOptions)
    file: Optional[FileHandlerOptions] = None
    syslog: SyslogHandlerOptions = field(default_factory=SyslogHandlerOptions)
    sampling: SamplingConfig = field(default_factory=SamplingConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    ratelimit: RateLimitConfig = field(default_factory=RateLimitConfig)
    redact: RedactConfig = field(default_factory=RedactConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    capture_warnings: bool = True
    propagate: bool = False  # root propagate

# ---------------------------
# Utilities
# ---------------------------

_LEVELS = {
    "NOTSET": logging.NOTSET,
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

def _as_level(level: str | int) -> int:
    if isinstance(level, int):
        return level
    return _LEVELS.get(level.upper(), logging.INFO)

def _now_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()

def _safe_json_default(obj: Any) -> Any:
    try:
        return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else str(obj)
    except Exception:
        return repr(obj)

def _coalesce(*vals):
    for v in vals:
        if v is not None:
            return v
    return None

# ---------------------------
# Formatters
# ---------------------------

class JSONFormatter(logging.Formatter):
    def __init__(self, service: str, environment: str, version: str, hostname: str) -> None:
        super().__init__()
        self.service = service
        self.environment = environment
        self.version = version
        self.hostname = hostname

    def format(self, record: logging.LogRecord) -> str:
        trace_id = getattr(record, "trace_id", None)
        span_id = getattr(record, "span_id", None)

        payload: Dict[str, Any] = {
            "ts": _now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "env": self.environment,
            "version": self.version,
            "host": self.hostname,
            "pid": os.getpid(),
            "thread": record.threadName,
            "source": f"{record.module}:{record.funcName}:{record.lineno}",
            "correlation_id": getattr(record, "correlation_id", None),
            "request_id": getattr(record, "request_id", None),
            "user_id": getattr(record, "user_id", None),
            "session_id": getattr(record, "session_id", None),
            "tenant": getattr(record, "tenant", None),
            "trace_id": trace_id,
            "span_id": span_id,
        }

        # Merge arbitrary extras if present
        extras = getattr(record, "extras", None)
        if isinstance(extras, Mapping):
            payload.update(extras)

        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["exc_message"] = str(record.exc_info[1]) if record.exc_info[1] else None
            payload["stack"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=_safe_json_default, ensure_ascii=False)

class ColorFormatter(logging.Formatter):
    _LEVEL_COLORS = {
        logging.DEBUG: "\033[37m",    # white
        logging.INFO: "\033[36m",     # cyan
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",    # red
        logging.CRITICAL: "\033[41m", # red bg
    }
    _RESET = "\033[0m"

    def __init__(self, pattern: str, use_color: bool = True) -> None:
        super().__init__(pattern)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        if not self.use_color:
            return base
        color = self._LEVEL_COLORS.get(record.levelno, "")
        reset = self._RESET if color else ""
        return f"{color}{base}{reset}"

# ---------------------------
# Filters
# ---------------------------

class ContextFilter(logging.Filter):
    """Injects contextvars and OTel trace/span into records."""
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _ctx_correlation_id.get()
        record.request_id = _ctx_request_id.get()
        record.user_id = _ctx_user_id.get()
        record.session_id = _ctx_session_id.get()
        record.tenant = _ctx_tenant.get()

        # Merge context extras
        extras = _ctx_extra.get() or {}
        if getattr(record, "extras", None):
            try:
                merged = dict(extras)
                merged.update(record.extras)  # record extras override context extras
                record.extras = merged
            except Exception:
                record.extras = extras
        else:
            record.extras = extras

        # Try to add otel
        trace_id, span_id = _get_otel_context()
        if trace_id:
            record.trace_id = trace_id
            record.span_id = span_id
        return True

class RedactFilter(logging.Filter):
    def __init__(self, cfg: RedactConfig) -> None:
        super().__init__()
        patterns: List[str] = []
        if cfg.email:
            patterns.append(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        if cfg.phone:
            patterns.append(r"(?:\+?\d[\s\-()]*){7,}\d")
        if cfg.card:
            patterns.append(r"\b(?:\d[ -]*?){13,19}\b")
        if cfg.secrets:
            # Basic token/secret patterns
            patterns.extend([
                r"(?i)api[_-]?key\s*[:=]\s*[\w\-]{16,}",
                r"(?i)secret\s*[:=]\s*[\w\-]{8,}",
                r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
                r"(?i)token\s*[:=]\s*[A-Za-z0-9\-\._~\+\/]+=*",
            ])
        patterns.extend(cfg.custom_patterns or [])
        self._regexes = [re.compile(p) for p in patterns]
        self._replacement = cfg.replacement

    def _redact_text(self, text: str) -> str:
        for rx in self._regexes:
            text = rx.sub(self._replacement, text)
        return text

    def _redact_mapping(self, obj: MutableMapping[str, Any]) -> None:
        for k, v in list(obj.items()):
            if isinstance(v, str):
                obj[k] = self._redact_text(v)
            elif isinstance(v, Mapping):
                v = dict(v)
                self._redact_mapping(v)  # type: ignore
                obj[k] = v
            elif isinstance(v, list):
                obj[k] = [self._redact_text(x) if isinstance(x, str) else x for x in v]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self._redact_text(record.msg)
            if record.args and isinstance(record.args, tuple):
                # Convert args to redacted strings (safest)
                record.args = tuple(self._redact_text(str(a)) for a in record.args)

            extras = getattr(record, "extras", None)
            if isinstance(extras, MutableMapping):
                self._redact_mapping(extras)
        except Exception:
            # Never break logging on redaction errors
            pass
        return True

class SamplingFilter(logging.Filter):
    def __init__(self, cfg: SamplingConfig) -> None:
        super().__init__()
        self.prob = {k.upper(): float(v) for k, v in (cfg.per_level_probability or {}).items()}

    def filter(self, record: logging.LogRecord) -> bool:
        p = self.prob.get(record.levelname, 1.0)
        if p >= 1.0:
            return True
        return random.random() < p

class DedupFilter(logging.Filter):
    def __init__(self, cfg: DedupConfig) -> None:
        super().__init__()
        self.window = float(cfg.window_seconds)
        self.max_keys = int(cfg.max_keys)
        self._lock = threading.Lock()
        self._last_seen: Dict[str, float] = {}

    def _key(self, record: logging.LogRecord) -> str:
        base = f"{record.levelno}|{record.name}|{record.getMessage()}"
        # Include key context fields for better uniqueness
        cid = getattr(record, "correlation_id", "")
        rid = getattr(record, "request_id", "")
        return f"{base}|{cid}|{rid}"

    def filter(self, record: logging.LogRecord) -> bool:
        key = self._key(record)
        now = time.monotonic()
        with self._lock:
            last = self._last_seen.get(key)
            allow = (last is None) or (now - last > self.window)
            if allow:
                self._last_seen[key] = now
                # Evict if map too large
                if len(self._last_seen) > self.max_keys:
                    # Drop oldest ~10%
                    by_time = sorted(self._last_seen.items(), key=lambda kv: kv[1])
                    for k, _ in by_time[: max(1, self.max_keys // 10)]:
                        self._last_seen.pop(k, None)
        return allow

class RateLimitFilter(logging.Filter):
    """Token-bucket per message key to limit bursts."""
    def __init__(self, cfg: RateLimitConfig) -> None:
        super().__init__()
        self.capacity = int(cfg.capacity)
        self.refill = float(cfg.refill_per_sec)
        self.max_keys = int(cfg.max_keys)
        self._lock = threading.Lock()
        self._tokens: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def _key(self, record: logging.LogRecord) -> str:
        base = f"{record.levelno}|{record.name}|{record.getMessage()}"
        return base

    def filter(self, record: logging.LogRecord) -> bool:
        key = self._key(record)
        now = time.monotonic()
        with self._lock:
            tokens, last = self._tokens.get(key, (self.capacity, now))
            # Refill
            tokens = min(self.capacity, tokens + self.refill * (now - last))
            allow = tokens >= 1.0
            tokens = tokens - 1.0 if allow else tokens
            self._tokens[key] = (tokens, now)
            # Evict if too many keys
            if len(self._tokens) > self.max_keys:
                by_tokens = sorted(self._tokens.items(), key=lambda kv: kv[1][0])
                for k, _ in by_tokens[: max(1, self.max_keys // 10)]:
                    self._tokens.pop(k, None)
        return allow

# ---------------------------
# Handlers
# ---------------------------

class GZipRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler that gzips old logs."""
    def doRollover(self) -> None:
        super().doRollover()
        try:
            # Compress the most recent backup (e.g., .1) if present
            dfn = f"{self.baseFilename}.1"
            if os.path.exists(dfn) and not os.path.exists(dfn + ".gz"):
                with open(dfn, "rb") as f_in, gzip.open(dfn + ".gz", "wb") as f_out:
                    while True:
                        chunk = f_in.read(1024 * 1024)
                        if not chunk:
                            break
                        f_out.write(chunk)
                os.remove(dfn)
        except Exception:
            # Never break logging due to compression issues
            pass

def _make_console_handler(cfg: LoggingConfig) -> Optional[logging.Handler]:
    if not cfg.console.enable:
        return None
    stream = sys.stdout if cfg.console.stream.lower() == "stdout" else sys.stderr
    h = logging.StreamHandler(stream=stream)
    if cfg.console.json or cfg.json:
        h.setFormatter(JSONFormatter(cfg.service, cfg.environment, cfg.version, cfg.hostname))
    else:
        pattern = "[%(asctime)s] %(levelname)s %(name)s | %(message)s (%(module)s:%(lineno)d) [cid=%(correlation_id)s rid=%(request_id)s]"
        h.setFormatter(ColorFormatter(pattern, use_color=cfg.console.use_color))
    return h

def _make_file_handler(file_opts: FileHandlerOptions, json_mode: bool, meta: Tuple[str, str, str, str]) -> logging.Handler:
    service, env, ver, host = meta
    h = GZipRotatingFileHandler(
        filename=file_opts.path,
        mode="a",
        maxBytes=file_opts.max_bytes,
        backupCount=file_opts.backup_count,
        encoding=file_opts.encoding,
        delay=file_opts.delay,
    )
    if json_mode:
        h.setFormatter(JSONFormatter(service, env, ver, host))
    else:
        fmt = "[%(asctime)s] %(levelname)s %(name)s | %(message)s [%(module)s:%(lineno)d]"
        h.setFormatter(logging.Formatter(fmt))
    return h

def _make_syslog_handler(cfg: SyslogHandlerOptions, json_mode: bool, meta: Tuple[str, str, str, str]) -> Optional[logging.Handler]:
    if not cfg.enable:
        return None
    service, env, ver, host = meta
    h = logging.handlers.SysLogHandler(address=cfg.address, facility=cfg.facility, socktype=cfg.socktype)
    if json_mode:
        h.setFormatter(JSONFormatter(service, env, ver, host))
    else:
        h.setFormatter(logging.Formatter("%(name)s: %(levelname)s %(message)s"))
    return h

# ---------------------------
# Public API
# ---------------------------

_INIT_LOCK = threading.Lock()
_INITIALIZED = False

def init_logging(cfg: LoggingConfig) -> None:
    """Initialize root and audit loggers according to provided config."""
    global _INITIALIZED
    with _INIT_LOCK:
        root = logging.getLogger()
        # Clear existing handlers on re-init
        for h in list(root.handlers):
            root.removeHandler(h)

        level = _as_level(cfg.level)
        root.setLevel(level)
        root.propagate = cfg.propagate

        meta = (cfg.service, cfg.environment, cfg.version, cfg.hostname)

        handlers: List[logging.Handler] = []
        ch = _make_console_handler(cfg)
        if ch:
            handlers.append(ch)
        if cfg.file:
            handlers.append(_make_file_handler(cfg.file, cfg.json, meta))
        sh = _make_syslog_handler(cfg.syslog, cfg.json, meta)
        if sh:
            handlers.append(sh)

        # Filters applied to all handlers
        ctx_filter = ContextFilter()
        redact_filter = RedactFilter(cfg.redact)
        samp_filter = SamplingFilter(cfg.sampling)
        dedup_filter = DedupFilter(cfg.dedup)
        rl_filter = RateLimitFilter(cfg.ratelimit)

        for h in handlers:
            h.addFilter(ctx_filter)
            h.addFilter(redact_filter)
            h.addFilter(samp_filter)
            h.addFilter(dedup_filter)
            h.addFilter(rl_filter)
            root.addHandler(h)

        if cfg.capture_warnings:
            logging.captureWarnings(True)

        # Configure audit logger
        if cfg.audit.enabled:
            audit_logger = logging.getLogger(cfg.audit.logger_name)
            audit_logger.setLevel(_as_level(cfg.audit.level))
            audit_logger.propagate = False
            for h in list(audit_logger.handlers):
                audit_logger.removeHandler(h)
            # default to same sinks as root
            if cfg.audit.file:
                ah = _make_file_handler(cfg.audit.file, True, meta)
                ah.addFilter(ctx_filter)
                ah.addFilter(redact_filter)  # redact audit too (policy-dependent)
                audit_logger.addHandler(ah)
            else:
                # inherit root handlers by duplicating references for isolation
                for h in handlers:
                    audit_logger.addHandler(h)

        _INITIALIZED = True

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

def update_level(logger_name: str, level: str | int) -> None:
    """Dynamically update logger level at runtime."""
    logging.getLogger(logger_name).setLevel(_as_level(level))

def add_file_sink(path: str, level: str | int = "INFO", json_mode: bool = True, max_bytes: int = 50*1024*1024, backup_count: int = 10, compress: bool = True) -> logging.Handler:
    """Attach additional rotating file sink to root."""
    service = os.getenv("SERVICE_NAME", "neuroforge")
    env = os.getenv("ENVIRONMENT", "dev")
    ver = os.getenv("SERVICE_VERSION", "0.0.1")
    host = socket.gethostname()

    h = GZipRotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8", delay=True)
    if json_mode:
        h.setFormatter(JSONFormatter(service, env, ver, host))
    else:
        h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s | %(message)s"))
    h.setLevel(_as_level(level))

    # Reuse common filters for new sink
    h.addFilter(ContextFilter())
    h.addFilter(RedactFilter(RedactConfig()))
    h.addFilter(SamplingFilter(SamplingConfig()))
    h.addFilter(DedupFilter(DedupConfig()))
    h.addFilter(RateLimitFilter(RateLimitConfig()))

    logging.getLogger().addHandler(h)
    return h

# ---------------------------
# Context management API
# ---------------------------

@dataclass
class _ContextTokenBundle:
    correlation: contextvars.Token
    request: contextvars.Token
    user: contextvars.Token
    session: contextvars.Token
    tenant: contextvars.Token
    extras: contextvars.Token

class with_context:
    """Context manager to bind contextvars during a scope."""
    def __init__(self, *,
                 correlation_id: Optional[str] = None,
                 request_id: Optional[str] = None,
                 user_id: Optional[str] = None,
                 session_id: Optional[str] = None,
                 tenant: Optional[str] = None,
                 **extras: Any) -> None:
        self.values = {
            "correlation_id": correlation_id,
            "request_id": request_id,
            "user_id": user_id,
            "session_id": session_id,
            "tenant": tenant,
        }
        self.extras = extras
        self._tokens: Optional[_ContextTokenBundle] = None

    def __enter__(self):
        tok_corr = _ctx_correlation_id.set(_coalesce(self.values["correlation_id"], _ctx_correlation_id.get()))
        tok_req  = _ctx_request_id.set(_coalesce(self.values["request_id"], _ctx_request_id.get()))
        tok_user = _ctx_user_id.set(_coalesce(self.values["user_id"], _ctx_user_id.get()))
        tok_sess = _ctx_session_id.set(_coalesce(self.values["session_id"], _ctx_session_id.get()))
        tok_ten  = _ctx_tenant.set(_coalesce(self.values["tenant"], _ctx_tenant.get()))
        base_extras = dict(_ctx_extra.get() or {})
        base_extras.update(self.extras or {})
        tok_extra = _ctx_extra.set(base_extras)
        self._tokens = _ContextTokenBundle(tok_corr, tok_req, tok_user, tok_sess, tok_ten, tok_extra)
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self._tokens:
            return False
        _ctx_correlation_id.reset(self._tokens.correlation)
        _ctx_request_id.reset(self._tokens.request)
        _ctx_user_id.reset(self._tokens.user)
        _ctx_session_id.reset(self._tokens.session)
        _ctx_tenant.reset(self._tokens.tenant)
        _ctx_extra.reset(self._tokens.extras)
        return False

def bind_context(**extras: Any) -> None:
    base = dict(_ctx_extra.get() or {})
    base.update(extras)
    _ctx_extra.set(base)

def clear_context(keys: Optional[Iterable[str]] = None) -> None:
    if keys is None:
        _ctx_correlation_id.set(None)
        _ctx_request_id.set(None)
        _ctx_user_id.set(None)
        _ctx_session_id.set(None)
        _ctx_tenant.set(None)
        _ctx_extra.set({})
        return
    base = dict(_ctx_extra.get() or {})
    for k in keys:
        base.pop(k, None)
    _ctx_extra.set(base)

# ---------------------------
# Convenience helpers
# ---------------------------

_once_lock = threading.Lock()
_once_keys: set[str] = set()

def log_once(logger: logging.Logger, key: str, level: str | int, msg: str, *args: Any, **kwargs: Any) -> bool:
    """Log a message only once per process lifetime under given key."""
    global _once_keys
    with _once_lock:
        if key in _once_keys:
            return False
        _once_keys.add(key)
    logger.log(_as_level(level), msg, *args, **kwargs)
    return True

def audit_logger() -> logging.Logger:
    return logging.getLogger("neuroforge.audit")

def log_exception(logger: logging.Logger, msg: str, *, extras: Optional[Dict[str, Any]] = None) -> None:
    logger.error(msg, exc_info=True, extra={"extras": extras or {}})

# ---------------------------
# Default bootstrap (optional)
# ---------------------------

def bootstrap_default_if_needed() -> None:
    """Idempotent bootstrap with sane defaults when init_logging wasn't called."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    cfg = LoggingConfig()
    init_logging(cfg)

# Ensure minimal logging if module is imported without explicit init
bootstrap_default_if_needed()
