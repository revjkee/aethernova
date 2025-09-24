# file: oblivionvault/observability/logging.py
"""
Industrial-grade logging for oblivionvault-core.

Key features (stdlib-only):
- JSON logs with safe redaction of secrets
- Context propagation via contextvars (request_id, correlation_id, user_id, tenant, extras)
- OpenTelemetry integration (trace_id, span_id) if OTel is present
- Multiprocess/multithread safety with QueueHandler/QueueListener
- File rotation, console, optional syslog
- Sampling and rate-limit filters, warnings capture
- Unified exception hooks for sys.excepthook and asyncio loop
- Uvicorn/FastAPI hook helpers (access/error log alignment)

Intended usage:
    from oblivionvault.observability.logging import (
        LogConfig, init_logging, get_logger, set_context, clear_context
    )

    cfg = LogConfig(service="oblivionvault", env="prod", to_console=True, to_file=True)
    init_logging(cfg)
    log = get_logger(__name__)
    set_context(request_id="...", user_id="...")
    log.info("artifact indexed", extra={"artifact_id": "a1"})
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import datetime as _dt
import io
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
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# ---- Optional OpenTelemetry (no hard dependency) ----
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAS_OTEL = True
except Exception:
    _HAS_OTEL = False
    _otel_trace = None  # type: ignore


# ---- Context vars ----
_ctx_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_ctx_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")
_ctx_user_id: contextvars.ContextVar[str] = contextvars.ContextVar("user_id", default="")
_ctx_tenant: contextvars.ContextVar[str] = contextvars.ContextVar("tenant", default="")
_ctx_extras: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("extras", default={})


# ---- Redaction ----
_DEFAULT_REDACT_KEYS = {
    "password", "pass", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "cookie", "set-cookie", "x-api-key",
    "private_key", "client_secret", "refresh_token", "access_token"
}
_REDACTION_MASK = "***"

def _redact_obj(obj: Any, redact_keys: Sequence[str]) -> Any:
    try:
        keys_low = {k.lower() for k in redact_keys}
        if isinstance(obj, Mapping):
            return {k: (_REDACTION_MASK if str(k).lower() in keys_low else _redact_obj(v, redact_keys))
                    for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            t = type(obj)
            return t(_redact_obj(v, redact_keys) for v in obj)
        if isinstance(obj, str):
            # redact inline if looks like token/secret patterns
            patterns = [
                r"(?:Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*",
                r"(?i)(?:token|secret|apikey|api_key|password)\s*[:=]\s*[A-Za-z0-9\-\._~\+\/]+=*",
                r"(?i)[A-F0-9]{32,64}"
            ]
            s = obj
            for p in patterns:
                s = re.sub(p, _REDACTION_MASK, s)
            return s
        return obj
    except Exception:
        # Fallback: avoid breaking logging
        return _REDACTION_MASK


# ---- JSON Formatter ----
class JsonFormatter(logging.Formatter):
    def __init__(self, *, service: str, env: str, redact_keys: Sequence[str], ts_key: str = "ts"):
        super().__init__()
        self.service = service
        self.env = env
        self.redact_keys = list(redact_keys)
        self.ts_key = ts_key

    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            self.ts_key: _utc_iso(),
            "message": record.getMessage(),
            "service": self.service,
            "env": self.env,
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        # Context
        req_id = _ctx_request_id.get()
        if not req_id:
            req_id = _generate_request_id()
            _ctx_request_id.set(req_id)
        data["request_id"] = req_id
        corr_id = _ctx_correlation_id.get()
        if corr_id:
            data["correlation_id"] = corr_id
        user_id = _ctx_user_id.get()
        if user_id:
            data["user_id"] = user_id
        tenant = _ctx_tenant.get()
        if tenant:
            data["tenant"] = tenant

        # Extras from context and record.extra
        extras = {}
        try:
            extras.update(_ctx_extras.get())
        except Exception:
            pass
        # Pick up dict-like "extra" from the record if present
        for attr in ("extra",):
            v = getattr(record, attr, None)
            if isinstance(v, Mapping):
                extras.update(v)

        # OpenTelemetry span context
        if _HAS_OTEL:
            try:
                span = _otel_trace.get_current_span()
                sc = span.get_span_context()
                if sc and sc.is_valid:
                    data["trace_id"] = _hex_otel_id(sc.trace_id, 32)
                    data["span_id"] = _hex_otel_id(sc.span_id, 16)
            except Exception:
                pass

        # Exception info
        if record.exc_info:
            data["exc_type"] = str(record.exc_info[0].__name__ if record.exc_info[0] else "")
            data["exc"] = self.formatException(record.exc_info)

        # Merge extras
        if extras:
            data.update(extras)

        # Redact
        safe = _redact_obj(data, self.redact_keys)

        # Ensure JSON serialization
        try:
            return json.dumps(safe, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            # As last resort, stringify fields
            safe_str = {k: _safe_str(v) for k, v in safe.items()}
            return json.dumps(safe_str, separators=(",", ":"), ensure_ascii=False)

    def formatException(self, ei) -> str:  # noqa: N802
        tb = "".join(traceback.format_exception(*ei))
        return _redact_obj(tb, self.redact_keys)  # type: ignore


# ---- Filters ----
class SamplingFilter(logging.Filter):
    def __init__(self, sample_rate: float):
        super().__init__()
        self.sample_rate = max(0.0, min(1.0, sample_rate))

    def filter(self, record: logging.LogRecord) -> bool:  # True -> pass
        if self.sample_rate >= 1.0:
            return True
        # Do not sample warnings and above
        if record.levelno >= logging.WARNING:
            return True
        # Simple LCG-based sampler (seeded by record attributes)
        key = f"{record.name}:{record.lineno}:{record.getMessage()}"
        h = _stable_hash(key)
        return (h % 10_000) / 10_000.0 < self.sample_rate


class RateLimitFilter(logging.Filter):
    """
    Limits identical messages per window per logger.
    """
    def __init__(self, max_per_window: int = 20, window_seconds: int = 10):
        super().__init__()
        self.max_per_window = max(1, max_per_window)
        self.window_seconds = max(1, window_seconds)
        self._buckets: Dict[Tuple[str, str], Tuple[int, float]] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        key = (record.name, record.getMessage())
        now = time.monotonic()
        count, start = self._buckets.get(key, (0, now))
        if now - start > self.window_seconds:
            self._buckets[key] = (1, now)
            return True
        if count < self.max_per_window:
            self._buckets[key] = (count + 1, start)
            return True
        # Drop
        return False


# ---- Config ----
@dataclass
class LogConfig:
    service: str = "oblivionvault"
    env: str = os.getenv("APP_ENV", "dev")
    level: str = os.getenv("LOG_LEVEL", "INFO")
    to_console: bool = True
    to_file: bool = False
    file_path: str = "./logs/oblivionvault.log"
    file_rotate_bytes: int = 20 * 1024 * 1024
    file_backup_count: int = 5
    to_syslog: bool = False
    syslog_address: Optional[str] = None  # e.g. "/dev/log" or ("localhost", 514)
    queue_logging: bool = True
    capture_warnings: bool = True
    install_excepthook: bool = True
    asyncio_hook: bool = True
    sampling_rate: float = 1.0  # 0..1 for INFO/DEBUG
    rate_limit_per_window: int = 100
    rate_limit_window_sec: int = 5
    redact_keys: Sequence[str] = field(default_factory=lambda: tuple(sorted(_DEFAULT_REDACT_KEYS)))
    uvicorn_tune: bool = True  # align uvicorn loggers with our pipeline


# ---- Public API ----
_listener: Optional[logging.handlers.QueueListener] = None
_queue: Optional[queue.Queue] = None
_initialized: bool = False

def init_logging(cfg: LogConfig) -> None:
    """
    Initialize global logging pipeline.
    Safe to call multiple times; subsequent calls reset handlers.
    """
    global _listener, _queue, _initialized

    # Reset root logger
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    level = _level_from_str(cfg.level)
    root.setLevel(level)

    # Build formatter and filters
    formatter = JsonFormatter(service=cfg.service, env=cfg.env, redact_keys=cfg.redact_keys)
    filters: List[logging.Filter] = [
        SamplingFilter(cfg.sampling_rate),
        RateLimitFilter(cfg.rate_limit_per_window, cfg.rate_limit_window_sec),
    ]

    # Handlers
    handlers: List[logging.Handler] = []
    if cfg.to_console:
        ch = logging.StreamHandler(stream=sys.stdout)
        ch.setFormatter(formatter)
        _apply_filters(ch, filters)
        handlers.append(ch)

    if cfg.to_file:
        _ensure_dir(cfg.file_path)
        fh = logging.handlers.RotatingFileHandler(
            cfg.file_path, maxBytes=cfg.file_rotate_bytes, backupCount=cfg.file_backup_count, encoding="utf-8"
        )
        fh.setFormatter(formatter)
        _apply_filters(fh, filters)
        handlers.append(fh)

    if cfg.to_syslog:
        if cfg.syslog_address is None:
            address = "/dev/log" if os.name != "nt" else ("localhost", 514)
        else:
            address = cfg.syslog_address  # type: ignore[assignment]
        sh = logging.handlers.SysLogHandler(address=address)  # type: ignore[arg-type]
        sh.setFormatter(formatter)
        _apply_filters(sh, filters)
        handlers.append(sh)

    # Queue pipeline for safety in multiprocess/multithread envs
    if cfg.queue_logging:
        _queue = queue.Queue(-1)
        qh = logging.handlers.QueueHandler(_queue)
        root.addHandler(qh)
        # Listener delivers to real handlers
        _listener = logging.handlers.QueueListener(_queue, *handlers, respect_handler_level=False)
        _listener.start()
    else:
        for h in handlers:
            root.addHandler(h)

    # Standard library pollution control
    logging.captureWarnings(cfg.capture_warnings)

    # Exception hooks
    if cfg.install_excepthook:
        _install_excepthook()
    if cfg.asyncio_hook:
        _install_asyncio_exception_handler()

    # Align uvicorn access/error loggers to our pipeline (if present)
    if cfg.uvicorn_tune:
        _tune_uvicorn_loggers(level)

    _initialized = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name if name else "oblivionvault")


def set_context(
    *,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    tenant: Optional[str] = None,
    **extras: Any,
) -> None:
    """
    Set or update structured context for subsequent log records in current task.
    """
    if request_id is not None:
        _ctx_request_id.set(request_id)
    if correlation_id is not None:
        _ctx_correlation_id.set(correlation_id)
    if user_id is not None:
        _ctx_user_id.set(user_id)
    if tenant is not None:
        _ctx_tenant.set(tenant)
    if extras:
        d = dict(_ctx_extras.get())
        d.update(extras)
        _ctx_extras.set(d)


def clear_context() -> None:
    _ctx_request_id.set("")
    _ctx_correlation_id.set("")
    _ctx_user_id.set("")
    _ctx_tenant.set("")
    _ctx_extras.set({})


# ---- Helpers / internals ----
def _apply_filters(handler: logging.Handler, filters: Iterable[logging.Filter]) -> None:
    for f in filters:
        handler.addFilter(f)

def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def _level_from_str(level: str) -> int:
    try:
        return getattr(logging, level.upper())
    except Exception:
        return logging.INFO

def _utc_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()

def _safe_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:
        try:
            return repr(v)
        except Exception:
            return "<unprintable>"

def _generate_request_id() -> str:
    return uuid.uuid4().hex

def _stable_hash(s: str) -> int:
    # Deterministic 32-bit hash
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h

def _hex_otel_id(num: int, width: int) -> str:
    h = f"{num:0{width}x}"
    return h[-width:]


# ---- Exception hooks ----
def _install_excepthook() -> None:
    def _hook(exc_type, exc, tb):
        log = get_logger("oblivionvault.unhandled")
        log.error("unhandled exception", exc_info=(exc_type, exc, tb))
        # Default behavior
        sys.__excepthook__(exc_type, exc, tb)
    sys.excepthook = _hook  # type: ignore[assignment]


def _install_asyncio_exception_handler() -> None:
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        return

    def _handler(loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
        msg = context.get("message") or "asyncio exception"
        exc = context.get("exception")
        log = get_logger("oblivionvault.asyncio")
        if exc:
            log.error(msg, extra={"asyncio_context": _redact_obj(context, _DEFAULT_REDACT_KEYS)}, exc_info=exc)
        else:
            log.error(msg, extra={"asyncio_context": _redact_obj(context, _DEFAULT_REDACT_KEYS)})
        # Call default handler
        loop.default_exception_handler(context)

    try:
        loop.set_exception_handler(_handler)
    except Exception:
        pass


# ---- Uvicorn/FastAPI helpers (optional use) ----
def setup_uvicorn_logging(level: Optional[str] = None) -> None:
    """
    Align uvicorn loggers (access/error) with oblivionvault pipeline.
    Call after init_logging() if you're running FastAPI/Uvicorn directly.
    """
    target_level = _level_from_str(level or logging.getLogger().getEffectiveLevel() and logging.getLevelName(logging.getLogger().getEffectiveLevel()))  # type: ignore
    _tune_uvicorn_loggers(target_level)


def _tune_uvicorn_loggers(level: int) -> None:
    # Reuse root handlers; disable uvicorn's own formatters
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "gunicorn.error", "gunicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []  # delegate to root/queue
        lg.setLevel(level)
        lg.propagate = True


# ---- Simple test main ----
if __name__ == "__main__":
    cfg = LogConfig(
        service="oblivionvault",
        env=os.getenv("APP_ENV", "dev"),
        to_console=True,
        to_file=False,
        queue_logging=True,
        sampling_rate=1.0,
    )
    init_logging(cfg)
    log = get_logger("demo")
    set_context(user_id="u42", tenant="acme", correlation_id="corr-123")
    log.info("hello world", extra={"phase": "init"})
    try:
        1 / 0
    except ZeroDivisionError:
        log.exception("division error", extra={"operation": "demo"})
