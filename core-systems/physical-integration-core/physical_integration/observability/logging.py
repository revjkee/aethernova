# physical_integration/observability/logging.py
# Python 3.10+
from __future__ import annotations

import contextlib
import io
import logging
import logging.handlers
import os
import random
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import FrameType
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple

# Fast JSON if present
try:
    import orjson as _json  # type: ignore
    def _dumps(obj: Any) -> bytes:
        return _json.dumps(obj, option=_json.OPT_APPEND_NEWLINE | _json.OPT_UTC_Z)
except Exception:  # pragma: no cover
    import json as _json  # type: ignore
    def _dumps(obj: Any) -> bytes:
        return (_json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")

# Optional OpenTelemetry trace extraction
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False

# -------------------------
# Context variables
# -------------------------
import contextvars

tenant_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant_id", default=None)
request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
correlation_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)
user_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_id", default=None)
extra_ctx_var: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("extra_ctx", default={})

def set_context(
    *,
    tenant_id: Optional[str] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    **extra: Any,
) -> None:
    if tenant_id is not None:
        tenant_id_var.set(tenant_id)
    if request_id is not None:
        request_id_var.set(request_id)
    if correlation_id is not None:
        correlation_id_var.set(correlation_id)
    if user_id is not None:
        user_id_var.set(user_id)
    if extra:
        merged = dict(extra_ctx_var.get())
        merged.update(extra)
        extra_ctx_var.set(merged)

@contextlib.contextmanager
def logging_context(**kwargs: Any):
    """
    Временное добавление ключей контекста в рамках блока.
    """
    token = extra_ctx_var.set({**extra_ctx_var.get(), **kwargs})
    try:
        yield
    finally:
        extra_ctx_var.reset(token)

def clear_context() -> None:
    tenant_id_var.set(None)
    request_id_var.set(None)
    correlation_id_var.set(None)
    user_id_var.set(None)
    extra_ctx_var.set({})

# -------------------------
# Secret redaction
# -------------------------

_SECRET_KEYS = re.compile(r"(password|passwd|secret|token|authorization|api[_-]?key|session|cookie|set-cookie)", re.I)
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"([A-Za-z0-9_\-]{16,})"),
)

def _redact_value(v: Any) -> Any:
    s = str(v)
    if len(s) <= 8:
        return "***"
    return s[:2] + "***" + s[-2:]

def _scrub(obj: Any) -> Any:
    """
    Рекурсивная замена секретов в dict/list/строках.
    """
    try:
        if isinstance(obj, Mapping):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                if _SECRET_KEYS.search(str(k)):
                    out[k] = "***"
                else:
                    out[k] = _scrub(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [ _scrub(x) for x in obj ]
        if isinstance(obj, str):
            s = obj
            for pat in _SECRET_VALUE_PATTERNS:
                if pat.search(s):
                    s = pat.sub("***", s)
            return s
        return obj
    except Exception:
        return "***"

# -------------------------
# Sampling / Rate limiting
# -------------------------

@dataclass
class LogSampler:
    """
    Вероятностный семплинг + токен-бакет дросселирование (глобально на процесс).
    """
    sample_rate: float = 1.0              # 0..1
    rate_limit_per_sec: int = 0           # 0 = off
    _tokens: float = field(default=0.0, init=False)
    _last: float = field(default_factory=time.monotonic, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def allow(self) -> bool:
        # Probabilistic sampling
        if self.sample_rate < 1.0 and random.random() > max(0.0, min(1.0, self.sample_rate)):
            return False
        # Token bucket
        if self.rate_limit_per_sec <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.rate_limit_per_sec, self._tokens + elapsed * self.rate_limit_per_sec)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

# -------------------------
# JSON Formatter
# -------------------------

class JSONFormatter(logging.Formatter):
    """
    Структурированный JSON-форматтер с:
      - UTC ISO8601 timestamp
      - уровнем, логгером, сообщением, PID, хостом
      - контекстом (tenant_id, request_id, correlation_id, user_id)
      - trace_id/span_id (OpenTelemetry, если доступен)
      - произвольным extra
      - редактированием секретов
    """

    def __init__(
        self,
        service: str,
        env: str,
        *,
        version: str = "1",
        scrub_secrets: bool = True,
        include_caller: bool = False,
        sampler: Optional[LogSampler] = None,
    ) -> None:
        super().__init__()
        self.service = service
        self.env = env
        self.version = version
        self.scrub = scrub_secrets
        self.include_caller = include_caller
        self.sampler = sampler or LogSampler()
        self.hostname = socket.gethostname()
        self.pid = os.getpid()

    def usesTime(self) -> bool:  # noqa: N802
        return True

    def format(self, record: logging.LogRecord) -> str:
        # sampling/ratelimit
        if not self.sampler.allow():
            return ""  # empty -> handler should skip

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        # message and extras
        msg = record.getMessage()
        base: Dict[str, Any] = {
            "ts": ts,
            "severity": record.levelname,
            "logger": record.name,
            "service": self.service,
            "env": self.env,
            "version": self.version,
            "message": msg,
            "pid": self.pid,
            "host": self.hostname,
            "thread": record.threadName,
        }

        # caller
        if self.include_caller and record.funcName and record.pathname:
            base["caller"] = f"{record.pathname}:{record.lineno} {record.funcName}()"

        # contextvars
        ctx: Dict[str, Any] = {}
        if tenant_id_var.get():
            ctx["tenant_id"] = tenant_id_var.get()
        if request_id_var.get():
            ctx["request_id"] = request_id_var.get()
        if correlation_id_var.get():
            ctx["correlation_id"] = correlation_id_var.get()
        if user_id_var.get():
            ctx["user_id"] = user_id_var.get()
        if extra_ctx_var.get():
            ctx.update(extra_ctx_var.get())

        # OpenTelemetry trace/span
        if _OTEL:
            try:
                span = _otel_trace.get_current_span()
                span_ctx = span.get_span_context()
                if span_ctx and span_ctx.is_valid:
                    base["trace_id"] = f"{span_ctx.trace_id:032x}"
                    base["span_id"] = f"{span_ctx.span_id:016x}"
            except Exception:
                pass

        # record extras (filter std attributes)
        std = set(vars(logging.makeLogRecord({})).keys()) | {"ctx", "extra"}
        extra = {k: v for k, v in record.__dict__.items() if k not in std}

        payload = base
        if ctx:
            payload["ctx"] = ctx
        if extra:
            payload["extra"] = extra

        # exception
        if record.exc_info:
            payload["exception"] = self._format_exception(record.exc_info)

        if self.scrub:
            payload = _scrub(payload)

        try:
            return _dumps(payload).decode("utf-8")
        except Exception:
            # fallback to safe string
            safe = {
                "ts": ts,
                "severity": record.levelname,
                "logger": record.name,
                "service": self.service,
                "env": self.env,
                "message": "Failed to serialize log record",
            }
            return _dumps(safe).decode("utf-8")

    @staticmethod
    def _format_exception(exc_info: Tuple[type[BaseException], BaseException, Optional[FrameType]]) -> Dict[str, Any]:
        sio = io.StringIO()
        logging.Formatter().formatException(exc_info)  # pre-cache formats
        exc_type, exc, tb = exc_info
        return {
            "type": getattr(exc_type, "__name__", "Exception"),
            "message": str(exc),
        }

# -------------------------
# Configurator
# -------------------------

@dataclass
class LoggingConfig:
    service: str = "physical-integration-core"
    env: str = os.getenv("ENV", "dev")
    level: str = os.getenv("LOG_LEVEL", "INFO")
    json_output: bool = True
    include_caller: bool = False
    scrub_secrets: bool = True
    sample_rate: float = float(os.getenv("LOG_SAMPLE_RATE", "1.0"))
    rate_limit_per_sec: int = int(os.getenv("LOG_RATE_LIMIT", "0"))
    # file rotation
    log_file: Optional[str] = os.getenv("LOG_FILE", None)
    rotate_when: str = "D"          # 'S','M','H','D','W0'-'W6','midnight'
    rotate_interval: int = 1
    rotate_backup: int = 7
    utf8: bool = True
    # propagate to uvicorn/std libgers
    patch_uvicorn: bool = True

_LEVEL_MAP = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}

def configure_logging(cfg: LoggingConfig) -> logging.Logger:
    """
    Инициализирует корневой логгер. Повторные вызовы очищают хендлеры и перенастраивают.
    """
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    level = _LEVEL_MAP.get(str(cfg.level).upper(), logging.INFO)
    root.setLevel(level)

    formatter: logging.Formatter
    if cfg.json_output:
        formatter = JSONFormatter(
            service=cfg.service,
            env=cffg_env := cfg.env,
            scrub_secrets=cfg.scrub_secrets,
            include_caller=cfg.include_caller,
            sampler=LogSampler(sample_rate=cfg.sample_rate, rate_limit_per_sec=cfg.rate_limit_per_sec),
        )
    else:
        fmt = "%(asctime)sZ %(levelname)s %(name)s %(message)s"
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S")

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # Optional file rotation
    if cfg.log_file:
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=cfg.log_file,
            when=cfg.rotate_when,
            interval=cfg.rotate_interval,
            backupCount=cfg.rotate_backup,
            encoding="utf-8" if cfg.utf8 else None,
            utc=True,
            delay=True,
        )
        fh.setLevel(level)
        fh.setFormatter(formatter)
        root.addHandler(fh)

    # Silence overly chatty loggers if needed
    for noisy in ("asyncio", "botocore", "urllib3"):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))

    # Patch uvicorn loggers to use same handlers/formatter
    if cfg.patch_uvicorn:
        _patch_uvicorn(root.handlers, level, formatter)

    return logging.getLogger(cfg.service)

def _patch_uvicorn(handlers: Iterable[logging.Handler], level: int, formatter: logging.Formatter) -> None:
    """
    Настраивает uvicorn/uvicorn.access/uvicorn.error на те же хендлеры/форматтер.
    """
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        for h in list(lg.handlers):
            lg.removeHandler(h)
        for h in handlers:
            clone = _clone_handler(h, formatter)
            lg.addHandler(clone)
        lg.propagate = False

def _clone_handler(h: logging.Handler, fmt: logging.Formatter) -> logging.Handler:
    if isinstance(h, logging.StreamHandler):
        nh = logging.StreamHandler(stream=h.stream)
    elif isinstance(h, logging.handlers.TimedRotatingFileHandler):
        nh = logging.handlers.TimedRotatingFileHandler(
            filename=h.baseFilename, when=h.when, interval=h.interval, backupCount=h.backupCount, utc=True, delay=True
        )
    else:
        nh = logging.StreamHandler(sys.stdout)
    nh.setLevel(h.level)
    nh.setFormatter(fmt)
    return nh

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "app")

# -------------------------
# ASGI middleware for HTTP access logs
# -------------------------

class AccessLogMiddleware:
    """
    Легковесный ASGI-middleware для access-логов в JSON с таймингом.
    Интегрируется в FastAPI/Starlette: app.add_middleware(AccessLogMiddleware)
    """
    def __init__(self, app, *, logger: Optional[logging.Logger] = None) -> None:
        self.app = app
        self.log = logger or logging.getLogger("http.access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method")
        path = scope.get("path")
        client = scope.get("client")
        client_ip = client[0] if client else None
        hdrs = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        req_id = hdrs.get("x-request-id") or hdrs.get("x-correlation-id")
        ua = hdrs.get("user-agent")

        if req_id:
            request_id_var.set(req_id)

        start = time.perf_counter()
        status_code_holder = {"code": 0}
        bytes_sent = {"n": 0}

        async def send_wrapper(event):
            if event["type"] == "http.response.start":
                status_code_holder["code"] = event.get("status", 0)
                headers = event.get("headers", [])
                for k, v in headers:
                    if k.decode().lower() == "content-length":
                        with contextlib.suppress(Exception):
                            bytes_sent["n"] = int(v.decode())
            return await send(event)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            dur_ms = int((time.perf_counter() - start) * 1000)
            self.log.info(
                "http_request",
                extra={
                    "method": method,
                    "path": path,
                    "status": status_code_holder["code"],
                    "duration_ms": dur_ms,
                    "client_ip": client_ip,
                    "user_agent": ua,
                    "bytes_sent": bytes_sent["n"],
                },
            )

# -------------------------
# Convenience helpers
# -------------------------

def set_level_from_env(default: str = "INFO") -> None:
    lvl = os.getenv("LOG_LEVEL", default).upper()
    logging.getLogger().setLevel(_LEVEL_MAP.get(lvl, logging.INFO))

def bind(**kwargs: Any) -> contextlib.AbstractContextManager:
    """
    Удобный алиас для временного добавления ключей в контекст логов.
    """
    return logging_context(**kwargs)

# -------------------------
# Example:
# -------------------------
# if __name__ == "__main__":
#     log = configure_logging(LoggingConfig(service="pic-api", env="prod", log_file="/var/log/pic-api.json"))
#     set_context(tenant_id="t-123", request_id="r-abc")
#     log.info("service started", extra={"port": 8080})
#     with bind(job="sync"):
#         log.warning("working", extra={"progress": 0.3})
#     try:
#         1 / 0
#     except Exception:
#         log.exception("boom")
