# -*- coding: utf-8 -*-
"""
Mythos Core — Observability: Structured Logging

Возможности:
- JSON-логи с обязательными полями времени, уровня, сервиса, окружения, запроса и трассировки.
- Маскировка секретов по регулярным выражениям.
- Sampling на уровне логера.
- Контекст через contextvars: request_id, user_id, tenant_id, произвольные поля.
- Корреляция с OpenTelemetry: trace_id и span_id при наличии otel контекста.
- Неблокирующие обработчики: QueueHandler + QueueListener с graceful shutdown.
- Интеграция: ротация файлов, stdout/stderr, syslog.
- Uvicorn/FastAPI интеграция: единый формат access и error логов, middleware для request_id и метрик.
- Динамическая переконфигурация уровня и масок.

Внешние зависимости: только стандартная библиотека. OpenTelemetry опционально.
"""

from __future__ import annotations

import base64
import json
import logging
import logging.handlers
import os
import queue
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import FrameType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
import contextvars
import contextlib

# OpenTelemetry опционально
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAVE_OTEL = True
except Exception:  # pragma: no cover
    _HAVE_OTEL = False

# --------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------

_ctx_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_ctx_bind: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("bind", default={})

def get_request_id() -> str:
    return _ctx_request_id.get()

def set_request_id(req_id: str) -> None:
    _ctx_request_id.set(req_id)

@contextlib.contextmanager
def bind_context(**kwargs: Any):
    """
    Временная привязка дополнительных полей к текущему контексту логов.
    """
    current = dict(_ctx_bind.get())
    current.update({k: v for k, v in kwargs.items() if v is not None})
    token = _ctx_bind.set(current)
    try:
        yield
    finally:
        _ctx_bind.reset(token)

def update_context(**kwargs: Any) -> None:
    cur = dict(_ctx_bind.get())
    cur.update({k: v for k, v in kwargs.items() if v is not None})
    _ctx_bind.set(cur)

def clear_context(keys: Optional[Iterable[str]] = None) -> None:
    if not keys:
        _ctx_bind.set({})
        return
    cur = dict(_ctx_bind.get())
    for k in keys:
        cur.pop(k, None)
    _ctx_bind.set(cur)

# --------------------------------------------------------------------------------------
# ULID для request_id
# --------------------------------------------------------------------------------------

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def _ulid() -> str:
    """
    Генерация ULID 26 символов Crockford Base32.
    """
    ts_ms = int(time.time() * 1000)
    randomness = os.urandom(10)
    # 48 бит времени + 80 бит случайности = 128 бит
    val = (ts_ms << 80) | int.from_bytes(randomness, "big")
    chars = []
    for _ in range(26):
        chars.append(_ULID_ALPHABET[val & 0x1F])
        val >>= 5
    return "".join(reversed(chars))

# --------------------------------------------------------------------------------------
# Конфигурация
# --------------------------------------------------------------------------------------

@dataclass
class LoggingConfig:
    service: str = "mythos-core"
    environment: str = os.getenv("ENV", "prod")
    version: str = os.getenv("APP_VERSION", "")
    level: str = os.getenv("LOG_LEVEL", "INFO")
    json_output: bool = True
    include_caller: bool = False
    include_stack: bool = True
    add_trace_ids: bool = True
    redact_patterns: List[str] = field(default_factory=lambda: [
        r"\bAKIA[0-9A-Z]{16}\b",                     # AWS access key
        r"(?i)(api|secret|token|key)[=: ]{0,3}[A-Za-z0-9/\+=\-]{8,}",  # generic secrets
        r"(?i)password[=: ]{0,3}[^,\s]{3,}",
        r"\b(?:\d[ -]*?){13,19}\b"                   # naive card pattern
    ])
    sampling: float = 1.0                            # 0..1 вероятность записи события
    destination: str = os.getenv("LOG_DEST", "stdout")  # stdout|stderr|file|syslog
    file_path: str = os.getenv("LOG_FILE", "logs/mythos-core.log")
    rotate_max_bytes: int = 20 * 1024 * 1024
    rotate_backups: int = 10
    syslog_address: Tuple[str, int] = ("localhost", 514)
    queue_size: int = 10000
    uvicorn_integration: bool = True

# --------------------------------------------------------------------------------------
# Фильтры
# --------------------------------------------------------------------------------------

class RedactingFilter(logging.Filter):
    def __init__(self, patterns: List[str]) -> None:
        super().__init__()
        self._regexes = [re.compile(p) for p in patterns]

    def filter(self, record: logging.LogRecord) -> bool:
        # Маскируем строковые поля сообщения и аргументов
        msg = str(record.getMessage())
        for rx in self._regexes:
            msg = rx.sub("[REDACTED]", msg)
        record.msg = msg
        # Маскируем возможные extra поля
        for k, v in list(record.__dict__.items()):
            if isinstance(v, str):
                s = v
                for rx in self._regexes:
                    s = rx.sub("[REDACTED]", s)
                record.__dict__[k] = s
        return True

class SamplingFilter(logging.Filter):
    def __init__(self, p: float) -> None:
        super().__init__()
        self.p = max(0.0, min(1.0, p))

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.ERROR:
            return True
        if self.p >= 1.0:
            return True
        # простая вероятностная выборка
        b = os.urandom(2)
        rnd = int.from_bytes(b, "big") / 65535.0
        return rnd < self.p

class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Добавляет request_id и привязанные поля
        record.request_id = get_request_id() or ""
        ctx = _ctx_bind.get()
        if isinstance(ctx, dict):
            for k, v in ctx.items():
                # избегаем перетирания полей логзаписи
                if k not in record.__dict__:
                    record.__dict__[k] = v
        # OTEL trace/span
        if _HAVE_OTEL:
            try:
                span = _otel_trace.get_current_span()
                ctx = span.get_span_context()
                if getattr(ctx, "is_valid", lambda: False)():
                    record.trace_id = f"{ctx.trace_id:032x}"
                    record.span_id = f"{ctx.span_id:016x}"
            except Exception:
                pass
        return True

# --------------------------------------------------------------------------------------
# JSON форматтер
# --------------------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, environment: str, version: str, include_caller: bool = False) -> None:
        super().__init__()
        self.service = service
        self.environment = environment
        self.version = version
        self.include_caller = include_caller
        self.host = socket.gethostname()
        self.pid = os.getpid()

    def formatTime(self, record: logging.LogRecord, datefmt: Optional[str] = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record),
            "severity": record.levelname,
            "message": msg,
            "logger": record.name,
            "service": self.service,
            "env": self.environment,
            "version": self.version,
            "host": self.host,
            "pid": self.pid,
        }
        rid = getattr(record, "request_id", "") or get_request_id()
        if rid:
            payload["request_id"] = rid

        trace_id = getattr(record, "trace_id", None)
        span_id = getattr(record, "span_id", None)
        if trace_id:
            payload["trace_id"] = trace_id
        if span_id:
            payload["span_id"] = span_id

        # Добавляем extra поля, не являющиеся стандартными
        std = set(logging.LogRecord(None, None, "", 0, "", (), None).__dict__.keys())
        std.update({"request_id", "trace_id", "span_id"})
        for k, v in record.__dict__.items():
            if k not in std and not k.startswith("_"):
                payload[k] = v

        if self.include_caller:
            payload["caller"] = {
                "module": record.module,
                "func": record.funcName,
                "file": record.pathname,
                "line": record.lineno,
            }

        if record.exc_info:
            payload["exc_type"] = str(record.exc_info[0].__name__)  # type: ignore[index]
            payload["exc_message"] = str(record.exc_info[1])        # type: ignore[index]
            payload["stack"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

# --------------------------------------------------------------------------------------
# Построение обработчиков и логера
# --------------------------------------------------------------------------------------

_listener: Optional[logging.handlers.QueueListener] = None
_queue: Optional[queue.Queue] = None

def _build_handler(cfg: LoggingConfig) -> logging.Handler:
    if cfg.destination == "stdout":
        h: logging.Handler = logging.StreamHandler(sys.stdout)
    elif cfg.destination == "stderr":
        h = logging.StreamHandler(sys.stderr)
    elif cfg.destination == "file":
        os.makedirs(os.path.dirname(cfg.file_path), exist_ok=True)
        h = logging.handlers.RotatingFileHandler(
            cfg.file_path, maxBytes=cfg.rotate_max_bytes, backupCount=cfg.rotate_backups, encoding="utf-8"
        )
    elif cfg.destination == "syslog":
        h = logging.handlers.SysLogHandler(address=cfg.syslog_address)
    else:
        h = logging.StreamHandler(sys.stdout)

    fmt = JsonFormatter(cfg.service, cfg.environment, cfg.version, include_caller=cfg.include_caller)
    h.setFormatter(fmt)
    h.addFilter(ContextFilter())
    h.addFilter(RedactingFilter(cfg.redact_patterns))
    h.addFilter(SamplingFilter(cfg.sampling))
    return h

def _level_from_str(level: str) -> int:
    try:
        return getattr(logging, level.upper())
    except Exception:
        return logging.INFO

def configure_logging(cfg: Optional[LoggingConfig] = None) -> None:
    """
    Инициализация корневого логера и интеграции с Uvicorn.
    Повторный вызов безопасен и переинициализирует обработчики.
    """
    global _listener, _queue
    cfg = cfg or LoggingConfig()

    root = logging.getLogger()
    root.setLevel(_level_from_str(cfg.level))

    # Сносим прежние обработчики
    for h in list(root.handlers):
        root.removeHandler(h)
    if _listener:
        try:
            _listener.stop()
        except Exception:
            pass
        _listener = None

    # Неблокирующая очередь
    _queue = queue.Queue(maxsize=cfg.queue_size)
    queue_handler = logging.handlers.QueueHandler(_queue)
    root.addHandler(queue_handler)

    target_handler = _build_handler(cfg)
    _listener = logging.handlers.QueueListener(_queue, target_handler, respect_handler_level=False)
    _listener.start()

    # Настройки логеров сторонних библиотек
    logging.captureWarnings(True)
    for noisy in ("asyncio", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(_level_from_str(cfg.level))

    if cfg.uvicorn_integration:
        _integrate_uvicorn(cfg)

def _integrate_uvicorn(cfg: LoggingConfig) -> None:
    """
    Перенастройка uvicorn.access и uvicorn.error так, чтобы они шли через наш root.
    """
    access = logging.getLogger("uvicorn.access")
    error = logging.getLogger("uvicorn.error")

    # Удаляем их собственные хендлеры, чтобы записи уходили в root
    for lg in (access, error):
        for h in list(lg.handlers):
            lg.removeHandler(h)
        lg.propagate = True

    # Делаем формат совместимым: uvicorn.access пишет record with extra dict in args
    class AccessFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            try:
                if isinstance(record.args, tuple) and record.args and isinstance(record.args[0], dict):
                    data = record.args[0]
                    record.msg = "HTTP access"
                    for k, v in data.items():
                        if k not in record.__dict__:
                            record.__dict__[k] = v
            except Exception:
                pass
            return True

    access.addFilter(AccessFilter())

# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "mythos")

def set_level(level: str) -> None:
    logging.getLogger().setLevel(_level_from_str(level))

@contextlib.contextmanager
def log_duration(logger: logging.Logger, msg: str, **fields: Any):
    """
    Контекстный менеджер для измерения времени операции.
    """
    t0 = time.perf_counter()
    try:
        yield
        dur_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(msg, extra={**fields, "duration_ms": dur_ms, "result": "ok"})
    except Exception as e:
        dur_ms = int((time.perf_counter() - t0) * 1000)
        logger.error(msg, extra={**fields, "duration_ms": dur_ms, "result": "error", "error": str(e)}, exc_info=True)
        raise

def new_request_id() -> str:
    rid = _ulid()
    set_request_id(rid)
    return rid

# --------------------------------------------------------------------------------------
# FastAPI middleware
# --------------------------------------------------------------------------------------

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp
    _HAVE_STARLETTE = True
except Exception:  # pragma: no cover
    _HAVE_STARLETTE = False

if _HAVE_STARLETTE:

    class RequestLoggingMiddleware(BaseHTTPMiddleware):
        """
        Добавляет X-Request-Id, измеряет длительность, логирует запрос и ответ.
        """
        def __init__(self, app: ASGIApp, logger: Optional[logging.Logger] = None) -> None:
            super().__init__(app)
            self.logger = logger or get_logger("http")

        async def dispatch(self, request: Request, call_next):
            # request id
            rid = request.headers.get("X-Request-Id") or new_request_id()
            set_request_id(rid)
            update_context(
                http_method=request.method,
                http_path=str(request.url.path),
                http_query=str(request.url.query or ""),
                http_scheme=request.url.scheme,
                http_host=request.headers.get("host", ""),
                user_agent=request.headers.get("user-agent", ""),
                client_ip=(request.headers.get("x-forwarded-for") or request.client.host if request.client else ""),
            )
            start = time.perf_counter()
            try:
                response: Response = await call_next(request)
                status_code = getattr(response, "status_code", 0)
                dur_ms = int((time.perf_counter() - start) * 1000)
                self.logger.info(
                    "HTTP request",
                    extra={"status_code": status_code, "duration_ms": dur_ms, "request_id": rid},
                )
                response.headers.setdefault("X-Request-Id", rid)
                return response
            except Exception:
                dur_ms = int((time.perf_counter() - start) * 1000)
                self.logger.error("HTTP request failed", extra={"duration_ms": dur_ms, "request_id": rid}, exc_info=True)
                # Пробрасываем дальше для стандартной обработки
                raise

    def install_fastapi_middleware(app) -> None:
        """
        Подключает middleware к приложению FastAPI/Starlette.
        """
        app.add_middleware(RequestLoggingMiddleware)

# --------------------------------------------------------------------------------------
# Грейсфул останов
# --------------------------------------------------------------------------------------

def shutdown_logging(timeout: float = 2.0) -> None:
    """
    Останавливает QueueListener и сбрасывает очередь.
    """
    global _listener, _queue
    if _listener:
        try:
            _listener.stop()
        except Exception:
            pass
        _listener = None
    if _queue:
        try:
            while not _queue.empty():
                _queue.get_nowait()
        except Exception:
            pass
        _queue = None

# --------------------------------------------------------------------------------------
# Пример инициализации в приложении:
#
# from mythos.observability.logging import configure_logging, LoggingConfig, get_logger, install_fastapi_middleware
# cfg = LoggingConfig(service="mythos-core", environment="prod", level="INFO")
# configure_logging(cfg)
# logger = get_logger(__name__)
# logger.info("service started", extra={"port": 8081})
#
# В FastAPI:
# app = FastAPI()
# install_fastapi_middleware(app)
# --------------------------------------------------------------------------------------
