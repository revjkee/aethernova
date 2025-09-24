# path: omnimind-core/omnimind/telemetry/logging.py
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import io
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
from types import FrameType
from typing import Any, Dict, Iterable, Optional
from contextvars import ContextVar

# =========================
# Контекст и константы
# =========================

_ctx: ContextVar[Dict[str, Any]] = ContextVar("omnimind_log_ctx", default={})

_DEFAULT_REDACTIONS = [
    # Authorization: Bearer/Basic/API keys
    (re.compile(r"(?i)\b(authorization|x-api-key|api-key|token|secret|password)\s*[:=]\s*([^\s,;]+)"),
     r"\1: [REDACTED]"),
    # JWT-like
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+"), "[REDACTED_JWT]"),
    # Email
    (re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # Possible credit card (very rough, 13-19 digits)
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CC]"),
]

_HEALTH_PATHS = {"/health", "/healthz", "/ready", "/readyz", "/metrics"}

# =========================
# Конфигурация
# =========================

@dataclass
class LoggingConfig:
    service_name: str = "omnimind-core"
    service_version: str = os.getenv("OMNIMIND_VERSION", "0.0.0")
    environment: str = os.getenv("ENVIRONMENT", "dev")
    level: str = os.getenv("LOG_LEVEL", "INFO")
    # Вывод
    json: bool = True
    console: bool = True
    color: bool = False  # для человекочитаемого формата
    # Ротация файла
    file_path: Optional[str] = os.getenv("LOG_FILE") or None
    file_rotate_when: str = "midnight"
    file_backup_count: int = 14
    # Syslog / Journald
    syslog_address: Optional[str] = os.getenv("SYSLOG_ADDRESS") or None  # например "/dev/log" или "host:514"
    syslog_facility: int = logging.handlers.SysLogHandler.LOG_LOCAL0
    journald: bool = bool(int(os.getenv("JOURNALD", "0")))
    # Rate-limiting и фильтры
    rate_limit_per_key_per_minute: int = 120
    suppress_health_access: bool = True
    # Очередь для неблокирующего логирования (в проде полезно)
    use_queue_handler: bool = True
    queue_capacity: int = 10000
    # Редакция
    redact_patterns: Iterable[tuple[re.Pattern[str], str]] = field(default_factory=lambda: list(_DEFAULT_REDACTIONS))


# =========================
# Форматтеры
# =========================

class JsonFormatter(logging.Formatter):
    def __init__(self, service_name: str, service_version: str, environment: str, redact: Iterable[tuple[re.Pattern[str], str]]) -> None:
        super().__init__()
        self.service_name = service_name
        self.service_version = service_version
        self.environment = environment
        self._redact = list(redact)

    def format(self, record: logging.LogRecord) -> str:
        ts = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="milliseconds")
        # Сбор базовых полей
        payload: Dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": self._scrub(str(record.getMessage())),
            "service": self.service_name,
            "service_version": self.service_version,
            "env": self.environment,
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
            "pid": os.getpid(),
            "tid": threading.get_ident(),
        }
        # Контекст из LogRecord/ContextVars
        for key in ("request_id", "session_id", "user_id", "org_id", "trace_id", "span_id"):
            val = getattr(record, key, None)
            if val:
                payload[key] = val

        # Доп. поля, переданные через extra
        for k, v in getattr(record, "extra_fields", {}).items():
            payload[k] = self._scrub(v)

        # Исключение
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["exc_message"] = self._scrub(str(record.exc_info[1])) if record.exc_info[1] else None
            payload["stack"] = self._scrub(self.formatException(record.exc_info))

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _scrub(self, obj: Any) -> Any:
        # Рекурсивная редакция строк, словарей и массивов
        if obj is None:
            return None
        if isinstance(obj, str):
            s = obj
            for pat, repl in self._redact:
                s = pat.sub(repl, s)
            return s
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._scrub(x) for x in obj]
        return obj


class HumanFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET": "\033[0m",
    }

    def __init__(self, color: bool, redact: Iterable[tuple[re.Pattern[str], str]]) -> None:
        super().__init__()
        self.color = color and sys.stderr.isatty()
        self._redact = list(redact)

    def format(self, record: logging.LogRecord) -> str:
        ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level = record.levelname
        msg = self._scrub(str(record.getMessage()))
        prefix = f"{ts} | {level:8s} | {record.name}"
        ctx = []
        for k in ("request_id", "user_id", "trace_id", "span_id"):
            v = getattr(record, k, None)
            if v:
                ctx.append(f"{k}={v}")
        if ctx:
            prefix += " [" + " ".join(ctx) + "]"
        line = f"{prefix} - {msg}"
        if record.exc_info:
            sio = io.StringIO()
            sio.write("\n")
            sio.write(self.formatException(record.exc_info))
            line += sio.getvalue()
        if self.color:
            c = self.COLORS.get(level, "")
            r = self.COLORS["RESET"]
            return f"{c}{line}{r}"
        return line

    def _scrub(self, s: str) -> str:
        for pat, repl in self._redact:
            s = pat.sub(repl, s)
        return s


# =========================
# Фильтры
# =========================

class RateLimitFilter(logging.Filter):
    """
    Ограничение частоты повторяющихся сообщений (по ключу: logger|level|msg шаблон).
    Сбрасывает избыточные записи сверх N в минуту.
    """
    def __init__(self, max_per_minute: int) -> None:
        super().__init__()
        self.max = max_per_minute
        self.bucket: Dict[str, tuple[int, float]] = {}  # key -> (count, window_start)

    def filter(self, record: logging.LogRecord) -> bool:
        if self.max <= 0:
            return True
        key = f"{record.name}|{record.levelno}|{getattr(record, 'msg', '')}"
        now = time.monotonic()
        count, start = self.bucket.get(key, (0, now))
        # Сбрасываем окно каждые 60с
        if now - start > 60.0:
            count, start = 0, now
        count += 1
        self.bucket[key] = (count, start)
        return count <= self.max


class HealthAccessFilter(logging.Filter):
    """
    Фильтр для шумных access-логов health/metrics.
    Ожидается, что record.extra_fields.get('path') содержит путь (см. middleware ниже).
    """
    def filter(self, record: logging.LogRecord) -> bool:
        path = None
        extra = getattr(record, "extra_fields", {})
        if isinstance(extra, dict):
            path = extra.get("path")
        if not path and hasattr(record, "path"):
            path = getattr(record, "path", None)
        if path in _HEALTH_PATHS:
            return False
        return True


# =========================
# LogRecord factory с контекстом и OTel
# =========================

_base_factory = logging.getLogRecordFactory()

def _record_factory(*args, **kwargs) -> logging.LogRecord:
    rec = _base_factory(*args, **kwargs)
    # Притягиваем контекст из ContextVar
    ctx = _ctx.get()
    for k in ("request_id", "session_id", "user_id", "org_id"):
        v = ctx.get(k)
        if v is not None:
            setattr(rec, k, v)
    # OpenTelemetry trace/span (если доступно)
    try:
        from opentelemetry import trace  # type: ignore
        span = trace.get_current_span()
        sc = span.get_span_context()
        if sc and sc.is_valid:
            setattr(rec, "trace_id", f"{sc.trace_id:032x}")
            setattr(rec, "span_id", f"{sc.span_id:016x}")
    except Exception:
        # Безопасно игнорируем, если OTel недоступен
        pass
    # Место для дополнительных полей (extra_fields) — всегда словарь
    if not hasattr(rec, "extra_fields") or not isinstance(rec.extra_fields, dict):
        setattr(rec, "extra_fields", {})
    return rec


# =========================
# Публичный API
# =========================

def setup_logging(cfg: LoggingConfig) -> None:
    """
    Инициализация логирования. Вызывать один раз на процесс.
    """
    logging.setLogRecordFactory(_record_factory)
    root = logging.getLogger()
    root.setLevel(_level_from_str(cfg.level))

    # Очередь для неблокирующего логирования
    qh: Optional[logging.handlers.QueueHandler] = None
    q: Optional[queue.Queue] = None
    if cfg.use_queue_handler:
        q = queue.Queue(maxsize=cfg.queue_capacity)
        qh = logging.handlers.QueueHandler(q)
        root.addHandler(qh)

    # Хэндлеры вывода
    handlers: list[logging.Handler] = []
    if cfg.console:
        ch = logging.StreamHandler(stream=sys.stderr)
        ch.setLevel(root.level)
        ch.addFilter(RateLimitFilter(cfg.rate_limit_per_key_per_minute))
        if cfg.suppress_health_access:
            ch.addFilter(HealthAccessFilter())
        if cfg.json:
            ch.setFormatter(JsonFormatter(cfg.service_name, cfg.service_version, cfg.environment, cfg.redact_patterns))
        else:
            ch.setFormatter(HumanFormatter(cfg.color, cfg.redact_patterns))
        handlers.append(ch)

    if cfg.file_path:
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=cfg.file_path,
            when=cfg.file_rotate_when,
            backupCount=int(cfg.file_backup_count),
            encoding="utf-8",
            delay=True,
        )
        fh.setLevel(root.level)
        fh.addFilter(RateLimitFilter(cfg.rate_limit_per_key_per_minute))
        if cfg.suppress_health_access:
            fh.addFilter(HealthAccessFilter())
        fh.setFormatter(JsonFormatter(cfg.service_name, cfg.service_version, cfg.environment, cfg.redact_patterns) if cfg.json
                        else HumanFormatter(False, cfg.redact_patterns))
        handlers.append(fh)

    if cfg.syslog_address:
        address: Any
        if ":" in cfg.syslog_address and not os.path.exists(cfg.syslog_address):
            host, port = cfg.syslog_address.split(":", 1)
            address = (host, int(port))
        else:
            address = cfg.syslog_address
        sh = logging.handlers.SysLogHandler(address=address, facility=cfg.syslog_facility, socktype=socket.SOCK_DGRAM)
        sh.setLevel(root.level)
        sh.addFilter(RateLimitFilter(cfg.rate_limit_per_key_per_minute))
        sh.setFormatter(JsonFormatter(cfg.service_name, cfg.service_version, cfg.environment, cfg.redact_patterns))
        handlers.append(sh)

    if cfg.journald:
        with contextlib.suppress(Exception):
            from systemd.journal import JournalHandler  # type: ignore
            jh = JournalHandler(SYSLOG_IDENTIFIER=cfg.service_name)
            jh.setLevel(root.level)
            jh.addFilter(RateLimitFilter(cfg.rate_limit_per_key_per_minute))
            jh.setFormatter(JsonFormatter(cfg.service_name, cfg.service_version, cfg.environment, cfg.redact_patterns))
            handlers.append(jh)

    # Если используется очередь — завернём хэндлеры в QueueListener
    if cfg.use_queue_handler and qh and handlers:
        listener = logging.handlers.QueueListener(q, *handlers, respect_handler_level=True)
        listener.daemon = True
        listener.start()
    else:
        for h in handlers:
            root.addHandler(h)

    # Согласование с Uvicorn/Gunicorn
    _configure_uvicorn(root.level, cfg)

    # Глобальный перехват необработанных исключений → лог ERROR
    sys.excepthook = _excepthook

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "omnimind")

def bind_context(**kwargs: Any) -> None:
    """
    Привязывает значения к контексту логирования текущей задачи/потока.
    """
    current = dict(_ctx.get())
    current.update({k: v for k, v in kwargs.items() if v is not None})
    _ctx.set(current)

@contextlib.contextmanager
def log_context(**kwargs: Any):
    """
    Контекст-менеджер для временной привязки контекста.
    """
    prev = _ctx.get()
    try:
        bind_context(**kwargs)
        yield
    finally:
        _ctx.set(prev)

def log_extra(**fields: Any) -> Dict[str, Any]:
    """
    Готовит extra с дополнительными полями, которые пойдут в JSON.
    """
    return {"extra_fields": fields}


# =========================
# ASGI middleware (request logging)
# =========================

class RequestContextMiddleware:
    """
    ASGI-middleware: назначает/протаскивает X-Request-Id, логирует начало/окончание запроса,
    считает латентность, добавляет минимальный набор полей в логи.
    """
    def __init__(self, app, *, logger: Optional[logging.Logger] = None, service_name: str = "omnimind-core"):
        self.app = app
        self.log = logger or get_logger("omnimind.asgi")
        self.service_name = service_name

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        req_id = headers.get("x-request-id") or _gen_request_id()
        method = scope.get("method", "")
        path = scope.get("path", "")
        client = scope.get("client", ("", 0))
        host = headers.get("host")

        # Bind context for this request
        token = _ctx.set({**_ctx.get(), "request_id": req_id})
        start = time.perf_counter()

        async def send_wrapper(message):
            # перехват статуса
            if message["type"] == "http.response.start":
                status = message.get("status", 0)
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                self.log.info(
                    "request",
                    extra=log_extra(
                        path=path,
                        method=method,
                        status=status,
                        elapsed_ms=elapsed_ms,
                        client_ip=client[0],
                        host=host,
                        service=self.service_name,
                    ),
                )
            return await send(message)

        try:
            # Лог начала запроса
            self.log.debug("request.start", extra=log_extra(path=path, method=method, client_ip=client[0], host=host))
            await self.app(scope, receive, send_wrapper)
        except Exception:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            self.log.exception("request.error", extra=log_extra(path=path, method=method, elapsed_ms=elapsed_ms))
            raise
        finally:
            _ctx.reset(token)


# =========================
# Вспомогательные
# =========================

def _level_from_str(level: str) -> int:
    try:
        return getattr(logging, level.upper())
    except Exception:
        return logging.INFO

def _excepthook(exc_type: type[BaseException], exc: BaseException, tb: Optional[FrameType]) -> None:
    log = get_logger("omnimind.unhandled")
    log.error("unhandled_exception", exc_info=(exc_type, exc, tb))

def _configure_uvicorn(level: int, cfg: LoggingConfig) -> None:
    """
    Перенаправляет uvicorn/gunicorn логгеры на наши хэндлеры.
    """
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "gunicorn", "gunicorn.error", "gunicorn.access"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        # Не добавляем хэндлеры напрямую — они уже висят на root (или через QueueListener)
        lg.propagate = True
    if cfg.suppress_health_access:
        logging.getLogger("uvicorn.access").addFilter(HealthAccessFilter())

def _gen_request_id() -> str:
    # компактный 16-символьный id
    return os.urandom(8).hex()


# =========================
# Пример использования (комментарии)
# =========================
# cfg = LoggingConfig(
#     service_name="omnimind-core",
#     environment="prod",
#     file_path="/var/log/omnimind/core.log",
#     syslog_address="/dev/log",
# )
# setup_logging(cfg)
# log = get_logger(__name__)
# with log_context(request_id="abc123", user_id="u-42"):
#     log.info("memory.upsert", extra=log_extra(memory_id="m-1", chunks=3))
#     try:
#         1/0
#     except ZeroDivisionError:
#         log.exception("calc.error", extra=log_extra(op="div"))
#
# # ASGI:
# # app.add_middleware(RequestContextMiddleware, service_name="omnimind-core")
