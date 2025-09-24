# security-core/security/telemetry/logging.py
"""
Промышленное логирование (телеметрия) для security-core.

Возможности:
- Структурированные JSONL логи (UTC ISO8601), безопасная сериализация.
- Контекст через contextvars: tenant_id, principal_id, request_id, correlation_id, trace_id, span_id, ip, user_agent.
- Опциональная корреляция с OpenTelemetry (trace/span) — если библиотека установлена.
- Маскирование чувствительных полей в extra/details.
- Неблокирующая очередь логов (QueueHandler/QueueListener) с бэкпрешером.
- Ротация файла по времени с gzip архивацией.
- Опциональный Syslog (UDP/TCP).
- Мягкий rate-limit фильтр (токен-бакет на ключ логгера/уровня/«сигнатуры»).
- Динамическая смена уровня логгера.
- Типизированные конфиги и простые фабрики.

Зависимости: стандартная библиотека.
OpenTelemetry (опционально): opentelemetry-api (если установлено) — только для чтения контекста.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import logging.handlers
import os
import queue
import socket
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------- Контекст ---------------------------

_ctx_tenant: ContextVar[Optional[str]] = ContextVar("telemetry_tenant", default=None)
_ctx_principal: ContextVar[Optional[str]] = ContextVar("telemetry_principal", default=None)
_ctx_ip: ContextVar[Optional[str]] = ContextVar("telemetry_ip", default=None)
_ctx_ua: ContextVar[Optional[str]] = ContextVar("telemetry_ua", default=None)
_ctx_reqid: ContextVar[Optional[str]] = ContextVar("telemetry_request_id", default=None)
_ctx_corr: ContextVar[Optional[str]] = ContextVar("telemetry_correlation_id", default=None)
_ctx_trace: ContextVar[Optional[str]] = ContextVar("telemetry_trace_id", default=None)
_ctx_span: ContextVar[Optional[str]] = ContextVar("telemetry_span_id", default=None)

def bind_context(
    *,
    tenant_id: Optional[str] = None,
    principal_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
) -> None:
    if tenant_id is not None: _ctx_tenant.set(tenant_id)
    if principal_id is not None: _ctx_principal.set(principal_id)
    if ip is not None: _ctx_ip.set(ip)
    if user_agent is not None: _ctx_ua.set(user_agent)
    if request_id is not None: _ctx_reqid.set(request_id)
    if correlation_id is not None: _ctx_corr.set(correlation_id)
    if trace_id is not None: _ctx_trace.set(trace_id)
    if span_id is not None: _ctx_span.set(span_id)

def clear_context() -> None:
    bind_context(tenant_id=None, principal_id=None, ip=None, user_agent=None,
                 request_id=None, correlation_id=None, trace_id=None, span_id=None)

@contextmanager
def context(**kwargs: Any):
    """Контекстный менеджер для временного связывания контекста."""
    tokens = {}
    for k, v in kwargs.items():
        var = {
            "tenant_id": _ctx_tenant,
            "principal_id": _ctx_principal,
            "ip": _ctx_ip,
            "user_agent": _ctx_ua,
            "request_id": _ctx_reqid,
            "correlation_id": _ctx_corr,
            "trace_id": _ctx_trace,
            "span_id": _ctx_span,
        }.get(k)
        if var is not None:
            tokens[var] = var.set(v)
    try:
        yield
    finally:
        for var, tok in tokens.items():
            var.reset(tok)

# --------------------------- Маскирование -----------------------

_DEFAULT_MASK_KEYS = {
    "password", "secret", "token", "access_token", "refresh_token",
    "authorization", "api_key", "apikey", "key", "private_key",
    "ssn", "card", "pan", "email",
}

def _mask_scalar(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        if "@" in v and "." in v.split("@")[-1]:
            name, dom = v.split("@", 1)
            return (name[:1] + "****" if name else "****") + "@" + (dom[:1] + "****")
        if any(ch.isdigit() for ch in v) and len(v) >= 6:
            return "***" + v[-4:]
        return "****"
    if isinstance(v, (bytes, bytearray)):
        return b"****"
    if isinstance(v, (int, float, bool)):
        return v
    return "****"

def redact(obj: Any, secret_keys: Iterable[str]) -> Any:
    sk = {str(x).lower() for x in secret_keys}
    def _walk(x: Any) -> Any:
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                if str(k).lower() in sk:
                    out[k] = _mask_scalar(v)
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(x, list):
            return [_walk(i) for i in x]
        return x
    return _walk(obj)

# --------------------------- JSON форматтер --------------------

def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _get_otlp_trace() -> Tuple[Optional[str], Optional[str]]:
    """
    Попытка получить trace/span из OpenTelemetry, если установлено.
    """
    try:
        from opentelemetry import trace  # type: ignore
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            tid = "{:032x}".format(ctx.trace_id)
            sid = "{:016x}".format(ctx.span_id)
            return tid, sid
    except Exception:
        pass
    return None, None

class JsonFormatter(logging.Formatter):
    def __init__(self, service_name: str, service_version: str, redact_keys: Iterable[str] = ()):
        super().__init__()
        self.service_name = service_name
        self.service_version = service_version
        self.redact_keys = set(_DEFAULT_MASK_KEYS) | set(map(str, redact_keys))

    def format(self, record: logging.LogRecord) -> str:
        ts = getattr(record, "created", time.time())
        msg = record.getMessage()
        # базовое
        payload: Dict[str, Any] = {
            "ts": _utc_iso(ts),
            "level": record.levelname,
            "logger": record.name,
            "msg": msg,
            "event": getattr(record, "event", None),
            "service": {"name": self.service_name, "version": self.service_version},
            "ctx": {
                "tenant_id": _ctx_tenant.get(),
                "principal_id": _ctx_principal.get(),
                "request_id": _ctx_reqid.get(),
                "correlation_id": _ctx_corr.get(),
                "ip": _ctx_ip.get(),
                "user_agent": _ctx_ua.get(),
                "trace_id": _ctx_trace.get(),
                "span_id": _ctx_span.get(),
            },
            "proc": {
                "pid": os.getpid(),
                "tid": getattr(record, "thread", None),
            },
            "caller": {
                "file": record.pathname,
                "line": record.lineno,
                "func": record.funcName,
            },
        }
        # OpenTelemetry (если нет своих trace/span в контексте)
        if not payload["ctx"]["trace_id"]:
            tid, sid = _get_otlp_trace()
            if tid:
                payload["ctx"]["trace_id"] = tid
                payload["ctx"]["span_id"] = sid

        # extra-поля: берём из record.__dict__ всё неприватное
        extra: Dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k in ("name","msg","args","levelname","levelno","pathname","filename","module",
                     "exc_info","exc_text","stack_info","lineno","funcName","created","msecs",
                     "relativeCreated","thread","threadName","processName","process"):
                continue
            if k in ("event",):  # уже включено
                continue
            if k.startswith("_"):
                continue
            extra[k] = v

        if extra:
            payload["extra"] = redact(extra, self.redact_keys)

        # исключение
        if record.exc_info:
            etype, evalue, etb = record.exc_info
            payload["exc"] = {
                "type": getattr(etype, "__name__", str(etype)),
                "message": str(evalue),
                "stack": "".join(traceback.format_exception(etype, evalue, etb))[:10000],
            }

        # компактный JSON
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

# --------------------------- Ротация с gzip -------------------

class GzipTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """
    Ротация по времени (как TimedRotatingFileHandler) + gzip архив прошлых файлов.
    """
    def __init__(self, filename: str, when: str = "midnight", interval: int = 1, backupCount: int = 7, encoding: Optional[str] = "utf-8"):
        super().__init__(filename, when=when, interval=interval, backupCount=backupCount, encoding=encoding, utc=True)

    def doRollover(self) -> None:
        if self.stream:
            self.stream.flush()
            self.stream.close()
            self.stream = None
        # оригинальная логика формирования имени
        currentTime = int(time.time())
        dfn = self.rotation_filename(self.baseFilename + "." + time.strftime(self.suffix, time.gmtime(self.rolloverAt - self.interval)))
        if os.path.exists(self.baseFilename):
            os.rename(self.baseFilename, dfn)
        # сжатие
        try:
            with open(dfn, "rb") as f_in, gzip.open(dfn + ".gz", "wb") as f_out:
                f_out.writelines(f_in)
            os.remove(dfn)
        except Exception:
            # не фейлим приложение
            pass
        # удаление старых
        if self.backupCount > 0:
            for s in self.getFilesToDelete():
                try:
                    os.remove(s)
                except Exception:
                    pass
        # открыть новый
        self.mode = "a"
        self.stream = self._open()
        # обновить время следующей ротации
        newRolloverAt = self.computeRollover(currentTime)
        while newRolloverAt <= currentTime:
            newRolloverAt = newRolloverAt + self.interval
        self.rolloverAt = newRolloverAt

# --------------------------- Rate-limit фильтр ----------------

class RateLimitFilter(logging.Filter):
    """
    Мягкий rate-limit: токен-бакет per (logger, level, signature).
    signature: первая 100-символьная часть сообщения или event.
    """
    def __init__(self, rate_per_sec: float = 50.0, burst: int = 200):
        super().__init__()
        self.rate = max(0.1, rate_per_sec)
        self.capacity = max(1, burst)
        self._state: Dict[Tuple[str, int, str], Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        key = (record.name, record.levelno, getattr(record, "event", "") or str(record.msg)[:100])
        now = time.time()
        with self._lock:
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1.0, now)
            return True

# --------------------------- Конфиг ---------------------------

@dataclass
class TelemetryConfig:
    service_name: str = "security-core"
    service_version: str = "0.0.0"
    level: str = "INFO"
    json_stdout: bool = True
    file_path: Optional[str] = None
    file_backup_days: int = 7
    syslog_address: Optional[Tuple[str, int]] = None   # ("127.0.0.1", 514)
    queue_size: int = 10000
    drop_on_full: bool = True
    rate_limit_per_sec: float = 0.0                     # 0 = отключено
    rate_burst: int = 0
    redact_extra_keys: Tuple[str, ...] = tuple()

# --------------------------- Настройка ------------------------

class _DropOnFullQueueHandler(logging.handlers.QueueHandler):
    """
    QueueHandler, который при заполнении очереди либо дропает запись, либо блокируется.
    """
    def __init__(self, q: "queue.Queue[logging.LogRecord]", drop_on_full: bool = True):
        super().__init__(q)
        self.drop_on_full = drop_on_full

    def enqueue(self, record: logging.LogRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            if not self.drop_on_full:
                self.queue.put(record, timeout=1.0)
            # иначе молча дропаем

_listener: Optional[logging.handlers.QueueListener] = None

def setup_logging(cfg: TelemetryConfig) -> None:
    """
    Полная настройка логирования приложения.
    """
    global _listener

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    root.setLevel(getattr(logging, cfg.level.upper(), logging.INFO))

    # Очередь и неблокирующий handler
    q: "queue.Queue[logging.LogRecord]" = queue.Queue(maxsize=cfg.queue_size)
    qh = _DropOnFullQueueHandler(q, drop_on_full=cfg.drop_on_full)

    # Фильтры (optional)
    if cfg.rate_limit_per_sec and cfg.rate_burst:
        qh.addFilter(RateLimitFilter(rate_per_sec=cfg.rate_limit_per_sec, burst=cfg.rate_burst))

    root.addHandler(qh)

    # Сборка целевых обработчиков
    targets: List[logging.Handler] = []
    fmt = JsonFormatter(cfg.service_name, cfg.service_version, cfg.redact_extra_keys)

    if cfg.json_stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        targets.append(sh)

    if cfg.file_path:
        os.makedirs(os.path.dirname(cfg.file_path), exist_ok=True)
        fh = GzipTimedRotatingFileHandler(cfg.file_path, when="midnight", interval=1, backupCount=cfg.file_backup_days)
        fh.setFormatter(fmt)
        targets.append(fh)

    if cfg.syslog_address:
        try:
            syslog = logging.handlers.SysLogHandler(address=cfg.syslog_address, socktype=socket.SOCK_DGRAM)
            syslog.setFormatter(fmt)
            targets.append(syslog)
        except Exception:
            # Безопасный фоллбэк: не ломаем приложение из‑за syslog
            pass

    # Запускаем слушатель очереди
    if _listener:
        try:
            _listener.stop()
        except Exception:
            pass
    _listener = logging.handlers.QueueListener(q, *targets, respect_handler_level=False)
    _listener.start()

def set_level(level: str, logger_name: Optional[str] = None) -> None:
    """
    Динамическая смена уровня корневого или конкретного логгера.
    """
    lvl = getattr(logging, level.upper(), logging.INFO)
    if logger_name:
        logging.getLogger(logger_name).setLevel(lvl)
    else:
        logging.getLogger().setLevel(lvl)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

# --------------------------- Пример использования -----------------------

if __name__ == "__main__":
    # Демонстрация
    cfg = TelemetryConfig(
        service_name="security-core",
        service_version="1.0.0",
        level="INFO",
        json_stdout=True,
        file_path="./logs/app.log",
        file_backup_days=3,
        queue_size=10000,
        drop_on_full=True,
        rate_limit_per_sec=100.0,
        rate_burst=300,
        redact_extra_keys=("auth", "password"),
    )
    setup_logging(cfg)

    log = get_logger("demo")
    bind_context(tenant_id="t-1", principal_id="u-42", ip="203.0.113.10",
                 user_agent="curl/8.6.0", request_id="req-abc", correlation_id="corr-xyz")

    log.info("server started", event="BOOT", extra={"port": 8080})
    try:
        1 / 0
    except ZeroDivisionError:
        log.exception("calculation failed", extra={"token": "super-secret-token", "email": "alice@example.org"})
    log.warning("high latency", event="LATENCY", extra={"ms": 1234, "endpoint": "/api/v1/items"})
