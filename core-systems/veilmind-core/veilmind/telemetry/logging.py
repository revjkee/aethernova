# -*- coding: utf-8 -*-
"""
veilmind-core.veilmind.telemetry.logging

Промышленное структурированное логирование с безопасными дефолтами:
  - JSON-формат (ECS/CloudEvents-like поля)
  - Сквозной контекст через contextvars (trace_id, span_id, request_id, subject_id, device_id, session_id)
  - Совместимость с OpenTelemetry (если установлен), авто-подхват trace_id/span_id
  - Редактирование/маскирование/хеширование чувствительных полей
  - Дедупликация повторных сообщений за окно
  - Вероятностная выборка (sampling) для INFO/DEBUG
  - Неблокирующие хендлеры: QueueHandler/QueueListener, ротация файлов, syslog
  - Переназначение uvicorn/gunicorn/warnings в общую систему логирования

Зависимости: только стандартная библиотека. OpenTelemetry (opentelemetry-sdk) — опционально.

Пример:
    from veilmind.telemetry.logging import TelemetryConfig, configure, get_logger, bind_context, set_trace_id

    cfg = TelemetryConfig(service="veilmind-core", environment="prod",
                          file_path="/var/log/veilmind/core.jsonl", hash_salt="changeme")
    configure(cfg)

    with bind_context(request_id="REQ-1", subject_id="alice@corp"):
        log = get_logger(__name__)
        log.info("policy decision", extra={"event": {"component": "pdp", "decision": "allow"}})
"""

from __future__ import annotations

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
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

# ------------------------------- Опциональный OTel ----------------------------

try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAVE_OTEL = True
except Exception:  # pragma: no cover
    _HAVE_OTEL = False

# ------------------------------- contextvars ----------------------------------

try:
    import contextvars

    _cv_trace_id = contextvars.ContextVar("trace_id", default=None)
    _cv_span_id = contextvars.ContextVar("span_id", default=None)
    _cv_request_id = contextvars.ContextVar("request_id", default=None)
    _cv_idempotency_key = contextvars.ContextVar("idempotency_key", default=None)

    _cv_subject_id = contextvars.ContextVar("subject_id", default=None)
    _cv_device_id = contextvars.ContextVar("device_id", default=None)
    _cv_session_id = contextvars.ContextVar("session_id", default=None)
except Exception:  # pragma: no cover
    _cv_trace_id = None  # type: ignore
    _cv_span_id = None  # type: ignore
    _cv_request_id = None  # type: ignore
    _cv_idempotency_key = None  # type: ignore
    _cv_subject_id = None  # type: ignore
    _cv_device_id = None  # type: ignore
    _cv_session_id = None  # type: ignore


# -------------------------------- Конфигурация --------------------------------

@dataclass
class TelemetryConfig:
    service: str = "app"
    environment: str = "dev"
    level: int = logging.INFO

    json_format: bool = True
    include_timestamp: bool = True
    tz_utc: bool = True

    # Куда писать
    to_stdout: bool = True
    file_path: Optional[str] = None
    file_max_bytes: int = 50 * 1024 * 1024
    file_backup_count: int = 10
    syslog_addr: Optional[str] = None  # пример: "/dev/log" или "127.0.0.1:514"
    syslog_facility: int = logging.handlers.SysLogHandler.LOG_USER

    # Безопасность/редакция
    redact_keys: Iterable[str] = field(
        default_factory=lambda: (
            "authorization",
            "proxy-authorization",
            "password",
            "secret",
            "token",
            "api_key",
            "api-key",
            "x-api-key",
            "set-cookie",
            "cookie",
            "pan",
            "ssn",
        )
    )
    redact_patterns: Iterable[str] = field(
        default_factory=lambda: (
            r"(?i)\bBearer\s+[A-Za-z0-9._\-]+",
            r"(?i)\b[A-F0-9]{32,64}\b",
            r"\b\d{16}\b",  # PAN
        )
    )
    hash_salt: Optional[str] = None  # для детерминированного хеширования значений (blake2b hex)

    # Дедупликация и sampling
    dedup_window_seconds: float = 5.0
    dedup_cache_size: int = 2048
    info_sample_rate: float = 1.0  # 0..1
    debug_sample_rate: float = 0.2  # 0..1

    # Очередь/слушатель
    queue_size: int = 10000

    # Наследование уровней внешних логгеров
    quiet_loggers: Iterable[str] = field(default_factory=lambda: ("uvicorn", "uvicorn.error", "uvicorn.access", "asyncio", "urllib3"))


# ------------------------------- Утилиты --------------------------------------

def _utc_iso(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.isoformat(timespec="milliseconds")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


def _hash_value(val: Any, salt: Optional[str]) -> str:
    # Ленивая зависимость только от hashlib встроенного через json.dumps
    import hashlib as _hashlib  # локальный импорт
    raw = json.dumps(val, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    h = _hashlib.blake2b(raw, digest_size=32, key=(salt or "").encode("utf-8") if salt else None)
    return h.hexdigest()


def _mask_string(s: str, keep_prefix: int = 2, keep_suffix: int = 2, mask_char: str = "*") -> str:
    n = len(s)
    if n <= keep_prefix + keep_suffix:
        return mask_char * n
    return s[:keep_prefix] + mask_char * (n - keep_prefix - keep_suffix) + s[-keep_suffix:]


def _deepcopy_jsonable(obj: Any) -> Any:
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, list):
        return [_deepcopy_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _deepcopy_jsonable(v) for k, v in obj.items()}
    return str(obj)


# ---------------------------- Фильтры/Форматтеры ------------------------------

class SamplingFilter(logging.Filter):
    """Вероятностный sampling для INFO/DEBUG, ошибки всегда проходят."""
    def __init__(self, info_rate: float, debug_rate: float) -> None:
        super().__init__()
        self.info_rate = max(0.0, min(1.0, info_rate))
        self.debug_rate = max(0.0, min(1.0, debug_rate))

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if record.levelno >= logging.WARNING:
            return True
        import random
        if record.levelno == logging.INFO:
            return random.random() < self.info_rate
        if record.levelno == logging.DEBUG:
            return random.random() < self.debug_rate
        return True


class DedupFilter(logging.Filter):
    """Подавление повторов одинаковых сообщений на небольшом окне времени."""
    def __init__(self, window_seconds: float = 5.0, maxsize: int = 2048) -> None:
        super().__init__()
        self.window = max(0.1, window_seconds)
        self.maxsize = max(128, maxsize)
        self._cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        sig = self._signature(record)
        now = time.time()
        with self._lock:
            ts = self._cache.get(sig)
            if ts and (now - ts) < self.window:
                return False
            self._cache[sig] = now
            if len(self._cache) > self.maxsize:
                # простая очистка: удалим самые старые
                for k in list(self._cache.keys())[: self.maxsize // 4]:
                    self._cache.pop(k, None)
            return True

    @staticmethod
    def _signature(record: logging.LogRecord) -> str:
        base = f"{record.name}|{record.levelno}|{record.getMessage()}"
        # добавим тип исключения для ошибок
        if record.exc_info and record.exc_info[0]:
            base += f"|{record.exc_info[0].__name__}"
        return base


class RedactFilter(logging.Filter):
    """Редактирование чувствительных полей в record.extra['event'] и в текстовом сообщении."""
    def __init__(self, keys: Iterable[str], patterns: Iterable[str], hash_salt: Optional[str]) -> None:
        super().__init__()
        self.keys = {k.lower() for k in keys}
        self.regexes = [re.compile(p) for p in patterns]
        self.hash_salt = hash_salt

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # extra.event
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            record.event = self._sanitize_dict(event)
        # сообщение
        try:
            msg = record.getMessage()
            for rx in self.regexes:
                msg = rx.sub("[REDACTED]", msg)
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True

    def _sanitize_dict(self, d: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in d.items():
            kl = str(k).lower()
            if kl in self.keys:
                if self.hash_salt:
                    out[k] = f"H[{_hash_value(v, self.hash_salt)}]"
                else:
                    out[k] = "[REDACTED]"
                continue
            if isinstance(v, dict):
                out[k] = self._sanitize_dict(v)
            elif isinstance(v, list):
                out[k] = [self._sanitize_dict(x) if isinstance(x, dict) else self._sanitize_value(kl, x) for x in v]
            else:
                out[k] = self._sanitize_value(kl, v)
        return out

    def _sanitize_value(self, key_lower: str, v: Any) -> Any:
        if key_lower in self.keys:
            return "[REDACTED]"
        if isinstance(v, str):
            s = v
            for rx in self.regexes:
                s = rx.sub("[REDACTED]", s)
            return s
        return v


class JsonFormatter(logging.Formatter):
    """Быстрый JSON‑форматтер с ECS/CloudEvents‑подобными полями."""
    def __init__(self, service: str, environment: str, include_ts: bool = True, tz_utc: bool = True) -> None:
        super().__init__()
        self.service = service
        self.environment = environment
        self.include_ts = include_ts
        self.tz_utc = tz_utc
        self.host = _hostname()
        # Предсоздадим map уровней
        self.level_map = {
            logging.DEBUG: "DEBUG",
            logging.INFO: "INFO",
            logging.WARNING: "WARN",
            logging.ERROR: "ERROR",
            logging.CRITICAL: "CRITICAL",
        }

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        base: Dict[str, Any] = {
            "service": self.service,
            "environment": self.environment,
            "host": self.host,
            "logger": record.name,
            "level": self.level_map.get(record.levelno, str(record.levelno)),
            "message": record.getMessage(),
            "pid": os.getpid(),
            "module": record.module,
            "file": record.pathname,
            "line": record.lineno,
        }
        if self.include_ts:
            base["ts"] = _utc_iso() if self.tz_utc else datetime.now().isoformat(timespec="milliseconds")

        # Контекст
        base.update(_current_context())

        # Событие/доп.поля
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            base["event"] = _deepcopy_jsonable(event)

        # Ошибка/стек
        if record.exc_info:
            base["error"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
            }
            try:
                base["stack"] = self.formatException(record.exc_info)
            except Exception:
                pass

        # Попытка обогатить OTel трейсом при отсутствии контекста
        if _HAVE_OTEL and not base.get("trace_id"):
            try:
                span = _otel_trace.get_current_span()
                if span and span.get_span_context() and span.get_span_context().is_valid:
                    sc = span.get_span_context()
                    base["trace_id"] = f"{sc.trace_id:032x}"
                    base["span_id"] = f"{sc.span_id:016x}"
            except Exception:
                pass

        return json.dumps(base, separators=(",", ":"), ensure_ascii=False)


# --------------------------- LoggerAdapter с контекстом -----------------------

class ContextLoggerAdapter(logging.LoggerAdapter):
    """Автоматически добавляет контекст и поддерживает extra['event'] как dict."""
    def process(self, msg: Any, kwargs: Dict[str, Any]) -> Any:
        extra = kwargs.get("extra", {})
        if "event" in extra and isinstance(extra["event"], dict):
            # позволит фильтрам редактировать event
            kwargs["extra"] = {"event": extra["event"]}
        return msg, kwargs


# --------------------------- Настройка логирования ----------------------------

_LISTENER: Optional[logging.handlers.QueueListener] = None
_QUEUE: Optional[queue.Queue] = None
_CONFIG: Optional[TelemetryConfig] = None


def configure(cfg: TelemetryConfig) -> None:
    """
    Глобальная настройка логирования. Повторные вызовы перезапускают слушатель.
    """
    global _LISTENER, _QUEUE, _CONFIG

    # Отключим старый listener
    if _LISTENER:
        try:
            _LISTENER.stop()
        except Exception:
            pass
        _LISTENER = None
    _QUEUE = queue.Queue(maxsize=cfg.queue_size)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(cfg.level)

    qh = logging.handlers.QueueHandler(_QUEUE)
    root.addHandler(qh)

    # Конечные хендлеры
    handlers = []

    if cfg.to_stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(cfg.level)
        handlers.append(sh)

    if cfg.file_path:
        fh = logging.handlers.RotatingFileHandler(
            cfg.file_path, maxBytes=cfg.file_max_bytes, backupCount=cfg.file_backup_count, encoding="utf-8"
        )
        fh.setLevel(cfg.level)
        handlers.append(fh)

    if cfg.syslog_addr:
        addr: Any
        if ":" in cfg.syslog_addr and not cfg.syslog_addr.startswith("/"):
            host, port = cfg.syslog_addr.split(":", 1)
            addr = (host, int(port))
        else:
            addr = cfg.syslog_addr
        sy = logging.handlers.SysLogHandler(address=addr, facility=cfg.syslog_facility)
        sy.setLevel(cfg.level)
        handlers.append(sy)

    # Форматтер и фильтры
    if cfg.json_format:
        fmt = JsonFormatter(service=cfg.service, environment=cfg.environment,
                            include_ts=cfg.include_timestamp, tz_utc=cfg.tz_utc)
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    for h in handlers:
        h.setFormatter(fmt)
        h.addFilter(RedactFilter(cfg.redact_keys, cfg.redact_patterns, cfg.hash_salt))
        h.addFilter(DedupFilter(cfg.dedup_window_seconds, cfg.dedup_cache_size))
        h.addFilter(SamplingFilter(cfg.info_sample_rate, cfg.debug_sample_rate))

    _LISTENER = logging.handlers.QueueListener(_QUEUE, *handlers, respect_handler_level=True)
    _LISTENER.daemon = True
    _LISTENER.start()

    # Успокоим шумные логгеры
    for ln in cfg.quiet_loggers:
        logging.getLogger(ln).setLevel(max(logging.WARNING, cfg.level))

    # Перенаправим warnings в logging
    logging.captureWarnings(True)

    _CONFIG = cfg


def get_logger(name: Optional[str] = None) -> ContextLoggerAdapter:
    """Получить адаптер логгера с поддержкой extra['event']."""
    lg = logging.getLogger(name or "app")
    return ContextLoggerAdapter(lg, {})


# --------------------------- Контекст и биндинги ------------------------------

class _ContextToken:
    def __init__(self, **tokens: Any) -> None:
        self.tokens = tokens


def set_trace_id(trace_id: Optional[str]) -> None:
    if _cv_trace_id:
        _cv_trace_id.set(trace_id)


def set_span_id(span_id: Optional[str]) -> None:
    if _cv_span_id:
        _cv_span_id.set(span_id)


def set_request_id(request_id: Optional[str]) -> None:
    if _cv_request_id:
        _cv_request_id.set(request_id)


def set_idempotency_key(key: Optional[str]) -> None:
    if _cv_idempotency_key:
        _cv_idempotency_key.set(key)


def set_subject(subject_id: Optional[str] = None, device_id: Optional[str] = None, session_id: Optional[str] = None) -> None:
    if _cv_subject_id:
        _cv_subject_id.set(subject_id)
    if _cv_device_id:
        _cv_device_id.set(device_id)
    if _cv_session_id:
        _cv_session_id.set(session_id)


def bind_context(
    *,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    request_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    subject_id: Optional[str] = None,
    device_id: Optional[str] = None,
    session_id: Optional[str] = None,
):
    """
    Контекст-менеджер для временного связывания сквозных идентификаторов.
    """
    class _Binder:
        def __enter__(self) -> _ContextToken:
            tokens = {}
            if _cv_trace_id: tokens["trace"] = _cv_trace_id.set(trace_id if trace_id is not None else _cv_trace_id.get())
            if _cv_span_id: tokens["span"] = _cv_span_id.set(span_id if span_id is not None else _cv_span_id.get())
            if _cv_request_id: tokens["req"] = _cv_request_id.set(request_id if request_id is not None else _cv_request_id.get())
            if _cv_idempotency_key: tokens["idem"] = _cv_idempotency_key.set(idempotency_key if idempotency_key is not None else _cv_idempotency_key.get())
            if _cv_subject_id: tokens["subj"] = _cv_subject_id.set(subject_id if subject_id is not None else _cv_subject_id.get())
            if _cv_device_id: tokens["dev"] = _cv_device_id.set(device_id if device_id is not None else _cv_device_id.get())
            if _cv_session_id: tokens["sess"] = _cv_session_id.set(session_id if session_id is not None else _cv_session_id.get())
            return _ContextToken(**tokens)

        def __exit__(self, exc_type, exc, tb) -> None:
            t = getattr(self, "tokens", None)
            return None

    return _Binder()


def _current_context() -> Dict[str, Any]:
    ctx: Dict[str, Any] = {}
    try:
        if _cv_trace_id:
            ctx["trace_id"] = _cv_trace_id.get()
        if _cv_span_id:
            ctx["span_id"] = _cv_span_id.get()
        if _cv_request_id:
            ctx["request_id"] = _cv_request_id.get()
        if _cv_idempotency_key:
            ctx["idempotency_key"] = _cv_idempotency_key.get()
        subject = {}
        if _cv_subject_id and _cv_subject_id.get():
            subject["id"] = _cv_subject_id.get()
        if _cv_device_id and _cv_device_id.get():
            subject["device"] = _cv_device_id.get()
        if _cv_session_id and _cv_session_id.get():
            subject["session"] = _cv_session_id.get()
        if subject:
            ctx["subject"] = subject
    except Exception:
        pass
    return ctx


# --------------------------- Вспомогательные адаптеры -------------------------

def enrich_from_http_headers(headers: Mapping[str, str]) -> None:
    """
    Инициализирует контекст по HTTP-заголовкам:
      - X-Trace-Id, X-Request-Id, Idempotency-Key
    """
    if not headers:
        return
    try:
        # Заголовки могут иметь разный регистр
        h = {k.lower(): v for k, v in headers.items()}
        tid = h.get("x-trace-id") or h.get("traceparent")  # traceparent не парсим глубоко
        rid = h.get("x-request-id")
        idem = h.get("idempotency-key")
        if tid:
            set_trace_id(tid)
        if rid:
            set_request_id(rid)
        if idem:
            set_idempotency_key(idem)
    except Exception:
        pass


# --------------------------- Пример запуска/самопроверка ----------------------

if __name__ == "__main__":
    cfg = TelemetryConfig(
        service="veilmind-core",
        environment=os.getenv("ENV", "dev"),
        file_path=None,
        to_stdout=True,
        hash_salt="demo_salt",
        level=logging.DEBUG,
        info_sample_rate=1.0,
        debug_sample_rate=1.0,
    )
    configure(cfg)

    log = get_logger("demo")
    set_trace_id("demo-trace-123")
    set_request_id("req-42")
    set_subject("alice@example.com", device_id="D-1", session_id="S-1")

    log.info("startup", extra={"event": {"component": "bootstrap", "config": {"env": cfg.environment}}})
    try:
        1 / 0
    except ZeroDivisionError:
        log.exception("unhandled error", extra={"event": {"component": "calc", "operation": "div"}})

    # Проверка редактирования
    log.info("sending Authorization: Bearer SECRET.TOKEN", extra={"event": {"authorization": "Bearer aaa.bbb.ccc"}})
    log.info("card", extra={"event": {"payment": {"pan": "4111111111111111"}}})

    log.debug("debug trace")
    log.warning("warning with idempotency", extra={"event": {"idempotency_key": "abc123"}})
