# cybersecurity-core/cybersecurity/adversary_emulation/observability/logging.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль журналирования для ядра киберэмуляции противника.

Ключевые возможности:
- Идемпотентная глобальная инициализация с очередью и фоновым Listener (не блокирует рабочие потоки).
- Структурные JSON-логи (RFC 3339 timestamp) + опциональный текстовый вывод для TTY.
- Встроенное обогащение записей контекстом (trace_id, span_id, correlation_id, run_id, actor, tenant и т.д.).
- Редакция чувствительных данных (секреты, токены, e-mail, ключи) через настраиваемый фильтр.
- Ротация файлов (по размеру или по времени), syslog и потоковый STDERR/STDOUT.
- Безопасная обработка исключений с полным stacktrace и признаком error.kind/error.message.
- Динамическое изменение уровня логирования во время работы.
- Опциональная интеграция с OpenTelemetry, если доступен пакет (fail-safe).

Зависимости: стандартная библиотека Python. Интеграция с OpenTelemetry активируется автоматически при наличии пакета.
"""

from __future__ import annotations

import contextvars
import dataclasses
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
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

# ---------------------------
# Глобальное состояние
# ---------------------------

_configured_lock = threading.RLock()
_configured = False
_listener: Optional[logging.handlers.QueueListener] = None
_log_queue: Optional[queue.Queue] = None

# ---------------------------
# Контекстные переменные
# ---------------------------

cv_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("correlation_id", default=None)
cv_trace_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("trace_id", default=None)
cv_span_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("span_id", default=None)
cv_run_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("run_id", default=None)
cv_actor: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("actor", default=None)
cv_tenant: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant", default=None)
cv_extra: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("extra", default={})


# ---------------------------
# Утилиты
# ---------------------------

def _now_ts() -> str:
    # RFC3339 (UTC) с миллисекундами
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)


# ---------------------------
# Настройки
# ---------------------------

@dataclasses.dataclass(frozen=True)
class LoggingSettings:
    level: str = _env_str("LOG_LEVEL", "INFO")  # DEBUG/INFO/WARN/ERROR
    fmt: str = _env_str("LOG_FORMAT", "json")   # json | text
    use_utc: bool = _env_bool("LOG_USE_UTC", True)

    # Консоль
    to_stderr: bool = _env_bool("LOG_STDERR", True)

    # Файловый вывод и ротация
    file_path: Optional[str] = os.getenv("LOG_FILE", None)
    rotate_type: str = _env_str("LOG_ROTATE", "size")  # none|size|time
    max_bytes: int = _env_int("LOG_MAX_BYTES", 25 * 1024 * 1024)
    backup_count: int = _env_int("LOG_BACKUP_COUNT", 10)
    when: str = _env_str("LOG_TIME_WHEN", "midnight")
    interval: int = _env_int("LOG_TIME_INTERVAL", 1)
    utc_when: bool = _env_bool("LOG_TIME_UTC", True)

    # Syslog
    syslog_enable: bool = _env_bool("LOG_SYSLOG_ENABLE", False)
    syslog_address: str = _env_str("LOG_SYSLOG_ADDR", "/dev/log")  # или "host:port"
    syslog_facility: int = logging.handlers.SysLogHandler.LOG_USER

    # OpenTelemetry (опционально)
    otel_enable: bool = _env_bool("LOG_OTEL_ENABLE", False)

    # Редакция чувствительных данных
    redact_enable: bool = _env_bool("LOG_REDACT_ENABLE", True)

    # Общие поля
    service_name: str = _env_str("SERVICE_NAME", "adversary-emulation")
    service_version: str = _env_str("SERVICE_VERSION", "0.0.0")
    env: str = _env_str("ENVIRONMENT", "dev")


SETTINGS = LoggingSettings()


# ---------------------------
# Фильтры
# ---------------------------

class ContextEnricher(logging.Filter):
    """Добавляет контекстные поля из contextvars ко всем записям."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.correlation_id = cv_correlation_id.get()
            record.trace_id = cv_trace_id.get()
            record.span_id = cv_span_id.get()
            record.run_id = cv_run_id.get()
            record.actor = cv_actor.get()
            record.tenant = cv_tenant.get()

            extra = cv_extra.get()
            if isinstance(extra, dict):
                for k, v in extra.items():
                    # избегаем перезаписи стандартных полей LogRecord
                    if not hasattr(record, k):
                        setattr(record, k, v)
        except Exception:
            # Не нарушаем логирование из-за проблем с контекстом
            pass
        return True


class RedactionFilter(logging.Filter):
    """
    Редактирует чувствительные данные в полях msg/args/extra.
    Простые шаблоны для токенов/секретов/почты/ключей. Можно расширить правила.
    """

    # Примеры: токены, секреты, e-mail, API-ключи, Bearer и т.п.
    REDACT_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
        (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9\-_\.=]+\b"), r"\1[REDACTED]"),
        (re.compile(r"(?i)\b(api[-_]?key|secret|token|password)\s*[:=]\s*[^,\s]+"), r"\1: [REDACTED]"),
        (re.compile(r"(?i)\b(access|refresh)_token\s*[:=]\s*[^,\s]+"), r"\1_token: [REDACTED]"),
        (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    )

    def __init__(self, enabled: bool = True) -> None:
        super().__init__()
        self.enabled = enabled

    @classmethod
    def _apply(cls, text: str) -> str:
        out = text
        for pattern, repl in cls.REDACT_PATTERNS:
            out = pattern.sub(repl, out)
        return out

    def filter(self, record: logging.LogRecord) -> bool:
        if not self.enabled:
            return True
        try:
            if isinstance(record.msg, str):
                record.msg = self._apply(record.msg)
            if record.args:
                # Перебираем позиционные аргументы
                if isinstance(record.args, tuple):
                    record.args = tuple(self._apply(str(a)) if isinstance(a, str) else a for a in record.args)
                # Словарные аргументы
                elif isinstance(record.args, dict):
                    record.args = {k: self._apply(str(v)) if isinstance(v, str) else v for k, v in record.args.items()}
        except Exception:
            # Никогда не падаем внутри фильтра
            pass
        return True


# ---------------------------
# Форматтеры
# ---------------------------

class JsonFormatter(logging.Formatter):
    """Структурный JSON-форматтер, безопасный к ошибкам."""

    def __init__(self, service: str, version: str, environment: str, use_utc: bool = True) -> None:
        super().__init__()
        self.service = service
        self.version = version
        self.environment = environment
        self.use_utc = use_utc
        self.host = _hostname()
        self.pid = os.getpid()

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.utcfromtimestamp(record.created).replace(tzinfo=timezone.utc).isoformat(timespec="milliseconds") \
            if self.use_utc else datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds")

        payload: Dict[str, Any] = {
            "timestamp": ts,
            "severity": record.levelname,
            "message": self._safe_message(record),
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process": self.pid,
            "thread": record.thread,
            "service": {"name": self.service, "version": self.version, "env": self.environment},
            "host": self.host,
        }

        # Контекст
        for attr in ("correlation_id", "trace_id", "span_id", "run_id", "actor", "tenant"):
            val = getattr(record, attr, None)
            if val is not None:
                payload[attr] = val

        # Доп. пользовательские поля (все нестандартные атрибуты LogRecord)
        self._inject_extra(record, payload)

        # Исключение
        if record.exc_info:
            etype, evalue, etb = record.exc_info
            payload["error"] = {
                "type": getattr(etype, "__name__", str(etype)),
                "message": str(evalue),
                "stacktrace": "".join(traceback.format_exception(etype, evalue, etb)),
            }

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _safe_message(record: logging.LogRecord) -> str:
        try:
            return record.getMessage()
        except Exception:
            return str(record.msg)

    @staticmethod
    def _inject_extra(record: logging.LogRecord, payload: Dict[str, Any]) -> None:
        # Список стандартных атрибутов, которые не считаем "extra"
        std = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info", "exc_text",
            "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process"
        }
        for k, v in record.__dict__.items():
            if k not in std and k not in payload and not k.startswith("_"):
                # Пробуем сериализовать безопасно
                try:
                    json.dumps(v)
                    payload[k] = v
                except Exception:
                    payload[k] = repr(v)


class TextFormatter(logging.Formatter):
    """Лаконичный текстовый форматтер без цветов (подходит для системных журналов и CI)."""

    default_fmt = "[%(asctime)s] %(levelname)s %(name)s: %(message)s (ctx: corr=%(correlation_id)s trace=%(trace_id)s span=%(span_id)s run=%(run_id)s act=%(actor)s ten=%(tenant)s) [%(filename)s:%(lineno)d]"

    def __init__(self, use_utc: bool = True) -> None:
        datefmt = "%Y-%m-%dT%H:%M:%S%z" if not use_utc else "%Y-%m-%dT%H:%M:%SZ"
        super().__init__(fmt=self.default_fmt, datefmt=datefmt)
        self.converter = time.gmtime if use_utc else time.localtime


# ---------------------------
# Конфигурация обработчиков
# ---------------------------

def _make_stream_handler(settings: LoggingSettings) -> logging.Handler:
    handler = logging.StreamHandler(stream=sys.stderr if settings.to_stderr else sys.stdout)
    handler.setFormatter(
        JsonFormatter(settings.service_name, settings.service_version, settings.env, use_utc=settings.use_utc)
        if settings.fmt == "json"
        else TextFormatter(use_utc=settings.use_utc)
    )
    return handler


def _make_file_handler(settings: LoggingSettings) -> Optional[logging.Handler]:
    if not settings.file_path:
        return None
    Path(settings.file_path).parent.mkdir(parents=True, exist_ok=True)

    if settings.rotate_type == "none":
        fh: logging.Handler = logging.FileHandler(settings.file_path, encoding="utf-8")
    elif settings.rotate_type == "size":
        fh = logging.handlers.RotatingFileHandler(
            settings.file_path, maxBytes=settings.max_bytes, backupCount=settings.backup_count, encoding="utf-8"
        )
    elif settings.rotate_type == "time":
        fh = logging.handlers.TimedRotatingFileHandler(
            settings.file_path,
            when=settings.when,
            interval=settings.interval,
            backupCount=settings.backup_count,
            utc=settings.utc_when,
            encoding="utf-8",
        )
    else:
        # Неверное значение, откатываемся к size
        fh = logging.handlers.RotatingFileHandler(
            settings.file_path, maxBytes=settings.max_bytes, backupCount=settings.backup_count, encoding="utf-8"
        )

    fh.setFormatter(
        JsonFormatter(settings.service_name, settings.service_version, settings.env, use_utc=settings.use_utc)
        if settings.fmt == "json"
        else TextFormatter(use_utc=settings.use_utc)
    )
    return fh


def _make_syslog_handler(settings: LoggingSettings) -> Optional[logging.Handler]:
    if not settings.syslog_enable:
        return None
    address: Any
    if ":" in settings.syslog_address:
        host, port = settings.syslog_address.split(":", 1)
        address = (host, int(port))
    else:
        address = settings.syslog_address  # локальный сокет
    sh = logging.handlers.SysLogHandler(address=address, facility=settings.syslog_facility)
    sh.setFormatter(
        JsonFormatter(settings.service_name, settings.service_version, settings.env, use_utc=settings.use_utc)
        if settings.fmt == "json"
        else TextFormatter(use_utc=settings.use_utc)
    )
    return sh


def _maybe_setup_otel_bridge(root_logger: logging.Logger, settings: LoggingSettings) -> None:
    """Опциональная интеграция с OpenTelemetry логами, если доступна."""
    if not settings.otel_enable:
        return
    try:
        # В Python экосистеме лог-мост OTel может отличаться по версиям;
        # защищаемся от ImportError и любых несовместимостей.
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter  # type: ignore

        provider = LoggerProvider()
        exporter = OTLPLogExporter()  # конфиг по переменным окружения OTEL_EXPORTER_OTLP_*
        provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
        otel_handler = LoggingHandler(level=_parse_level(settings.level), logger_provider=provider)

        # Формат JSON, чтобы сохранить единообразие
        otel_handler.setFormatter(JsonFormatter(settings.service_name, settings.service_version, settings.env, use_utc=settings.use_utc))

        root_logger.addHandler(otel_handler)
        root_logger.debug("OpenTelemetry logging bridge enabled")
    except Exception:
        # Тихо пропускаем, чтобы не ломать приложение
        root_logger.debug("OpenTelemetry logging bridge not enabled", exc_info=False)


# ---------------------------
# Инициализация
# ---------------------------

def _parse_level(level_name: str) -> int:
    return getattr(logging, level_name.upper(), logging.INFO)


def configure(settings: LoggingSettings = SETTINGS) -> None:
    """Инициализирует глобальную конфигурацию логирования. Идемпотентна."""
    global _configured, _listener, _log_queue

    with _configured_lock:
        if _configured:
            return

        root = logging.getLogger()
        root.setLevel(_parse_level(settings.level))

        # Очередь и асинхронный Listener
        _log_queue = queue.Queue(-1)
        queue_handler = logging.handlers.QueueHandler(_log_queue)

        # Базовые фильтры на входе в очередь
        queue_handler.addFilter(ContextEnricher())
        queue_handler.addFilter(RedactionFilter(enabled=settings.redact_enable))

        # Подменяем все существующие обработчики на QueueHandler
        for h in list(root.handlers):
            root.removeHandler(h)
        root.addHandler(queue_handler)

        # Настраиваем конечные обработчики для Listener
        handlers: Iterable[logging.Handler] = [h for h in [
            _make_stream_handler(settings),
            _make_file_handler(settings),
            _make_syslog_handler(settings),
        ] if h is not None]

        _listener = logging.handlers.QueueListener(_log_queue, *handlers, respect_handler_level=True)
        _listener.daemon = True
        _listener.start()

        # Отключаем шум популярных логгеров по умолчанию (можно переопределить позже)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("botocore").setLevel(logging.WARNING)

        # Опционально подключаем OpenTelemetry bridge
        _maybe_setup_otel_bridge(root, settings)

        _configured = True
        root.debug("Logging configured", extra={"service": settings.service_name, "env": settings.env})


# ---------------------------
# Публичные API
# ---------------------------

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Возвращает настроенный логгер.
    Гарантирует, что конфигурация выполнена ровно один раз.
    """
    if not _configured:
        configure()
    return logging.getLogger(name) if name else logging.getLogger()


def set_level(level: str, logger_name: Optional[str] = None) -> None:
    """
    Динамически меняет уровень логирования.
    Пример: set_level("DEBUG"), set_level("ERROR", "cybersecurity.core")
    """
    log = get_logger(__name__)
    lvl = _parse_level(level)
    if logger_name:
        logging.getLogger(logger_name).setLevel(lvl)
        log.debug("Logger level changed", extra={"logger_name": logger_name, "level": level})
    else:
        logging.getLogger().setLevel(lvl)
        log.debug("Root logger level changed", extra={"level": level})


def set_context(
    *,
    correlation_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    run_id: Optional[str] = None,
    actor: Optional[str] = None,
    tenant: Optional[str] = None,
    **extra: Any,
) -> None:
    """
    Устанавливает контекст для текущего контекста выполнения (async/thread-safe).
    """
    if correlation_id is not None:
        cv_correlation_id.set(correlation_id)
    if trace_id is not None:
        cv_trace_id.set(trace_id)
    if span_id is not None:
        cv_span_id.set(span_id)
    if run_id is not None:
        cv_run_id.set(run_id)
    if actor is not None:
        cv_actor.set(actor)
    if tenant is not None:
        cv_tenant.set(tenant)

    current_extra = dict(cv_extra.get())
    current_extra.update(extra)
    cv_extra.set(current_extra)


def clear_context(*keys: str) -> None:
    """
    Очищает контекст.
    Если keys не переданы — очищает все.
    """
    if not keys:
        cv_correlation_id.set(None)
        cv_trace_id.set(None)
        cv_span_id.set(None)
        cv_run_id.set(None)
        cv_actor.set(None)
        cv_tenant.set(None)
        cv_extra.set({})
        return

    # Частичная очистка
    for k in keys:
        if k == "correlation_id":
            cv_correlation_id.set(None)
        elif k == "trace_id":
            cv_trace_id.set(None)
        elif k == "span_id":
            cv_span_id.set(None)
        elif k == "run_id":
            cv_run_id.set(None)
        elif k == "actor":
            cv_actor.set(None)
        elif k == "tenant":
            cv_tenant.set(None)
        elif k == "extra":
            cv_extra.set({})
        else:
            # Удаление ключа из extra
            extra = dict(cv_extra.get())
            if k in extra:
                extra.pop(k, None)
                cv_extra.set(extra)


def security_event(
    logger: logging.Logger,
    *,
    action: str,
    outcome: str,
    severity: str = "INFO",
    category: Optional[str] = None,
    src: Optional[Mapping[str, Any]] = None,
    dst: Optional[Mapping[str, Any]] = None,
    user: Optional[Mapping[str, Any]] = None,
    **details: Any,
) -> None:
    """
    Унифицированная запись security-события.
    Пример:
        security_event(log, action="credential.use", outcome="success",
                       src={"ip": "10.0.0.1"}, user={"id":"42"}, resource="/admin")
    """
    level = _parse_level(severity)
    payload: Dict[str, Any] = {
        "event": {"kind": "security", "action": action, "outcome": outcome, "category": category},
        "src": src or {},
        "dst": dst or {},
        "user": user or {},
    }
    payload.update(details)
    logger.log(level, "security_event", extra=payload)


def shutdown() -> None:
    """
    Корректно останавливает listener и сбрасывает буферы.
    Полезно в тестах и при управляемом завершении.
    """
    global _listener, _log_queue, _configured
    with _configured_lock:
        root = logging.getLogger()
        if _listener:
            _listener.stop()
            _listener = None
        if _log_queue:
            try:
                while not _log_queue.empty():
                    _log_queue.get_nowait()
            except Exception:
                pass
            _log_queue = None
        # Удаляем QueueHandler и оставшиеся хендлеры
        for h in list(root.handlers):
            root.removeHandler(h)
            try:
                h.flush()
                h.close()
            except Exception:
                pass
        _configured = False


# ---------------------------
# Автоконфигурация при импортe (опционально)
# ---------------------------

if _env_bool("LOG_AUTOCONFIGURE", True):
    try:
        configure()
    except Exception:
        # Пытаемся максимально не сорвать запуск приложения
        logging.basicConfig(level=_parse_level(SETTINGS.level))
        logging.getLogger(__name__).exception("Fallback logging configured due to initialization error")
