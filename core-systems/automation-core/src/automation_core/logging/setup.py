# automation-core/src/automation_core/logging/setup.py
# -*- coding: utf-8 -*-
"""
Промышленная настройка логирования для automation-core.

Факты и ссылки:
- Основа — стандартные модули logging и logging.config.dictConfig (официальная документация Python).  # noqa: E501
- Ротация файлов — RotatingFileHandler и TimedRotatingFileHandler из logging.handlers.               # noqa: E501
- Инжекция трассировочного контекста — через OpenTelemetry Python (если установлен),                 # noqa: E501
  совместимо со спецификацией W3C Trace Context (trace_id/span_id).                                 # noqa: E501
См. источники: Python logging, dictConfig, handlers; W3C Trace Context; OpenTelemetry logging.       # noqa: E501
"""

from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import logging.config
import logging.handlers
import os
import re
import socket
import sys
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# ---------------------------- Контекстные переменные ----------------------------

_request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
_tenant_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("tenant_id", default=None)
_user_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("user_id", default=None)

def set_request_context(
    request_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> None:
    """Устанавливает идентификаторы контекста для последующего логирования."""
    if request_id is not None:
        _request_id_var.set(request_id)
    if tenant_id is not None:
        _tenant_id_var.set(tenant_id)
    if user_id is not None:
        _user_id_var.set(user_id)

# ---------------------------- OpenTelemetry (опционально) -----------------------

def _get_otel_trace_context() -> Dict[str, Optional[str]]:
    """
    Пытается получить trace_id и span_id из текущего контекста OpenTelemetry.
    Если OTel не установлен или контекст отсутствует — возвращает None-поля.

    Подтверждение: OpenTelemetry logging интеграция автоматически инжектирует
    трассировочный контекст в записи логов/record factory. :contentReference[oaicite:1]{index=1}
    Спецификация формата (W3C Trace Context). :contentReference[oaicite:2]{index=2}
    """
    try:
        from opentelemetry import trace  # type: ignore
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if getattr(ctx, "is_valid", lambda: False)():
            # W3C Trace Context: trace_id 16 байт (32 hex), span_id 8 байт (16 hex). :contentReference[oaicite:3]{index=3}
            trace_id = f"{ctx.trace_id:032x}"
            span_id = f"{ctx.span_id:016x}"
            return {"trace_id": trace_id, "span_id": span_id}
    except Exception:
        pass
    return {"trace_id": None, "span_id": None}

# ---------------------------- Фильтры и форматтеры ------------------------------

class RedactFilter(logging.Filter):
    """
    Редактор чувствительных данных: применяет набор регэкспов к message и extra-полям.
    Примеры паттернов: (?i)api[_-]?key, (?i)secret, (?i)password
    """
    def __init__(self, patterns: Sequence[str], replacement: str = "[REDACTED]") -> None:
        super().__init__()
        self._compiled = [re.compile(p) for p in patterns]
        self._replacement = replacement

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        try:
            if isinstance(record.msg, str):
                for rx in self._compiled:
                    record.msg = rx.sub(self._replacement, record.msg)
            # Пройдемся по известным строковым атрибутам
            for key, val in list(record.__dict__.items()):
                if isinstance(val, str):
                    for rx in self._compiled:
                        record.__dict__[key] = rx.sub(self._replacement, val)
        except Exception:
            # Никогда не ломаем логирование
            pass
        return True


class SamplingFilter(logging.Filter):
    """
    Простая выборочная фильтрация DEBUG/INFO: пропускает только 1 из N сообщений
    для заданных уровней, чтобы снизить шум в высоконагруженных сервисах.
    """
    def __init__(self, every_n: int = 10, levels: Sequence[int] = (logging.DEBUG,)) -> None:
        super().__init__()
        self.every_n = max(1, int(every_n))
        self.levels = set(levels)
        self._counter = 0

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if record.levelno not in self.levels:
            return True
        self._counter = (self._counter + 1) % self.every_n
        return self._counter == 0


class JsonFormatter(logging.Formatter):
    """
    Минималистичный JSON-форматтер с расширенным контекстом.
    Поля: ts, level, logger, msg, module, line, pid, thread, host, service, env,
          version, request_id, tenant_id, user_id, trace_id, span_id, extra.
    """
    def __init__(self, service: str, environment: str, version: str) -> None:
        super().__init__()
        self.service = service
        self.environment = environment
        self.version = version
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        otel = _get_otel_trace_context()
        payload: Dict[str, Any] = {
            "ts": _dt.datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "pid": record.process,
            "thread": record.threadName,
            "host": self.hostname,
            "service": self.service,
            "env": self.environment,
            "version": self.version,
            "request_id": _request_id_var.get(),
            "tenant_id": _tenant_id_var.get(),
            "user_id": _user_id_var.get(),
            "trace_id": otel["trace_id"],
            "span_id": otel["span_id"],
        }
        # Включим дополнительные поля, если они сериализуемы
        for k, v in record.__dict__.items():
            if k in payload:
                continue
            if k.startswith("_"):
                continue
            if k in (
                "msg", "args", "name", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "process", "asctime"
            ):
                continue
            try:
                json.dumps(v)  # проверка сериализуемости
                payload.setdefault("extra", {})[k] = v
            except Exception:
                payload.setdefault("extra", {})[k] = repr(v)

        if record.exc_info:
            payload["error"] = {
                "type": str(record.exc_info[0].__name__),
                "message": str(record.exc_info[1]),
                "stack": self.formatException(record.exc_info),
            }
        return json.dumps(payload, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """
    Компактный текстовый формат для разработки.
    """
    default_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    default_datefmt = "%Y-%m-%dT%H:%M:%S"

    def __init__(self) -> None:
        super().__init__(self.default_fmt, self.default_datefmt)


# ---------------------------- Конфигуратор dictConfig --------------------------

def build_dict_config(
    *,
    service: str = "automation-core",
    environment: str = None,
    version: str = "1.0.0",
    level: str = None,
    json_logs: bool = True,
    redact_patterns: Optional[Sequence[str]] = None,
    sampling_every_n: Optional[int] = None,
    console: bool = True,
    file_path: Optional[str] = None,
    rotate_when: Optional[str] = None,  # 'S','M','H','D','midnight','W0'-'W6'
    rotate_interval: int = 1,
    rotate_max_bytes: int = 10 * 1024 * 1024,
    rotate_backup_count: int = 10,
) -> Dict[str, Any]:
    """
    Собирает конфигурацию для logging.config.dictConfig.

    Подтверждение:
    - dictConfig — штатный способ конфигурирования логирования в Python. :contentReference[oaicite:4]{index=4}
    - Ротация файлов средствами logging.handlers (RotatingFileHandler/TimedRotatingFileHandler). :contentReference[oaicite:5]{index=5}
    """
    environment = environment or os.getenv("APP_ENV", "dev")
    level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    redact_patterns = redact_patterns or [
        r"(?i)api[_-]?key\s*=\s*[\w\-]+",
        r"(?i)secret\s*=\s*[\w\-]+",
        r"(?i)password\s*=\s*[^&\s]+",
        r"(?i)token\s*=\s*[\w\.-]+",
    ]

    handlers: Dict[str, Any] = {}
    filters: Dict[str, Any] = {
        "redact": {
            "()": f"{__name__}.RedactFilter",
            "patterns": list(redact_patterns),
            "replacement": "[REDACTED]",
        }
    }
    if sampling_every_n and sampling_every_n > 1:
        filters["sample"] = {
            "()": f"{__name__}.SamplingFilter",
            "every_n": int(sampling_every_n),
            "levels": [logging.DEBUG],
        }

    if console:
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": level,
            "stream": "ext://sys.stdout",
            "filters": ["redact"] + (["sample"] if "sample" in filters else []),
            "formatter": "json" if json_logs else "console",
        }

    if file_path:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        if rotate_when:
            # Временная ротация
            handlers["file"] = {
                "class": "logging.handlers.TimedRotatingFileHandler",
                "level": level,
                "filename": file_path,
                "when": rotate_when,
                "interval": int(rotate_interval),
                "backupCount": int(rotate_backup_count),
                "encoding": "utf-8",
                "filters": ["redact"] + (["sample"] if "sample" in filters else []),
                "formatter": "json" if json_logs else "console",
                "utc": True,
            }
        else:
            # Ротация по размеру
            handlers["file"] = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": level,
                "filename": file_path,
                "maxBytes": int(rotate_max_bytes),
                "backupCount": int(rotate_backup_count),
                "encoding": "utf-8",
                "filters": ["redact"] + (["sample"] if "sample" in filters else []),
                "formatter": "json" if json_logs else "console",
            }

    formatters: Dict[str, Any] = {
        "json": {
            "()": f"{__name__}.JsonFormatter",
            "service": service,
            "environment": environment,
            "version": version,
        },
        "console": {
            "()": f"{__name__}.ConsoleFormatter",
        },
    }

    root_handlers = list(handlers.keys()) or ["console"]

    cfg: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": filters,
        "formatters": formatters,
        "handlers": handlers,
        "root": {
            "level": level,
            "handlers": root_handlers,
        },
    }
    return cfg


def configure_logging(
    *,
    service: str = "automation-core",
    environment: Optional[str] = None,
    version: str = "1.0.0",
    level: Optional[str] = None,
    json_logs: bool = True,
    redact_patterns: Optional[Sequence[str]] = None,
    sampling_every_n: Optional[int] = None,
    console: bool = True,
    file_path: Optional[str] = None,
    rotate_when: Optional[str] = None,
    rotate_interval: int = 1,
    rotate_max_bytes: int = 10 * 1024 * 1024,
    rotate_backup_count: int = 10,
) -> None:
    """
    Применяет конфигурацию к корневому логгеру через dictConfig.
    """
    cfg = build_dict_config(
        service=service,
        environment=environment,
        version=version,
        level=level,
        json_logs=json_logs,
        redact_patterns=redact_patterns,
        sampling_every_n=sampling_every_n,
        console=console,
        file_path=file_path,
        rotate_when=rotate_when,
        rotate_interval=rotate_interval,
        rotate_max_bytes=rotate_max_bytes,
        rotate_backup_count=rotate_backup_count,
    )
    logging.config.dictConfig(cfg)  # Официальный способ конфигурирования. :contentReference[oaicite:6]{index=6}


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Возвращает именованный логгер (или корневой)."""
    return logging.getLogger(name if name else "")

# ---------------------------- Пример минимального применения -------------------

if __name__ == "__main__":
    # Пример безопасной дефолтной конфигурации: JSON в stdout + ротация файлов ночью.
    configure_logging(
        service=os.getenv("SERVICE_NAME", "automation-core"),
        environment=os.getenv("APP_ENV", "dev"),
        version=os.getenv("APP_VERSION", "1.0.0"),
        level=os.getenv("LOG_LEVEL", "INFO"),
        json_logs=True,
        console=True,
        file_path=os.getenv("LOG_FILE", "./logs/app.log"),
        rotate_when=os.getenv("LOG_ROTATE_WHEN", "midnight"),
        rotate_backup_count=int(os.getenv("LOG_BACKUP_COUNT", "14")),
    )
    set_request_context(request_id="demo-req", tenant_id="t-42", user_id="u-100")
    log = get_logger(__name__)
    log.info("logging subsystem initialized")
    try:
        raise RuntimeError("example exception")
    except Exception:
        log.exception("captured exception")
