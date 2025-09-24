# -*- coding: utf-8 -*-
"""
ledger.telemetry.logging — промышленная настройка логирования.

Возможности:
- JSON‑логи (однострочно), UTC‑время в RFC3339.
- Контекст через contextvars: request_id, trace_id/span_id, subject/roles.
- Поддержка traceparent (W3C) и прокидывание из вашего AuthMiddleware.
- Интеграция с OpenTelemetry logs/trace (если установлен opentelemetry).
- Breadcrumbs в Sentry (если установлен sentry-sdk).
- Маскировка секретов (token, password, api_key, authorization и т. п.).
- Семплирование DEBUG/INFO (конфигурируемо).
- Адаптация Uvicorn/Gunicorn: единый формат.
- Хук для добавления кастомных полей.
- Безопасные дефолты уровней для шумных библиотек.

Зависимости: только стандартная библиотека Python.
Опционально: opentelemetry-sdk, sentry-sdk.
"""

from __future__ import annotations

import json
import logging
import logging.config
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import contextvars

# ============================ Контекст запроса ============================

cv_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
cv_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")
cv_span_id: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="-")
cv_subject: contextvars.ContextVar[str] = contextvars.ContextVar("subject", default="-")
cv_roles: contextvars.ContextVar[str] = contextvars.ContextVar("roles", default="-")
cv_env: contextvars.ContextVar[str] = contextvars.ContextVar("env", default=os.getenv("APP_ENV", "staging"))
cv_service: contextvars.ContextVar[str] = contextvars.ContextVar("service", default=os.getenv("APP_NAME", "ledger-core"))
cv_version: contextvars.ContextVar[str] = contextvars.ContextVar("version", default=os.getenv("APP_VERSION", "0.0.0"))

def bind_context(
    *,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    subject: Optional[str] = None,
    roles: Optional[Iterable[str]] = None,
    env: Optional[str] = None,
    service: Optional[str] = None,
    version: Optional[str] = None,
) -> None:
    if request_id: cv_request_id.set(request_id)
    if trace_id: cv_trace_id.set(trace_id)
    if span_id: cv_span_id.set(span_id)
    if subject: cv_subject.set(subject)
    if roles: cv_roles.set(",".join(roles))
    if env: cv_env.set(env)
    if service: cv_service.set(service)
    if version: cv_version.set(version)

def clear_context() -> None:
    for cv in (cv_request_id, cv_trace_id, cv_span_id, cv_subject, cv_roles):
        try:
            cv.set(cv.default)  # type: ignore
        except Exception:
            pass

# ============================ Маскировка/редакция ============================

_SENSITIVE_KEYS = re.compile(
    r"(authorization|password|passwd|secret|token|api[_-]?key|x[-_]api[-_]key|set-cookie|cookie)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._-]+|basic\s+[a-z0-9=:+/_-]+|eyJ[a-zA-Z0-9_-]{10,})"
)
_MASK = "[REDACTED]"

def _redact(obj: Any) -> Any:
    # Маскируем значения по ключам и "похожие на токены" строки.
    try:
        if isinstance(obj, dict):
            return {k: (_MASK if _SENSITIVE_KEYS.search(str(k)) else _redact(v)) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [ _redact(v) for v in obj ]
        if isinstance(obj, str):
            if _SENSITIVE_VALUE.search(obj):
                return _MASK
            return obj
        return obj
    except Exception:
        return obj

# ============================ JSON Formatter ============================

class JsonFormatter(logging.Formatter):
    def __init__(self, *, static_fields: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.static_fields = static_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "env": cv_env.get(),
            "service": cv_service.get(),
            "version": cv_version.get(),
            "request_id": cv_request_id.get(),
            "trace_id": cv_trace_id.get(),
            "span_id": cv_span_id.get(),
            "subject": cv_subject.get(),
            "roles": cv_roles.get(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            base["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            base["exc"] = self.formatException(record.exc_info)

        # Встроенные допполя (record.__dict__) и static_fields
        extras = {k: v for k, v in record.__dict__.items()
                  if k not in ("name","msg","args","levelname","levelno","pathname","filename","module","exc_info","exc_text","stack_info","lineno","funcName","created","msecs","relativeCreated","thread","threadName","processName","process","asctime")}
        base.update(self.static_fields)
        if extras:
            base["extra"] = _redact(extras)

        try:
            return json.dumps(base, ensure_ascii=False, separators=(",", ":"), default=str)
        except Exception:
            # Фоллбек: безопасная строка
            return json.dumps({"ts": ts, "level": record.levelname, "logger": record.name, "msg": "LOG_FORMAT_ERROR"})

# ============================ Фильтры ============================

class SamplingFilter(logging.Filter):
    """
    Семплирует DEBUG/INFO сообщения.
    Пример: sample_debug=0.1 (10% помечаются), INFO не семплируем.
    """
    def __init__(self, sample_debug: float = 1.0, sample_info: float = 1.0):
        super().__init__()
        self._sd = float(max(0.0, min(1.0, sample_debug)))
        self._si = float(max(0.0, min(1.0, sample_info)))

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True
        import random
        p = self._sd if record.levelno <= logging.DEBUG else self._si
        return random.random() < p

class RedactFilter(logging.Filter):
    """
    Маскирует потенциально чувствительные поля в record.extra (см. JsonFormatter).
    Важно: реальная маскировка выполняется в форматтере (_redact), фильтр оставлен для совместимости.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        return True

# ============================ OpenTelemetry/Sentry интеграция ============================

def _try_init_otel_log_bridge() -> None:
    """
    Если установлен opentelemetry, подтягиваем trace_id/span_id из текущего span.
    (Логи остаются через stdlib; мы не включаем экспериментальный OTEL logging handler по умолчанию.)
    """
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            # OTel trace_id: 16 байт, печатается как 32 hex
            cv_trace_id.set("{:032x}".format(ctx.trace_id))
            cv_span_id.set("{:016x}".format(ctx.span_id))
    except Exception:
        pass

def _try_sentry_breadcrumb(record: logging.LogRecord) -> None:
    try:
        import sentry_sdk
        sentry_sdk.add_breadcrumb(
            category=record.name,
            message=record.getMessage(),
            level=_sentry_level(record.levelno),
            data={
                "request_id": cv_request_id.get(),
                "trace_id": cv_trace_id.get(),
                "span_id": cv_span_id.get(),
            },
        )
    except Exception:
        pass

def _sentry_level(level_no: int) -> str:
    if level_no >= logging.ERROR: return "error"
    if level_no >= logging.WARNING: return "warning"
    if level_no >= logging.INFO: return "info"
    return "debug"

# ============================ Handlers ============================

class StderrJsonHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(stream=sys.stderr)
        self.setFormatter(JsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        _try_init_otel_log_bridge()
        _try_sentry_breadcrumb(record)
        super().emit(record)

# ============================ Публичное API ============================

def setup_logging(
    *,
    level: str = os.getenv("LOG_LEVEL", "INFO"),
    sample_debug: float = float(os.getenv("LOG_SAMPLE_DEBUG", "1.0")),
    sample_info: float = float(os.getenv("LOG_SAMPLE_INFO", "1.0")),
    uvicorn_quiet: bool = True,
    third_party_levels: Optional[Dict[str, str]] = None,
    static_fields: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Инициализация глобального логирования. Вызывайте в bootstrap.

    level: глобальный уровень (строка, как в stdlib)
    sample_debug/info: семплирование для снижения шума
    uvicorn_quiet: приглушить шум Uvicorn/Gunicorn default логгеров
    third_party_levels: словарь уровней для библиотек {"httpx": "WARNING"}
    static_fields: статические поля, добавляемые в каждый лог (например, {"region": "eu-north-1"})
    """
    root = logging.getLogger()
    root.setLevel(_to_level(level))

    # Уберём стандартные обработчики (например, от Uvicorn) и заменим на JSON stderr
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = StderrJsonHandler()
    # Подменим форматтер со статическими полями
    handler.setFormatter(JsonFormatter(static_fields=static_fields or {}))
    handler.addFilter(RedactFilter())
    handler.addFilter(SamplingFilter(sample_debug=sample_debug, sample_info=sample_info))
    root.addHandler(handler)

    # Настроим уровни шумных библиотек
    noisy = {
        "uvicorn": "WARNING",
        "uvicorn.access": "WARNING" if uvicorn_quiet else "INFO",
        "gunicorn": "WARNING",
        "asyncio": "WARNING",
        "httpx": "INFO",
        "urllib3": "WARNING",
        "sqlalchemy.engine": os.getenv("SQL_LOG_LEVEL", "WARNING"),
    }
    if third_party_levels:
        noisy.update(third_party_levels)
    for name, lvl in noisy.items():
        logging.getLogger(name).setLevel(_to_level(lvl))

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "app")

def _to_level(v: str | int) -> int:
    if isinstance(v, int):
        return v
    try:
        return getattr(logging, str(v).upper())
    except Exception:
        return logging.INFO

# ============================ Хелперы для HTTP/ASGI ============================

def extract_trace_from_headers(headers: Dict[str, str]) -> None:
    """
    Извлекает traceparent (W3C) и X-Request-Id из заголовков и биндит в контекст логов.
    Вызывайте из HTTP middleware до обработки запроса.
    """
    req_id = headers.get("x-request-id") or headers.get("x_request_id") or "-"
    tp = headers.get("traceparent")
    trace_id = "-"
    span_id = "-"
    if tp and isinstance(tp, str):
        # traceparent: version-traceid-spanid-flags
        parts = tp.split("-")
        if len(parts) >= 3 and len(parts[1]) == 32 and len(parts[2]) == 16:
            trace_id = parts[1]
            span_id = parts[2]
    bind_context(request_id=req_id, trace_id=trace_id, span_id=span_id)

def enrich_with_principal(subject: Optional[str], roles: Optional[Iterable[str]]) -> None:
    bind_context(subject=subject or "-", roles=roles or [])

# ============================ Health‑утилита для логирования ============================

def logging_health() -> Dict[str, Any]:
    """
    Возвращает состояние подсистемы логирования (для /health).
    """
    root = logging.getLogger()
    return {
        "handlers": [type(h).__name__ for h in root.handlers],
        "level": logging.getLevelName(root.level),
        "env": cv_env.get(),
        "service": cv_service.get(),
        "version": cv_version.get(),
    }

# ============================ Примеры использования ============================
# В bootstrap:
#   from ledger.telemetry.logging import setup_logging, bind_context
#   setup_logging(level="INFO", static_fields={"region": os.getenv("REGION","eu-north-1")})
#   bind_context(service="ledger-core", version=os.getenv("APP_VERSION","0.0.0"), env=os.getenv("APP_ENV","staging"))
#
# В ASGI middleware (до роутеров):
#   extract_trace_from_headers({k.lower(): v for k,v in request.headers.items()})
#   principal = request.scope.get("auth.principal")
#   enrich_with_principal(getattr(principal, "subject", None), getattr(principal, "roles", None))
#
# Получение логгера:
#   log = get_logger(__name__)
#   log.info("tx_created", extra={"tx_id": tx.id, "amount": tx.amount, "authorization": "Bearer abc"})  # будет замаскировано
