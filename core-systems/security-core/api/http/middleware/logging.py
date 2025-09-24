# security-core/api/http/middleware/logging.py
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import re
import sys
import time
import traceback
import typing as t
import uuid
from dataclasses import dataclass, field
from functools import partial
from types import TracebackType

from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Опционально используем OpenTelemetry, если установлен
try:
    from opentelemetry import trace as otel_trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False

# -------------------------
# Контекст и настройки
# -------------------------

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")
_tenant_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("tenant", default="")
_actor_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("actor", default="")

# Упрощенный JSON‑форматтер без внешних зависимостей
class JsonFormatter(logging.Formatter):
    def __init__(self, static_fields: t.Optional[dict] = None):
        super().__init__()
        self.static_fields = static_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Подмешиваем extra
        for key, val in record.__dict__.items():
            if key in ("args", "msg", "name", "levelno", "levelname", "pathname", "filename",
                       "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                       "created", "msecs", "relativeCreated", "thread", "threadName",
                       "processName", "process"):
                continue
            # Избежать коллизий с базовыми полями
            if key in payload:
                payload[f"extra_{key}"] = val
            else:
                payload[key] = val

        payload.update(self.static_fields)

        # Добавляем контекст
        rid = _request_id_ctx.get()
        tid = _trace_id_ctx.get()
        ten = _tenant_ctx.get()
        act = _actor_ctx.get()
        if rid:
            payload.setdefault("request_id", rid)
        if tid:
            payload.setdefault("trace_id", tid)
        if ten:
            payload.setdefault("tenant", ten)
        if act:
            payload.setdefault("actor", act)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _default_logger() -> logging.Logger:
    logger = logging.getLogger("security_core.http")
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonFormatter({"component": "http-logging-middleware"}))
        logger.addHandler(handler)
        logger.setLevel(os.getenv("SEC_CORE_HTTP_LOG_LEVEL", "INFO").upper())
    return logger

def get_request_id() -> str:
    return _request_id_ctx.get()

def get_trace_id() -> str:
    return _trace_id_ctx.get()

def get_tenant() -> str:
    return _tenant_ctx.get()

def get_actor() -> str:
    return _actor_ctx.get()

@dataclass
class LoggingConfig:
    # Что логировать
    log_request_headers: bool = True
    log_request_body: bool = False
    log_response_headers: bool = False
    log_response_body: bool = False

    # Сэмплирование тел
    request_body_sample_rate: float = 0.1
    response_body_sample_rate: float = 0.05

    # Ограничения
    max_body_log_bytes: int = 4096
    max_header_value_len: int = 1024

    # Исключаемые пути
    exclude_paths: t.Tuple[re.Pattern, ...] = field(default_factory=lambda: (
        re.compile(r"^/health/?$"),
        re.compile(r"^/metrics/?$"),
        re.compile(r"^/(docs|redoc|openapi\.json)$"),
        re.compile(r"^/favicon\.ico$"),
    ))

    # Редакторы секретов
    redaction_patterns: t.Tuple[re.Pattern, ...] = field(default_factory=lambda: (
        re.compile(r"(?i)(authorization:\s*bearer\s+)[\w\.\-\+=/]+"),
        re.compile(r"(?i)(api[-_]?key[:=]\s*)[^\s,;]+"),
        re.compile(r"(?i)(secret|password|pass|token|sessionid|cookie)[\"\']?\s*[:=]\s*[\"\']?[^\"\'\s,;]+"),
    ))
    redaction_mask: str = "<redacted>"

    # Корреляция
    request_id_header: str = "x-request-id"
    correlation_headers: t.Tuple[str, ...] = ("x-correlation-id", "x-request-id")
    tenant_headers: t.Tuple[str, ...] = ("x-tenant-id", "x-org-id", "x-project-id")
    actor_headers: t.Tuple[str, ...] = ("x-actor", "x-user-id", "x-user")

    # Источник IP
    real_ip_headers: t.Tuple[str, ...] = ("x-forwarded-for", "x-real-ip")

    # Прочее
    slow_threshold_ms: int = 1500
    include_query_string: bool = True

    # Авто‑выключение логов тел для больших объектов
    skip_body_if_over_bytes: int = 1_000_000

    # Включать лог на уровне DEBUG подробный набор
    debug_verbose: bool = False

    @staticmethod
    def from_env() -> "LoggingConfig":
        def get_bool(env: str, default: bool) -> bool:
            v = os.getenv(env)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "y", "on")
        def get_float(env: str, default: float) -> float:
            try:
                return float(os.getenv(env, default))
            except Exception:
                return default
        def get_int(env: str, default: int) -> int:
            try:
                return int(os.getenv(env, default))
            except Exception:
                return default

        return LoggingConfig(
            log_request_headers=get_bool("SEC_CORE_LOG_REQ_HEADERS", True),
            log_request_body=get_bool("SEC_CORE_LOG_REQ_BODY", False),
            log_response_headers=get_bool("SEC_CORE_LOG_RESP_HEADERS", False),
            log_response_body=get_bool("SEC_CORE_LOG_RESP_BODY", False),
            request_body_sample_rate=get_float("SEC_CORE_LOG_REQ_BODY_RATE", 0.1),
            response_body_sample_rate=get_float("SEC_CORE_LOG_RESP_BODY_RATE", 0.05),
            max_body_log_bytes=get_int("SEC_CORE_LOG_MAX_BODY_BYTES", 4096),
            slow_threshold_ms=get_int("SEC_CORE_LOG_SLOW_MS", 1500),
            debug_verbose=get_bool("SEC_CORE_LOG_DEBUG_VERBOSE", False),
        )

# -------------------------
# Вспомогательные функции
# -------------------------

def _match_any(patterns: t.Tuple[re.Pattern, ...], path: str) -> bool:
    for p in patterns:
        if p.search(path):
            return True
    return False

def _gen_request_id() -> str:
    return str(uuid.uuid4())

def _parse_traceparent_header(traceparent: str) -> t.Tuple[str, str]:
    # Формат: version-traceid-spanid-flags
    # Пример: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
    parts = traceparent.split("-")
    if len(parts) == 4:
        return parts[1], parts[2]
    return "", ""

def _first_header_value(headers: t.Sequence[t.Tuple[bytes, bytes]], keys: t.Tuple[str, ...]) -> str:
    lower = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers}
    for key in keys:
        v = lower.get(key.lower())
        if v:
            return v
    return ""

def _client_ip(headers: t.Sequence[t.Tuple[bytes, bytes]], default: str) -> str:
    val = _first_header_value(headers, ("x-forwarded-for", "x-real-ip"))
    if val:
        # Берем первый IP из XFF
        return val.split(",")[0].strip()
    return default

def _safe_len(b: t.Optional[bytes]) -> int:
    return len(b) if b is not None else 0

def _should_sample(rate: float) -> bool:
    if rate >= 1.0:
        return True
    if rate <= 0.0:
        return False
    # Простое детерминированное сэмплирование по UUID request_id
    rid = _request_id_ctx.get() or ""
    if not rid:
        rid = _gen_request_id()
    try:
        # Используем первые 8 hex символов
        x = int(rid.replace("-", "")[:8], 16)
        return (x % 10_000) < int(rate * 10_000)
    except Exception:
        return False

def _redact_text(text: str, patterns: t.Tuple[re.Pattern, ...], mask: str) -> str:
    for p in patterns:
        text = p.sub(lambda m: (m.group(1) if m.groups() else "") + mask, text)
    return text

def _truncate_bytes(data: bytes, limit: int) -> bytes:
    if len(data) <= limit:
        return data
    return data[:limit] + b"...[truncated]"

def _is_textual(content_type: str) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    return any((
        ct.startswith("text/"),
        "json" in ct,
        "xml" in ct,
        "javascript" in ct,
        "x-www-form-urlencoded" in ct,
    ))

# -------------------------
# Middleware
# -------------------------

class LoggingMiddleware:
    """
    Структурированное логирование HTTP запросов/ответов для ASGI (FastAPI/Starlette).
    Безопасно работает со streaming‑телами, поддерживает корреляцию и redaction.
    """
    def __init__(self, app: ASGIApp, logger: t.Optional[logging.Logger] = None, config: t.Optional[LoggingConfig] = None):
        self.app = app
        self.logger = logger or _default_logger()
        self.cfg = config or LoggingConfig.from_env()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        path: str = scope.get("path", "/")
        raw_headers: t.Sequence[t.Tuple[bytes, bytes]] = scope.get("headers", [])
        http_version: str = scope.get("http_version", "1.1")
        client_host: str = (scope.get("client") or ("", 0))[0]
        ua = _first_header_value(raw_headers, ("user-agent",))
        content_type = _first_header_value(raw_headers, ("content-type",))

        if self.cfg.include_query_string and scope.get("query_string"):
            try:
                qs = scope["query_string"].decode("latin-1")
                full_path = f"{path}?{qs}" if qs else path
            except Exception:
                full_path = path
        else:
            full_path = path

        # Пропускаем лишние пути
        if _match_any(self.cfg.exclude_paths, path):
            await self.app(scope, receive, send)
            return

        # Корреляция
        incoming_req_id = _first_header_value(raw_headers, (self.cfg.request_id_header,))
        corr_id = _first_header_value(raw_headers, self.cfg.correlation_headers) or incoming_req_id or _gen_request_id()
        _request_id_ctx.set(corr_id)

        # W3C traceparent
        traceparent = _first_header_value(raw_headers, ("traceparent",))
        trace_id, span_id = _parse_traceparent_header(traceparent) if traceparent else ("", "")
        if not trace_id and _OTEL:
            # попробуем взять из активного span
            span = otel_trace.get_current_span()
            ctx = span.get_span_context() if span else None  # type: ignore
            if ctx and ctx.trace_id:
                trace_id = "{:032x}".format(ctx.trace_id)
        _trace_id_ctx.set(trace_id)

        # Тенант/Актор
        tenant = _first_header_value(raw_headers, self.cfg.tenant_headers)
        actor = _first_header_value(raw_headers, self.cfg.actor_headers)
        if tenant:
            _tenant_ctx.set(tenant)
        if actor:
            _actor_ctx.set(actor)

        # Клиентский IP
        remote_ip = _client_ip(raw_headers, client_host or "")

        # Подготовка логов
        start = time.perf_counter()
        request_body_cache: t.Optional[bytes] = None
        response_status: int = 0
        response_headers: t.List[t.Tuple[bytes, bytes]] = []
        response_body_size = 0
        response_content_type = ""

        # Обертка receive для захвата тела запроса (без порчи потока)
        async def wrapped_receive() -> Message:
            nonlocal request_body_cache
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                if request_body_cache is None:
                    request_body_cache = body
                else:
                    # накапливаем до лимита skip_body_if_over_bytes
                    if _safe_len(request_body_cache) + len(body) <= self.cfg.skip_body_if_over_bytes:
                        request_body_cache += body
                # не меняем more_body
            return message

        # Обертка send для перехвата ответа
        async def wrapped_send(message: Message) -> None:
            nonlocal response_status, response_headers, response_body_size, response_content_type
            if message["type"] == "http.response.start":
                response_status = int(message["status"])
                response_headers = list(message.get("headers") or [])
                response_content_type = _first_header_value(response_headers, ("content-type",))
            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                response_body_size += len(body)
            await send(message)

        # Выполняем запрос
        err: t.Optional[BaseException] = None
        try:
            await self.app(scope, wrapped_receive, wrapped_send)
        except BaseException as e:
            err = e
            # Логируем ошибку и пробрасываем дальше
            await self._log_exception(
                method=method,
                path=full_path,
                http_version=http_version,
                ua=ua,
                content_type=content_type,
                remote_ip=remote_ip,
            )
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            await self._log_summary(
                method=method,
                path=full_path,
                http_version=http_version,
                ua=ua,
                req_headers=raw_headers,
                req_content_type=content_type,
                req_body=request_body_cache,
                status=response_status,
                resp_headers=response_headers,
                resp_content_type=response_content_type,
                resp_size=response_body_size,
                remote_ip=remote_ip,
                duration_ms=duration_ms,
                error=err,
            )

    # -------------------------
    # Логика логирования
    # -------------------------

    async def _log_exception(self, *, method: str, path: str, http_version: str, ua: str, content_type: str, remote_ip: str) -> None:
        logger = self.logger
        exc_type, exc, tb = sys.exc_info()
        stack = "".join(traceback.format_exception(exc_type, exc, tb))
        logger.error(
            "Unhandled exception during request",
            extra={
                "event": "http.server.exception",
                "http_method": method,
                "http_path": path,
                "http_version": http_version,
                "user_agent": ua,
                "remote_ip": remote_ip,
                "content_type": content_type,
                "exception_type": getattr(exc_type, "__name__", str(exc_type)),
                "exception_message": str(exc) if exc else "",
                "stacktrace": stack,
            },
        )

    async def _log_summary(
        self,
        *,
        method: str,
        path: str,
        http_version: str,
        ua: str,
        req_headers: t.Sequence[t.Tuple[bytes, bytes]],
        req_content_type: str,
        req_body: t.Optional[bytes],
        status: int,
        resp_headers: t.Sequence[t.Tuple[bytes, bytes]],
        resp_content_type: str,
        resp_size: int,
        remote_ip: str,
        duration_ms: int,
        error: t.Optional[BaseException],
    ) -> None:
        logger = self.logger

        level = logging.INFO
        if error is not None or status >= 500:
            level = logging.ERROR
        elif duration_ms >= self.cfg.slow_threshold_ms:
            level = logging.WARNING
        elif status >= 400:
            level = logging.WARNING

        # Базовые поля
        extra: dict = {
            "event": "http.server.request",
            "http_method": method,
            "http_path": path,
            "http_version": http_version,
            "status_code": status,
            "duration_ms": duration_ms,
            "remote_ip": remote_ip,
            "user_agent": ua,
            "request_id": _request_id_ctx.get(),
            "trace_id": _trace_id_ctx.get(),
            "tenant": _tenant_ctx.get(),
            "actor": _actor_ctx.get(),
            "response_size": resp_size,
        }

        # Заголовки (с подрезкой длинных значений)
        if self.cfg.log_request_headers:
            extra["request_headers"] = _clip_headers(req_headers, self.cfg.max_header_value_len)
        if self.cfg.log_response_headers:
            extra["response_headers"] = _clip_headers(resp_headers, self.cfg.max_header_value_len)

        # Захват тела запроса (безопасно и выборочно)
        if (
            self.cfg.log_request_body
            and req_body is not None
            and _safe_len(req_body) <= self.cfg.skip_body_if_over_bytes
            and _is_textual(req_content_type)
            and _should_sample(self.cfg.request_body_sample_rate)
        ):
            text = _bytes_to_text(req_body, req_content_type, self.cfg.max_body_log_bytes)
            text = _redact_text(text, self.cfg.redaction_patterns, self.cfg.redaction_mask)
            extra["request_body"] = text
        else:
            extra["request_body_bytes"] = _safe_len(req_body)

        # Ответ
        if (
            self.cfg.log_response_body
            and _is_textual(resp_content_type)
            and _should_sample(self.cfg.response_body_sample_rate)
        ):
            # Тело ответа может быть стримом — мы не храним его полностью.
            # Поэтому логируем только размер и заголовок Content-Type.
            extra["response_body_note"] = "body not captured (streaming); only size logged"
        # Всегда полезно знать тип/размер
        extra["response_content_type"] = resp_content_type or ""

        # OpenTelemetry украшения
        if _OTEL:
            try:
                span = otel_trace.get_current_span()
                if span and span.is_recording():
                    span.set_attribute("http.request_id", _request_id_ctx.get())
                    span.set_attribute("http.route", path)
                    span.set_attribute("http.method", method)
                    span.set_attribute("http.status_code", status)
                    span.set_attribute("enduser.id", _actor_ctx.get() or "")
                    span.set_attribute("net.peer.ip", remote_ip or "")
                    span.set_attribute("http.duration_ms", duration_ms)
            except Exception:  # не ломаем приложение из‑за трассировки
                pass

        logger.log(level, f"{method} {path} -> {status} in {duration_ms}ms", extra=extra)


# -------------------------
# Утилиты для заголовков/тел
# -------------------------

def _clip_headers(headers: t.Sequence[t.Tuple[bytes, bytes]], max_len: int) -> t.Dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers:
        key = k.decode("latin-1")
        val = v.decode("latin-1", errors="replace")
        if len(val) > max_len:
            val = val[:max_len] + "...[truncated]"
        out[key] = val
    return out

def _bytes_to_text(data: bytes, content_type: str, limit: int) -> str:
    # Пытаемся угадать кодировку из content-type; по умолчанию utf-8
    encoding = "utf-8"
    if "charset=" in (content_type or "").lower():
        try:
            encoding = content_type.lower().split("charset=")[1].split(";")[0].strip()
        except Exception:
            encoding = "utf-8"
    try:
        txt = data.decode(encoding, errors="replace")
    except Exception:
        txt = data.decode("utf-8", errors="replace")
    if len(txt) > limit:
        return txt[:limit] + "...[truncated]"
    return txt

# -------------------------
# Пример подключения (для справки)
# -------------------------
# from fastapi import FastAPI
# app = FastAPI()
# app.add_middleware(LoggingMiddleware, logger=_default_logger(), config=LoggingConfig.from_env())
#
# Переменные окружения:
#   SEC_CORE_HTTP_LOG_LEVEL=INFO|DEBUG|WARNING|ERROR
#   SEC_CORE_LOG_REQ_HEADERS=true|false
#   SEC_CORE_LOG_REQ_BODY=true|false
#   SEC_CORE_LOG_RESP_HEADERS=true|false
#   SEC_CORE_LOG_RESP_BODY=true|false
#   SEC_CORE_LOG_REQ_BODY_RATE=0.1
#   SEC_CORE_LOG_RESP_BODY_RATE=0.05
#   SEC_CORE_LOG_MAX_BODY_BYTES=4096
#   SEC_CORE_LOG_SLOW_MS=1500
#   SEC_CORE_LOG_DEBUG_VERBOSE=false
