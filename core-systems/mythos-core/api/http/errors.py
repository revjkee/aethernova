# mythos-core/api/http/errors.py
# -*- coding: utf-8 -*-
"""
Единая система ошибок для HTTP API Mythos Core.

Особенности:
- RFC 7807 (application/problem+json) с расширениями (code, trace_id, errors, extras).
- Иерархия AppError c стабильными кодами и статусами.
- Безопасная редакция PII в сообщениях/контексте.
- Интеграция со Starlette/FastAPI: middleware + exception handlers.
- Структурные логи (structlog -> logging fallback).
"""

from __future__ import annotations

import json
import re
import typing as t
from dataclasses import dataclass, field
from http import HTTPStatus
from types import SimpleNamespace
from uuid import UUID, uuid4

# --------- Логи (structlog -> logging fallback) ---------
try:
    import structlog

    def _configure_logging():
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ]
        )
        return structlog.get_logger("mythos.http.errors")

    log = _configure_logging()
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(
        level="INFO",
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("mythos.http.errors")

# --------- Опциональные зависимости (Starlette/FastAPI) ---------
try:  # Starlette совместимость
    from starlette.responses import JSONResponse as _JSONResponse  # type: ignore
    from starlette.requests import Request as _Request  # type: ignore
    from starlette.middleware.base import BaseHTTPMiddleware  # type: ignore
    from starlette.exceptions import HTTPException as StarletteHTTPException  # type: ignore
except Exception:  # pragma: no cover
    _JSONResponse = None
    _Request = None
    BaseHTTPMiddleware = object  # type: ignore
    StarletteHTTPException = Exception  # type: ignore

try:  # FastAPI-валидация
    from fastapi.exceptions import RequestValidationError as _RequestValidationError  # type: ignore
except Exception:  # pragma: no cover
    _RequestValidationError = None

# --------- Публичные константы/типы ---------
__all__ = [
    "AppError",
    "ErrorCode",
    "ProblemDetails",
    "ProblemDetailMiddleware",
    "register_exception_handlers",
    # фабрики
    "BadRequestError",
    "ValidationError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "TooManyRequestsError",
    "UnprocessableError",
    "DependencyError",
    "TimeoutError",
    "InternalServerError",
    # утилиты
    "error_to_response",
    "from_exception",
]

class ErrorCode(str):
    """Стабильные машинные коды ошибок (контракт API)."""
    E_BAD_REQUEST = "E_BAD_REQUEST"
    E_VALIDATION = "E_VALIDATION"
    E_UNAUTHORIZED = "E_UNAUTHORIZED"
    E_FORBIDDEN = "E_FORBIDDEN"
    E_NOT_FOUND = "E_NOT_FOUND"
    E_CONFLICT = "E_CONFLICT"
    E_RATE_LIMIT = "E_RATE_LIMIT"
    E_TOO_MANY_REQUESTS = "E_TOO_MANY_REQUESTS"
    E_UNPROCESSABLE = "E_UNPROCESSABLE"
    E_DEPENDENCY = "E_DEPENDENCY"
    E_TIMEOUT = "E_TIMEOUT"
    E_INTERNAL = "E_INTERNAL"

# Карта кодов → HTTP-статусов и «title»
_CODE_META: dict[str, tuple[HTTPStatus, str]] = {
    ErrorCode.E_BAD_REQUEST: (HTTPStatus.BAD_REQUEST, "Bad Request"),
    ErrorCode.E_VALIDATION: (HTTPStatus.UNPROCESSABLE_ENTITY, "Validation Failed"),
    ErrorCode.E_UNAUTHORIZED: (HTTPStatus.UNAUTHORIZED, "Unauthorized"),
    ErrorCode.E_FORBIDDEN: (HTTPStatus.FORBIDDEN, "Forbidden"),
    ErrorCode.E_NOT_FOUND: (HTTPStatus.NOT_FOUND, "Not Found"),
    ErrorCode.E_CONFLICT: (HTTPStatus.CONFLICT, "Conflict"),
    ErrorCode.E_RATE_LIMIT: (HTTPStatus.TOO_MANY_REQUESTS, "Rate Limit"),
    ErrorCode.E_TOO_MANY_REQUESTS: (HTTPStatus.TOO_MANY_REQUESTS, "Too Many Requests"),
    ErrorCode.E_UNPROCESSABLE: (HTTPStatus.UNPROCESSABLE_ENTITY, "Unprocessable Entity"),
    ErrorCode.E_DEPENDENCY: (HTTPStatus.FAILED_DEPENDENCY, "Upstream Dependency Error"),
    ErrorCode.E_TIMEOUT: (HTTPStatus.GATEWAY_TIMEOUT, "Timeout"),
    ErrorCode.E_INTERNAL: (HTTPStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"),
}

# --------- Редакция PII ---------
_PII_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    re.compile(r"\+?\d[\d \-()]{6,}\d"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),  # карты
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),  # IBAN
    re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),  # BIC
    re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),  # IPv4
]

def _redact(value: t.Any) -> t.Any:
    """Редактирует потенциально чувствительные данные в строках/структурах."""
    def _redact_str(s: str) -> str:
        redacted = s
        for p in _PII_PATTERNS:
            redacted = p.sub("[REDACTED]", redacted)
        return redacted

    if value is None:
        return None
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v) for v in value)
    return value

# --------- Модель problem+json ---------
@dataclass
class ProblemDetails:
    type: str
    title: str
    status: int
    detail: t.Optional[str] = None
    instance: t.Optional[str] = None
    # Расширения
    code: t.Optional[str] = None
    trace_id: t.Optional[str] = None
    errors: t.Optional[list[dict[str, t.Any]]] = None
    extras: dict[str, t.Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, t.Any]:
        payload: dict[str, t.Any] = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
        }
        if self.detail is not None:
            payload["detail"] = self.detail
        if self.instance:
            payload["instance"] = self.instance
        if self.code:
            payload["code"] = self.code
        if self.trace_id:
            payload["trace_id"] = self.trace_id
        if self.errors:
            payload["errors"] = self.errors
        if self.extras:
            payload["extras"] = self.extras
        return payload

# --------- Базовое исключение ---------
class AppError(Exception):
    """
    Базовое исключение приложения с поддержкой RFC 7807.

    Аргументы:
      code: стабильный машинный код ошибки (см. ErrorCode).
      detail: человекочитаемое сообщение (будет отредактировано при необходимости).
      status: HTTP-статус (по умолчанию из _CODE_META).
      instance: путь/идентификатор операции.
      type_uri: URI типа ошибки (документация/спецификация).
      errors: список ошибок полей [{'field': 'name', 'message': '...'}].
      extras: произвольный контекст (с отредактированием PII).
      headers: HTTP-заголовки для ответа.
      public: если False — detail заменится на безопасное сообщение.
    """

    def __init__(
        self,
        code: str,
        *,
        detail: t.Optional[str] = None,
        status: t.Optional[int] = None,
        instance: t.Optional[str] = None,
        type_uri: str = "about:blank",
        errors: t.Optional[list[dict[str, t.Any]]] = None,
        extras: t.Optional[dict[str, t.Any]] = None,
        headers: t.Optional[dict[str, str]] = None,
        public: bool = True,
    ) -> None:
        self.code = code
        meta = _CODE_META.get(code, (HTTPStatus.INTERNAL_SERVER_ERROR, "Error"))
        self.status = int(status or meta[0])
        self.title = meta[1]
        self.detail = detail
        self.instance = instance
        self.type_uri = type_uri
        self.errors = errors or []
        self.extras = extras or {}
        self.headers = headers or {}
        self.public = public
        super().__init__(detail or self.title)

    def to_problem(
        self,
        *,
        trace_id: t.Optional[str] = None,
        redact_pii: bool = True,
    ) -> ProblemDetails:
        detail = self.detail
        extras = self.extras
        errs = self.errors
        if redact_pii:
            detail = _redact(detail)
            extras = _redact(extras)
            errs = _redact(errs)

        if not self.public and self.status >= 500:
            # скрываем детали внутренних ошибок
            detail = "Internal error. Contact support if the issue persists."

        return ProblemDetails(
            type=self.type_uri or "about:blank",
            title=self.title,
            status=self.status,
            detail=detail,
            instance=self.instance,
            code=self.code,
            trace_id=trace_id,
            errors=errs or None,
            extras=extras or {},
        )

# --------- Производные ошибки/фабрики ---------
class BadRequestError(AppError):
    def __init__(self, detail: str = "Bad request", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_BAD_REQUEST, detail=detail, **kw)

class ValidationError(AppError):
    def __init__(self, detail: str = "Validation failed", errors: t.Optional[list[dict]] = None, **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_VALIDATION, detail=detail, errors=errors, **kw)

class UnauthorizedError(AppError):
    def __init__(self, detail: str = "Unauthorized", **kw: t.Any) -> None:
        headers = kw.pop("headers", {}) or {}
        headers.setdefault("WWW-Authenticate", 'Bearer realm="mythos-core"')
        super().__init__(ErrorCode.E_UNAUTHORIZED, detail=detail, headers=headers, **kw)

class ForbiddenError(AppError):
    def __init__(self, detail: str = "Forbidden", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_FORBIDDEN, detail=detail, **kw)

class NotFoundError(AppError):
    def __init__(self, detail: str = "Not found", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_NOT_FOUND, detail=detail, **kw)

class ConflictError(AppError):
    def __init__(self, detail: str = "Conflict", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_CONFLICT, detail=detail, **kw)

class RateLimitError(AppError):
    def __init__(self, detail: str = "Rate limit exceeded", retry_after_seconds: t.Optional[int] = None, **kw: t.Any) -> None:
        headers = kw.pop("headers", {}) or {}
        if retry_after_seconds:
            headers.setdefault("Retry-After", str(int(retry_after_seconds)))
        super().__init__(ErrorCode.E_RATE_LIMIT, detail=detail, headers=headers, **kw)

# Алиас для совместимости
TooManyRequestsError = RateLimitError

class UnprocessableError(AppError):
    def __init__(self, detail: str = "Unprocessable entity", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_UNPROCESSABLE, detail=detail, **kw)

class DependencyError(AppError):
    def __init__(self, detail: str = "Dependency error", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_DEPENDENCY, detail=detail, **kw)

class TimeoutError(AppError):  # noqa: A001 - имя осознанно совпадает
    def __init__(self, detail: str = "Timeout", **kw: t.Any) -> None:
        super().__init__(ErrorCode.E_TIMEOUT, detail=detail, **kw)

class InternalServerError(AppError):
    def __init__(self, detail: str = "Internal server error", **kw: t.Any) -> None:
        # public=False скроет detail во внешнем ответе
        kw.setdefault("public", False)
        super().__init__(ErrorCode.E_INTERNAL, detail=detail, **kw)

# --------- Утилиты трассировки ---------
def _extract_trace_id(request: t.Any) -> str:
    # X-Request-ID или X-Correlation-ID; если нет — генерируем
    if request is not None:
        for h in ("x-request-id", "x-correlation-id", "x-trace-id"):
            try:
                v = request.headers.get(h)  # type: ignore[attr-defined]
                if v:
                    return v
            except Exception:
                pass
    return str(uuid4())

# --------- Преобразование исключений ---------
def from_exception(exc: Exception) -> AppError:
    """Нормализовать любое исключение к AppError."""
    if isinstance(exc, AppError):
        return exc

    # Starlette HTTPException
    if _JSONResponse and isinstance(exc, StarletteHTTPException):
        status = int(getattr(exc, "status_code", 500))
        detail = str(getattr(exc, "detail", "")) or HTTPStatus(status).phrase
        headers = getattr(exc, "headers", None)
        if status == HTTPStatus.NOT_FOUND:
            return NotFoundError(detail=detail, headers=headers)
        if status == HTTPStatus.FORBIDDEN:
            return ForbiddenError(detail=detail, headers=headers)
        if status == HTTPStatus.UNAUTHORIZED:
            return UnauthorizedError(detail=detail, headers=headers)
        if status == HTTPStatus.CONFLICT:
            return ConflictError(detail=detail, headers=headers)
        if status == HTTPStatus.UNPROCESSABLE_ENTITY:
            return UnprocessableError(detail=detail, headers=headers)
        if status == HTTPStatus.TOO_MANY_REQUESTS:
            return RateLimitError(detail=detail, headers=headers)
        if 400 <= status < 500:
            return BadRequestError(detail=detail, headers=headers, status=status)
        return InternalServerError(detail=detail, headers=headers, status=status)

    # FastAPI RequestValidationError
    if _RequestValidationError and isinstance(exc, _RequestValidationError):
        errors = []
        try:
            # pydantic v1/v2 совместимость: .errors() -> список
            for e in exc.errors():  # type: ignore[attr-defined]
                errors.append(
                    {
                        "field": ".".join(str(x) for x in e.get("loc", []) if x is not None),
                        "message": e.get("msg", "Invalid value"),
                        "type": e.get("type"),
                    }
                )
        except Exception:
            pass
        return ValidationError(errors=errors or None, extras={"raw": str(exc)})

    # Прочие — внутренняя ошибка
    return InternalServerError(detail=str(exc))

# --------- Сериализация в HTTP-ответ ---------
def error_to_response(
    error: AppError,
    *,
    request: t.Optional[t.Any] = None,
) -> tuple[int, dict[str, str], dict[str, t.Any]]:
    """
    Преобразовать AppError в кортеж (status, headers, json_dict) для проблемного ответа.
    Не зависит от Starlette; подходит для любых фреймворков.
    """
    trace_id = _extract_trace_id(request)
    pd = error.to_problem(trace_id=trace_id)
    headers = {"Content-Type": "application/problem+json"}
    headers.update(error.headers or {})
    # Дублируем correlation id в заголовок
    headers.setdefault("X-Request-ID", trace_id)
    return error.status, headers, pd.to_dict()

# --------- Starlette/FastAPI интеграция ---------
class ProblemDetailMiddleware(BaseHTTPMiddleware):  # type: ignore[misc]
    """
    Middleware перехвата исключений и выдачи RFC 7807.

    Добавляет заголовок X-Request-ID, пишет структурные логи, редактирует PII.
    """

    async def dispatch(self, request: _Request, call_next):  # type: ignore[override]
        trace_id = _extract_trace_id(request)
        try:
            response = await call_next(request)
            # пробрасываем X-Request-ID вниз по пайплайну
            try:
                response.headers.setdefault("X-Request-ID", trace_id)
            except Exception:
                pass
            return response
        except Exception as exc:  # noqa: BLE001
            app_err = from_exception(exc)
            status, headers, payload = error_to_response(app_err, request=request)

            # Лог: без PII (редакция включена в to_problem)
            log.error(
                "http_request_failed",
                status=status,
                code=app_err.code,
                title=app_err.title,
                path=str(getattr(request, "url", "")),
                method=getattr(request, "method", ""),
                trace_id=headers.get("X-Request-ID"),
                errors=len(app_err.errors or []),
                exc_info=True,
            )

            if _JSONResponse is None:  # pragma: no cover
                # Фолбэк — минимальная совместимость
                body = json.dumps(payload).encode("utf-8")
                # Возвращаем простой объект-заглушку
                resp = SimpleNamespace(status_code=status, headers=headers, body=body)
                return resp

            return _JSONResponse(payload, status_code=status, headers=headers)

def register_exception_handlers(app: t.Any) -> None:
    """
    Зарегистрировать обработчики исключений для FastAPI/Starlette-приложения.
    """
    if getattr(app, "add_exception_handler", None) is None:
        return

    # FastAPI RequestValidationError
    if _RequestValidationError:
        @app.exception_handler(_RequestValidationError)  # type: ignore[misc]
        async def _handle_validation_error(_req: _Request, exc: Exception):  # type: ignore[override]
            app_err = from_exception(exc)
            status, headers, payload = error_to_response(app_err, request=_req)
            return _JSONResponse(payload, status_code=status, headers=headers)

    # Starlette HTTPException
    @app.exception_handler(StarletteHTTPException)  # type: ignore[misc]
    async def _handle_http_exc(_req: _Request, exc: Exception):  # type: ignore[override]
        app_err = from_exception(exc)
        status, headers, payload = error_to_response(app_err, request=_req)
        return _JSONResponse(payload, status_code=status, headers=headers)

    # Любое необработанное исключение
    @app.exception_handler(Exception)  # type: ignore[misc]
    async def _handle_any(_req: _Request, exc: Exception):  # type: ignore[override]
        app_err = from_exception(exc)
        status, headers, payload = error_to_response(app_err, request=_req)
        return _JSONResponse(payload, status_code=status, headers=headers)

# --------- Пример включения (докстринга достаточно, без побочных эффектов) ---------
"""
Пример (FastAPI):

    from fastapi import FastAPI
    from mythos_core.api.http.errors import ProblemDetailMiddleware, register_exception_handlers, NotFoundError

    app = FastAPI()
    app.add_middleware(ProblemDetailMiddleware)
    register_exception_handlers(app)

    @app.get("/items/{item_id}")
    async def get_item(item_id: str):
        raise NotFoundError(detail=f"Item {item_id} not found", extras={"item_id": item_id})
"""
