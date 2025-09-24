# chronowatch-core/api/http/errors.py
# -*- coding: utf-8 -*-
"""
Единый слой ошибок API для ChronoWatch Core.

Особенности:
- RFC 7807 (application/problem+json) для всех ответов об ошибках
- Собственные коды ошибок (ErrorCode) + HTTP статус
- Безопасная маскировка внутренних деталей вне debug-режима
- Структурное логирование с correlation/request id
- Интеграция с OpenTelemetry (если установлен) и Sentry (если установлен)
- Обработчики FastAPI/Starlette: AppError, HTTPException, RequestValidationError, Exception
- Совместимость с Pydantic v1/v2
- Только async, без синхронных блокировок

Подключение:
    from api.http.errors import setup_exception_handlers
    setup_exception_handlers(app, debug=False, expose_internal=False)

Гарантирует стабильный контракт для клиентов и удобство в SRE/обслуживании.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import traceback
import uuid
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_409_CONFLICT,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    HTTP_422_UNPROCESSABLE_ENTITY,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_502_BAD_GATEWAY,
    HTTP_503_SERVICE_UNAVAILABLE,
    HTTP_504_GATEWAY_TIMEOUT,
)

try:
    # FastAPI (предпочтительно)
    from fastapi import HTTPException
    from fastapi.exceptions import RequestValidationError
except Exception:  # pragma: no cover
    # Чистый Starlette fallback
    from starlette.exceptions import HTTPException  # type: ignore
    # Валидация в Starlette другая; обработчик будет только общий
    class RequestValidationError(Exception):  # type: ignore
        errors: Any = None

try:  # Pydantic v1/v2 совместимость
    from pydantic import BaseModel, Field  # type: ignore
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    Field = lambda *a, **k: None  # type: ignore

# Опциональные зависимости для наблюдаемости
try:
    import sentry_sdk  # type: ignore
except Exception:  # pragma: no cover
    sentry_sdk = None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore

LOG = logging.getLogger("chronowatch.api.errors")

DOCS_BASE_URL = os.getenv(
    "ERROR_DOCS_BASE_URL",
    "https://docs.chronowatch.example/errors"
)
REQUEST_ID_HEADER = os.getenv("REQUEST_ID_HEADER", "X-Request-ID")


# ------------------------- Коды ошибок домена ------------------------- #

class ErrorCode:
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    TIMEOUT = "TIMEOUT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_STATUS_BY_CODE: Mapping[str, int] = {
    ErrorCode.BAD_REQUEST: HTTP_400_BAD_REQUEST,
    ErrorCode.UNAUTHORIZED: HTTP_401_UNAUTHORIZED,
    ErrorCode.FORBIDDEN: HTTP_403_FORBIDDEN,
    ErrorCode.NOT_FOUND: HTTP_404_NOT_FOUND,
    ErrorCode.CONFLICT: HTTP_409_CONFLICT,
    ErrorCode.PAYLOAD_TOO_LARGE: HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    ErrorCode.VALIDATION_FAILED: HTTP_422_UNPROCESSABLE_ENTITY,
    ErrorCode.RATE_LIMITED: HTTP_429_TOO_MANY_REQUESTS,
    ErrorCode.DEPENDENCY_FAILED: HTTP_502_BAD_GATEWAY,
    ErrorCode.TIMEOUT: HTTP_504_GATEWAY_TIMEOUT,
    ErrorCode.SERVICE_UNAVAILABLE: HTTP_503_SERVICE_UNAVAILABLE,
    ErrorCode.INTERNAL_ERROR: HTTP_500_INTERNAL_SERVER_ERROR,
}


# ------------------------- Базовое исключение приложения ------------------------- #

class AppError(Exception):
    """
    Исключение уровня приложения, безопасное для клиента.
    """
    def __init__(
        self,
        message: str,
        *,
        code: str = ErrorCode.INTERNAL_ERROR,
        status_code: Optional[int] = None,
        type_url: Optional[str] = None,
        instance: Optional[str] = None,
        meta: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code or _STATUS_BY_CODE.get(code, HTTP_500_INTERNAL_SERVER_ERROR)
        self.type_url = type_url or f"{DOCS_BASE_URL}/{code.lower()}"
        self.instance = instance
        self.meta = dict(meta or {})
        self.headers = dict(headers or {})
        self.cause = cause
        self.error_id = str(uuid.uuid4())


# ------------------------- Модель Problem Details (RFC 7807) ------------------------- #

class ProblemDetails(BaseModel):  # type: ignore[misc]
    type: str = Field(default="about:blank")  # ссылка на описание типа ошибки
    title: str = Field(default="Error")
    status: int = Field(default=HTTP_500_INTERNAL_SERVER_ERROR)
    detail: Optional[str] = Field(default=None)
    instance: Optional[str] = Field(default=None)

    # Расширения (custom)
    code: str = Field(default=ErrorCode.INTERNAL_ERROR)
    error_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = Field(default=None)
    correlation_id: Optional[str] = Field(default=None)
    meta: Dict[str, Any] = Field(default_factory=dict)

    class Config:  # pydantic v1/v2 совместимо
        extra = "ignore"
        json_encoders = {
            Exception: lambda e: repr(e),
        }


# ------------------------- Утилиты ------------------------- #

def _extract_request_id(request: Request) -> Optional[str]:
    rid = request.headers.get(REQUEST_ID_HEADER)
    if rid:
        return rid
    # Fallback: попробуем из state, если middleware его кладёт
    return getattr(request.state, "request_id", None)


def _otel_span_context() -> Dict[str, Any]:
    if not trace:
        return {}
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return {}
        return {
            "otel_trace_id": format(ctx.trace_id, "032x"),
            "otel_span_id": format(ctx.span_id, "016x"),
            "otel_trace_flags": int(ctx.trace_flags),
        }
    except Exception:
        return {}


def _safe_detail(message: str, *, debug: bool, default: str = "Internal server error") -> str:
    return message if debug else default


def _log_exception(
    request: Request,
    status: int,
    code: str,
    detail: str,
    error_id: str,
    exc: BaseException,
    meta: Optional[Mapping[str, Any]] = None,
) -> None:
    payload = {
        "event": "api_error",
        "status": status,
        "code": code,
        "detail": detail,
        "error_id": error_id,
        "method": request.method,
        "path": str(request.url),
        "client": request.client.host if request.client else None,
        "request_id": _extract_request_id(request),
        **_otel_span_context(),
        "meta": dict(meta or {}),
    }
    LOG.error(json.dumps(payload, ensure_ascii=False), exc_info=exc)


def _capture_sentry(exc: BaseException) -> None:
    if sentry_sdk is None:
        return
    try:
        sentry_sdk.capture_exception(exc)
    except Exception:  # pragma: no cover
        pass


# ------------------------- Построение problem+json ------------------------- #

def _build_problem_from_app_error(
    request: Request,
    err: AppError,
    *,
    debug: bool,
    expose_internal: bool,
) -> Tuple[ProblemDetails, int, Mapping[str, str]]:
    status = err.status_code
    detail = err.message if (debug or expose_internal) else _default_title_by_status(status)
    title = _default_title_by_status(status)

    problem = ProblemDetails(
        type=err.type_url,
        title=title,
        status=status,
        detail=detail,
        instance=err.instance or request.url.path,
        code=err.code,
        error_id=err.error_id,
        request_id=_extract_request_id(request),
        correlation_id=request.headers.get("X-Correlation-ID"),
        meta=dict(err.meta),
    )
    # Обогатим OTEL id для удобства трейсинга
    problem.meta.update(_otel_span_context())

    headers = dict(err.headers or {})
    return problem, status, headers


def _default_title_by_status(status: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }.get(status, "Error")


def _problem_response(problem: ProblemDetails, headers: Optional[Mapping[str, str]] = None) -> JSONResponse:
    media_type = "application/problem+json"
    return JSONResponse(
        status_code=problem.status,
        content=json.loads(problem.model_dump_json()),  # pydantic v1/v2 совместимо
        headers=dict(headers or {}),
        media_type=media_type,
    )


# ------------------------- Публичные фабрики ------------------------- #

def problem(
    *,
    code: str,
    detail: str,
    status: Optional[int] = None,
    instance: Optional[str] = None,
    meta: Optional[Mapping[str, Any]] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> AppError:
    """Создать AppError с заданным кодом и деталями."""
    return AppError(
        message=detail,
        code=code,
        status_code=status,
        instance=instance,
        meta=meta,
        headers=headers,
    )


# ------------------------- Регистрация обработчиков ------------------------- #

def setup_exception_handlers(app, *, debug: bool = False, expose_internal: bool = False) -> None:
    """
    Зарегистрировать единые обработчики исключений для FastAPI/Starlette приложения.
    :param debug: Если True — детальные сообщения внутренних ошибок в ответе.
    :param expose_internal: Если True — разрешить показывать .message из AppError (для внутренних систем).
    """
    # AppError
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> Response:
        problem_obj, status, headers = _build_problem_from_app_error(
            request, exc, debug=debug, expose_internal=expose_internal
        )
        _log_exception(request, status, exc.code, problem_obj.detail or "", exc.error_id, exc, exc.meta)
        if status >= 500:
            _capture_sentry(exc)
        return _problem_response(problem_obj, headers)

    # HTTPException (FastAPI/Starlette)
    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException) -> Response:
        code = _map_status_to_code(exc.status_code)
        title = _default_title_by_status(exc.status_code)
        detail = str(exc.detail) if (debug or exc.status_code < 500) else title
        err = AppError(
            message=detail,
            code=code,
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
            instance=request.url.path,
        )
        problem_obj, status, headers = _build_problem_from_app_error(
            request, err, debug=debug, expose_internal=expose_internal
        )
        _log_exception(request, status, code, detail, err.error_id, exc)
        if status >= 500:
            _capture_sentry(exc)
        return _problem_response(problem_obj, headers)

    # Ошибки валидации запроса FastAPI
    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(request: Request, exc: RequestValidationError) -> Response:
        errors_meta = _format_validation_errors(exc)
        err = AppError(
            message="Validation failed",
            code=ErrorCode.VALIDATION_FAILED,
            status_code=HTTP_422_UNPROCESSABLE_ENTITY,
            instance=request.url.path,
            meta={"errors": errors_meta},
            cause=exc,
        )
        problem_obj, status, headers = _build_problem_from_app_error(
            request, err, debug=True if debug else False, expose_internal=True if debug else False
        )
        _log_exception(request, status, err.code, "Validation failed", err.error_id, exc, err.meta)
        return _problem_response(problem_obj, headers)

    # Любые неперехваченные исключения
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        trace_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        err = AppError(
            message=_safe_detail(str(exc), debug=debug, default="Internal server error"),
            code=ErrorCode.INTERNAL_ERROR,
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            instance=request.url.path,
            meta={"exception_type": type(exc).__name__, "stacktrace": trace_str if debug else None},
            cause=exc,
        )
        problem_obj, status, headers = _build_problem_from_app_error(
            request, err, debug=debug, expose_internal=expose_internal
        )
        _log_exception(request, status, err.code, problem_obj.detail or "", err.error_id, exc, err.meta)
        _capture_sentry(exc)
        return _problem_response(problem_obj, headers)


# ------------------------- Вспомогательные функции ------------------------- #

def _map_status_to_code(status: int) -> str:
    for code, s in _STATUS_BY_CODE.items():
        if s == status:
            return code
    # эвристика
    if 500 <= status <= 599:
        return ErrorCode.INTERNAL_ERROR
    if 400 <= status <= 499:
        return ErrorCode.BAD_REQUEST
    return ErrorCode.INTERNAL_ERROR


def _format_validation_errors(exc: RequestValidationError) -> Any:
    """
    Приводит ошибки FastAPI/Pydantic к стабильному формату.
    """
    try:
        # FastAPI формирует .errors() по pydantic
        if hasattr(exc, "errors"):
            errs = exc.errors()  # type: ignore[attr-defined]
        else:
            errs = getattr(exc, "errors", None) or []
    except Exception:
        errs = []

    formatted = []
    for e in errs:
        # Pydantic v1/v2 имеют немного разные поля; берём безопасно
        loc = e.get("loc") or e.get("location") or []
        msg = e.get("msg") or e.get("message") or "Invalid value"
        etype = e.get("type") or e.get("error") or "value_error"
        formatted.append({"loc": list(loc), "msg": msg, "type": etype})
    # Если пусто, положим строковое представление
    if not formatted:
        formatted = [{"loc": [], "msg": str(exc), "type": "validation_error"}]
    return formatted


# ------------------------- Готовые конструкторы ошибок ------------------------- #
# Эти функции удобно вызывать из хендлеров/сервисов.

def bad_request(detail: str, *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.BAD_REQUEST, detail=detail, meta=meta)

def unauthorized(detail: str = "Unauthorized", *, meta: Optional[Mapping[str, Any]] = None, headers: Optional[Mapping[str, str]] = None) -> AppError:
    hdrs = {"WWW-Authenticate": 'Bearer realm="api"'}
    if headers:
        hdrs.update(headers)
    return AppError(detail, code=ErrorCode.UNAUTHORIZED, headers=hdrs, status_code=HTTP_401_UNAUTHORIZED, meta=meta)

def forbidden(detail: str = "Forbidden", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.FORBIDDEN, detail=detail, meta=meta)

def not_found(detail: str = "Not found", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.NOT_FOUND, detail=detail, meta=meta)

def conflict(detail: str = "Conflict", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.CONFLICT, detail=detail, meta=meta)

def payload_too_large(detail: str = "Payload too large", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.PAYLOAD_TOO_LARGE, detail=detail, meta=meta)

def unsupported_media_type(detail: str = "Unsupported media type", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.UNSUPPORTED_MEDIA_TYPE, detail=detail, meta=meta)

def rate_limited(detail: str = "Too many requests", *, meta: Optional[Mapping[str, Any]] = None, retry_after_seconds: Optional[int] = None) -> AppError:
    headers = {"Retry-After": str(retry_after_seconds)} if retry_after_seconds is not None else None
    return AppError(detail, code=ErrorCode.RATE_LIMITED, status_code=HTTP_429_TOO_MANY_REQUESTS, meta=meta, headers=headers)

def dependency_failed(detail: str = "Upstream dependency failed", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return AppError(detail, code=ErrorCode.DEPENDENCY_FAILED, status_code=HTTP_502_BAD_GATEWAY, meta=meta)

def timeout(detail: str = "Gateway timeout", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return AppError(detail, code=ErrorCode.TIMEOUT, status_code=HTTP_504_GATEWAY_TIMEOUT, meta=meta)

def service_unavailable(detail: str = "Service unavailable", *, meta: Optional[Mapping[str, Any]] = None, retry_after_seconds: Optional[int] = None) -> AppError:
    headers = {"Retry-After": str(retry_after_seconds)} if retry_after_seconds is not None else None
    return AppError(detail, code=ErrorCode.SERVICE_UNAVAILABLE, status_code=HTTP_503_SERVICE_UNAVAILABLE, meta=meta, headers=headers)

def internal_error(detail: str = "Internal server error", *, meta: Optional[Mapping[str, Any]] = None) -> AppError:
    return problem(code=ErrorCode.INTERNAL_ERROR, detail=detail, meta=meta)
