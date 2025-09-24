# file: cybersecurity-core/api/http/errors.py
"""
Единый модуль ошибок HTTP для FastAPI/Starlette.

Особенности:
- Ответы в формате Problem Details (RFC 7807): application/problem+json.
- Собственные коды ошибок (ErrorCode) и базовое исключение AppError.
- Обработчики для:
  * AppError
  * RequestValidationError (FastAPI)
  * HTTPException (Starlette)
  * Неожиданных Exception (500)
- Корреляция запросов: X-Correlation-ID (из запроса или auto-uuid4).
- Безопасная утечка деталей: при DEBUG=0 скрываем внутренние сведения.
- Поддержка Retry-After для ограничений/недоступности.
- Структурное логирование.

Совместимо с FastAPI (pydantic v1/v2). Не привязано к конкретным роутам.

Использование:
    from fastapi import FastAPI
    from cybersecurity_core.api.http.errors import register_exception_handlers

    app = FastAPI()
    register_exception_handlers(app)
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette import status
from starlette.applications import Starlette

__all__ = [
    "ErrorCode",
    "FieldError",
    "Problem",
    "AppError",
    "BadRequestError",
    "UnauthorizedError",
    "ForbiddenError",
    "NotFoundError",
    "ConflictError",
    "UnprocessableEntityError",
    "TooManyRequestsError",
    "ServiceUnavailableError",
    "InternalServerError",
    "register_exception_handlers",
    "problem_response",
]

logger = logging.getLogger("cybersecurity_core.errors")

# Константы
PROBLEM_CONTENT_TYPE = "application/problem+json"
CORRELATION_HEADER = "X-Correlation-ID"
REQUEST_ID_HEADER = "X-Request-ID"

# Флаг безопасного вывода подробностей
DEBUG = os.getenv("CYBERSEC_DEBUG", "0") not in ("0", "false", "False", "")


class ErrorCode(str, Enum):
    VALIDATION_ERROR = "validation_error"
    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNPROCESSABLE_ENTITY = "unprocessable_entity"
    RATE_LIMITED = "rate_limited"
    SERVICE_UNAVAILABLE = "service_unavailable"
    INTERNAL_ERROR = "internal_error"

    # Доменные/кастомные примеры (при необходимости расширяйте)
    POLICY_VIOLATION = "policy_violation"
    INTEGRATION_ERROR = "integration_error"


class FieldError(BaseModel):
    """Описание ошибки конкретного поля для валидации/422."""
    loc: List[Union[str, int]]
    msg: str
    type: Optional[str] = None


class Problem(BaseModel):
    """
    RFC 7807-совместимая модель ответа.
    'type' оставлен tag:-URI, чтобы не ссылаться на внешние ресурсы.
    """
    type: str
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None

    # Расширения (extension members)
    code: ErrorCode
    correlation_id: str
    fields: Optional[List[FieldError]] = None
    remediation: Optional[str] = None
    docs: Optional[str] = None
    retry_after: Optional[int] = None  # секунды

    class Config:
        use_enum_values = True  # сериализация enum как строк


@dataclass(frozen=True)
class _AppErrorData:
    status: int
    code: ErrorCode
    title: str
    detail: Optional[str] = None
    fields: Optional[List[FieldError]] = None
    remediation: Optional[str] = None
    docs: Optional[str] = None
    retry_after: Optional[int] = None
    headers: Optional[Dict[str, str]] = None


class AppError(Exception):
    """Базовое прикладное исключение для контролируемых ошибок API."""
    __slots__ = ("status", "code", "title", "detail", "fields", "remediation", "docs", "retry_after", "headers")

    def __init__(
        self,
        *,
        status: int,
        code: ErrorCode,
        title: str,
        detail: Optional[str] = None,
        fields: Optional[List[FieldError]] = None,
        remediation: Optional[str] = None,
        docs: Optional[str] = None,
        retry_after: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(detail or title)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.fields = fields
        self.remediation = remediation
        self.docs = docs
        self.retry_after = retry_after
        self.headers = headers or {}

    def to_problem(self, *, correlation_id: str, instance: Optional[str] = None) -> Problem:
        return Problem(
            type=f"tag:cybersecurity-core:aethernova:{self.code}",
            title=self.title,
            status=self.status,
            detail=self.detail,
            instance=instance,
            code=self.code,
            correlation_id=correlation_id,
            fields=self.fields,
            remediation=self.remediation,
            docs=self.docs,
            retry_after=self.retry_after,
        )


# Частные исключения
class BadRequestError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.BAD_REQUEST,
            title="Bad Request",
            detail=detail,
            **kw,
        )


class UnauthorizedError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_401_UNAUTHORIZED,
            code=ErrorCode.UNAUTHORIZED,
            title="Unauthorized",
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
            **kw,
        )


class ForbiddenError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.FORBIDDEN,
            title="Forbidden",
            detail=detail,
            **kw,
        )


class NotFoundError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.NOT_FOUND,
            title="Not Found",
            detail=detail,
            **kw,
        )


class ConflictError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_409_CONFLICT,
            code=ErrorCode.CONFLICT,
            title="Conflict",
            detail=detail,
            **kw,
        )


class UnprocessableEntityError(AppError):
    def __init__(
        self,
        detail: Optional[str] = None,
        fields: Optional[List[FieldError]] = None,
        **kw: Any,
    ) -> None:
        super().__init__(
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.UNPROCESSABLE_ENTITY,
            title="Unprocessable Entity",
            detail=detail,
            fields=fields,
            **kw,
        )


class TooManyRequestsError(AppError):
    def __init__(self, retry_after: int, detail: Optional[str] = None, **kw: Any) -> None:
        headers = {"Retry-After": str(retry_after)}
        if "headers" in kw and isinstance(kw["headers"], dict):
            headers.update(kw["headers"])
            kw.pop("headers")
        super().__init__(
            status=status.HTTP_429_TOO_MANY_REQUESTS,
            code=ErrorCode.RATE_LIMITED,
            title="Too Many Requests",
            detail=detail,
            retry_after=retry_after,
            headers=headers,
            **kw,
        )


class ServiceUnavailableError(AppError):
    def __init__(self, retry_after: Optional[int] = None, detail: Optional[str] = None, **kw: Any) -> None:
        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)
        if "headers" in kw and isinstance(kw["headers"], dict):
            headers.update(kw["headers"])
            kw.pop("headers")
        super().__init__(
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=ErrorCode.SERVICE_UNAVAILABLE,
            title="Service Unavailable",
            detail=detail,
            retry_after=retry_after,
            headers=headers,
            **kw,
        )


class InternalServerError(AppError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=ErrorCode.INTERNAL_ERROR,
            title="Internal Server Error",
            detail=detail,
            **kw,
        )


# Вспомогательные функции

def _get_correlation_id(request: Optional[Request]) -> str:
    """
    Берём корреляционный идентификатор из заголовков или генерируем новый.
    """
    try:
        if request is not None:
            cid = request.headers.get(CORRELATION_HEADER) or request.headers.get(REQUEST_ID_HEADER)
            if cid:
                return cid
    except Exception:  # не должен ломать обработчик
        pass
    return str(uuid.uuid4())


def _problem_json_response(problem: Problem, headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    hdrs = {CORRELATION_HEADER: problem.correlation_id}
    if problem.retry_after:
        hdrs["Retry-After"] = str(problem.retry_after)
    if headers:
        hdrs.update(headers)
    return JSONResponse(
        status_code=problem.status,
        content=problem.dict(),
        media_type=PROBLEM_CONTENT_TYPE,
        headers=hdrs,
    )


def problem_response(
    *,
    status_code: int,
    code: ErrorCode,
    title: str,
    detail: Optional[str] = None,
    fields: Optional[List[FieldError]] = None,
    remediation: Optional[str] = None,
    docs: Optional[str] = None,
    retry_after: Optional[int] = None,
    request: Optional[Request] = None,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Быстрое создание Problem Details-ответа вне механизма исключений.
    """
    cid = _get_correlation_id(request)
    problem = Problem(
        type=f"tag:cybersecurity-core:aethernova:{code}",
        title=title,
        status=status_code,
        detail=detail,
        instance=str(getattr(request, "url", "")) if request else None,
        code=code,
        correlation_id=cid,
        fields=fields,
        remediation=remediation,
        docs=docs,
        retry_after=retry_after,
    )
    return _problem_json_response(problem, headers=headers)


# Обработчики исключений

async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    cid = _get_correlation_id(request)
    instance = str(request.url)
    problem = exc.to_problem(correlation_id=cid, instance=instance)

    # Логирование (без чувствительных данных)
    logger.warning(
        "app_error",
        extra={
            "code": problem.code,
            "status": problem.status,
            "title": problem.title,
            "correlation_id": cid,
            "path": str(request.url.path),
            "method": request.method,
        },
    )
    return _problem_json_response(problem, headers=exc.headers)


async def _handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    cid = _get_correlation_id(request)
    instance = str(request.url)

    fields: List[FieldError] = []
    try:
        # FastAPI/ Pydantic совместимый формат .errors()
        for e in exc.errors():
            loc = list(e.get("loc", []))
            msg = e.get("msg") or e.get("message") or "Invalid value"
            typ = e.get("type")
            fields.append(FieldError(loc=loc, msg=msg, type=typ))
    except Exception:
        # fallback при неожиданных форматах
        fields.append(FieldError(loc=["body"], msg="Validation failed", type="validation_error"))

    problem = Problem(
        type=f"tag:cybersecurity-core:aethernova:{ErrorCode.VALIDATION_ERROR}",
        title="Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=None,
        instance=instance,
        code=ErrorCode.VALIDATION_ERROR,
        correlation_id=cid,
        fields=fields,
    )

    logger.info(
        "validation_error",
        extra={
            "status": problem.status,
            "count": len(fields),
            "correlation_id": cid,
            "path": str(request.url.path),
            "method": request.method,
        },
    )
    return _problem_json_response(problem)


async def _handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    cid = _get_correlation_id(request)
    instance = str(request.url)

    # Маппинг статус-кодов к внутренним кодам
    status_code = exc.status_code or status.HTTP_500_INTERNAL_SERVER_ERROR
    code_map = {
        status.HTTP_400_BAD_REQUEST: ErrorCode.BAD_REQUEST,
        status.HTTP_401_UNAUTHORIZED: ErrorCode.UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN: ErrorCode.FORBIDDEN,
        status.HTTP_404_NOT_FOUND: ErrorCode.NOT_FOUND,
        status.HTTP_409_CONFLICT: ErrorCode.CONFLICT,
        status.HTTP_422_UNPROCESSABLE_ENTITY: ErrorCode.UNPROCESSABLE_ENTITY,
        status.HTTP_429_TOO_MANY_REQUESTS: ErrorCode.RATE_LIMITED,
        status.HTTP_503_SERVICE_UNAVAILABLE: ErrorCode.SERVICE_UNAVAILABLE,
        status.HTTP_500_INTERNAL_SERVER_ERROR: ErrorCode.INTERNAL_ERROR,
    }
    code = code_map.get(status_code, ErrorCode.INTERNAL_ERROR)

    detail = str(exc.detail) if exc.detail else None
    title_by_status = {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        503: "Service Unavailable",
        500: "Internal Server Error",
    }
    title = title_by_status.get(status_code, "Error")

    retry_after = None
    if status_code in (status.HTTP_429_TOO_MANY_REQUESTS, status.HTTP_503_SERVICE_UNAVAILABLE):
        try:
            retry_after = int(exc.headers.get("Retry-After")) if exc.headers else None
        except Exception:
            retry_after = None

    problem = Problem(
        type=f"tag:cybersecurity-core:aethernova:{code}",
        title=title,
        status=status_code,
        detail=detail,
        instance=instance,
        code=code,
        correlation_id=cid,
        retry_after=retry_after,
    )

    logger.warning(
        "http_exception",
        extra={
            "status": status_code,
            "code": code,
            "title": title,
            "correlation_id": cid,
            "path": str(request.url.path),
            "method": request.method,
        },
    )
    return _problem_json_response(problem, headers=exc.headers)


async def _handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    cid = _get_correlation_id(request)
    instance = str(request.url)

    # В debug можно показать detail, иначе скрываем внутренности
    detail = str(exc) if DEBUG else None

    problem = Problem(
        type=f"tag:cybersecurity-core:aethernova:{ErrorCode.INTERNAL_ERROR}",
        title="Internal Server Error",
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=detail,
        instance=instance,
        code=ErrorCode.INTERNAL_ERROR,
        correlation_id=cid,
    )

    logger.exception(
        "unhandled_exception",
        extra={
            "correlation_id": cid,
            "path": str(request.url.path),
            "method": request.method,
        },
    )
    return _problem_json_response(problem)


def register_exception_handlers(app: Union[Starlette, Any]) -> None:
    """
    Регистрирует обработчики исключений в приложении FastAPI/Starlette.
    """
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(HTTPException, _handle_http_exception)
    app.add_exception_handler(Exception, _handle_unexpected_exception)
