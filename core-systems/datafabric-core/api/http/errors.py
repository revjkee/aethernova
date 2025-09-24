# datafabric-core/api/http/errors.py
# Industrial-grade error taxonomy and handlers for DataFabric Core HTTP API.
# Features:
# - RFC 7807 "application/problem+json" responses
# - Stable error codes (machine-readable) and human messages (localizable)
# - Domain exception hierarchy with HTTP mappings
# - Request ID propagation and deterministic error_id
# - Safe/verbose detail switching by environment
# - Integration with FastAPI, Pydantic, httpx, asyncio timeouts
# - OpenAPI-compatible models

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import traceback
import typing as t

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

# -----------------------------------------------------------------------------
# Constants & helpers
# -----------------------------------------------------------------------------

PROBLEM_JSON = "application/problem+json"

PUBLIC_ENVIRONMENTS = {"production"}  # safe details only
DEFAULT_LOCALE = "en"

def _is_public_env(env: str | None) -> bool:
    return (env or "production") in PUBLIC_ENVIRONMENTS

def _locale_from_request(request: Request) -> str:
    # Very light locale inference; extend with header parsing/bindings
    acc = request.headers.get("Accept-Language", "")
    if acc:
        return acc.split(",")[0].strip().lower()[:5]
    return DEFAULT_LOCALE

def _request_id(request: Request) -> str | None:
    return getattr(getattr(request, "state", object()), "request_id", None)

def _deterministic_error_id(code: str, rid: str | None) -> str:
    # Stable short id for correlation without leaking stack
    h = hashlib.sha256()
    h.update((code or "").encode("utf-8"))
    h.update((rid or "").encode("utf-8"))
    return h.hexdigest()[:16]

# -----------------------------------------------------------------------------
# Problem Details (RFC 7807)
# -----------------------------------------------------------------------------

class ProblemDetails(BaseModel):
    type: str = Field(default="about:blank", description="URI reference that identifies the problem type")
    title: str = Field(..., description="Short, human-readable summary of the problem type")
    status: int = Field(..., description="HTTP status code")
    detail: t.Optional[t.Union[str, dict, list]] = Field(default=None, description="Human-readable explanation")
    instance: t.Optional[str] = Field(default=None, description="URI reference that identifies the specific occurrence")
    code: str = Field(..., description="Stable machine-readable error code")
    request_id: t.Optional[str] = Field(default=None, description="Request correlation id")
    error_id: str = Field(..., description="Short deterministic error id for logs and support")
    extras: t.Optional[dict[str, t.Any]] = Field(default=None, description="Additional domain-specific fields")

    class Config:
        json_schema_extra = {
            "example": {
                "type": "https://errors.datafabric.io/common/bad_request",
                "title": "Bad Request",
                "status": 400,
                "detail": "Invalid payload",
                "instance": "/api/v1/echo",
                "code": "COMMON_BAD_REQUEST",
                "request_id": "0f0b0a0c-aaaa-bbbb-cccc-111122223333",
                "error_id": "7b3a9e2b5a1c8d04",
                "extras": {"field": "message", "reason": "too_long"},
            }
        }

# -----------------------------------------------------------------------------
# Localization stub (hook for i18n)
# -----------------------------------------------------------------------------

# Key -> { locale: message }
_LOCALIZATION: dict[str, dict[str, str]] = {
    "COMMON_BAD_REQUEST": {
        "en": "Bad Request",
        "ru": "Некорректный запрос",
    },
    "COMMON_UNAUTHORIZED": {
        "en": "Unauthorized",
        "ru": "Требуется аутентификация",
    },
    "COMMON_FORBIDDEN": {
        "en": "Forbidden",
        "ru": "Доступ запрещен",
    },
    "COMMON_NOT_FOUND": {
        "en": "Not Found",
        "ru": "Ресурс не найден",
    },
    "COMMON_CONFLICT": {
        "en": "Conflict",
        "ru": "Конфликт состояния",
    },
    "COMMON_UNPROCESSABLE": {
        "en": "Unprocessable Entity",
        "ru": "Необрабатываемый запрос",
    },
    "COMMON_PAYLOAD_TOO_LARGE": {
        "en": "Payload Too Large",
        "ru": "Слишком большой запрос",
    },
    "COMMON_UNSUPPORTED_MEDIA_TYPE": {
        "en": "Unsupported Media Type",
        "ru": "Неподдерживаемый тип данных",
    },
    "COMMON_TOO_MANY_REQUESTS": {
        "en": "Too Many Requests",
        "ru": "Слишком много запросов",
    },
    "COMMON_UPSTREAM_ERROR": {
        "en": "Upstream dependency failed",
        "ru": "Сбой внешней зависимости",
    },
    "COMMON_TIMEOUT": {
        "en": "Operation timed out",
        "ru": "Превышено время ожидания",
    },
    "COMMON_INTERNAL": {
        "en": "Internal Server Error",
        "ru": "Внутренняя ошибка сервера",
    },
    "COMMON_SERVICE_UNAVAILABLE": {
        "en": "Service Unavailable",
        "ru": "Сервис недоступен",
    },
}

def _localize(code: str, locale: str) -> str:
    table = _LOCALIZATION.get(code) or {}
    return table.get(locale) or table.get(DEFAULT_LOCALE) or code

# -----------------------------------------------------------------------------
# Domain exception hierarchy
# -----------------------------------------------------------------------------

class DomainError(Exception):
    code: str = "COMMON_INTERNAL"
    http_status: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    problem_type: str = "https://errors.datafabric.io/common/internal"
    safe_extras_keys: tuple[str, ...] = ()

    def __init__(self, message: str | None = None, *, extras: dict[str, t.Any] | None = None):
        super().__init__(message)
        self.message = message
        self.extras = extras or {}

    def to_problem(self, request: Request, *, env: str | None = None) -> ProblemDetails:
        rid = _request_id(request)
        eid = _deterministic_error_id(self.code, rid)
        locale = _locale_from_request(request)
        title = _localize(self.code, locale)
        detail: t.Any = self.message
        extras_out: dict[str, t.Any] | None = None

        # In public envs, limit details/extras to safe content only
        if _is_public_env(env):
            if detail and not isinstance(detail, (dict, list)):
                # Keep short message, avoid stack traces
                detail = str(detail)
            if self.extras:
                extras_out = {k: v for k, v in self.extras.items() if k in self.safe_extras_keys} or None
        else:
            # In non-public envs expose extras for debugging
            extras_out = self.extras or None

        return ProblemDetails(
            type=self.problem_type,
            title=title,
            status=self.http_status,
            detail=detail,
            instance=str(request.url.path),
            code=self.code,
            request_id=rid,
            error_id=eid,
            extras=extras_out,
        )

class BadRequestError(DomainError):
    code = "COMMON_BAD_REQUEST"
    http_status = status.HTTP_400_BAD_REQUEST
    problem_type = "https://errors.datafabric.io/common/bad_request"
    safe_extras_keys = ("field", "reason")

class UnauthorizedError(DomainError):
    code = "COMMON_UNAUTHORIZED"
    http_status = status.HTTP_401_UNAUTHORIZED
    problem_type = "https://errors.datafabric.io/common/unauthorized"

class ForbiddenError(DomainError):
    code = "COMMON_FORBIDDEN"
    http_status = status.HTTP_403_FORBIDDEN
    problem_type = "https://errors.datafabric.io/common/forbidden"

class NotFoundError(DomainError):
    code = "COMMON_NOT_FOUND"
    http_status = status.HTTP_404_NOT_FOUND
    problem_type = "https://errors.datafabric.io/common/not_found"
    safe_extras_keys = ("resource", "id")

class ConflictError(DomainError):
    code = "COMMON_CONFLICT"
    http_status = status.HTTP_409_CONFLICT
    problem_type = "https://errors.datafabric.io/common/conflict"
    safe_extras_keys = ("resource", "id")

class UnprocessableEntityError(DomainError):
    code = "COMMON_UNPROCESSABLE"
    http_status = status.HTTP_422_UNPROCESSABLE_ENTITY
    problem_type = "https://errors.datafabric.io/common/unprocessable"
    safe_extras_keys = ("field", "reason", "errors")

class PayloadTooLargeError(DomainError):
    code = "COMMON_PAYLOAD_TOO_LARGE"
    http_status = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    problem_type = "https://errors.datafabric.io/common/payload_too_large"
    safe_extras_keys = ("limit", )

class UnsupportedMediaTypeError(DomainError):
    code = "COMMON_UNSUPPORTED_MEDIA_TYPE"
    http_status = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    problem_type = "https://errors.datafabric.io/common/unsupported_media_type"
    safe_extras_keys = ("supported", )

class TooManyRequestsError(DomainError):
    code = "COMMON_TOO_MANY_REQUESTS"
    http_status = status.HTTP_429_TOO_MANY_REQUESTS
    problem_type = "https://errors.datafabric.io/common/too_many_requests"

class UpstreamError(DomainError):
    code = "COMMON_UPSTREAM_ERROR"
    http_status = status.HTTP_502_BAD_GATEWAY
    problem_type = "https://errors.datafabric.io/common/upstream"
    safe_extras_keys = ("service", "status", "endpoint")

class TimeoutError_(DomainError):
    code = "COMMON_TIMEOUT"
    http_status = status.HTTP_504_GATEWAY_TIMEOUT
    problem_type = "https://errors.datafabric.io/common/timeout"
    safe_extras_keys = ("stage", "timeout_sec")

class ServiceUnavailableError(DomainError):
    code = "COMMON_SERVICE_UNAVAILABLE"
    http_status = status.HTTP_503_SERVICE_UNAVAILABLE
    problem_type = "https://errors.datafabric.io/common/service_unavailable"
    safe_extras_keys = ("retry_after_sec",)

class InternalServerError(DomainError):
    code = "COMMON_INTERNAL"
    http_status = status.HTTP_500_INTERNAL_SERVER_ERROR
    problem_type = "https://errors.datafabric.io/common/internal"

# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------

def render_problem(problem: ProblemDetails) -> JSONResponse:
    return JSONResponse(
        status_code=problem.status,
        content=json.loads(problem.model_dump_json()),
        media_type=PROBLEM_JSON,
        headers={
            # Guides clients and caches; extend as needed
            "Content-Type": PROBLEM_JSON,
            "Cache-Control": "no-store",
        },
    )

# -----------------------------------------------------------------------------
# Handlers installer
# -----------------------------------------------------------------------------

def install_error_handlers(app) -> None:
    """
    Call this from app factory after middlewares:
        from .errors import install_error_handlers
        install_error_handlers(app)
    """
    logger = logging.getLogger("errors")
    env = os.getenv("DFC_ENVIRONMENT", "production")

    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError):
        problem = exc.to_problem(request, env=env)
        _log_problem(logger, problem, exc=exc)
        return render_problem(problem)

    @app.exception_handler(RequestValidationError)
    async def pydantic_validation_handler(request: Request, exc: RequestValidationError):
        # Flatten validation issues minimally; avoid leaking internal traces
        issues = exc.errors()
        safe = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in issues]
        err = UnprocessableEntityError(
            "Validation error",
            extras={"errors": safe},
        )
        problem = err.to_problem(request, env=env)
        _log_problem(logger, problem)
        return render_problem(problem)

    @app.exception_handler(socket.timeout)
    async def socket_timeout_handler(request: Request, exc: socket.timeout):
        err = TimeoutError_("Socket timeout", extras={"stage": "socket"})
        problem = err.to_problem(request, env=env)
        _log_problem(logger, problem)
        return render_problem(problem)

    # Optional httpx integration
    if httpx is not None:
        @app.exception_handler(httpx.TimeoutException)
        async def httpx_timeout_handler(request: Request, exc: Exception):
            err = TimeoutError_("Upstream timeout", extras={"stage": "httpx"})
            problem = err.to_problem(request, env=env)
            _log_problem(logger, problem)
            return render_problem(problem)

        @app.exception_handler(httpx.HTTPStatusError)
        async def httpx_status_handler(request: Request, exc: "httpx.HTTPStatusError"):
            resp = exc.response
            err = UpstreamError(
                f"Upstream returned {resp.status_code}",
                extras={"service": _guess_service(resp), "status": resp.status_code, "endpoint": str(resp.request.url)},
            )
            problem = err.to_problem(request, env=env)
            _log_problem(logger, problem)
            return render_problem(problem)

        @app.exception_handler(httpx.RequestError)
        async def httpx_request_handler(request: Request, exc: "httpx.RequestError"):
            err = UpstreamError("Upstream request failed", extras={"service": _guess_service(exc.request) if hasattr(exc, "request") else None})
            problem = err.to_problem(request, env=env)
            _log_problem(logger, problem)
            return render_problem(problem)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        # Avoid leaking internals in prod, provide trace in non-public envs
        err = InternalServerError("Unhandled error")
        problem = err.to_problem(request, env=env)

        if not _is_public_env(env):
            # Attach traceback for non-public envs
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            ext = dict(problem.extras or {})
            ext["traceback"] = tb
            problem.extras = ext

        _log_problem(logger, problem, exc=exc)
        return render_problem(problem)

# -----------------------------------------------------------------------------
# Logging helper
# -----------------------------------------------------------------------------

def _log_problem(logger: logging.Logger, problem: ProblemDetails, *, exc: Exception | None = None) -> None:
    extra = {
        "request_id": problem.request_id,
        "error_id": problem.error_id,
        "code": problem.code,
        "status": problem.status,
        "type": problem.type,
        "title": problem.title,
    }
    if exc:
        logger.exception(problem.title, extra=extra)
    else:
        logger.error(problem.title, extra=extra)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _guess_service(obj: t.Any) -> str | None:
    try:
        if hasattr(obj, "url"):
            host = getattr(obj.url, "host", None)
            return str(host) if host else None
        if hasattr(obj, "request") and obj.request is not None:
            host = getattr(obj.request.url, "host", None)
            return str(host) if host else None
    except Exception:  # pragma: no cover
        return None
    return None

# Convenience factories for raising with consistent codes
def bad_request(message: str, **extras) -> BadRequestError:
    return BadRequestError(message, extras=extras)

def unauthorized(message: str = "Unauthorized") -> UnauthorizedError:
    return UnauthorizedError(message)

def forbidden(message: str = "Forbidden") -> ForbiddenError:
    return ForbiddenError(message)

def not_found(resource: str, id_: t.Any) -> NotFoundError:
    return NotFoundError("Not found", extras={"resource": resource, "id": id_})

def conflict(resource: str, id_: t.Any) -> ConflictError:
    return ConflictError("Conflict", extras={"resource": resource, "id": id_})

def unprocessable(message: str, **extras) -> UnprocessableEntityError:
    return UnprocessableEntityError(message, extras=extras)

def payload_too_large(limit: int) -> PayloadTooLargeError:
    return PayloadTooLargeError("Payload too large", extras={"limit": limit})

def unsupported_media_type(supported: list[str]) -> UnsupportedMediaTypeError:
    return UnsupportedMediaTypeError("Unsupported media type", extras={"supported": supported})

def too_many_requests() -> TooManyRequestsError:
    return TooManyRequestsError("Too many requests")

def upstream_error(service: str, status_code: int, endpoint: str) -> UpstreamError:
    return UpstreamError("Upstream error", extras={"service": service, "status": status_code, "endpoint": endpoint})

def timeout(stage: str, timeout_sec: float | int) -> TimeoutError_:
    return TimeoutError_("Timeout", extras={"stage": stage, "timeout_sec": timeout_sec})

def service_unavailable(retry_after_sec: int | None = None) -> ServiceUnavailableError:
    return ServiceUnavailableError("Service unavailable", extras={"retry_after_sec": retry_after_sec} if retry_after_sec else {})
