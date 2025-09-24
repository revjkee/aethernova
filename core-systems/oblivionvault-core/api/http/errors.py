# -*- coding: utf-8 -*-
"""
OblivionVault Core — HTTP error handling (RFC 7807 Problem Details)

Features:
- Structured Problem Details (application/problem+json) per RFC 7807
- Stable error code taxonomy (OV-E***/OV-S***)
- Safe messages with PII/secret redaction; correlation via X-Request-ID
- First-class FastAPI/Starlette integration: register_exception_handlers(app)
- Mappings for AppError subclasses, HTTPException, Pydantic ValidationError,
  asyncio timeouts, JSON decode errors, and generic exceptions
- Retry-After support and docs links; production/dev disclosure controls

Usage (FastAPI):
    from api.http.errors import register_exception_handlers
    app = FastAPI()
    register_exception_handlers(app)

Rely only on stdlib + optional FastAPI/Starlette if present.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Type, Union

try:
    # Optional FastAPI/Starlette imports
    from fastapi import Request
    from fastapi.exceptions import RequestValidationError
    from starlette.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException
    _HAS_FASTAPI = True
except Exception:  # pragma: no cover - optional
    Request = Any  # type: ignore
    RequestValidationError = None  # type: ignore
    JSONResponse = None  # type: ignore
    StarletteHTTPException = None  # type: ignore
    _HAS_FASTAPI = False

# ------------------------------------------------------------------------------
# Configuration & constants
# ------------------------------------------------------------------------------

_LOG = logging.getLogger("oblivionvault.errors")

DEFAULT_ERROR_NAMESPACE = "https://errors.oblivionvault.io"
DEFAULT_DOCS_BASE = "https://docs.oblivionvault.io/errors"
DEFAULT_INSTANCE_PREFIX = "urn:ov:error:"

ENV = os.getenv("OBLIVIONVAULT_ENV", "dev").lower()  # dev|staging|prod
IS_PROD = ENV == "prod"

# Redaction tokens
REDACTED = "***"

# Headers
HDR_REQUEST_ID = "X-Request-ID"
HDR_RETRY_AFTER = "Retry-After"
CONTENT_TYPE_PROBLEM_JSON = "application/problem+json"


# ------------------------------------------------------------------------------
# Error code taxonomy
# ------------------------------------------------------------------------------

class ErrorCode:
    """
    Stable application error codes (string constants), grouped by class.
    E4xx - client errors; E5xx - server errors; Sxxx - security; Vxxx - validation.
    """
    BAD_REQUEST = "OV-E400"
    VALIDATION_FAILED = "OV-V422"
    UNAUTHORIZED = "OV-S401"
    FORBIDDEN = "OV-S403"
    NOT_FOUND = "OV-E404"
    CONFLICT = "OV-E409"
    PAYLOAD_TOO_LARGE = "OV-E413"
    RATE_LIMITED = "OV-E429"

    TIMEOUT = "OV-E408"
    DEPENDENCY_UNAVAILABLE = "OV-E503"
    SERVICE_UNAVAILABLE = "OV-E503A"
    INTERNAL_ERROR = "OV-E500"

    # Domain-specific samples (extend as needed)
    LEGAL_HOLD_BLOCK = "OV-L423"
    RETENTION_VIOLATION = "OV-L424"


# ------------------------------------------------------------------------------
# RFC 7807 data structures
# ------------------------------------------------------------------------------

@dataclass
class FieldError:
    field: str
    message: str
    code: Optional[str] = None

@dataclass
class ProblemDetails:
    type: str
    title: str
    status: int
    detail: str
    code: str
    correlationId: str
    timestamp: str
    instance: Optional[str] = None
    errors: Optional[List[FieldError]] = None
    remediations: Optional[List[str]] = None
    docs: Optional[str] = None
    retryAfter: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "code": self.code,
            "instance": self.instance,
            "correlationId": self.correlationId,
            "timestamp": self.timestamp,
        }
        if self.errors:
            data["errors"] = [asdict(e) for e in self.errors]
        if self.remediations:
            data["remediations"] = self.remediations
        if self.docs:
            data["docs"] = self.docs
        if self.retryAfter is not None:
            data["retryAfter"] = self.retryAfter
        if self.extra:
            data["extra"] = self.extra
        return data


# ------------------------------------------------------------------------------
# Base application exceptions
# ------------------------------------------------------------------------------

class AppError(Exception):
    """
    Base application error with HTTP mapping and RFC 7807 fields.
    Subclass for domain-specific errors.
    """
    status: HTTPStatus = HTTPStatus.BAD_REQUEST
    code: str = ErrorCode.BAD_REQUEST
    title: str = "Bad Request"
    detail: str = "The request could not be understood or was missing required parameters."
    retry_after: Optional[int] = None
    headers: Optional[Mapping[str, str]] = None
    errors: Optional[List[FieldError]] = None
    docs: Optional[str] = None
    remediations: Optional[List[str]] = None
    extra: Dict[str, Any] = {}

    def __init__(
        self,
        *,
        detail: Optional[str] = None,
        errors: Optional[List[FieldError]] = None,
        retry_after: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        docs: Optional[str] = None,
        remediations: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if detail:
            self.detail = detail
        if errors is not None:
            self.errors = errors
        if retry_after is not None:
            self.retry_after = retry_after
        if headers is not None:
            self.headers = headers
        if docs:
            self.docs = docs
        if remediations:
            self.remediations = remediations
        if extra:
            self.extra = extra
        super().__init__(self.detail)


# Concrete subclasses (extend as needed)
class ValidationAppError(AppError):
    status = HTTPStatus.UNPROCESSABLE_ENTITY
    code = ErrorCode.VALIDATION_FAILED
    title = "Validation Failed"
    detail = "The request payload failed validation."

class UnauthorizedError(AppError):
    status = HTTPStatus.UNAUTHORIZED
    code = ErrorCode.UNAUTHORIZED
    title = "Unauthorized"
    detail = "Authentication is required to access this resource."

class ForbiddenError(AppError):
    status = HTTPStatus.FORBIDDEN
    code = ErrorCode.FORBIDDEN
    title = "Forbidden"
    detail = "You do not have permission to access this resource."

class NotFoundError(AppError):
    status = HTTPStatus.NOT_FOUND
    code = ErrorCode.NOT_FOUND
    title = "Not Found"
    detail = "The requested resource was not found."

class ConflictError(AppError):
    status = HTTPStatus.CONFLICT
    code = ErrorCode.CONFLICT
    title = "Conflict"
    detail = "The request could not be completed due to a conflict."

class PayloadTooLargeError(AppError):
    status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = ErrorCode.PAYLOAD_TOO_LARGE
    title = "Payload Too Large"
    detail = "The request payload is too large."

class RateLimitError(AppError):
    status = HTTPStatus.TOO_MANY_REQUESTS
    code = ErrorCode.RATE_LIMITED
    title = "Too Many Requests"
    detail = "Rate limit exceeded. Please try again later."

class TimeoutAppError(AppError):
    status = HTTPStatus.REQUEST_TIMEOUT
    code = ErrorCode.TIMEOUT
    title = "Request Timeout"
    detail = "The request timed out."

class DependencyUnavailableError(AppError):
    status = HTTPStatus.SERVICE_UNAVAILABLE
    code = ErrorCode.DEPENDENCY_UNAVAILABLE
    title = "Upstream Dependency Unavailable"
    detail = "An upstream dependency is unavailable."

class InternalServerError(AppError):
    status = HTTPStatus.INTERNAL_SERVER_ERROR
    code = ErrorCode.INTERNAL_ERROR
    title = "Internal Server Error"
    detail = "An internal error occurred."


# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------

def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat()

def _status_title(status: HTTPStatus) -> str:
    return f"{status.value} {status.phrase}"

def _build_type_url(code: str) -> str:
    return f"{DEFAULT_ERROR_NAMESPACE}/{code}"

def _docs_url(code: str) -> str:
    return f"{DEFAULT_DOCS_BASE}/{code}"

def _correlation_id_from(request: Optional[Any]) -> str:
    try:
        if request and hasattr(request, "headers"):
            rid = request.headers.get(HDR_REQUEST_ID)
            if rid:
                return rid
    except Exception:  # pragma: no cover
        pass
    return str(uuid.uuid4())

def _safe_detail(detail: str) -> str:
    if IS_PROD:
        # Basic redaction patterns; extend as necessary
        tokens = ["secret", "password", "token", "key", "authorization", "cookie"]
        lowered = detail.lower()
        if any(t in lowered for t in tokens):
            return "An internal error occurred."
    return detail

def _redact_map(d: Mapping[str, Any]) -> Dict[str, Any]:
    redacted = {}
    for k, v in d.items():
        if any(s in k.lower() for s in ("secret", "password", "token", "key", "authorization", "cookie")):
            redacted[k] = REDACTED
        else:
            redacted[k] = v
    return redacted

def _problem_from_app_error(e: AppError, request: Optional[Any]) -> Tuple[ProblemDetails, Dict[str, str]]:
    status = e.status
    title = e.title or _status_title(status)
    correlation_id = _correlation_id_from(request)
    headers = dict(e.headers or {})
    if e.retry_after:
        headers[HDR_RETRY_AFTER] = str(e.retry_after)

    detail = _safe_detail(e.detail or title)

    problem = ProblemDetails(
        type=_build_type_url(e.code),
        title=title,
        status=int(status),
        detail=detail,
        code=e.code,
        instance=f"{DEFAULT_INSTANCE_PREFIX}{uuid.uuid4()}",
        correlationId=correlation_id,
        timestamp=_now_rfc3339(),
        errors=e.errors,
        remediations=e.remediations,
        docs=e.docs or _docs_url(e.code),
        retryAfter=e.retry_after,
        extra=e.extra or {},
    )

    return problem, headers

def _problem_from_generic(
    exc: Exception, request: Optional[Any], status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR
) -> Tuple[ProblemDetails, Dict[str, str]]:
    code = ErrorCode.INTERNAL_ERROR if status == HTTPStatus.INTERNAL_SERVER_ERROR else ErrorCode.BAD_REQUEST
    title = _status_title(status)
    correlation_id = _correlation_id_from(request)
    detail = title if IS_PROD else f"{title}: {exc.__class__.__name__}: {str(exc)}"
    extra: Dict[str, Any] = {}

    if not IS_PROD:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        extra["stack"] = tb[-16000:]  # guard size

    problem = ProblemDetails(
        type=_build_type_url(code),
        title=title,
        status=int(status),
        detail=_safe_detail(detail),
        code=code,
        instance=f"{DEFAULT_INSTANCE_PREFIX}{uuid.uuid4()}",
        correlationId=correlation_id,
        timestamp=_now_rfc3339(),
        errors=None,
        remediations=None,
        docs=_docs_url(code),
        retryAfter=None,
        extra=extra,
    )
    return problem, {}

def problem_from_validation_error(errs: Iterable[Tuple[str, str, Optional[str]]], request: Optional[Any] = None) -> ProblemDetails:
    """
    Build ProblemDetails from iterable of (field, message, code?) tuples.
    """
    fields = [FieldError(field=f, message=m, code=c) for (f, m, c) in errs]
    problem = ProblemDetails(
        type=_build_type_url(ErrorCode.VALIDATION_FAILED),
        title=_status_title(HTTPStatus.UNPROCESSABLE_ENTITY),
        status=int(HTTPStatus.UNPROCESSABLE_ENTITY),
        detail="Validation failed for one or more fields.",
        code=ErrorCode.VALIDATION_FAILED,
        instance=f"{DEFAULT_INSTANCE_PREFIX}{uuid.uuid4()}",
        correlationId=_correlation_id_from(request),
        timestamp=_now_rfc3339(),
        errors=fields,
        remediations=["Correct the highlighted fields and retry." if IS_PROD else "Fix invalid fields and retry."],
        docs=_docs_url(ErrorCode.VALIDATION_FAILED),
    )
    return problem


# ------------------------------------------------------------------------------
# FastAPI/Starlette handlers
# ------------------------------------------------------------------------------

async def _json_response(problem: ProblemDetails, headers: Optional[Mapping[str, str]] = None):
    if not _HAS_FASTAPI:
        # Fallback serialization if Starlette not present (for unit usage)
        payload = problem.to_dict()
        return problem.status, headers or {}, json.dumps(payload)
    return JSONResponse(
        content=problem.to_dict(),
        status_code=problem.status,
        media_type=CONTENT_TYPE_PROBLEM_JSON,
        headers=dict(headers or {}),
    )

def _log_problem(problem: ProblemDetails, level: int = logging.ERROR) -> None:
    # Avoid leaking sensitive info in logs
    payload = problem.to_dict()
    if "extra" in payload and isinstance(payload["extra"], dict):
        payload["extra"] = _redact_map(payload["extra"])
    _LOG.log(level, "problem_details: %s", json.dumps(payload, ensure_ascii=False))

async def _handle_app_error(request: Request, exc: AppError):  # type: ignore[override]
    problem, headers = _problem_from_app_error(exc, request)
    _log_problem(problem, level=logging.WARNING if problem.status < 500 else logging.ERROR)
    return await _json_response(problem, headers=headers)

async def _handle_http_exception(request: Request, exc: Any):  # StarletteHTTPException
    status = HTTPStatus(exc.status_code or 500)
    # Leverage provided detail if safe
    detail = str(exc.detail) if getattr(exc, "detail", None) else _status_title(status)
    app_exc = InternalServerError(detail=detail) if status >= HTTPStatus.INTERNAL_SERVER_ERROR else AppError(detail=detail)
    app_exc.status = status  # type: ignore
    app_exc.title = _status_title(status)  # type: ignore
    app_exc.code = ErrorCode.BAD_REQUEST if status < 500 else ErrorCode.INTERNAL_ERROR  # type: ignore
    problem, headers = _problem_from_app_error(app_exc, request)
    _log_problem(problem, level=logging.WARNING if status < 500 else logging.ERROR)
    return await _json_response(problem, headers=headers)

async def _handle_validation_error(request: Request, exc: Any):
    # FastAPI RequestValidationError has .errors()
    errs = []
    try:
        for e in exc.errors():  # type: ignore[attr-defined]
            loc = ".".join(str(p) for p in e.get("loc", []) if p is not None)
            msg = e.get("msg", "Invalid value")
            typ = e.get("type")
            errs.append((loc or "_", msg, typ))
    except Exception:  # pragma: no cover
        errs.append(("_", "Invalid request", None))
    problem = problem_from_validation_error(errs, request)
    _log_problem(problem, level=logging.INFO)
    return await _json_response(problem)

async def _handle_timeout(request: Request, exc: Exception):
    app_exc = TimeoutAppError()
    problem, headers = _problem_from_app_error(app_exc, request)
    _log_problem(problem, level=logging.WARNING)
    return await _json_response(problem, headers=headers)

async def _handle_generic(request: Request, exc: Exception):
    # Map common categories
    if isinstance(exc, asyncio.TimeoutError):
        return await _handle_timeout(request, exc)

    problem, headers = _problem_from_generic(exc, request, status=HTTPStatus.INTERNAL_SERVER_ERROR)
    _log_problem(problem, level=logging.ERROR)
    return await _json_response(problem, headers=headers)

def register_exception_handlers(app: Any) -> None:
    """
    Register all exception handlers on a FastAPI/Starlette app.
    Safe to call multiple times.
    """
    if not _HAS_FASTAPI:
        _LOG.warning("FastAPI/Starlette not detected; register_exception_handlers is a no-op.")
        return

    # AppError hierarchy
    app.add_exception_handler(AppError, _handle_app_error)

    # Starlette HTTPException, if available
    if StarletteHTTPException:
        app.add_exception_handler(StarletteHTTPException, _handle_http_exception)

    # FastAPI request validation
    if RequestValidationError:
        app.add_exception_handler(RequestValidationError, _handle_validation_error)

    # asyncio timeouts (explicitly)
    app.add_exception_handler(asyncio.TimeoutError, _handle_timeout)

    # Generic fallback
    app.add_exception_handler(Exception, _handle_generic)


# ------------------------------------------------------------------------------
# Public helpers to raise common errors (optional sugar)
# ------------------------------------------------------------------------------

def bad_request(detail: str, *, errors: Optional[List[FieldError]] = None) -> AppError:
    return AppError(detail=detail, errors=errors)

def not_found(detail: str = "Resource not found") -> NotFoundError:
    return NotFoundError(detail=detail)

def unauthorized(detail: str = "Authentication required") -> UnauthorizedError:
    return UnauthorizedError(detail=detail, headers={"WWW-Authenticate": "Bearer"})

def forbidden(detail: str = "Insufficient permissions") -> ForbiddenError:
    return ForbiddenError(detail=detail)

def conflict(detail: str = "Conflict") -> ConflictError:
    return ConflictError(detail=detail)

def rate_limited(retry_after_seconds: int, detail: str = "Rate limit exceeded") -> RateLimitError:
    return RateLimitError(detail=detail, retry_after=retry_after_seconds, headers={HDR_RETRY_AFTER: str(retry_after_seconds)})

def payload_too_large(detail: str = "Payload too large") -> PayloadTooLargeError:
    return PayloadTooLargeError(detail=detail)

def dependency_unavailable(detail: str = "Upstream dependency unavailable") -> DependencyUnavailableError:
    return DependencyUnavailableError(detail=detail)

def internal_error(detail: str = "Internal error") -> InternalServerError:
    return InternalServerError(detail=detail)


# ------------------------------------------------------------------------------
# Minimal self-check (optional)
# ------------------------------------------------------------------------------

if __name__ == "__main__":  # simple ad-hoc check
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(message)s")
    # Simulate problem serialization
    p = ProblemDetails(
        type=_build_type_url(ErrorCode.BAD_REQUEST),
        title=_status_title(HTTPStatus.BAD_REQUEST),
        status=int(HTTPStatus.BAD_REQUEST),
        detail="Invalid input",
        code=ErrorCode.BAD_REQUEST,
        instance=f"{DEFAULT_INSTANCE_PREFIX}{uuid.uuid4()}",
        correlationId=str(uuid.uuid4()),
        timestamp=_now_rfc3339(),
        errors=[FieldError(field="name", message="must not be empty")],
        remediations=["Provide a non-empty 'name'"],
        docs=_docs_url(ErrorCode.BAD_REQUEST),
        extra={"traceHint": "demo"},
    )
    print(json.dumps(p.to_dict(), indent=2))
