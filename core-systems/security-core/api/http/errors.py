# File: security-core/api/http/errors.py
# Industrial-grade HTTP error handling for security-core (FastAPI/Starlette).
# Features:
# - RFC 7807 application/problem+json responses
# - Stable SEC-* error codes and typed domain exceptions
# - Safe prod messages, detailed dev diagnostics
# - Correlation via X-Request-ID / X-Correlation-ID
# - Sensitive data masking in context
# - Validation and HTTP exception bridging
# - Optional Retry-After support for 429/503
# Python 3.10+

from __future__ import annotations

import json
import logging
import os
import re
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette import status

logger = logging.getLogger("security_core.errors")


# ----------------------------
# Configuration and constants
# ----------------------------

PROBLEM_CONTENT_TYPE = "application/problem+json"
DEFAULT_ERROR_DOCS_BASE = "/docs/errors#"

SENSITIVE_KEYS = {
    "password",
    "passphrase",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "authorization",
    "api_key",
    "x-api-key",
    "client_secret",
    "private_key",
}

ENV_DEBUG = os.getenv("SECURITY_CORE_DEBUG", "").lower() in {"1", "true", "yes"}
ENV_NAME = os.getenv("ENV", os.getenv("PYTHON_ENV", "production")).lower()


def _is_debug() -> bool:
    return ENV_DEBUG or ENV_NAME in {"dev", "development", "debug", "local"}


def _docs_url_fragment(code: str) -> str:
    return f"{DEFAULT_ERROR_DOCS_BASE}{code.lower()}"


def _new_error_id() -> str:
    return str(uuid.uuid4())


def _pick_correlation_id(req: Optional[Request]) -> str:
    if req is None:
        return _new_error_id()
    hdrs = req.headers
    return hdrs.get("X-Request-ID") or hdrs.get("X-Correlation-ID") or _new_error_id()


def _mask_value(value: Any) -> Any:
    if value is None:
        return value
    s = str(value)
    if not s:
        return s
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:2]}***{s[-3:]}"


def _mask_sensitive(data: Any) -> Any:
    try:
        if isinstance(data, Mapping):
            out: Dict[str, Any] = {}
            for k, v in data.items():
                if k.lower() in SENSITIVE_KEYS:
                    out[k] = _mask_value(v)
                else:
                    out[k] = _mask_sensitive(v)
            return out
        if isinstance(data, (list, tuple)):
            return type(data)(_mask_sensitive(v) for v in data)
        return data
    except Exception:
        return None


# ----------------------------
# Error codes and titles
# ----------------------------

class ErrorCode(str, Enum):
    AUTH_FAILED = "SEC-AUTH-001"
    FORBIDDEN = "SEC-AUTH-002"
    VALIDATION_FAILED = "SEC-REQ-001"
    UNSUPPORTED_MEDIA_TYPE = "SEC-REQ-002"
    PAYLOAD_TOO_LARGE = "SEC-REQ-003"
    NOT_FOUND = "SEC-RES-001"
    CONFLICT = "SEC-RES-002"
    RATE_LIMITED = "SEC-RATE-001"
    BACKEND_TIMEOUT = "SEC-BE-001"
    SERVICE_UNAVAILABLE = "SEC-BE-002"
    INTEGRITY_VIOLATION = "SEC-DB-001"
    INTERNAL_ERROR = "SEC-INT-001"


DEFAULT_TITLES: Mapping[ErrorCode, str] = {
    ErrorCode.AUTH_FAILED: "Authentication failed",
    ErrorCode.FORBIDDEN: "Access denied",
    ErrorCode.VALIDATION_FAILED: "Validation failed",
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
    ErrorCode.PAYLOAD_TOO_LARGE: "Payload too large",
    ErrorCode.NOT_FOUND: "Resource not found",
    ErrorCode.CONFLICT: "Conflict",
    ErrorCode.RATE_LIMITED: "Rate limit exceeded",
    ErrorCode.BACKEND_TIMEOUT: "Backend timeout",
    ErrorCode.SERVICE_UNAVAILABLE: "Service unavailable",
    ErrorCode.INTEGRITY_VIOLATION: "Integrity constraint violation",
    ErrorCode.INTERNAL_ERROR: "Internal server error",
}


# ----------------------------
# RFC 7807 Problem container
# ----------------------------

@dataclass(slots=True)
class Problem:
    type: str
    title: str
    status: int
    code: str
    detail: Optional[str] = None
    instance: Optional[str] = None
    correlation_id: Optional[str] = None
    hint: Optional[str] = None
    docs_url: Optional[str] = None
    # optional extra diagnostics (masked)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "code": self.code,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.instance:
            payload["instance"] = self.instance
        if self.correlation_id:
            payload["correlation_id"] = self.correlation_id
        if self.hint:
            payload["hint"] = self.hint
        if self.docs_url:
            payload["docs_url"] = self.docs_url
        if self.context:
            payload["context"] = _mask_sensitive(self.context)
        return payload


def problem_response(problem: Problem, headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    return JSONResponse(
        content=problem.to_dict(),
        status_code=problem.status,
        media_type=PROBLEM_CONTENT_TYPE,
        headers=headers or {},
    )


# ----------------------------
# Domain exceptions
# ----------------------------

class SecurityCoreError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        http_status: int,
        detail: Optional[str] = None,
        *,
        title: Optional[str] = None,
        instance: Optional[str] = None,
        hint: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        docs_url: Optional[str] = None,
    ) -> None:
        super().__init__(detail or DEFAULT_TITLES.get(code, "Error"))
        self.code = code
        self.http_status = http_status
        self.detail = detail
        self.title = title or DEFAULT_TITLES[code]
        self.instance = instance
        self.hint = hint
        self.context = context or {}
        self.docs_url = docs_url or _docs_url_fragment(code)

    def to_problem(self, correlation_id: str) -> Problem:
        safe_detail = self.detail if _is_debug() else None
        return Problem(
            type=f"https://aethernova.ai/problems/{self.code.lower()}",
            title=self.title,
            status=self.http_status,
            code=self.code,
            detail=safe_detail,
            instance=self.instance,
            correlation_id=correlation_id,
            hint=self.hint if _is_debug() else None,
            docs_url=self.docs_url,
            context=self.context if _is_debug() else {},
        )


class AuthenticationError(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.AUTH_FAILED, status.HTTP_401_UNAUTHORIZED, detail, **kw)


class AuthorizationError(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.FORBIDDEN, status.HTTP_403_FORBIDDEN, detail, **kw)


class NotFoundError(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.NOT_FOUND, status.HTTP_404_NOT_FOUND, detail, **kw)


class ConflictError(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.CONFLICT, status.HTTP_409_CONFLICT, detail, **kw)


class ValidationFailed(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, context: Optional[Dict[str, Any]] = None, **kw: Any) -> None:
        super().__init__(
            ErrorCode.VALIDATION_FAILED,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail,
            context=context,
            **kw,
        )


class RateLimited(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.RATE_LIMITED, status.HTTP_429_TOO_MANY_REQUESTS, detail, **kw)


class BackendTimeout(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.BACKEND_TIMEOUT, status.HTTP_504_GATEWAY_TIMEOUT, detail, **kw)


class ServiceUnavailable(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.SERVICE_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE, detail, **kw)


class IntegrityViolation(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.INTEGRITY_VIOLATION, status.HTTP_409_CONFLICT, detail, **kw)


class UnsupportedMedia(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.UNSUPPORTED_MEDIA_TYPE, status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail, **kw)


class PayloadTooLarge(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.PAYLOAD_TOO_LARGE, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail, **kw)


class InternalError(SecurityCoreError):
    def __init__(self, detail: Optional[str] = None, **kw: Any) -> None:
        super().__init__(ErrorCode.INTERNAL_ERROR, status.HTTP_500_INTERNAL_SERVER_ERROR, detail, **kw)


# ----------------------------
# Exception handlers
# ----------------------------

def _log_exception(req: Optional[Request], err: Exception, code: ErrorCode, correlation_id: str) -> None:
    path = req.url.path if req else "-"
    method = req.method if req else "-"
    msg = f"{code} {method} {path} cid={correlation_id}"
    if _is_debug():
        logger.exception(msg)
    else:
        logger.error(msg)


def _traceback(err: Exception) -> Optional[str]:
    if not _is_debug():
        return None
    return "".join(traceback.format_exception(type(err), err, err.__traceback__))


async def _handle_security_core_error(request: Request, exc: SecurityCoreError):
    cid = _pick_correlation_id(request)
    _log_exception(request, exc, exc.code, cid)
    pb = exc.to_problem(correlation_id=cid)
    headers: Dict[str, str] = {}
    # optional Retry-After for rate limit or service unavailable
    if exc.code in {ErrorCode.RATE_LIMITED, ErrorCode.SERVICE_UNAVAILABLE}:
        headers["Retry-After"] = "30"
    return problem_response(pb, headers=headers)


async def _handle_http_exception(request: Request, exc: StarletteHTTPException):
    cid = _pick_correlation_id(request)
    status_code = exc.status_code
    # map to our codes
    if status_code == status.HTTP_401_UNAUTHORIZED:
        code = ErrorCode.AUTH_FAILED
    elif status_code == status.HTTP_403_FORBIDDEN:
        code = ErrorCode.FORBIDDEN
    elif status_code == status.HTTP_404_NOT_FOUND:
        code = ErrorCode.NOT_FOUND
    elif status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
        code = ErrorCode.VALIDATION_FAILED
    elif status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE:
        code = ErrorCode.PAYLOAD_TOO_LARGE
    elif status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE:
        code = ErrorCode.UNSUPPORTED_MEDIA_TYPE
    else:
        code = ErrorCode.INTERNAL_ERROR

    detail = str(exc.detail) if _is_debug() else None
    _log_exception(request, exc, code, cid)
    pb = Problem(
        type=f"https://aethernova.ai/problems/{code.lower()}",
        title=DEFAULT_TITLES[code],
        status=status_code,
        code=code,
        detail=detail,
        instance=str(request.url),
        correlation_id=cid,
        docs_url=_docs_url_fragment(code),
    )
    return problem_response(pb)


async def _handle_validation_error(request: Request, exc: RequestValidationError):
    cid = _pick_correlation_id(request)
    code = ErrorCode.VALIDATION_FAILED
    errors = exc.errors() if _is_debug() else []
    context = {"errors": errors} if _is_debug() else {}
    _log_exception(request, exc, code, cid)
    pb = Problem(
        type=f"https://aethernova.ai/problems/{code.lower()}",
        title=DEFAULT_TITLES[code],
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code=code,
        detail="Validation error" if _is_debug() else None,
        instance=str(request.url),
        correlation_id=cid,
        docs_url=_docs_url_fragment(code),
        context=context,
    )
    return problem_response(pb)


async def _handle_unhandled_exception(request: Request, exc: Exception):
    cid = _pick_correlation_id(request)
    code = ErrorCode.INTERNAL_ERROR
    _log_exception(request, exc, code, cid)
    tb = _traceback(exc)
    pb = Problem(
        type=f"https://aethernova.ai/problems/{code.lower()}",
        title=DEFAULT_TITLES[code],
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code=code,
        detail=tb,  # only present in debug
        instance=str(request.url),
        correlation_id=cid,
        docs_url=_docs_url_fragment(code),
    )
    return problem_response(pb)


# ----------------------------
# Public API
# ----------------------------

def register_error_handlers(app: FastAPI) -> None:
    """
    Wire up all exception handlers for FastAPI app.
    Call once during application initialization.
    """
    app.add_exception_handler(SecurityCoreError, _handle_security_core_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(Exception, _handle_unhandled_exception)


# ----------------------------
# Helpers to raise domain errors
# ----------------------------

def raise_auth_failed(detail: Optional[str] = None, **kw: Any) -> None:
    raise AuthenticationError(detail=detail, **kw)


def raise_forbidden(detail: Optional[str] = None, **kw: Any) -> None:
    raise AuthorizationError(detail=detail, **kw)


def raise_not_found(detail: Optional[str] = None, **kw: Any) -> None:
    raise NotFoundError(detail=detail, **kw)


def raise_conflict(detail: Optional[str] = None, **kw: Any) -> None:
    raise ConflictError(detail=detail, **kw)


def raise_validation_failed(detail: Optional[str] = None, context: Optional[Dict[str, Any]] = None, **kw: Any) -> None:
    raise ValidationFailed(detail=detail, context=context, **kw)


def raise_rate_limited(detail: Optional[str] = None, **kw: Any) -> None:
    raise RateLimited(detail=detail, **kw)


def raise_backend_timeout(detail: Optional[str] = None, **kw: Any) -> None:
    raise BackendTimeout(detail=detail, **kw)


def raise_service_unavailable(detail: Optional[str] = None, **kw: Any) -> None:
    raise ServiceUnavailable(detail=detail, **kw)


def raise_integrity_violation(detail: Optional[str] = None, **kw: Any) -> None:
    raise IntegrityViolation(detail=detail, **kw)


def raise_unsupported_media(detail: Optional[str] = None, **kw: Any) -> None:
    raise UnsupportedMedia(detail=detail, **kw)


def raise_payload_too_large(detail: Optional[str] = None, **kw: Any) -> None:
    raise PayloadTooLarge(detail=detail, **kw)


def raise_internal_error(detail: Optional[str] = None, **kw: Any) -> None:
    raise InternalError(detail=detail, **kw)
