# zero-trust-core/api/http/errors.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import logging
import traceback
import types
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union, Callable, Sequence

# -------- Optional deps (safe fallbacks) --------
try:
    # Starlette/FastAPI types
    from starlette.requests import Request  # type: ignore
    from starlette.responses import JSONResponse  # type: ignore
    from starlette.middleware.base import BaseHTTPMiddleware  # type: ignore
    from starlette.types import ASGIApp  # type: ignore
    from starlette.exceptions import HTTPException as StarletteHTTPException  # type: ignore
except Exception:  # pragma: no cover
    Request = Any  # type: ignore
    JSONResponse = None  # type: ignore
    BaseHTTPMiddleware = object  # type: ignore
    ASGIApp = Any  # type: ignore
    StarletteHTTPException = None  # type: ignore

try:
    # Pydantic/FastAPI validation error
    from fastapi.exceptions import RequestValidationError  # type: ignore
except Exception:  # pragma: no cover
    RequestValidationError = None  # type: ignore

# -------- Logger --------
logger = logging.getLogger("zero_trust.http.errors")


# -------- Public Error Codes --------
class ErrorCode(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    INVALID_INPUT = "INVALID_INPUT"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL = "INTERNAL"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    MFA_ENROLL_REQUIRED = "MFA_ENROLL_REQUIRED"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    BAD_GATEWAY = "BAD_GATEWAY"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"


# -------- Default catalog (status, title) --------
_DEFAULT_CATALOG: Dict[ErrorCode, Tuple[int, str]] = {
    ErrorCode.UNAUTHENTICATED: (HTTPStatus.UNAUTHORIZED, "Authentication required"),
    ErrorCode.FORBIDDEN: (HTTPStatus.FORBIDDEN, "Insufficient privileges"),
    ErrorCode.NOT_FOUND: (HTTPStatus.NOT_FOUND, "Resource not found"),
    ErrorCode.INVALID_INPUT: (HTTPStatus.UNPROCESSABLE_ENTITY, "Invalid input"),
    ErrorCode.CONFLICT: (HTTPStatus.CONFLICT, "State conflict"),
    ErrorCode.RATE_LIMITED: (HTTPStatus.TOO_MANY_REQUESTS, "Rate limit exceeded"),
    ErrorCode.INTERNAL: (HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
    ErrorCode.TENANT_MISMATCH: (HTTPStatus.FORBIDDEN, "Tenant mismatch"),
    ErrorCode.POLICY_VIOLATION: (HTTPStatus.FORBIDDEN, "Policy violation"),
    ErrorCode.STEP_UP_REQUIRED: (HTTPStatus.UNAUTHORIZED, "Step-up authentication required"),
    ErrorCode.MFA_ENROLL_REQUIRED: (HTTPStatus.FORBIDDEN, "MFA enrollment required"),
    ErrorCode.DEPENDENCY_FAILURE: (HTTPStatus.FAILED_DEPENDENCY, "Upstream dependency failure"),
    ErrorCode.BAD_GATEWAY: (HTTPStatus.BAD_GATEWAY, "Bad gateway"),
    ErrorCode.SERVICE_UNAVAILABLE: (HTTPStatus.SERVICE_UNAVAILABLE, "Service unavailable"),
    ErrorCode.TIMEOUT: (HTTPStatus.GATEWAY_TIMEOUT, "Upstream timeout"),
}


# -------- Sensitive field redaction --------
_SENSITIVE_KEYS = {
    "password", "pass", "pwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "cookie", "set-cookie", "api_key", "x-api-key", "private_key",
    "client_secret", "credential", "key", "otp"
}


def _redact_value(value: Any) -> Any:
    try:
        s = str(value)
    except Exception:
        return "***"
    if not s:
        return s
    return f"{s[:2]}***{s[-2:]}" if len(s) > 4 else "***"


def redact(obj: Any, sensitive_keys: Iterable[str] = _SENSITIVE_KEYS) -> Any:
    """
    Deeply redacts values of keys considered sensitive.
    """
    keys = {k.lower() for k in sensitive_keys}

    def _walk(v: Any) -> Any:
        if isinstance(v, Mapping):
            out: Dict[str, Any] = {}
            for k, val in v.items():
                if k.lower() in keys:
                    out[k] = _redact_value(val)
                else:
                    out[k] = _walk(val)
            return out
        if isinstance(v, (list, tuple, set)):
            t = type(v)
            return t(_walk(x) for x in v)  # type: ignore
        return v

    return _walk(obj)


# -------- RFC 7807 Problem Details --------
@dataclass
class ProblemDetails:
    type: str = "about:blank"
    title: str = "Error"
    status: int = HTTPStatus.INTERNAL_SERVER_ERROR
    detail: Optional[str] = None
    instance: Optional[str] = None

    # Extensions:
    code: Optional[str] = None
    correlation_id: Optional[str] = None
    tenant_id: Optional[str] = None
    user_message: Optional[str] = None
    fields: Optional[Dict[str, Any]] = None
    retryable: Optional[bool] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Remove None values to keep payload compact
        return {k: v for k, v in d.items() if v is not None}


# -------- Core AppError --------
class AppError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        *,
        detail: Optional[str] = None,
        http_status: Optional[int] = None,
        title: Optional[str] = None,
        user_message: Optional[str] = None,
        fields: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        retryable: bool = False,
        cause: Optional[BaseException] = None,
        instance: Optional[str] = None,
        problem_type: str = "about:blank",
    ) -> None:
        self.code = code
        default_status, default_title = _DEFAULT_CATALOG.get(code, (HTTPStatus.INTERNAL_SERVER_ERROR, "Error"))
        self.http_status = int(http_status or default_status)
        self.title = title or default_title
        self.detail = detail
        self.user_message = user_message
        self.fields = redact(fields or {})
        self.correlation_id = correlation_id
        self.tenant_id = tenant_id
        self.retryable = retryable
        self.cause = cause
        self.instance = instance
        self.problem_type = problem_type

        super().__init__(self.__str__())

    def __str__(self) -> str:
        base = f"{self.code} ({self.http_status} {self.title})"
        if self.detail:
            base += f": {self.detail}"
        return base

    # Problem representation
    def to_problem(self, request: Optional[Request] = None) -> ProblemDetails:
        instance = self.instance
        if instance is None and request is not None:
            try:
                instance = str(request.url.path)  # type: ignore[attr-defined]
            except Exception:
                instance = None

        return ProblemDetails(
            type=self.problem_type,
            title=self.title,
            status=self.http_status,
            detail=self.detail,
            instance=instance,
            code=self.code.value,
            correlation_id=self.correlation_id,
            tenant_id=self.tenant_id,
            user_message=self.user_message,
            fields=self.fields or None,
            retryable=self.retryable,
        )

    # Factories
    @staticmethod
    def unauthenticated(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.UNAUTHENTICATED, detail=detail, **kw)

    @staticmethod
    def forbidden(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.FORBIDDEN, detail=detail, **kw)

    @staticmethod
    def not_found(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.NOT_FOUND, detail=detail, **kw)

    @staticmethod
    def invalid_input(detail: Optional[str] = None, fields: Optional[Dict[str, Any]] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.INVALID_INPUT, detail=detail, fields=fields, **kw)

    @staticmethod
    def conflict(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.CONFLICT, detail=detail, **kw)

    @staticmethod
    def rate_limited(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.RATE_LIMITED, detail=detail, **kw)

    @staticmethod
    def internal(detail: Optional[str] = None, **kw: Any) -> "AppError":
        return AppError(ErrorCode.INTERNAL, detail=detail, **kw)


# -------- Correlation helpers --------
_CORR_HEADERS = ("x-correlation-id", "x-request-id", "x-trace-id")


def ensure_correlation_id(request: Optional[Request] = None) -> str:
    # Extract or generate correlation id
    try:
        if request is not None:
            headers = request.headers  # type: ignore[attr-d]()
