# automation-core/src/automation_core/exceptions/core.py
"""
Unified exception model for Automation Core.

Key features
------------
- `CoreError`: single base class for all domain exceptions.
- Problem Details (RFC 9457) serialization via `.to_problem_details()`.     # Ref
- HTTP status and retryability semantics aligned with RFC 9110/6585.        # Ref
- Correct exception chaining (PEP 3134) using `__cause__`/`__context__`.     # Ref
- JSON-friendly logging payloads via `.to_log_record()` (no PII by default). # Ref
- Mapping of built-in exceptions to domain errors (`map_exception`).
- Helpers: `ensure(...)`, `log_exception(...)`.

References
----------
- RFC 9457 (Problem Details for HTTP APIs): obsoletes RFC 7807.             # https://www.rfc-editor.org/rfc/rfc9457.html
- RFC 9110 (HTTP Semantics) — статус-коды 4xx/5xx и их семантика.           # https://www.rfc-editor.org/rfc/rfc9110.html
- RFC 6585 (Additional HTTP Status Codes) — в т.ч. 429 Too Many Requests.   # https://datatracker.ietf.org/doc/html/rfc6585
- PEP 3134 (Exception Chaining) — приоритет __cause__ над __context__.       # https://peps.python.org/pep-3134/
- Python docs: Built-in Exceptions / logging cookbook.                       # https://docs.python.org/3/library/exceptions.html
                                                                             # https://docs.python.org/3/howto/logging-cookbook.html
"""

from __future__ import annotations

import datetime as _dt
import enum
import json
import logging
import re
import traceback
import types
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Dict, Generator, Iterable, Optional, Tuple


# ------------------------------ Error codes -----------------------------------


class ErrorCode(str, enum.Enum):
    INTERNAL = "internal_error"
    CONFIG = "config_error"
    VALIDATION = "validation_error"
    AUTHENTICATION = "authentication_failed"
    PERMISSION = "permission_denied"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    PRECONDITION = "precondition_failed"
    RATE_LIMIT = "rate_limit_exceeded"
    TIMEOUT = "timeout"
    DEP_UNAVAILABLE = "dependency_unavailable"
    EXTERNAL_SERVICE = "external_service_error"
    SERIALIZATION = "serialization_error"
    DESERIALIZATION = "deserialization_error"
    STATE = "state_error"
    INVARIANT = "invariant_violation"


# Default titles for Problem Details (RFC 9457)
_DEFAULT_TITLES: Dict[ErrorCode, str] = {
    ErrorCode.INTERNAL: "Internal Server Error",
    ErrorCode.CONFIG: "Configuration Error",
    ErrorCode.VALIDATION: "Validation Error",
    ErrorCode.AUTHENTICATION: "Authentication Failed",
    ErrorCode.PERMISSION: "Permission Denied",
    ErrorCode.NOT_FOUND: "Resource Not Found",
    ErrorCode.CONFLICT: "Conflict",
    ErrorCode.PRECONDITION: "Precondition Failed",
    ErrorCode.RATE_LIMIT: "Too Many Requests",
    ErrorCode.TIMEOUT: "Timeout",
    ErrorCode.DEP_UNAVAILABLE: "Dependency Unavailable",
    ErrorCode.EXTERNAL_SERVICE: "Upstream Service Error",
    ErrorCode.SERIALIZATION: "Serialization Error",
    ErrorCode.DESERIALIZATION: "Deserialization Error",
    ErrorCode.STATE: "Invalid State",
    ErrorCode.INVARIANT: "Invariant Violation",
}

# Default HTTP status mapping (RFC 9110 / RFC 6585)
_DEFAULT_STATUS: Dict[ErrorCode, HTTPStatus] = {
    ErrorCode.INTERNAL: HTTPStatus.INTERNAL_SERVER_ERROR,             # 500
    ErrorCode.CONFIG: HTTPStatus.INTERNAL_SERVER_ERROR,               # 500
    ErrorCode.VALIDATION: HTTPStatus.BAD_REQUEST,                     # 400
    ErrorCode.AUTHENTICATION: HTTPStatus.UNAUTHORIZED,                # 401
    ErrorCode.PERMISSION: HTTPStatus.FORBIDDEN,                       # 403
    ErrorCode.NOT_FOUND: HTTPStatus.NOT_FOUND,                        # 404
    ErrorCode.CONFLICT: HTTPStatus.CONFLICT,                          # 409
    ErrorCode.PRECONDITION: HTTPStatus.PRECONDITION_FAILED,           # 412
    ErrorCode.RATE_LIMIT: HTTPStatus.TOO_MANY_REQUESTS,               # 429 (RFC 6585)
    ErrorCode.TIMEOUT: HTTPStatus.GATEWAY_TIMEOUT,                    # 504
    ErrorCode.DEP_UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,        # 503
    ErrorCode.EXTERNAL_SERVICE: HTTPStatus.BAD_GATEWAY,               # 502
    ErrorCode.SERIALIZATION: HTTPStatus.UNPROCESSABLE_CONTENT,        # 422 (RFC 9110)
    ErrorCode.DESERIALIZATION: HTTPStatus.UNPROCESSABLE_CONTENT,      # 422
    ErrorCode.STATE: HTTPStatus.INTERNAL_SERVER_ERROR,                # 500
    ErrorCode.INVARIANT: HTTPStatus.INTERNAL_SERVER_ERROR,            # 500
}

# Retryability hints: infrastructure can backoff/retry if True
_DEFAULT_RETRYABLE: Dict[ErrorCode, bool] = {
    ErrorCode.INTERNAL: False,
    ErrorCode.CONFIG: False,
    ErrorCode.VALIDATION: False,
    ErrorCode.AUTHENTICATION: False,
    ErrorCode.PERMISSION: False,
    ErrorCode.NOT_FOUND: False,
    ErrorCode.CONFLICT: False,
    ErrorCode.PRECONDITION: False,
    ErrorCode.RATE_LIMIT: True,
    ErrorCode.TIMEOUT: True,
    ErrorCode.DEP_UNAVAILABLE: True,
    ErrorCode.EXTERNAL_SERVICE: True,
    ErrorCode.SERIALIZATION: False,
    ErrorCode.DESERIALIZATION: False,
    ErrorCode.STATE: False,
    ErrorCode.INVARIANT: False,
}


# ------------------------------ Utilities -------------------------------------


_SECRET_KV_RE = re.compile(
    r"(?:token|secret|password|passwd|pwd|key|private|credential|auth|bearer)",
    re.IGNORECASE,
)


def _redact(obj: Any) -> Any:
    """
    Best-effort redaction for dict-like details to prevent secret leakage in logs.
    Non-destructive (returns a shallow copy).
    """
    try:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(k, str) and _SECRET_KV_RE.search(k):
                    out[k] = "******"
                else:
                    out[k] = v
            return out
        return obj
    except Exception:
        return obj


def _now_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()


def iter_chain(exc: BaseException) -> Generator[BaseException, None, None]:
    """
    Walk exception chain per PEP 3134: prefer __cause__, else __context__ if no cause.
    Yields the starting exception and then its chain up to the outermost.     # PEP 3134
    """
    current = exc
    seen: set[int] = set()
    while current and id(current) not in seen:
        seen.add(id(current))
        yield current
        nxt = getattr(current, "__cause__", None) or (getattr(current, "__cause__", None) is None and getattr(current, "__context__", None)) or None
        current = nxt  # type: ignore[assignment]


# ------------------------------ CoreError -------------------------------------


class CoreError(Exception):
    """
    Unified domain exception.

    Attributes
    ----------
    code : ErrorCode
    message : str
    details : dict (redacted in logs)
    http_status : int (RFC 9110)
    retryable : bool (hint for backoff)
    id : str (opaque instance identifier, UUID v4)
    """

    __slots__ = ("code", "message", "details", "http_status", "retryable", "id")

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode = ErrorCode.INTERNAL,
        details: Optional[Dict[str, Any]] = None,
        http_status: Optional[int] = None,
        retryable: Optional[bool] = None,
        cause: Optional[BaseException] = None,
        id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause  # explicit chaining; reported with priority  # PEP 3134
        self.code: ErrorCode = code
        self.message = message
        self.details: Dict[str, Any] = dict(details or {})
        self.http_status = int(http_status) if http_status is not None else int(_DEFAULT_STATUS[code])
        self.retryable = bool(_DEFAULT_RETRYABLE[code] if retryable is None else retryable)
        self.id = id or f"err-{uuid.uuid4()}"

    # ------------------ Representations ------------------

    def __str__(self) -> str:  # human-friendly
        return f"{self.code.value}: {self.message}"

    def to_problem_details(self, *, type_ns: str = "urn:problem:automation-core") -> Dict[str, Any]:
        """
        Build Problem Details object (RFC 9457, application/problem+json).
        Fields: type, title, status, detail, instance, plus extension members.
        """
        pd = {
            "type": f"{type_ns}:{self.code.value}",
            "title": _DEFAULT_TITLES[self.code],
            "status": self.http_status,
            "detail": self.message,
            "instance": self.id,
            # Extensions (allowed by RFC 9457)
            "code": self.code.value,
            "retryable": self.retryable,
            "timestamp": _now_iso(),
        }
        if self.details:
            pd["details"] = _redact(self.details)
        # Cause chain summary (messages only, for safe exposure)
        chain: list[str] = []
        for ex in iter_chain(self):
            if ex is self:
                continue
            chain.append(f"{ex.__class__.__name__}: {str(ex)}")
        if chain:
            pd["causes"] = chain
        return pd

    def to_log_record(self, *, include_trace: bool = True) -> Dict[str, Any]:
        """
        JSON-friendly record for logging. No PII: details are redacted by keys.
        """
        rec = {
            "@timestamp": _now_iso(),
            "error.id": self.id,
            "error.code": self.code.value,
            "error.message": self.message,
            "error.http_status": self.http_status,
            "error.retryable": self.retryable,
            "error.type": self.__class__.__name__,
            "error.details": _redact(self.details) if self.details else {},
        }
        if include_trace:
            traces: list[str] = []
            for ex in iter_chain(self):
                traces.append("".join(traceback.format_exception(type(ex), ex, ex.__traceback__)))
            rec["error.traces"] = traces
        return rec

    def with_status(self, status: int) -> "CoreError":
        self.http_status = int(status)
        return self

    def with_details(self, **kwargs: Any) -> "CoreError":
        self.details.update(kwargs)
        return self


# ------------------------------ Specializations --------------------------------


class ConfigurationError(CoreError):
    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.CONFIG, **kw)


class ValidationError(CoreError):
    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.VALIDATION, **kw)


class AuthenticationFailed(CoreError):
    def __init__(self, message: str = "Authentication required or failed", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.AUTHENTICATION, **kw)


class PermissionDenied(CoreError):
    def __init__(self, message: str = "Operation not permitted", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.PERMISSION, **kw)


class NotFoundError(CoreError):
    def __init__(self, message: str = "Resource not found", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.NOT_FOUND, **kw)


class ConflictError(CoreError):
    def __init__(self, message: str = "Conflict", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.CONFLICT, **kw)


class PreconditionFailed(CoreError):
    def __init__(self, message: str = "Precondition failed", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.PRECONDITION, **kw)


class RateLimitExceeded(CoreError):
    def __init__(self, message: str = "Too many requests", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.RATE_LIMIT, **kw)


class OperationTimeout(CoreError):
    def __init__(self, message: str = "Operation timed out", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.TIMEOUT, **kw)


class DependencyUnavailable(CoreError):
    def __init__(self, message: str = "Dependency unavailable", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.DEP_UNAVAILABLE, **kw)


class ExternalServiceError(CoreError):
    def __init__(self, message: str = "Upstream service error", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.EXTERNAL_SERVICE, **kw)


class SerializationError(CoreError):
    def __init__(self, message: str = "Serialization error", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.SERIALIZATION, **kw)


class DeserializationError(CoreError):
    def __init__(self, message: str = "Deserialization error", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.DESERIALIZATION, **kw)


class StateError(CoreError):
    def __init__(self, message: str = "Invalid state", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.STATE, **kw)


class InvariantViolation(CoreError):
    def __init__(self, message: str = "Invariant violation", **kw: Any) -> None:
        super().__init__(message, code=ErrorCode.INVARIANT, **kw)


# ------------------------------ Mapping helpers --------------------------------


def map_exception(exc: BaseException) -> CoreError:
    """
    Map built-in exceptions to domain-specific ones.
    This function is deterministic and side-effect free.
    """
    # Preserve explicit CoreError
    if isinstance(exc, CoreError):
        return exc

    if isinstance(exc, TimeoutError):  # built-in
        return OperationTimeout(str(exc), cause=exc)

    if isinstance(exc, PermissionError):
        return PermissionDenied(str(exc), cause=exc)

    if isinstance(exc, KeyError):
        msg = str(exc).strip("'")
        return NotFoundError(f"Key not found: {msg}", cause=exc)

    if isinstance(exc, ValueError):
        return ValidationError(str(exc), cause=exc)

    if isinstance(exc, FileNotFoundError):
        return NotFoundError(str(exc), cause=exc)

    if isinstance(exc, ConnectionError):
        return DependencyUnavailable(str(exc), cause=exc)

    # Fallback
    return CoreError(str(exc) or exc.__class__.__name__, cause=exc)


def ensure(condition: bool, error: Optional[CoreError] = None, *, message: str = "Precondition failed") -> None:
    """
    Raise `error` if condition is False; default to PreconditionFailed (412).
    """
    if not condition:
        raise error or PreconditionFailed(message)


# ------------------------------ Logging helper ---------------------------------


def log_exception(logger: logging.Logger, exc: BaseException, *, level: int = logging.ERROR, include_trace: bool = True, extra: Optional[Dict[str, Any]] = None) -> None:
    """
    Log exception using JSON-friendly payload (Python logging cookbook allows
    structured logging without external deps).                                                   # Ref
    """
    core_err = map_exception(exc)
    record = core_err.to_log_record(include_trace=include_trace)
    if extra:
        record.update(_redact(extra))
    # Emit as a single JSON line; handlers/formatters may reformat as needed.
    logger.log(level, json.dumps(record, ensure_ascii=False))


# ------------------------------ Example (doctest-style) ------------------------
# The following snippet illustrates usage; it is not executed at import time.
#
# try:
#     raise ValueError("bad input")
# except Exception as e:
#     err = map_exception(e).with_details(field="amount")
#     print(err.to_problem_details())  # RFC 9457-compliant dict
#
# logger = logging.getLogger("automation_core")
# try:
#     1 / 0
# except Exception as e:
#     log_exception(logger, e, include_trace=True)
#
# Notes:
# - Problem Details per RFC 9457: fields type/title/status/detail/instance.    # Ref
# - HTTP status semantics per RFC 9110/6585 (e.g., 429 Too Many Requests).     # Ref
# - Exception chaining follows PEP 3134: __cause__ preferred over __context__. # Ref
