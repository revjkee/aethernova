# SPDX-License-Identifier: Apache-2.0
"""
Industrial HTTP error utilities with RFC 7807 (application/problem+json) support.

Features:
- RFC 7807 Problem Details builder (safe-by-default)
- Rich HttpError hierarchy (4xx/5xx)
- Correlation ID via contextvars (+ helpers)
- Structured logging without leaking internals in production
- Optional adapters for Starlette/FastAPI and Flask (loaded lazily)
- Zero external dependencies (standard library only)

Usage (Starlette/FastAPI):
    from ops.api.http.errors import HttpError, register_starlette_exception_handlers

    app = FastAPI()
    register_starlette_exception_handlers(app, debug=False)

    @app.get("/boom")
    def boom():
        raise NotFound(detail="Resource X not found", code="RES_NOT_FOUND")

Usage (Flask, optional):
    from ops.api.http.errors import register_flask_error_handlers
    app = Flask(__name__)
    register_flask_error_handlers(app, debug=False)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
import contextvars
import datetime as _dt
import json
import logging
import traceback
import typing as t
import uuid

# --------------------------------------------------------------------------- #
# Correlation context
# --------------------------------------------------------------------------- #

_CORR_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

def set_correlation_id(value: str | None) -> None:
    """Set correlation id for current context (e.g., from incoming header)."""
    _CORR_ID.set(value)

def get_correlation_id(default: str | None = None) -> str | None:
    """Get correlation id for current context."""
    val = _CORR_ID.get()
    return val if val else default

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

PROBLEM_JSON = "application/problem+json"
DEFAULT_TYPE = "about:blank"

# --------------------------------------------------------------------------- #
# Core HTTP Error
# --------------------------------------------------------------------------- #

@dataclass(eq=False)
class HttpError(Exception):
    """Base HTTP error with RFC 7807 fields."""
    status: int
    title: str
    detail: str | None = None
    type: str = DEFAULT_TYPE
    instance: str | None = None  # urn:uuid:<...> or request path
    code: str | None = None      # application-specific code
    headers: dict[str, str] = field(default_factory=dict)
    extra: dict[str, t.Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (100 <= int(self.status) <= 599):
            raise ValueError(f"Invalid HTTP status: {self.status}")
        if self.instance is None:
            # Stable unique URI-ish instance id
            self.instance = f"urn:uuid:{uuid.uuid4()}"

    def __str__(self) -> str:
        return f"{self.status} {self.title}: {self.detail or ''}".strip()

    def to_problem(
        self,
        *,
        include_trace: bool = False,
        correlation_id: str | None = None,
        now: _dt.datetime | None = None,
    ) -> dict[str, t.Any]:
        """Serialize into RFC 7807 Problem Details object."""
        problem: dict[str, t.Any] = {
            "type": self.type or DEFAULT_TYPE,
            "title": self.title,
            "status": int(self.status),
            "detail": self.detail,
            "instance": self.instance,
        }
        # Application-specific code (optional)
        if self.code:
            problem["code"] = self.code
        # Timestamp and correlation insight
        ts = (now or _dt.datetime.utcnow()).replace(tzinfo=_dt.timezone.utc).isoformat()
        problem["timestamp"] = ts
        corr = correlation_id or get_correlation_id()
        if corr:
            problem["correlation_id"] = corr
        # Extra payload (non-confidential)
        if self.extra:
            problem["extra"] = self.extra
        # Optional trace (debug only; never enable in prod)
        if include_trace and "trace" not in problem:
            problem["trace"] = self._capture_trace()
        return problem

    def _capture_trace(self) -> str:
        return "".join(traceback.format_stack())

    def with_header(self, key: str, value: str) -> "HttpError":
        self.headers[key] = value
        return self

# --------------------------------------------------------------------------- #
# Error hierarchy (common cases)
# --------------------------------------------------------------------------- #

class BadRequest(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.BAD_REQUEST), title="Bad Request", detail=detail, **kw)

class Unauthorized(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.UNAUTHORIZED), title="Unauthorized", detail=detail, **kw)

class Forbidden(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.FORBIDDEN), title="Forbidden", detail=detail, **kw)

class NotFound(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.NOT_FOUND), title="Not Found", detail=detail, **kw)

class Conflict(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.CONFLICT), title="Conflict", detail=detail, **kw)

class Gone(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.GONE), title="Gone", detail=detail, **kw)

class UnsupportedMediaType(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.UNSUPPORTED_MEDIA_TYPE), title="Unsupported Media Type", detail=detail, **kw)

class UnprocessableEntity(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=422, title="Unprocessable Entity", detail=detail, **kw)

class TooManyRequests(HttpError):
    def __init__(self, detail: str | None = None, retry_after_seconds: int | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.TOO_MANY_REQUESTS), title="Too Many Requests", detail=detail, **kw)
        if retry_after_seconds is not None:
            self.headers.setdefault("Retry-After", str(int(retry_after_seconds)))

class ServiceUnavailable(HttpError):
    def __init__(self, detail: str | None = None, retry_after_seconds: int | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.SERVICE_UNAVAILABLE), title="Service Unavailable", detail=detail, **kw)
        if retry_after_seconds is not None:
            self.headers.setdefault("Retry-After", str(int(retry_after_seconds)))

class InternalServerError(HttpError):
    def __init__(self, detail: str | None = None, **kw: t.Any) -> None:
        super().__init__(status=int(HTTPStatus.INTERNAL_SERVER_ERROR), title="Internal Server Error", detail=detail, **kw)

# --------------------------------------------------------------------------- #
# Builders and helpers
# --------------------------------------------------------------------------- #

def mask_internal_error(exc: Exception, *, debug: bool) -> HttpError:
    """
    Convert arbitrary exceptions to safe HttpError.
    In debug=True, include exception details; otherwise, mask specifics.
    """
    if isinstance(exc, HttpError):
        return exc
    if debug:
        return InternalServerError(detail=f"{exc.__class__.__name__}: {exc}")
    return InternalServerError(detail="An internal error occurred")

def problem_response_payload(
    err: HttpError,
    *,
    debug: bool = False,
    correlation_id: str | None = None,
) -> tuple[dict[str, t.Any], int, dict[str, str]]:
    """Build (problem_json, status, headers)."""
    problem = err.to_problem(include_trace=bool(debug), correlation_id=correlation_id)
    headers = {"Content-Type": PROBLEM_JSON}
    if err.headers:
        headers.update(err.headers)
    return problem, err.status, headers

def log_error(
    err: HttpError,
    *,
    logger: logging.Logger | None = None,
    level: int | None = None,
    request_path: str | None = None,
) -> None:
    """Structured logging for errors."""
    lg = logger or logging.getLogger("http.errors")
    lvl = level if level is not None else (logging.WARNING if err.status < 500 else logging.ERROR)
    payload = {
        "event": "http_error",
        "status": err.status,
        "title": err.title,
        "detail": err.detail,
        "code": err.code,
        "type": err.type,
        "instance": err.instance,
        "correlation_id": get_correlation_id(),
        "extra": err.extra or {},
        "path": request_path,
    }
    try:
        lg.log(lvl, json.dumps(payload, ensure_ascii=False))
    except Exception:  # pragma: no cover
        lg.log(lvl, f"{err} [{payload}]")

# --------------------------------------------------------------------------- #
# Optional Starlette/FastAPI adapter (lazy import)
# --------------------------------------------------------------------------- #

def register_starlette_exception_handlers(app: t.Any, *, debug: bool = False) -> None:
    """
    Register exception handlers for Starlette/FastAPI if available.

    - HttpError -> RFC7807 JSONResponse
    - Exception -> masked InternalServerError
    """
    try:
        from starlette.requests import Request  # type: ignore
        from starlette.responses import JSONResponse  # type: ignore
    except Exception:  # Starlette not installed
        return

    async def _http_error_handler(request: "Request", exc: HttpError):
        corr = _extract_correlation_id_from_request(request)
        set_correlation_id(corr)
        problem, status, headers = problem_response_payload(exc, debug=debug, correlation_id=corr)
        log_error(exc, request_path=str(getattr(request, "url", "")))
        return JSONResponse(problem, status_code=status, headers=headers)

    async def _generic_error_handler(request: "Request", exc: Exception):
        corr = _extract_correlation_id_from_request(request)
        set_correlation_id(corr)
        err = mask_internal_error(exc, debug=debug)
        problem, status, headers = problem_response_payload(err, debug=debug, correlation_id=corr)
        log_error(err, request_path=str(getattr(request, "url", "")))
        return JSONResponse(problem, status_code=status, headers=headers)

    # Starlette/FastAPI API: add_exception_handler(ExceptionType, handler)
    app.add_exception_handler(HttpError, _http_error_handler)
    app.add_exception_handler(Exception, _generic_error_handler)

def _extract_correlation_id_from_request(request: t.Any) -> str | None:
    """Try to pull correlation id from common headers, else None."""
    try:
        headers = request.headers  # Starlette
        for key in ("x-correlation-id", "x-request-id", "traceparent"):
            val = headers.get(key) or headers.get(key.title())
            if val:
                return val.strip()
    except Exception:
        pass
    return get_correlation_id()

# --------------------------------------------------------------------------- #
# Optional Flask adapter (lazy import)
# --------------------------------------------------------------------------- #

def register_flask_error_handlers(app: t.Any, *, debug: bool = False) -> None:
    """
    Register error handlers for Flask if available.
    """
    try:
        from flask import Response, request  # type: ignore
    except Exception:
        return

    def _http_error_handler(exc: HttpError):
        corr = request.headers.get("X-Correlation-Id") or request.headers.get("X-Request-Id")
        set_correlation_id(corr)
        body, status, headers = problem_response_payload(exc, debug=debug, correlation_id=corr)
        log_error(exc, request_path=request.path)
        return Response(json.dumps(body), status=status, headers=headers, mimetype=PROBLEM_JSON)

    def _generic_error_handler(exc: Exception):
        corr = request.headers.get("X-Correlation-Id") or request.headers.get("X-Request-Id")
        set_correlation_id(corr)
        err = mask_internal_error(exc, debug=debug)
        body, status, headers = problem_response_payload(err, debug=debug, correlation_id=corr)
        log_error(err, request_path=request.path)
        return Response(json.dumps(body), status=status, headers=headers, mimetype=PROBLEM_JSON)

    app.register_error_handler(HttpError, _http_error_handler)
    app.register_error_handler(Exception, _generic_error_handler)

# --------------------------------------------------------------------------- #
# Utilities to raise common errors succinctly
# --------------------------------------------------------------------------- #

def require(condition: bool, *, detail: str = "Validation failed", code: str | None = None) -> None:
    """
    Assert-like guard that raises 400 if condition is False.
    """
    if not condition:
        raise BadRequest(detail=detail, code=code)

def not_none(value: t.Optional[t.Any], *, detail: str = "Resource not found", code: str | None = None):
    """
    Helper: ensure a value is present, else 404.
    """
    if value is None:
        raise NotFound(detail=detail, code=code)
    return value

# --------------------------------------------------------------------------- #
# Minimal self-test (manual run)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    set_correlation_id("demo-corr-id-123")
    try:
        raise TooManyRequests("Rate limit exceeded", retry_after_seconds=30, code="RATE_LIMIT")
    except HttpError as e:
        problem, status, hdrs = problem_response_payload(e, debug=True)
        print("STATUS:", status)
        print("HEADERS:", hdrs)
        print(json.dumps(problem, indent=2))
