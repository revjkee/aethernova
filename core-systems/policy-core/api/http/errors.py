# policy-core/api/http/errors.py
# Статус: НЕ ВЕРИФИЦИРОВАНО — модуль рассчитан на FastAPI/Starlette, адаптируйте при ином фреймворке.
# Назначение: Единый слой ошибок HTTP с поддержкой RFC 7807 (application/problem+json),
#             доменными кодами, безопасным логированием и корреляцией запросов.

from __future__ import annotations

import json
import logging
import traceback
import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional

try:
    # FastAPI поверх Starlette
    from fastapi import Request
    from fastapi.responses import JSONResponse
    from fastapi.exceptions import RequestValidationError
except Exception:  # pragma: no cover
    # Базовые типы Starlette; если FastAPI не используется.
    from starlette.requests import Request  # type: ignore
    from starlette.responses import JSONResponse  # type: ignore
    RequestValidationError = None  # type: ignore

try:
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from starlette import status as http_status
except Exception:  # pragma: no cover
    StarletteHTTPException = None  # type: ignore

try:
    # Поддержка pydantic валидаций
    from pydantic import ValidationError as PydanticValidationError  # type: ignore
except Exception:  # pragma: no cover
    PydanticValidationError = None  # type: ignore


LOG = logging.getLogger("policy_core.api.errors")

PROBLEM_JSON = "application/problem+json"
SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "access_token", "refresh_token", "authorization", "cookie", "set-cookie", "client_secret"}
DEFAULT_PROBLEM_BASE = "/problems"  # может быть заменён на внешний URL


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(v: int, lo: int = 0, hi: int = 100) -> int:
    return lo if v < lo else hi if v > hi else v


def _coalesce(*vals):
    for v in vals:
        if v is not None:
            return v
    return None


def _redact_mapping(m: Mapping[str, Any]) -> Dict[str, Any]:
    """Безопасно «затирает» чувствительные ключи в словаре (плоский уровень)."""
    out: Dict[str, Any] = {}
    for k, v in m.items():
        if k.lower() in SENSITIVE_KEYS:
            out[k] = "***"
        else:
            out[k] = v
    return out


def _shorten(s: str, limit: int = 1000) -> str:
    if len(s) <= limit:
        return s
    return s[: limit - 1] + "…"


def _status_reason(status_code: int) -> str:
    # Минимальная карта Reason-Phrase; Starlette отдаёт стандартные фразы по коду,
    # но не полагаемся на это.
    reasons = {
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        412: "Precondition Failed",
        415: "Unsupported Media Type",
        422: "Unprocessable Entity",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }
    return reasons.get(status_code, "Error")


def _pick_correlation_id(request: Optional[Request]) -> str:
    if request is None:
        return str(uuid.uuid4())
    headers = request.headers
    for name in ("x-request-id", "x-correlation-id", "x-correlationid"):
        val = headers.get(name)
        if val:
            return val[:128]
    return str(uuid.uuid4())


def _pick_locale(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    return request.headers.get("accept-language")


@dataclass
class ProblemDetails:
    # RFC 7807 базовые поля
    type: str
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None

    # Расширения домена
    code: str = "unknown_error"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    i18n_key: Optional[str] = None
    user_message: Optional[str] = None
    timestamp: str = field(default_factory=_utc_now_iso)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "instance": self.instance,
            "code": self.code,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
        }
        if self.i18n_key:
            body["i18n_key"] = self.i18n_key
        if self.user_message:
            body["user_message"] = self.user_message
        if self.extra:
            # Перекладываем строго JSON-сериализуемые поля
            try:
                json.dumps(self.extra)
                body["extra"] = self.extra
            except Exception:
                body["extra"] = {"_warning": "non-serializable extra omitted"}
        return body

    def to_response(self, headers: Optional[Mapping[str, str]] = None) -> JSONResponse:
        hdrs: Dict[str, str] = {"Content-Type": PROBLEM_JSON, "X-Correlation-ID": self.correlation_id}
        if headers:
            hdrs.update({k: str(v) for k, v in headers.items()})
        return JSONResponse(status_code=self.status, content=self.to_dict(), headers=hdrs, media_type=PROBLEM_JSON)


class APIError(Exception):
    """Базовый класс доменных ошибок API."""

    status: int = 500
    code: str = "internal_error"
    title: Optional[str] = None
    i18n_key: Optional[str] = None
    log_level: int = logging.ERROR  # может быть INFO/WARNING/ERROR
    headers: Dict[str, str]

    def __init__(
        self,
        detail: Optional[str] = None,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        title: Optional[str] = None,
        i18n_key: Optional[str] = None,
        user_message: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        instance: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(detail or self.__class__.__name__)
        self.detail = _shorten(detail) if detail else None
        self.status = status or self.status
        self.code = code or self.code
        self.title = title or self.title or _status_reason(self.status)
        self.i18n_key = i18n_key or self.i18n_key
        self.user_message = user_message
        self.extra = dict(extra or {})
        self.headers = dict(headers or {})
        self.instance = instance
        self.cause = cause

    def to_problem(
        self,
        *,
        request: Optional[Request] = None,
        problem_base: str = DEFAULT_PROBLEM_BASE,
        correlation_id: Optional[str] = None,
    ) -> ProblemDetails:
        corr = correlation_id or _pick_correlation_id(request)
        problem_type = f"{problem_base.rstrip('/')}/{self.code}"
        extra = _redact_mapping(self.extra)
        if self.cause and isinstance(self.cause, Exception):
            # Сигнализируем о типе вложенной причины без утечки деталей
            extra.setdefault("cause", self.cause.__class__.__name__)
        return ProblemDetails(
            type=problem_type,
            title=self.title or _status_reason(self.status),
            status=self.status,
            detail=self.detail,
            instance=self.instance,
            code=self.code,
            correlation_id=corr,
            i18n_key=self.i18n_key,
            user_message=self.user_message,
            extra=extra,
        )


# ------- Готовые доменные исключения (минимальный набор) -------

class BadRequestError(APIError):
    status = 400
    code = "bad_request"
    log_level = logging.INFO


class UnauthorizedError(APIError):
    status = 401
    code = "unauthorized"
    log_level = logging.WARNING

    def __init__(self, detail: Optional[str] = None, *, www_authenticate: Optional[str] = None, **kw: Any) -> None:
        headers = dict(kw.pop("headers", {}) or {})
        if www_authenticate:
            headers["WWW-Authenticate"] = www_authenticate
        super().__init__(detail, headers=headers, **kw)


class ForbiddenError(APIError):
    status = 403
    code = "forbidden"
    log_level = logging.WARNING


class NotFoundError(APIError):
    status = 404
    code = "not_found"
    log_level = logging.INFO


class ConflictError(APIError):
    status = 409
    code = "conflict"
    log_level = logging.WARNING


class UnprocessableEntityError(APIError):
    status = 422
    code = "validation_error"
    log_level = logging.INFO


class RateLimitError(APIError):
    status = 429
    code = "rate_limited"
    log_level = logging.WARNING

    def __init__(self, detail: Optional[str] = None, *, retry_after: Optional[int] = None, **kw: Any) -> None:
        headers = dict(kw.pop("headers", {}) or {})
        if retry_after is not None:
            headers["Retry-After"] = str(max(0, int(retry_after)))
        super().__init__(detail, headers=headers, **kw)


class ServiceUnavailableError(APIError):
    status = 503
    code = "service_unavailable"
    log_level = logging.ERROR


# ------- Регистрация обработчиков исключений для FastAPI/Starlette -------

def register_exception_handlers(
    app,
    *,
    problem_base: str = DEFAULT_PROBLEM_BASE,
    include_server_details: bool = False,
    metrics_hook: Optional[Callable[[str, int, Dict[str, str]], None]] = None,
) -> None:
    """
    Регистрирует обработчики исключений. metrics_hook(name, status, tags) — опциональная метрика
    (например, Prometheus counter), куда передаётся имя события, код статуса и теги.
    """

    async def _handle_api_error(request: Request, exc: APIError):
        problem = exc.to_problem(request=request, problem_base=problem_base)
        _log_problem(problem, exc.log_level, request=request, exc=exc)
        _emit_metric(metrics_hook, "api_error", problem.status, {"code": exc.code})
        return problem.to_response(exc.headers)

    async def _handle_http_exception(request: Request, exc: StarletteHTTPException):  # type: ignore
        detail = _shorten(str(getattr(exc, "detail", ""))) if getattr(exc, "detail", None) else None
        headers = getattr(exc, "headers", None) or {}
        mapped = APIError(
            detail or _status_reason(exc.status_code),
            status=exc.status_code,
            code=_http_code_to_domain_code(exc.status_code),
            title=_status_reason(exc.status_code),
            headers=headers,
        )
        problem = mapped.to_problem(request=request, problem_base=problem_base)
        log_level = logging.WARNING if 400 <= exc.status_code < 500 else logging.ERROR
        _log_problem(problem, log_level, request=request, exc=exc)
        _emit_metric(metrics_hook, "http_exception", problem.status, {"code": mapped.code})
        return problem.to_response(headers)

    async def _handle_request_validation(request: Request, exc: RequestValidationError):  # type: ignore
        # FastAPI валидация запроса
        errors = getattr(exc, "errors", lambda: [])()
        simplified = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in errors]
        mapped = UnprocessableEntityError(
            "Request validation failed",
            extra={"errors": simplified},
            i18n_key="validation.request_failed",
        )
        problem = mapped.to_problem(request=request, problem_base=problem_base)
        _log_problem(problem, mapped.log_level, request=request, exc=exc)
        _emit_metric(metrics_hook, "request_validation_error", problem.status, {"code": mapped.code})
        return problem.to_response(mapped.headers)

    async def _handle_pydantic_validation(request: Request, exc: PydanticValidationError):  # type: ignore
        try:
            errors = exc.errors()
        except Exception:
            errors = []
        simplified = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in errors]
        mapped = UnprocessableEntityError(
            "Validation failed",
            extra={"errors": simplified},
            i18n_key="validation.failed",
        )
        problem = mapped.to_problem(request=request, problem_base=problem_base)
        _log_problem(problem, mapped.log_level, request=request, exc=exc)
        _emit_metric(metrics_hook, "pydantic_validation_error", problem.status, {"code": mapped.code})
        return problem.to_response(mapped.headers)

    async def _handle_unexpected(request: Request, exc: Exception):
        # Генерик 500, без утечки деталей в проде
        detail = None
        extra: Dict[str, Any] = {}
        if include_server_details:
            detail = _shorten(f"{exc.__class__.__name__}: {exc}")
            extra["trace"] = _shorten("".join(traceback.format_exception(exc)), 4000)
        mapped = APIError(
            detail or "Internal server error",
            status=500,
            code="internal_error",
            title=_status_reason(500),
            extra=extra,
        )
        problem = mapped.to_problem(request=request, problem_base=problem_base)
        _log_problem(problem, logging.ERROR, request=request, exc=exc)
        _emit_metric(metrics_hook, "unexpected_exception", problem.status, {"code": mapped.code})
        return problem.to_response(mapped.headers)

    # Реестр обработчиков
    app.add_exception_handler(APIError, _handle_api_error)
    if StarletteHTTPException is not None:
        app.add_exception_handler(StarletteHTTPException, _handle_http_exception)  # type: ignore
    if RequestValidationError is not None:
        app.add_exception_handler(RequestValidationError, _handle_request_validation)  # type: ignore
    if PydanticValidationError is not None:
        app.add_exception_handler(PydanticValidationError, _handle_pydantic_validation)  # type: ignore
    app.add_exception_handler(Exception, _handle_unexpected)


# ------- Вспомогательные функции -------

def _http_code_to_domain_code(status_code: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        412: "precondition_failed",
        415: "unsupported_media_type",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        502: "bad_gateway",
        503: "service_unavailable",
        504: "gateway_timeout",
    }.get(status_code, "http_error")


def _log_problem(problem: ProblemDetails, level: int, *, request: Optional[Request], exc: Optional[BaseException]) -> None:
    # Структурированное логирование без PII
    try:
        fields: Dict[str, Any] = {
            "event": "http_problem",
            "status": problem.status,
            "title": problem.title,
            "type": problem.type,
            "code": problem.code,
            "correlation_id": problem.correlation_id,
            "method": getattr(request, "method", None),
            "path": getattr(getattr(request, "url", None), "path", None),
            "client": getattr(getattr(request, "client", None), "host", None),
        }
        if problem.detail:
            fields["detail"] = _shorten(problem.detail, 500)
        # заголовки не логируем целиком, только язык
        locale = _pick_locale(request)
        if locale:
            fields["locale"] = locale
        LOG.log(level, json.dumps(fields, ensure_ascii=False))
    except Exception:
        # Падает — откатываемся на простое сообщение
        LOG.log(level, f"[{problem.status}] {problem.title} ({problem.code}) cid={problem.correlation_id}")


def _emit_metric(hook: Optional[Callable[[str, int, Dict[str, str]], None]], name: str, status: int, tags: Dict[str, str]) -> None:
    if hook:
        safe_tags = {k: str(v) for k, v in tags.items()}
        safe_tags["status"] = str(status)
        try:
            hook(name, status, safe_tags)
        except Exception:  # pragma: no cover
            LOG.debug("metrics_hook raised", exc_info=True)


# ------- Утилиты для явного формирования ошибок в хендлерах -------

def problem_response(
    status: int,
    *,
    code: str,
    title: Optional[str] = None,
    detail: Optional[str] = None,
    request: Optional[Request] = None,
    problem_base: str = DEFAULT_PROBLEM_BASE,
    headers: Optional[Mapping[str, str]] = None,
    user_message: Optional[str] = None,
    i18n_key: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> JSONResponse:
    """Сформировать problem+json напрямую в эндпоинте."""
    err = APIError(
        detail,
        status=status,
        code=code,
        title=title or _status_reason(status),
        user_message=user_message,
        i18n_key=i18n_key,
        extra=extra,
        headers=headers,
    )
    problem = err.to_problem(request=request, problem_base=problem_base)
    return problem.to_response(headers)


# ------- Пример интеграции (док-строка, не исполняется) -------
"""
# app.py
from fastapi import FastAPI
from policy_core.api.http.errors import register_exception_handlers, NotFoundError

app = FastAPI()
register_exception_handlers(app, problem_base="https://docs.example.com/problems", include_server_details=False)

@app.get("/items/{item_id}")
async def read_item(item_id: str):
    raise NotFoundError(f"Item {item_id} not found", extra={"item_id": item_id})
"""
