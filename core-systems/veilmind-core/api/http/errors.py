# veilmind-core/api/http/errors.py
"""
Единый обработчик ошибок для HTTP API (FastAPI/Starlette) с выводом в формате RFC 7807:
Content-Type: application/problem+json

Возможности:
- Базовый класс AppError + набор производных (BadRequest, Unauthorized, Forbidden, NotFound, Conflict, RateLimit и др.)
- Автоматическая корреляция (X-Request-ID) и генерация при отсутствии
- Безопасное логирование (редакция секретов)
- Поля RFC 7807 + расширения (code, correlation_id, retriable, retry_after, fields)
- Единая регистрация хендлеров исключений: register_error_handlers(app)
- Совместимость с Pydantic v1/v2
"""

from __future__ import annotations

import json
import logging
import os
import traceback
import types
import uuid
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple, Type

# Pydantic v1/v2 совместимость
try:
    from pydantic import BaseModel, Field  # type: ignore
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore
    def Field(*_args, **_kwargs):  # type: ignore
        return None

# Starlette / FastAPI
try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException
except Exception:  # pragma: no cover
    # Позволяет импортировать модуль без FastAPI (например, в тестах)
    FastAPI = Any  # type: ignore
    Request = Any  # type: ignore
    JSONResponse = Any  # type: ignore
    RequestValidationError = type("RequestValidationError", (Exception,), {})  # type: ignore
    class StarletteHTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: Any = None, headers: Optional[Mapping[str, str]] = None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers or {}

logger = logging.getLogger("veilmind.http.errors")

PROBLEM_JSON_CT = "application/problem+json"
DEFAULT_ERROR_DOC_BASE = os.getenv("ERROR_DOC_BASE", "https://docs.veilmind.example/errors/")  # для поля type
DEBUG = os.getenv("VMC_DEBUG", "").lower() in ("1", "true", "yes")


# ----------------------------------------------------------------------
# Модели ответа (RFC 7807 + расширения)
# ----------------------------------------------------------------------
class ProblemDetails(BaseModel):  # type: ignore[misc]
    type: str = Field(default="about:blank", description="URI для типа ошибки")
    title: str = Field(default="Error")
    status: int = Field(default=500)
    detail: Optional[str] = Field(default=None)
    instance: Optional[str] = Field(default=None)

    # Расширения под X-:
    code: Optional[str] = Field(default=None, description="Стабильный машинный код ошибки")
    correlation_id: Optional[str] = Field(default=None)
    retriable: Optional[bool] = Field(default=None)
    retry_after: Optional[int] = Field(default=None, description="Рекомендованная задержка (сек)")
    fields: Optional[Dict[str, str]] = Field(default=None, description="Ошибки валидации по полям")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Безопасный контекст")

    class Config:
        arbitrary_types_allowed = True


# ----------------------------------------------------------------------
# Базовое исключение домена
# ----------------------------------------------------------------------
class AppError(Exception):
    http_status: int = 500
    code: str = "unknown_error"
    title: str = "Internal Server Error"
    detail: Optional[str] = None
    retriable: bool = False
    retry_after: Optional[int] = None
    headers: Dict[str, str] = {}

    def __init__(
        self,
        detail: Optional[str] = None,
        *,
        code: Optional[str] = None,
        http_status: Optional[int] = None,
        title: Optional[str] = None,
        retriable: Optional[bool] = None,
        retry_after: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        fields: Optional[Mapping[str, str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ):
        super().__init__(detail or self.detail or self.title)
        if code:
            self.code = code
        if http_status:
            self.http_status = http_status
        if title:
            self.title = title
        if retriable is not None:
            self.retriable = retriable
        if retry_after is not None:
            self.retry_after = retry_after
        if headers:
            self.headers = dict(headers)
        self.fields = dict(fields) if fields else None
        self.context = _safe_context(context or {})


# ----------------------------------------------------------------------
# Специализированные ошибки
# ----------------------------------------------------------------------
class BadRequest(AppError):
    http_status = 400
    code = "bad_request"
    title = "Bad Request"


class Unauthorized(AppError):
    http_status = 401
    code = "unauthorized"
    title = "Unauthorized"
    headers = {"WWW-Authenticate": "Bearer"}  # по умолчанию OIDC


class Forbidden(AppError):
    http_status = 403
    code = "forbidden"
    title = "Forbidden"


class NotFound(AppError):
    http_status = 404
    code = "not_found"
    title = "Not Found"


class Conflict(AppError):
    http_status = 409
    code = "conflict"
    title = "Conflict"


class UnprocessableEntity(AppError):
    http_status = 422
    code = "unprocessable_entity"
    title = "Unprocessable Entity"


class TooManyRequests(AppError):
    http_status = 429
    code = "rate_limited"
    title = "Too Many Requests"
    retriable = True


class PayloadTooLarge(AppError):
    http_status = 413
    code = "payload_too_large"
    title = "Payload Too Large"


class UpstreamTimeout(AppError):
    http_status = 504
    code = "upstream_timeout"
    title = "Gateway Timeout"
    retriable = True


class UpstreamUnavailable(AppError):
    http_status = 503
    code = "upstream_unavailable"
    title = "Service Unavailable"
    retriable = True


# ----------------------------------------------------------------------
# Утилиты
# ----------------------------------------------------------------------
_SENSITIVE_KEYS = {"password", "pass", "token", "secret", "authorization", "api_key", "apikey", "access_token", "refresh_token"}


def _redact_value(value: Any) -> Any:
    try:
        s = str(value)
    except Exception:  # pragma: no cover
        return "***"
    if not s:
        return s
    if len(s) <= 8:
        return "***"
    return f"{s[:2]}***{s[-2:]}"


def _redact_mapping(obj: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        if k.lower() in _SENSITIVE_KEYS:
            out[k] = _redact_value(v)
        elif isinstance(v, Mapping):
            out[k] = _redact_mapping(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [_redact_mapping(x) if isinstance(x, Mapping) else ("***" if isinstance(x, str) and len(x) > 64 else x) for x in v]
        else:
            out[k] = v
    return out


def _safe_context(ctx: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        return _redact_mapping(ctx)
    except Exception:  # pragma: no cover
        return {}


def _get_correlation_id(request: Optional[Request]) -> str:
    try:
        if request is not None:
            cid = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
            if cid:
                return cid[:128]
    except Exception:
        pass
    return str(uuid.uuid4())


def _translate(message: Optional[str], *, locale: Optional[str], code: Optional[str]) -> Optional[str]:
    """
    Заглушка локализации. При необходимости подключите i18n-провайдер.
    """
    _ = {
        "ru": {
            "bad_request": "Некорректный запрос",
            "unauthorized": "Требуется аутентификация",
            "forbidden": "Доступ запрещён",
            "not_found": "Ресурс не найден",
            "conflict": "Конфликт состояния",
            "rate_limited": "Слишком много запросов",
            "payload_too_large": "Слишком большой запрос",
            "upstream_unavailable": "Сервис недоступен",
            "upstream_timeout": "Таймаут шлюза",
        }
    }
    if locale and code and code in _.get(locale, {}):
        return _[locale][code]
    return message


def _problem_from_exception(
    exc: Exception,
    request: Optional[Request],
    *,
    locale: Optional[str] = None,
) -> Tuple[ProblemDetails, Dict[str, str]]:
    """
    Возвращает ProblemDetails и заголовки ответа.
    """
    correlation_id = _get_correlation_id(request)

    # AppError
    if isinstance(exc, AppError):
        title = _translate(exc.title, locale=locale, code=exc.code)
        p = ProblemDetails(
            type=f"{DEFAULT_ERROR_DOC_BASE}{exc.code}" if exc.code else "about:blank",
            title=title or exc.title,
            status=exc.http_status,
            detail=exc.detail,
            instance=(str(request.url) if request else None) if hasattr(request, "url") else None,
            code=exc.code,
            correlation_id=correlation_id,
            retriable=exc.retriable,
            retry_after=exc.retry_after,
            fields=exc.fields,
            context=exc.context,
        )
        headers = dict(exc.headers)
        if exc.retry_after:
            headers.setdefault("Retry-After", str(exc.retry_after))
        headers.setdefault("X-Request-ID", correlation_id)
        return p, headers

    # Starlette HTTPException
    if isinstance(exc, StarletteHTTPException):
        code = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict"}.get(
            exc.status_code, "http_error"
        )
        title_map = {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            409: "Conflict",
        }
        title = _translate(title_map.get(exc.status_code, "HTTP Error"), locale=locale, code=code)
        p = ProblemDetails(
            type=f"{DEFAULT_ERROR_DOC_BASE}{code}",
            title=title,
            status=exc.status_code,
            detail=str(exc.detail) if exc.detail is not None else None,
            instance=(str(request.url) if request else None) if hasattr(request, "url") else None,
            code=code,
            correlation_id=correlation_id,
            retriable=False,
        )
        headers = dict(getattr(exc, "headers", {}) or {})
        headers.setdefault("X-Request-ID", correlation_id)
        return p, headers

    # FastAPI RequestValidationError
    if isinstance(exc, RequestValidationError):
        fields: Dict[str, str] = {}
        try:
            for e in exc.errors():
                loc = ".".join(str(x) for x in e.get("loc", []) if x != "body")
                msg = e.get("msg", "")
                if loc:
                    fields[loc] = msg
        except Exception:
            fields = {}
        p = ProblemDetails(
            type=f"{DEFAULT_ERROR_DOC_BASE}validation_failed",
            title=_translate("Unprocessable Entity", locale=locale, code="unprocessable_entity") or "Unprocessable Entity",
            status=422,
            detail="Validation failed",
            instance=(str(request.url) if request else None) if hasattr(request, "url") else None,
            code="validation_failed",
            correlation_id=correlation_id,
            retriable=False,
            fields=fields or None,
        )
        headers = {"X-Request-ID": correlation_id}
        return p, headers

    # Прочие (внутренние) ошибки
    p = ProblemDetails(
        type=f"{DEFAULT_ERROR_DOC_BASE}internal",
        title=_translate("Internal Server Error", locale=locale, code="internal") or "Internal Server Error",
        status=500,
        detail=("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if DEBUG else None),
        instance=(str(request.url) if request else None) if hasattr(request, "url") else None,
        code="internal",
        correlation_id=correlation_id,
        retriable=False,
    )
    headers = {"X-Request-ID": correlation_id}
    return p, headers


def _model_dump(obj: Any) -> Dict[str, Any]:
    """
    Pydantic v1/v2 совместимый дамп.
    """
    if hasattr(obj, "model_dump"):  # pydantic v2
        return obj.model_dump(exclude_none=True)  # type: ignore[attr-defined]
    if hasattr(obj, "dict"):  # pydantic v1
        return obj.dict(exclude_none=True)  # type: ignore[attr-defined]
    return dict(obj)


def _build_json_response(problem: ProblemDetails, headers: Optional[Mapping[str, str]] = None) -> JSONResponse:
    payload = _model_dump(problem)
    return JSONResponse(
        status_code=problem.status,
        content=payload,
        media_type=PROBLEM_JSON_CT,
        headers=dict(headers or {}),
    )


# ----------------------------------------------------------------------
# Публичные хендлеры исключений
# ----------------------------------------------------------------------
async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    problem, headers = _problem_from_exception(exc, request, locale=_pick_locale(request))
    _log_problem(problem, exc=exc, request=request)
    return _build_json_response(problem, headers)


async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:  # type: ignore[override]
    problem, headers = _problem_from_exception(exc, request, locale=_pick_locale(request))
    _log_problem(problem, exc=exc, request=request)
    return _build_json_response(problem, headers)


async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:  # type: ignore[override]
    problem, headers = _problem_from_exception(exc, request, locale=_pick_locale(request))
    _log_problem(problem, exc=exc, request=request)
    return _build_json_response(problem, headers)


async def handle_unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    problem, headers = _problem_from_exception(exc, request, locale=_pick_locale(request))
    _log_problem(problem, exc=exc, request=request)
    return _build_json_response(problem, headers)


# ----------------------------------------------------------------------
# Регистрация в приложении
# ----------------------------------------------------------------------
def register_error_handlers(app: FastAPI) -> None:
    """
    Пример использования:
        app = FastAPI()
        register_error_handlers(app)
    """
    app.add_exception_handler(AppError, handle_app_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_error)
    app.add_exception_handler(Exception, handle_unhandled_error)  # последний, «catch‑all»


# ----------------------------------------------------------------------
# Логирование и контент‑нега
# ----------------------------------------------------------------------
def _pick_locale(request: Optional[Request]) -> Optional[str]:
    try:
        lang = (request.headers.get("Accept-Language") or "").lower()
        if lang.startswith("ru"):
            return "ru"
    except Exception:
        pass
    return None


def _log_problem(problem: ProblemDetails, *, exc: Exception, request: Optional[Request]) -> None:
    """
    Структурированное логирование ошибок:
    - 4xx логируем на уровне WARNING (без трейсбэка)
    - 5xx логируем на уровне ERROR (с трейсбэком в debug или кратко в проде)
    """
    data = {
        "event": "http_error",
        "status": problem.status,
        "code": problem.code,
        "type": problem.type,
        "title": problem.title,
        "detail": problem.detail if DEBUG else None,
        "correlation_id": problem.correlation_id,
        "instance": problem.instance,
        "retriable": problem.retriable,
        "retry_after": problem.retry_after,
        "fields": problem.fields,
    }
    # Попытка добавить безопасный контекст запроса
    try:
        if request is not None:
            data["method"] = request.method
            data["path"] = str(request.url)
            # тело запроса может быть уже прочитано; не блокируем на этом
            # запрещаем попадание чувствительных данных (редактирование)
    except Exception:
        pass

    # Выбор уровня
    if 400 <= problem.status < 500:
        logger.warning(json.dumps({k: v for k, v in data.items() if v is not None}, ensure_ascii=False))
    else:
        if DEBUG:
            logger.error(
                json.dumps({k: v for k, v in data.items() if v is not None}, ensure_ascii=False),
                exc_info=exc,
            )
        else:
            logger.error(json.dumps({k: v for k, v in data.items() if v is not None}, ensure_ascii=False))


# ----------------------------------------------------------------------
# Удобные фабрики для часто встречающихся случаев
# ----------------------------------------------------------------------
def problem_response(
    *,
    status: int,
    title: str,
    detail: Optional[str] = None,
    code: Optional[str] = None,
    fields: Optional[Mapping[str, str]] = None,
    retriable: Optional[bool] = None,
    retry_after: Optional[int] = None,
    instance: Optional[str] = None,
    correlation_id: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> JSONResponse:
    """
    Быстро вернуть кастомную проблему из обработчика.
    """
    cid = correlation_id or str(uuid.uuid4())
    p = ProblemDetails(
        type=f"{DEFAULT_ERROR_DOC_BASE}{code or 'custom'}",
        title=title,
        status=status,
        detail=detail,
        instance=instance,
        code=code or "custom",
        correlation_id=cid,
        retriable=retriable,
        retry_after=retry_after,
        fields=dict(fields) if fields else None,
    )
    hdrs = dict(headers or {})
    if retry_after:
        hdrs.setdefault("Retry-After", str(retry_after))
    hdrs.setdefault("X-Request-ID", cid)
    return _build_json_response(p, hdrs)


# ----------------------------------------------------------------------
# Пример декларативного поднятия ошибок внутри бизнес‑кода:
# raise NotFound(detail="Consent not found", context={"resource": "consent", "id": consent_id})
# ----------------------------------------------------------------------
