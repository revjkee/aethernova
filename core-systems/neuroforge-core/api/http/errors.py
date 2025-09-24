# neuroforge-core/api/http/errors.py
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import logging
import os
import traceback
import types
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Type, Union, Callable
import contextvars

# Логгер модуля
log = logging.getLogger("neuroforge.http.errors")

# ----------------------------
# Глобальная конфигурация
# ----------------------------

_show_internal_details: bool = bool(int(os.getenv("NF_SHOW_INTERNAL_DETAILS", "0")))
_default_type_uri: str = os.getenv("NF_PROBLEM_TYPE_DEFAULT", "about:blank")

# Контекст запроса: корреляция
_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")


def configure(*, show_internal_details: Optional[bool] = None, default_type_uri: Optional[str] = None) -> None:
    """
    Конфигурирует поведение модуля.
    """
    global _show_internal_details, _default_type_uri
    if show_internal_details is not None:
        _show_internal_details = bool(show_internal_details)
    if default_type_uri:
        _default_type_uri = str(default_type_uri).strip() or "about:blank"


def set_correlation_id(value: Optional[str]) -> str:
    """
    Устанавливает (и возвращает) ID корреляции в контексте.
    """
    val = (value or "").strip() or str(uuid.uuid4())
    _correlation_id.set(val)
    return val


def get_correlation_id() -> str:
    """
    Возвращает текущий ID корреляции.
    """
    return _correlation_id.get() or ""


# ----------------------------
# Модели ошибок (RFC 7807)
# ----------------------------

PROBLEM_JSON = "application/problem+json"


@dataclass(frozen=True)
class FieldError:
    """
    Детали ошибки валидации конкретного поля.
    """
    path: str
    message: str
    code: Optional[str] = None


@dataclass
class ProblemDetails:
    """
    RFC 7807 + расширения (code, correlationId, fields, retryAfterSec, extras).
    """
    title: str
    status: int
    detail: Optional[str] = None
    type: str = _default_type_uri
    instance: Optional[str] = None
    code: Optional[str] = None
    correlationId: Optional[str] = None
    fields: List[FieldError] = field(default_factory=list)
    retryAfterSec: Optional[int] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        obj = {
            "type": self.type or "about:blank",
            "title": self.title,
            "status": int(self.status),
        }
        if self.detail:
            obj["detail"] = self.detail
        if self.instance:
            obj["instance"] = self.instance
        if self.code:
            obj["code"] = self.code
        if self.correlationId:
            obj["correlationId"] = self.correlationId
        if self.fields:
            obj["fields"] = [asdict(f) for f in self.fields]
        if self.retryAfterSec is not None:
            obj["retryAfterSec"] = int(self.retryAfterSec)
        if self.extras:
            # Исключаем ключи RFC 7807, чтобы не дублировать
            reserved = {"type", "title", "status", "detail", "instance", "code", "correlationId", "fields", "retryAfterSec"}
            obj.update({k: v for k, v in self.extras.items() if k not in reserved})
        return obj

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


# ----------------------------
# Исключения приложения
# ----------------------------

class AppError(Exception):
    """
    Базовое прикладное исключение, сериализуемое в Problem Details.
    """
    status: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "INTERNAL_ERROR"
    title: str = "Internal Server Error"
    type: str = _default_type_uri
    retry_after: Optional[int] = None
    headers: Dict[str, str]

    def __init__(
        self,
        detail: Optional[str] = None,
        *,
        fields: Optional[Iterable[FieldError]] = None,
        instance: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        extras: Optional[Mapping[str, Any]] = None,
        retry_after: Optional[int] = None,
        status: Optional[int] = None,
        code: Optional[str] = None,
        title: Optional[str] = None,
        type: Optional[str] = None,
    ) -> None:
        super().__init__(detail or self.title)
        self.detail = detail
        self.fields = list(fields or [])
        self.instance = instance
        self.headers = dict(headers or {})
        self.extras = dict(extras or {})
        if retry_after is not None:
            self.retry_after = int(retry_after)
        if status is not None:
            self.status = int(status)
        if code is not None:
            self.code = str(code)
        if title is not None:
            self.title = str(title)
        if type is not None:
            self.type = str(type)

    def to_problem(self, *, correlation_id: Optional[str] = None) -> ProblemDetails:
        cid = correlation_id or get_correlation_id()
        detail = self.detail
        if not _show_internal_details and self.status >= 500:
            detail = None  # Скрываем внутренние детали на 5xx
        pd = ProblemDetails(
            title=self.title,
            status=self.status,
            detail=detail,
            type=self.type or _default_type_uri,
            instance=self.instance,
            code=self.code,
            correlationId=cid or None,
            fields=self.fields,
            retryAfterSec=self.retry_after,
            extras=self.extras,
        )
        return pd


# Частые прикладные ошибки
class BadRequest(AppError):
    status = HTTPStatus.BAD_REQUEST
    code = "BAD_REQUEST"
    title = "Bad Request"


class ValidationProblem(AppError):
    status = HTTPStatus.UNPROCESSABLE_ENTITY
    code = "VALIDATION_ERROR"
    title = "Validation Failed"


class Unauthorized(AppError):
    status = HTTPStatus.UNAUTHORIZED
    code = "UNAUTHORIZED"
    title = "Unauthorized"


class Forbidden(AppError):
    status = HTTPStatus.FORBIDDEN
    code = "FORBIDDEN"
    title = "Forbidden"


class NotFound(AppError):
    status = HTTPStatus.NOT_FOUND
    code = "NOT_FOUND"
    title = "Not Found"


class Conflict(AppError):
    status = HTTPStatus.CONFLICT
    code = "CONFLICT"
    title = "Conflict"


class TooManyRequests(AppError):
    status = HTTPStatus.TOO_MANY_REQUESTS
    code = "RATE_LIMITED"
    title = "Too Many Requests"

    def __init__(self, detail: Optional[str] = None, *, retry_after: Optional[int] = None, **kw: Any) -> None:
        super().__init__(detail, retry_after=retry_after, **kw)
        if self.retry_after:
            self.headers.setdefault("Retry-After", str(self.retry_after))


class PayloadTooLarge(AppError):
    status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "PAYLOAD_TOO_LARGE"
    title = "Payload Too Large"


class UnsupportedMediaType(AppError):
    status = HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    code = "UNSUPPORTED_MEDIA_TYPE"
    title = "Unsupported Media Type"


class MethodNotAllowed(AppError):
    status = HTTPStatus.METHOD_NOT_ALLOWED
    code = "METHOD_NOT_ALLOWED"
    title = "Method Not Allowed"


class RequestTimeout(AppError):
    status = HTTPStatus.REQUEST_TIMEOUT
    code = "REQUEST_TIMEOUT"
    title = "Request Timeout"


class BadGateway(AppError):
    status = HTTPStatus.BAD_GATEWAY
    code = "BAD_UPSTREAM"
    title = "Bad Gateway"


class ServiceUnavailable(AppError):
    status = HTTPStatus.SERVICE_UNAVAILABLE
    code = "SERVICE_UNAVAILABLE"
    title = "Service Unavailable"


class GatewayTimeout(AppError):
    status = HTTPStatus.GATEWAY_TIMEOUT
    code = "GATEWAY_TIMEOUT"
    title = "Gateway Timeout"


# ----------------------------
# Маппинг произвольных исключений
# ----------------------------

ExceptionMapper = Callable[[BaseException], Optional[AppError]]
_custom_mappers: List[ExceptionMapper] = []


def register_exception_mapper(mapper: ExceptionMapper) -> None:
    """
    Регистрирует пользовательский маппер исключений -> AppError.
    Первый вернувший не-None определяет результат.
    """
    _custom_mappers.append(mapper)


def map_exception(exc: BaseException) -> AppError:
    """
    Преобразует произвольное исключение в AppError.
    """
    if isinstance(exc, AppError):
        return exc

    for mapper in _custom_mappers:
        try:
            mapped = mapper(exc)
            if isinstance(mapped, AppError):
                return mapped
        except Exception:  # не даём кастомному мапперу уронить обработку
            log.exception("exception mapper failed")

    # Fallback: внутренний сбой
    return AppError(
        detail=str(exc) if _show_internal_details else None,
        extras={"exception": exc.__class__.__name__ if _show_internal_details else None},
    )


# ----------------------------
# Рендеринг ответа
# ----------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_response_payload(problem: ProblemDetails) -> Tuple[str, int, Dict[str, str]]:
    """
    Строит JSON-строку, код и заголовки для ответа.
    """
    body = problem.to_json()
    status = int(problem.status)
    headers: Dict[str, str] = {"Content-Type": PROBLEM_JSON}
    if problem.correlationId:
        headers["x-request-id"] = problem.correlationId
    if problem.retryAfterSec is not None:
        headers["Retry-After"] = str(problem.retryAfterSec)
    return body, status, headers


# ----------------------------
# FastAPI/Starlette интеграция (если установлены)
# ----------------------------

def _starlette_available() -> bool:
    try:
        import starlette  # noqa
        return True
    except Exception:
        return False


def fastapi_exception_handler():
    """
    Возвращает обработчик исключений для FastAPI/Starlette.
    Использование (FastAPI):
        from fastapi import FastAPI
        app = FastAPI()
        from .errors import register_fastapi
        register_fastapi(app)
    """
    if not _starlette_available():
        raise RuntimeError("Starlette/FastAPI не обнаружены")

    from starlette.responses import JSONResponse  # type: ignore
    from starlette.requests import Request  # type: ignore

    async def handler(request: "Request", exc: BaseException):
        # Корреляция: извлекаем из заголовков или генерируем
        cid = (
            request.headers.get("x-request-id")
            or request.headers.get("x-correlation-id")
            or get_correlation_id()
        )
        set_correlation_id(cid)
        app_err = map_exception(exc)
        problem = app_err.to_problem(correlation_id=cid)
        body, status, headers = build_response_payload(problem)

        # Логирование
        _log_exception(app_err, request_url=str(getattr(request, "url", "")))

        return JSONResponse(content=json.loads(body), status_code=status, headers=headers, media_type=PROBLEM_JSON)

    return handler


def register_fastapi(app: Any) -> None:
    """
    Регистрирует обработчики для FastAPI/Starlette, если доступны.
    Также обрабатывает pydantic/fastapi валидацию, если присутствует.
    """
    if not _starlette_available():
        return

    try:
        from fastapi.exceptions import RequestValidationError  # type: ignore
        from starlette.requests import Request  # type: ignore
        from starlette.exceptions import HTTPException as StarletteHTTPException  # type: ignore
        from starlette.responses import JSONResponse  # type: ignore
    except Exception:  # pragma: no cover
        return

    async def app_error_handler(request: "Request", exc: AppError):
        handler = fastapi_exception_handler()
        return await handler(request, exc)

    async def http_exc_handler(request: "Request", exc: "StarletteHTTPException"):
        # Переводим Starlette HTTPException в AppError
        status = exc.status_code
        detail = exc.detail if isinstance(exc.detail, str) else None
        headers = exc.headers or {}
        code = HTTPStatus(status).phrase.upper().replace(" ", "_")
        app_err = AppError(detail=detail, status=status, code=code, title=HTTPStatus(status).phrase, headers=headers)
        handler = fastapi_exception_handler()
        return await handler(request, app_err)

    async def request_validation_handler(request: "Request", exc: "RequestValidationError"):
        # Формируем ValidationProblem из ошибок pydantic
        fields = []
        try:
            for e in exc.errors():
                loc = ".".join(str(p) for p in e.get("loc", []))
                msg = e.get("msg", "Invalid value")
                typ = e.get("type")
                fields.append(FieldError(path=loc or "body", message=msg, code=typ))
        except Exception:
            fields = [FieldError(path="body", message="Invalid request")]

        app_err = ValidationProblem(detail="Request validation failed", fields=fields)
        handler = fastapi_exception_handler()
        return await handler(request, app_err)

    # Регистрация
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exc_handler)
    try:
        from fastapi.exceptions import RequestValidationError  # type: ignore
        app.add_exception_handler(RequestValidationError, request_validation_handler)
    except Exception:
        pass


# ----------------------------
# Универсальный ASGI middleware
# ----------------------------

def problem_middleware(app: Callable) -> Callable:
    """
    Оборачивает произвольное ASGI-приложение, обеспечивая ответы Problem+JSON.
    """
    async def _app(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)

        # Извлечение корреляции из заголовков
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cid = headers.get("x-request-id") or headers.get("x-correlation-id") or get_correlation_id()
        set_correlation_id(cid)

        try:
            await app(scope, receive, send)
        except BaseException as exc:
            app_err = map_exception(exc)
            problem = app_err.to_problem(correlation_id=cid)
            body, status, hdrs = build_response_payload(problem)

            # Лог
            _log_exception(app_err, request_url=_scope_url(scope))

            # Ответ
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()],
                }
            )
            await send({"type": "http.response.body", "body": body.encode()})

    return _app


# ----------------------------
# Вспомогательное
# ----------------------------

def _scope_url(scope: Mapping[str, Any]) -> str:
    try:
        scheme = scope.get("scheme", "http")
        server = scope.get("server") or ("", 0)
        host = f"{server[0]}:{server[1]}" if server and server[0] else headers_host(scope) or ""
        path = scope.get("raw_path", scope.get("path", b"")).decode() if isinstance(scope.get("raw_path"), (bytes, bytearray)) else scope.get("path", "")
        query = scope.get("query_string", b"").decode()
        return f"{scheme}://{host}{path}{('?' + query) if query else ''}"
    except Exception:
        return ""

def headers_host(scope: Mapping[str, Any]) -> str:
    try:
        for k, v in scope.get("headers", []):
            if k.decode().lower() == "host":
                return v.decode()
    except Exception:
        pass
    return ""

def _log_exception(err: AppError, *, request_url: str = "") -> None:
    """
    Структурированное логирование исключения.
    """
    cid = get_correlation_id()
    level = logging.ERROR if err.status >= 500 else logging.WARNING
    extra = {
        "event": "http_error",
        "code": err.code,
        "status": err.status,
        "title": err.title,
        "correlation_id": cid,
        "url": request_url,
    }
    if _show_internal_details:
        extra["stack"] = traceback.format_exc()
        extra["detail"] = err.detail
        extra["extras"] = err.extras
        extra["fields"] = [asdict(f) for f in getattr(err, "fields", [])]

    log.log(level, f"http_error status={err.status} code={err.code} cid={cid} url={request_url}", extra=extra)


# ----------------------------
# Утилиты фабрик
# ----------------------------

def problem_from_status(status: int, *, detail: Optional[str] = None, code: Optional[str] = None, title: Optional[str] = None, **kw: Any) -> AppError:
    """
    Быстрое создание AppError по статусу HTTP.
    """
    status_int = int(status)
    title = title or HTTPStatus(status_int).phrase
    code = code or title.upper().replace(" ", "_")
    return AppError(detail=detail, status=status_int, code=code, title=title, **kw)


# ----------------------------
# Пример использования (докстринг)
# ----------------------------

__doc__ = """
Использование с FastAPI:
    from fastapi import FastAPI
    from neuroforge_core.api.http.errors import register_fastapi, AppError, NotFound

    app = FastAPI()
    register_fastapi(app)

    @app.get("/items/{item_id}")
    async def get_item(item_id: str):
        if item_id != "42":
            raise NotFound(detail="Item not found")
        return {"id": item_id}

Использование как ASGI middleware:
    from neuroforge_core.api.http.errors import problem_middleware
    app = problem_middleware(app)

Изменение конфигурации:
    from neuroforge_core.api.http.errors import configure
    configure(show_internal_details=False)
"""
