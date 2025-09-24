# ledger-core/api/http/errors.py
"""
Промышленный модуль ошибок HTTP API с поддержкой RFC 7807 (Problem Details).
Совместим с FastAPI/Starlette и Flask, но не зависит от них напрямую.

Основные возможности:
- HttpError: базовый класс исключений с кодом домена, статусом и безопасной сериализацией.
- ErrorCode: enum стабильных кодов с маппингом на статусы и заголовки.
- Преобразование любых исключений в Problem Details (+ корреляция).
- Ретраибельность (retriable) и признак временности (temporary).
- Маскировка чувствительных полей при логировании/отдаче.
- Адаптеры: to_starlette_response(), to_flask_response(), fastapi_exception_handler().
- normalize_exception(): нормализует распространенные исключения (таймауты, валидация и т.п.).

RFC 7807: https://datatracker.ietf.org/doc/html/rfc7807
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import traceback
import types
import typing as t
from dataclasses import dataclass, field
from http import HTTPStatus

__all__ = [
    "ErrorCode",
    "HttpError",
    "problem_from_exception",
    "normalize_exception",
    "fastapi_exception_handler",
    "to_starlette_response",
    "to_flask_response",
]

logger = logging.getLogger(__name__)


class ErrorCode(str):
    BAD_REQUEST = "BAD_REQUEST"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    UNPROCESSABLE_ENTITY = "UNPROCESSABLE_ENTITY"
    DEPENDENCY_TIMEOUT = "DEPENDENCY_TIMEOUT"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_STATUS_BY_CODE: dict[str, HTTPStatus] = {
    ErrorCode.BAD_REQUEST: HTTPStatus.BAD_REQUEST,
    ErrorCode.VALIDATION_ERROR: HTTPStatus.UNPROCESSABLE_ENTITY,
    ErrorCode.AUTHENTICATION_FAILED: HTTPStatus.UNAUTHORIZED,
    ErrorCode.AUTHORIZATION_FAILED: HTTPStatus.FORBIDDEN,
    ErrorCode.NOT_FOUND: HTTPStatus.NOT_FOUND,
    ErrorCode.CONFLICT: HTTPStatus.CONFLICT,
    ErrorCode.RATE_LIMITED: HTTPStatus.TOO_MANY_REQUESTS,
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
    ErrorCode.UNPROCESSABLE_ENTITY: HTTPStatus.UNPROCESSABLE_ENTITY,
    ErrorCode.DEPENDENCY_TIMEOUT: HTTPStatus.GATEWAY_TIMEOUT,
    ErrorCode.DEPENDENCY_FAILURE: HTTPStatus.BAD_GATEWAY,
    ErrorCode.SERVICE_UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,
    ErrorCode.INTERNAL_ERROR: HTTPStatus.INTERNAL_SERVER_ERROR,
}

# Хедеры по умолчанию, добавляемые в ответ для согласованности
_DEFAULT_HEADERS: dict[str, str] = {
    "Content-Type": "application/problem+json; charset=utf-8",
    "Cache-Control": "no-store",
}

# Регулярные выражения для маскировки в extra/details
_REDACT_KEYS = re.compile(r"(pass(word)?|token|secret|authorization|api[_-]?key|cookie)", re.I)


def _redact_value(v: t.Any) -> t.Any:
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    s = str(v)
    if not s:
        return s
    # Маскируем все, что выглядит как ключ/секрет/токен
    if len(s) <= 8:
        return "******"
    return s[:3] + "…" + s[-2:]


def _redact_mapping(m: dict[str, t.Any]) -> dict[str, t.Any]:
    out: dict[str, t.Any] = {}
    for k, v in m.items():
        if _REDACT_KEYS.search(k):
            out[k] = _redact_value(v)
        elif isinstance(v, dict):
            out[k] = _redact_mapping(v)
        else:
            out[k] = v
    return out


@dataclass
class HttpError(Exception):
    """
    Исключение домена HTTP с сериализацией в RFC 7807.
    """

    code: str = ErrorCode.INTERNAL_ERROR
    title: str = "Internal Server Error"
    detail: str | None = None
    status: int = field(default=int(HTTPStatus.INTERNAL_SERVER_ERROR))
    type: str = field(default="about:blank")  # URI с документацией по коду, если есть
    instance: str | None = None  # URI конкретного ресурса/запроса
    correlation_id: str | None = None  # x-request-id/trace-id
    extra: dict[str, t.Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    retriable: bool = False
    temporary: bool = False
    retry_after: int | None = None  # сек, применяемо к RATE_LIMITED/UNAVAILABLE
    causes: list[str] = field(default_factory=list)  # цепочка причин (строки)
    log_level: int = field(default=logging.WARNING)

    def __post_init__(self) -> None:
        # Выставляем статус по коду, если явно не задан
        if not self.status:
            self.status = int(_STATUS_BY_CODE.get(self.code, HTTPStatus.INTERNAL_SERVER_ERROR))
        # Итоговый заголовок
        if self.retry_after and self.status in (
            HTTPStatus.TOO_MANY_REQUESTS,
            HTTPStatus.SERVICE_UNAVAILABLE,
        ):
            self.headers.setdefault("Retry-After", str(self.retry_after))

    @classmethod
    def bad_request(cls, detail: str, **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.BAD_REQUEST,
            title="Bad Request",
            detail=detail,
            status=int(HTTPStatus.BAD_REQUEST),
            **kw,
        )

    @classmethod
    def validation(cls, detail: str, errors: t.Any | None = None, **kw: t.Any) -> "HttpError":
        extra = dict(kw.pop("extra", {}) or {})
        if errors is not None:
            extra["errors"] = errors
        return cls(
            code=ErrorCode.VALIDATION_ERROR,
            title="Validation Error",
            detail=detail,
            status=int(HTTPStatus.UNPROCESSABLE_ENTITY),
            extra=extra,
            **kw,
        )

    @classmethod
    def not_found(cls, detail: str = "Resource not found", **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.NOT_FOUND,
            title="Not Found",
            detail=detail,
            status=int(HTTPStatus.NOT_FOUND),
            **kw,
        )

    @classmethod
    def unauthorized(cls, detail: str = "Authentication required", **kw: t.Any) -> "HttpError":
        headers = dict(kw.pop("headers", {}) or {})
        # Явно указываем базовый механизм как пример; переопределяйте в вызывающем коде
        headers.setdefault("WWW-Authenticate", 'Bearer realm="ledger-core"')
        return cls(
            code=ErrorCode.AUTHENTICATION_FAILED,
            title="Unauthorized",
            detail=detail,
            status=int(HTTPStatus.UNAUTHORIZED),
            headers=headers,
            **kw,
        )

    @classmethod
    def forbidden(cls, detail: str = "Not enough privileges", **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.AUTHORIZATION_FAILED,
            title="Forbidden",
            detail=detail,
            status=int(HTTPStatus.FORBIDDEN),
            **kw,
        )

    @classmethod
    def conflict(cls, detail: str, **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.CONFLICT, title="Conflict", detail=detail, status=int(HTTPStatus.CONFLICT), **kw
        )

    @classmethod
    def rate_limited(cls, detail: str = "Too Many Requests", retry_after: int | None = None, **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.RATE_LIMITED,
            title="Too Many Requests",
            detail=detail,
            status=int(HTTPStatus.TOO_MANY_REQUESTS),
            retriable=True,
            temporary=True,
            retry_after=retry_after,
            **kw,
        )

    @classmethod
    def dependency_timeout(cls, detail: str = "Upstream timeout", **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.DEPENDENCY_TIMEOUT,
            title="Gateway Timeout",
            detail=detail,
            status=int(HTTPStatus.GATEWAY_TIMEOUT),
            retriable=True,
            temporary=True,
            **kw,
        )

    @classmethod
    def dependency_failure(cls, detail: str = "Upstream failure", **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.DEPENDENCY_FAILURE,
            title="Bad Gateway",
            detail=detail,
            status=int(HTTPStatus.BAD_GATEWAY),
            retriable=True,
            temporary=True,
            **kw,
        )

    @classmethod
    def internal(cls, detail: str = "Internal Server Error", **kw: t.Any) -> "HttpError":
        return cls(
            code=ErrorCode.INTERNAL_ERROR,
            title="Internal Server Error",
            detail=detail,
            status=int(HTTPStatus.INTERNAL_SERVER_ERROR),
            log_level=logging.ERROR,
            **kw,
        )

    def to_problem(self, redact: bool = True) -> dict[str, t.Any]:
        """
        Сериализует исключение в RFC 7807 словарь.
        Обязательно: type, title, status, detail?, instance?
        Дополнительно: code, correlation_id, retriable, temporary, extra, causes
        """
        body: dict[str, t.Any] = {
            "type": self.type or "about:blank",
            "title": self.title or HTTPStatus(self.status).phrase,
            "status": self.status,
            "detail": self.detail or "",
            "code": self.code,
        }
        if self.instance:
            body["instance"] = self.instance
        if self.correlation_id:
            body["correlation_id"] = self.correlation_id
        if self.retriable:
            body["retriable"] = True
        if self.temporary:
            body["temporary"] = True
        if self.causes:
            body["causes"] = list(self.causes)[:10]

        extra = dict(self.extra or {})
        if redact:
            extra = _redact_mapping(extra)
        if extra:
            body["extra"] = extra
        return body

    def to_headers(self) -> dict[str, str]:
        headers = {**_DEFAULT_HEADERS, **(self.headers or {})}
        if self.correlation_id:
            headers.setdefault("X-Request-ID", self.correlation_id)
        # Безопасность: не включаем stacktrace в заголовки/тело
        return headers

    # ------------- Адаптеры ответов -------------

    def to_starlette_response(self):  # pragma: no cover - импорт по месту
        """
        Возвращает starlette.responses.JSONResponse без жесткой зависимости.
        """
        try:
            from starlette.responses import JSONResponse  # type: ignore
        except Exception:  # noqa: BLE001
            raise RuntimeError("Starlette/FastAPI is not installed")
        return JSONResponse(self.to_problem(), status_code=self.status, headers=self.to_headers())

    def to_flask_response(self):  # pragma: no cover - импорт по месту
        """
        Возвращает Flask совместимый респонс (json, status, headers).
        """
        return json.dumps(self.to_problem()), self.status, self.to_headers()


# -------- Нормализация исключений в HttpError --------

def normalize_exception(exc: BaseException, correlation_id: str | None = None) -> HttpError:
    """
    Маппинг распространенных исключений в HttpError.
    Без привязки к конкретному фреймворку.
    """
    # Уже HttpError
    if isinstance(exc, HttpError):
        if correlation_id and not exc.correlation_id:
            exc.correlation_id = correlation_id
        return exc

    # asyncio таймауты
    if isinstance(exc, (asyncio.TimeoutError,)):
        return HttpError.dependency_timeout(detail="Async operation timed out", correlation_id=correlation_id)

    # requests/HTTPX таймауты без жестких импортов
    name = exc.__class__.__name__
    if name in ("Timeout", "ReadTimeout", "ConnectTimeout"):
        return HttpError.dependency_timeout(detail=str(exc), correlation_id=correlation_id)

    # Pydantic/Marshmallow валидация (по имени класса)
    if name in ("ValidationError", "ValidationException"):
        detail = getattr(exc, "message", None) or "Validation failed"
        errors = getattr(exc, "errors", None)
        if callable(errors):
            try:
                errors = errors()
            except Exception:  # noqa: BLE001
                errors = None
        return HttpError.validation(detail=str(detail), errors=errors, correlation_id=correlation_id)

    # Starlette/FastAPI HTTPException (без import)
    if name == "HTTPException":
        status = getattr(exc, "status_code", 500) or 500
        detail = getattr(exc, "detail", None) or HTTPStatus(status).phrase
        headers = getattr(exc, "headers", None) or {}
        # Пробуем подобрать подходящий доменный код
        code = {
            400: ErrorCode.BAD_REQUEST,
            401: ErrorCode.AUTHENTICATION_FAILED,
            403: ErrorCode.AUTHORIZATION_FAILED,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.CONFLICT,
            415: ErrorCode.UNSUPPORTED_MEDIA_TYPE,
            422: ErrorCode.UNPROCESSABLE_ENTITY,
            429: ErrorCode.RATE_LIMITED,
            502: ErrorCode.DEPENDENCY_FAILURE,
            503: ErrorCode.SERVICE_UNAVAILABLE,
            504: ErrorCode.DEPENDENCY_TIMEOUT,
        }.get(status, ErrorCode.INTERNAL_ERROR)
        return HttpError(
            code=code,
            title=HTTPStatus(status).phrase,
            detail=str(detail),
            status=int(status),
            headers=dict(headers),
            correlation_id=correlation_id,
            retriable=status in (429, 502, 503, 504),
            temporary=status in (429, 503, 504),
            log_level=logging.WARNING if status < 500 else logging.ERROR,
        )

    # Прочие исключения -> 500
    err = HttpError.internal(detail=str(exc) or "Unhandled exception", correlation_id=correlation_id)
    # Дополняем причину фрагментом стека (безопасно, без локальных значений)
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=3))
    err.causes.append(tb)
    return err


def problem_from_exception(exc: BaseException, correlation_id: str | None = None) -> tuple[dict[str, t.Any], int, dict[str, str]]:
    """
    Универсальная точка: из исключения формирует (problem, status, headers).
    """
    he = normalize_exception(exc, correlation_id=correlation_id)
    body = he.to_problem()
    headers = he.to_headers()
    status = he.status
    # Логирование
    log_fn = logger.log
    log_fn(he.log_level, "HttpError %s %s: %s", status, he.code, he.detail, extra={"correlation_id": he.correlation_id})
    return body, status, headers


# -------- Интеграция с фреймворками --------

def to_starlette_response(exc: BaseException, correlation_id: str | None = None):
    """
    Быстрая обертка: превращает исключение в Starlette JSONResponse.
    """
    he = normalize_exception(exc, correlation_id=correlation_id)
    return he.to_starlette_response()


async def fastapi_exception_handler(request, exc):  # pragma: no cover
    """
    Обработчик для FastAPI: app.add_exception_handler(Exception, fastapi_exception_handler)
    Ставит correlation_id из заголовка X-Request-ID или traceparent (если есть).
    """
    corr = (
        getattr(request, "state", types.SimpleNamespace()).request_id
        if hasattr(getattr(request, "state", None), "request_id")
        else request.headers.get("x-request-id")
        or request.headers.get("traceparent")
    )
    he = normalize_exception(exc, correlation_id=corr)
    return he.to_starlette_response()


def to_flask_response(exc: BaseException, correlation_id: str | None = None):
    """
    Быстрая обертка: превращает исключение в Flask-совместимый ответ.
    """
    he = normalize_exception(exc, correlation_id=correlation_id)
    return he.to_flask_response()


# -------- Пример безопасной ручной генерации --------

def problem(
    code: str,
    detail: str,
    *,
    title: str | None = None,
    status: int | None = None,
    correlation_id: str | None = None,
    extra: dict[str, t.Any] | None = None,
    headers: dict[str, str] | None = None,
    retriable: bool | None = None,
    temporary: bool | None = None,
) -> HttpError:
    """
    Удобная фабрика для ручного создания ошибок.
    """
    st = int(status or int(_STATUS_BY_CODE.get(code, HTTPStatus.BAD_REQUEST)))
    return HttpError(
        code=code,
        title=title or HTTPStatus(st).phrase,
        detail=detail,
        status=st,
        correlation_id=correlation_id,
        extra=extra or {},
        headers=headers or {},
        retriable=bool(retriable),
        temporary=bool(temporary),
    )


# -------- Минимальные self-test утилиты (не выполняются в рантайме прод) --------

if __name__ == "__main__":  # pragma: no cover
    # Простейшая проверка сериализации
    e = HttpError.validation("payload invalid", errors=[{"loc": ["field"], "msg": "required"}], correlation_id="abc-123")
    body = e.to_problem()
    print(json.dumps(body, indent=2, ensure_ascii=False))
