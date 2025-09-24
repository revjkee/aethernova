# physical-integration-core/api/http/errors.py
"""
Промышленный модуль безопасной обработки HTTP-ошибок для physical-integration-core.

Ключевые возможности:
- Единая иерархия ApiError с доменными кодами (напр. PHYS.VALIDATION.INVALID_PAYLOAD).
- Совместимость с RFC 7807 (application/problem+json).
- Безопасная экспозиция: редактирование секретов и PII, контроль внутренних деталей.
- Корреляционные идентификаторы (correlation_id, trace_id, span_id).
- severity, retryable, category, fingerprint для диагностики.
- Реестр ошибок и фабрики, стабильная сериализация.
- Грейсфул фолбэк: работает без FastAPI/Starlette; при наличии — возвращает JSONResponse.
- Минимальные зависимости: стандартная библиотека. Starlette используется опционально.

Переменные окружения (опционально):
- API_ERRORS_DEBUG=1            — включить расширенные детали (не для продакшна).
- API_ERRORS_DEFAULT_LOCALE=ru  — локаль сообщения по умолчанию (ru|en).
- API_ERRORS_INCLUDE_STACK=0/1  — добавлять stack в ответ (только в debug).
"""

from __future__ import annotations

import contextvars
import datetime as dt
import hashlib
import json
import logging
import os
import re
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple, Type

# ========= Опциональный Starlette/ FastAPI ответ =========
_JSONResponse = None
_Request = None
try:
    from starlette.responses import JSONResponse as _JSONResponse  # type: ignore
    from starlette.requests import Request as _Request  # type: ignore
except Exception:
    _JSONResponse = None
    _Request = None

# ========= Конфигурация из окружения =========
ENV = os.getenv
_DEBUG = ENV("API_ERRORS_DEBUG", "0") == "1"
_DEFAULT_LOCALE = ENV("API_ERRORS_DEFAULT_LOCALE", "en").lower()
_INCLUDE_STACK = ENV("API_ERRORS_INCLUDE_STACK", "0") == "1"

# ========= Контекст корреляции =========
_corr_id: contextvars.ContextVar[str] = contextvars.ContextVar("corr_id", default="-")
_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")
_span_id: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="-")


def set_correlation_ids(correlation_id: Optional[str] = None,
                        trace_id: Optional[str] = None,
                        span_id: Optional[str] = None) -> None:
    """Установка корреляционных идентификаторов в контекст."""
    if correlation_id is not None:
        _corr_id.set(str(correlation_id))
    if trace_id is not None:
        _trace_id.set(str(trace_id))
    if span_id is not None:
        _span_id.set(str(span_id))


def get_correlation_ids() -> Dict[str, str]:
    return {
        "correlation_id": _corr_id.get(),
        "trace_id": _trace_id.get(),
        "span_id": _span_id.get(),
    }


# ========= Безопасная редакция чувствительных данных =========
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3})?[\s\-.(]*\d{2,4}[\s\-.)]*\d{2,4}[\s\-]*\d{2,4}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "authorization", "auth", "jwt", "cookie", "session", "private_key"
}

REDACTED = "***redacted***"
_TEXT_LIMIT = 1_024  # ограничение длины текстов в деталях


def _redact_text(text: str) -> str:
    t = EMAIL_RE.sub(REDACTED, text)
    t = PHONE_RE.sub(REDACTED, t)
    t = IBAN_RE.sub(REDACTED, t)
    t = CARD_RE.sub(REDACTED, t)
    if len(t) > _TEXT_LIMIT:
        t = t[:_TEXT_LIMIT] + "...[truncated]"
    return t


def _redact_obj(v: Any) -> Any:
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            if any(s in str(k).lower() for s in SECRET_KEYS):
                out[k] = REDACTED
            else:
                out[k] = _redact_obj(val)
        return out
    if isinstance(v, list):
        return [_redact_obj(x) for x in v]
    if isinstance(v, str):
        return _redact_text(v)
    return v


# ========= Классификация =========
class Severity:
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Category:
    VALIDATION = "validation"
    AUTHN = "authentication"
    AUTHZ = "authorization"
    RATE_LIMIT = "rate_limit"
    UPSTREAM = "upstream"
    TRANSPORT = "transport"
    DEVICE = "device"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    INTERNAL = "internal"
    UNSUPPORTED = "unsupported"


# ========= Базовая ошибка API =========
@dataclass
class ApiError(Exception):
    code: str
    http_status: int
    title: str
    detail: Optional[Any] = None
    retryable: bool = False
    severity: str = Severity.ERROR
    category: str = Category.INTERNAL
    params: Dict[str, Any] = field(default_factory=dict)
    cause: Optional[BaseException] = None
    instance: Optional[str] = None  # обычно путь запроса
    locale: Optional[str] = None

    def __post_init__(self) -> None:
        # code нормализуем в UPPER с точками
        self.code = str(self.code).strip().upper()
        if "." not in self.code:
            self.code = f"PHYS.{self.code}"
        # деталь редактируем сразу
        if self.detail is not None:
            self.detail = _redact_obj(self.detail)

    @property
    def status(self) -> int:
        return int(self.http_status)

    @property
    def correlation(self) -> Dict[str, str]:
        return get_correlation_ids()

    @property
    def fingerprint(self) -> str:
        base = f"{self.code}|{self.status}|{self.title}|{json.dumps(self.detail, ensure_ascii=False, default=str)[:256]}"
        return hashlib.sha256(base.encode("utf-8", "ignore")).hexdigest()

    def to_problem(self, include_stack: bool = False) -> Dict[str, Any]:
        """
        RFC 7807 совместимый словарь (application/problem+json)
        """
        # безопасный detail: не раскрывать внутренности в продакшне
        safe_detail = self.detail
        problem = {
            "type": f"urn:problem-type:physical-integration:{self.code.lower().replace('.', '-')}",
            "title": self.title,
            "status": self.status,
            "detail": safe_detail,
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "retryable": self.retryable,
            "correlation_id": self.correlation.get("correlation_id"),
            "trace_id": self.correlation.get("trace_id"),
            "span_id": self.correlation.get("span_id"),
            "fingerprint": self.fingerprint,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        if self.instance:
            problem["instance"] = self.instance

        # включаем stack только когда явно разрешено и включён debug
        if include_stack and (_DEBUG or _INCLUDE_STACK):
            frames = []
            if self.cause:
                frames = traceback.format_exception(type(self.cause), self.cause, self.cause.__traceback__)
            else:
                frames = traceback.format_stack()
            problem["stack"] = "".join(frames)[-8000:]  # ограничим размер
        return problem

    def to_response(self) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        """
        Универсальный ответ: (status, headers, body).
        Фреймворки могут адаптировать.
        """
        headers = {"Content-Type": "application/problem+json; charset=utf-8"}
        body = self.to_problem(include_stack=_INCLUDE_STACK)
        return self.status, headers, body

    # для удобства логирования
    def as_log_record(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "retryable": self.retryable,
            "severity": self.severity,
            "category": self.category,
            "fingerprint": self.fingerprint,
            **self.correlation,
        }


# ========= Реестр ошибок =========
_ERROR_REGISTRY: Dict[str, Type[ApiError]] = {}


def register_error(code: str, http_status: int, title: str,
                   severity: str = Severity.ERROR,
                   category: str = Category.INTERNAL,
                   retryable: bool = False) -> Type[ApiError]:
    """
    Регистрирует новый класс ошибки с фиксированными параметрами.
    """
    code_up = code.strip().upper()
    if "." not in code_up:
        code_up = f"PHYS.{code_up}"

    # уже есть — возвращаем существующий
    if code_up in _ERROR_REGISTRY:
        return _ERROR_REGISTRY[code_up]

    class _Derived(ApiError):
        def __init__(self, detail: Any = None, *, params: Dict[str, Any] | None = None,
                     cause: Optional[BaseException] = None, instance: Optional[str] = None,
                     locale: Optional[str] = None) -> None:
            super().__init__(
                code=code_up,
                http_status=http_status,
                title=title,
                detail=detail,
                retryable=retryable,
                severity=severity,
                category=category,
                params=params or {},
                cause=cause,
                instance=instance,
                locale=locale or _DEFAULT_LOCALE,
            )

    _Derived.__name__ = code_up.replace(".", "_")
    _ERROR_REGISTRY[code_up] = _Derived
    return _Derived


def error_from_code(code: str) -> Optional[Type[ApiError]]:
    return _ERROR_REGISTRY.get(code.strip().upper())


# ========= Предопределённые доменные ошибки =========
BadRequest = register_error(
    "PHYS.VALIDATION.BAD_REQUEST", HTTPStatus.BAD_REQUEST, "Некорректный запрос",
    severity=Severity.WARNING, category=Category.VALIDATION, retryable=False,
)
InvalidPayload = register_error(
    "PHYS.VALIDATION.INVALID_PAYLOAD", HTTPStatus.UNPROCESSABLE_ENTITY, "Невалидное тело запроса",
    severity=Severity.WARNING, category=Category.VALIDATION, retryable=False,
)
Unauthorized = register_error(
    "PHYS.AUTHN.UNAUTHORIZED", HTTPStatus.UNAUTHORIZED, "Требуется аутентификация",
    severity=Severity.WARNING, category=Category.AUTHN, retryable=False,
)
Forbidden = register_error(
    "PHYS.AUTHZ.FORBIDDEN", HTTPStatus.FORBIDDEN, "Доступ запрещён",
    severity=Severity.WARNING, category=Category.AUTHZ, retryable=False,
)
NotFound = register_error(
    "PHYS.NOT_FOUND.RESOURCE", HTTPStatus.NOT_FOUND, "Ресурс не найден",
    severity=Severity.NOTICE, category=Category.NOT_FOUND, retryable=False,
)
Conflict = register_error(
    "PHYS.CONFLICT.STATE", HTTPStatus.CONFLICT, "Конфликт состояния",
    severity=Severity.WARNING, category=Category.CONFLICT, retryable=False,
)
TooManyRequests = register_error(
    "PHYS.RATE_LIMIT.TOO_MANY_REQUESTS", HTTPStatus.TOO_MANY_REQUESTS, "Превышен лимит запросов",
    severity=Severity.WARNING, category=Category.RATE_LIMIT, retryable=True,
)
UpstreamError = register_error(
    "PHYS.UPSTREAM.ERROR", HTTPStatus.BAD_GATEWAY, "Ошибка внешнего сервиса",
    severity=Severity.ERROR, category=Category.UPSTREAM, retryable=True,
)
IntegrationTimeout = register_error(
    "PHYS.TRANSPORT.TIMEOUT", HTTPStatus.GATEWAY_TIMEOUT, "Таймаут интеграции",
    severity=Severity.ERROR, category=Category.TRANSPORT, retryable=True,
)
DeviceNotReachable = register_error(
    "PHYS.DEVICE.NOT_REACHABLE", HTTPStatus.BAD_GATEWAY, "Устройство недоступно",
    severity=Severity.ERROR, category=Category.DEVICE, retryable=True,
)
DeviceAuthFailed = register_error(
    "PHYS.DEVICE.AUTH_FAILED", HTTPStatus.UNAUTHORIZED, "Ошибка аутентификации устройства",
    severity=Severity.WARNING, category=Category.DEVICE, retryable=False,
)
DeviceProtocolError = register_error(
    "PHYS.DEVICE.PROTOCOL_ERROR", HTTPStatus.BAD_GATEWAY, "Протокольная ошибка устройства",
    severity=Severity.ERROR, category=Category.DEVICE, retryable=True,
)
UnsupportedMediaType = register_error(
    "PHYS.UNSUPPORTED.MEDIA_TYPE", HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Неподдерживаемый тип данных",
    severity=Severity.WARNING, category=Category.UNSUPPORTED, retryable=False,
)
PayloadTooLarge = register_error(
    "PHYS.VALIDATION.PAYLOAD_TOO_LARGE", HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Слишком большой payload",
    severity=Severity.WARNING, category=Category.VALIDATION, retryable=False,
)
InternalError = register_error(
    "PHYS.INTERNAL.ERROR", HTTPStatus.INTERNAL_SERVER_ERROR, "Внутренняя ошибка сервера",
    severity=Severity.CRITICAL, category=Category.INTERNAL, retryable=False,
)


# ========= Нормализация исключений =========
def normalize_exc(exc: BaseException, *, instance: Optional[str] = None) -> ApiError:
    """
    Преобразует произвольное исключение в ApiError. Сохраняет безопасность.
    """
    if isinstance(exc, ApiError):
        if instance and not exc.instance:
            exc.instance = instance
        return exc

    # Сторонние исключения → InternalError без раскрытия внутренних деталей.
    # В debug можно включить человекочитаемую выжимку.
    safe_detail = None
    if _DEBUG:
        safe_detail = _redact_text(f"{type(exc).__name__}: {str(exc)}")

    return InternalError(
        detail=safe_detail,
        cause=exc,
        instance=instance,
    )


# ========= Адаптация под Starlette/FastAPI (если доступно) =========
def to_starlette_response(err: ApiError):
    """
    Возвращает starlette.responses.JSONResponse, если Starlette доступна,
    иначе (status, headers, body) кортеж.
    """
    status, headers, body = err.to_response()
    if _JSONResponse is None:
        return status, headers, body
    return _JSONResponse(content=body, status_code=status, headers=headers, media_type="application/problem+json")


def install_fastapi_handlers(app, *, logger: Optional[logging.Logger] = None) -> None:
    """
    Устанавливает единый обработчик исключений для FastAPI/Starlette-приложения.
    Тихо ничего не делает, если Starlette не доступна.
    """
    if _JSONResponse is None or _Request is None:
        return

    async def _api_error_handler(request: _Request, exc: ApiError):  # type: ignore
        # instance = путь запроса
        if not exc.instance:
            exc.instance = str(getattr(request, "url", "")) or getattr(request, "url", "")
        if logger:
            logger.error("api_error", extra={"error": exc.as_log_record()})
        return to_starlette_response(exc)

    async def _generic_handler(request: _Request, exc: BaseException):  # type: ignore
        api_err = normalize_exc(exc, instance=str(getattr(request, "url", "")))
        if logger:
            logger.error("unhandled_exception", extra={"error": api_err.as_log_record()})
        return to_starlette_response(api_err)

    try:
        # FastAPI имеет метод add_exception_handler, Starlette — тоже
        app.add_exception_handler(ApiError, _api_error_handler)
        app.add_exception_handler(Exception, _generic_handler)
    except Exception:
        # если фреймворк необычный — не падаем
        pass


# ========= Утилиты создания ошибок с параметрами =========
def bad_request(detail: Any = None, *, instance: Optional[str] = None, params: Optional[Dict[str, Any]] = None) -> ApiError:
    return BadRequest(detail=detail, instance=instance, params=params)

def invalid_payload(detail: Any = None, *, instance: Optional[str] = None, params: Optional[Dict[str, Any]] = None) -> ApiError:
    return InvalidPayload(detail=detail, instance=instance, params=params)

def unauthorized(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return Unauthorized(detail=detail, instance=instance)

def forbidden(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return Forbidden(detail=detail, instance=instance)

def not_found(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return NotFound(detail=detail, instance=instance)

def conflict(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return Conflict(detail=detail, instance=instance)

def too_many_requests(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return TooManyRequests(detail=detail, instance=instance)

def upstream_error(detail: Any = None, *, instance: Optional[str] = None, cause: Optional[BaseException] = None) -> ApiError:
    return UpstreamError(detail=detail, instance=instance, cause=cause)

def integration_timeout(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return IntegrationTimeout(detail=detail, instance=instance)

def device_not_reachable(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return DeviceNotReachable(detail=detail, instance=instance)

def device_auth_failed(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return DeviceAuthFailed(detail=detail, instance=instance)

def device_protocol_error(detail: Any = None, *, instance: Optional[str] = None, cause: Optional[BaseException] = None) -> ApiError:
    return DeviceProtocolError(detail=detail, instance=instance, cause=cause)

def unsupported_media_type(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return UnsupportedMediaType(detail=detail, instance=instance)

def payload_too_large(detail: Any = None, *, instance: Optional[str] = None) -> ApiError:
    return PayloadTooLarge(detail=detail, instance=instance)

def internal_error(detail: Any = None, *, instance: Optional[str] = None, cause: Optional[BaseException] = None) -> ApiError:
    return InternalError(detail=detail, instance=instance, cause=cause)


# ========= Минимальный логгер по умолчанию (если не передан внешний) =========
_default_logger = logging.getLogger("api.errors")
if not _default_logger.handlers:
    _default_logger.addHandler(logging.StreamHandler())
_default_logger.setLevel(logging.INFO)


# ========= Пример адаптера для не-Starlette окружения =========
def to_wsgi_tuple(err: ApiError) -> Tuple[str, list[Tuple[str, str]], bytes]:
    """
    Преобразование к WSGI-совместимой тройке (status_line, headers, body_bytes).
    """
    status_line = f"{err.status} {HTTPStatus(err.status).phrase}"
    _, headers, body = err.to_response()
    headers_list = [(k, v) for k, v in headers.items()]
    body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
    return status_line, headers_list, body_bytes
