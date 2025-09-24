#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Engine-Core — Unified Error Layer (HTTP/gRPC/Protobuf/RFC7807)

Возможности:
- Единые коды ошибок (Enum) и категории
- Маппинг: ErrorCode -> HTTP статус / gRPC StatusCode
- RFC7807 (application/problem+json) с расширениями: code, category, request_id, trace_id
- Совместимость с google.rpc.Status и error_details (ErrorInfo, BadRequest, RetryInfo, RequestInfo)
- Безопасная огласка: public/internal; автоматическое "очищение" деталей
- i18n: шаблоны сообщений (format placeholders)
- Декоратор регистрации доменных ошибок
- Обработчик FastAPI: plug-and-play
"""

from __future__ import annotations

import json
import os
import traceback
import typing as t
from dataclasses import dataclass, field
from enum import Enum
from http import HTTPStatus

from fastapi import Request
from fastapi.responses import JSONResponse

# --- Опциональные зависимости (без жёсткого импорта) ---
try:  # grpc
    import grpc  # type: ignore
except Exception:  # pragma: no cover
    grpc = None  # type: ignore

try:  # protobuf google.rpc.*
    from google.protobuf.any_pb2 import Any as PbAny  # type: ignore
    from google.rpc.status_pb2 import Status as PbStatus  # type: ignore
    from google.rpc.error_details_pb2 import (  # type: ignore
        ErrorInfo as PbErrorInfo,
        BadRequest as PbBadRequest,
        BadRequest_FieldViolation as PbFieldViolation,
        RetryInfo as PbRetryInfo,
        RequestInfo as PbRequestInfo,
        QuotaFailure as PbQuotaFailure,
    )
except Exception:  # pragma: no cover
    PbAny = PbStatus = PbErrorInfo = PbBadRequest = PbFieldViolation = PbRetryInfo = PbRequestInfo = PbQuotaFailure = None  # type: ignore


# =============================================================================
# Конфигурация и константы
# =============================================================================

SERVICE_NAME = os.getenv("ENGINE_SERVICE", "engine-core-http")

# Типы URL для деталей (совместимо с google.rpc.*)
TYPE_URLS = {
    "error_info": "type.googleapis.com/google.rpc.ErrorInfo",
    "bad_request": "type.googleapis.com/google.rpc.BadRequest",
    "retry_info": "type.googleapis.com/google.rpc.RetryInfo",
    "request_info": "type.googleapis.com/google.rpc.RequestInfo",
    "quota_failure": "type.googleapis.com/google.rpc.QuotaFailure",
}

# =============================================================================
# Коды и категории ошибок
# =============================================================================

class ErrorCategory(str, Enum):
    CLIENT = "client"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMIT = "rate_limit"
    SERVER = "server"
    DEPENDENCY = "dependency"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    UNKNOWN = "unknown"


class ErrorCode(str, Enum):
    # Клиентские/валидация
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    FAILED_PRECONDITION = "FAILED_PRECONDITION"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    OUT_OF_RANGE = "OUT_OF_RANGE"
    # Аутентификация/авторизация
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    # Лимиты/квоты
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    # Сетевые/таймауты/зависимости
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    UNAVAILABLE = "UNAVAILABLE"
    # Серверные
    INTERNAL = "INTERNAL"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    # Прочие
    UNKNOWN = "UNKNOWN"


# Маппинг код -> HTTP
HTTP_MAP: t.Dict[ErrorCode, HTTPStatus] = {
    ErrorCode.INVALID_ARGUMENT: HTTPStatus.BAD_REQUEST,
    ErrorCode.FAILED_PRECONDITION: HTTPStatus.BAD_REQUEST,
    ErrorCode.OUT_OF_RANGE: HTTPStatus.BAD_REQUEST,
    ErrorCode.UNAUTHENTICATED: HTTPStatus.UNAUTHORIZED,
    ErrorCode.PERMISSION_DENIED: HTTPStatus.FORBIDDEN,
    ErrorCode.NOT_FOUND: HTTPStatus.NOT_FOUND,
    ErrorCode.CONFLICT: HTTPStatus.CONFLICT,
    ErrorCode.RESOURCE_EXHAUSTED: HTTPStatus.TOO_MANY_REQUESTS,
    ErrorCode.DEADLINE_EXCEEDED: HTTPStatus.GATEWAY_TIMEOUT,
    ErrorCode.UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,
    ErrorCode.NOT_IMPLEMENTED: HTTPStatus.NOT_IMPLEMENTED,
    ErrorCode.INTERNAL: HTTPStatus.INTERNAL_SERVER_ERROR,
    ErrorCode.UNKNOWN: HTTPStatus.INTERNAL_SERVER_ERROR,
}

# Маппинг код -> gRPC (если доступен)
GRPC_MAP: t.Dict[ErrorCode, t.Any] = {}
if grpc is not None:  # pragma: no cover
    GRPC_MAP = {
        ErrorCode.INVALID_ARGUMENT: grpc.StatusCode.INVALID_ARGUMENT,
        ErrorCode.FAILED_PRECONDITION: grpc.StatusCode.FAILED_PRECONDITION,
        ErrorCode.OUT_OF_RANGE: grpc.StatusCode.OUT_OF_RANGE,
        ErrorCode.UNAUTHENTICATED: grpc.StatusCode.UNAUTHENTICATED,
        ErrorCode.PERMISSION_DENIED: grpc.StatusCode.PERMISSION_DENIED,
        ErrorCode.NOT_FOUND: grpc.StatusCode.NOT_FOUND,
        ErrorCode.CONFLICT: grpc.StatusCode.ABORTED,
        ErrorCode.RESOURCE_EXHAUSTED: grpc.StatusCode.RESOURCE_EXHAUSTED,
        ErrorCode.DEADLINE_EXCEEDED: grpc.StatusCode.DEADLINE_EXCEEDED,
        ErrorCode.UNAVAILABLE: grpc.StatusCode.UNAVAILABLE,
        ErrorCode.NOT_IMPLEMENTED: grpc.StatusCode.UNIMPLEMENTED,
        ErrorCode.INTERNAL: grpc.StatusCode.INTERNAL,
        ErrorCode.UNKNOWN: grpc.StatusCode.UNKNOWN,
    }

CATEGORY_MAP: t.Dict[ErrorCode, ErrorCategory] = {
    ErrorCode.INVALID_ARGUMENT: ErrorCategory.VALIDATION,
    ErrorCode.FAILED_PRECONDITION: ErrorCategory.VALIDATION,
    ErrorCode.OUT_OF_RANGE: ErrorCategory.VALIDATION,
    ErrorCode.UNAUTHENTICATED: ErrorCategory.UNAUTHORIZED,
    ErrorCode.PERMISSION_DENIED: ErrorCategory.FORBIDDEN,
    ErrorCode.NOT_FOUND: ErrorCategory.NOT_FOUND,
    ErrorCode.CONFLICT: ErrorCategory.CONFLICT,
    ErrorCode.RESOURCE_EXHAUSTED: ErrorCategory.RATE_LIMIT,
    ErrorCode.DEADLINE_EXCEEDED: ErrorCategory.TIMEOUT,
    ErrorCode.UNAVAILABLE: ErrorCategory.DEPENDENCY,
    ErrorCode.NOT_IMPLEMENTED: ErrorCategory.SERVER,
    ErrorCode.INTERNAL: ErrorCategory.SERVER,
    ErrorCode.UNKNOWN: ErrorCategory.UNKNOWN,
}

# =============================================================================
# Детали ошибок и исключения
# =============================================================================

@dataclass
class ErrorDetail:
    """
    Упрощённый контейнер для деталей ошибок (совместимый с google.rpc.* через to_protobuf()).
    """
    type_url: str
    payload: t.Dict[str, t.Any] = field(default_factory=dict)

    def to_protobuf(self) -> t.Optional[t.Any]:
        if PbAny is None:
            return None
        any_pb = PbAny()
        # Попытка построить известные типы
        msg = None
        if self.type_url == TYPE_URLS["error_info"] and PbErrorInfo is not None:
            msg = PbErrorInfo(reason=self.payload.get("reason", ""), domain=self.payload.get("domain", ""))
            meta = self.payload.get("metadata", {}) or {}
            msg.metadata.update({str(k): str(v) for k, v in meta.items()})
        elif self.type_url == TYPE_URLS["bad_request"] and PbBadRequest is not None:
            msg = PbBadRequest()
            for f in self.payload.get("field_violations", []):
                fv = PbFieldViolation(field=f.get("field", ""), description=f.get("description", ""))
                msg.field_violations.append(fv)
        elif self.type_url == TYPE_URLS["retry_info"] and PbRetryInfo is not None:
            # retry_delay_ms -> seconds/nanos
            delay_ms = int(self.payload.get("retry_delay_ms", 0))
            from google.protobuf.duration_pb2 import Duration  # type: ignore
            d = Duration()
            d.seconds = delay_ms // 1000
            d.nanos = (delay_ms % 1000) * 1_000_000
            msg = PbRetryInfo(retry_delay=d)
        elif self.type_url == TYPE_URLS["request_info"] and PbRequestInfo is not None:
            msg = PbRequestInfo(request_id=self.payload.get("request_id", ""), serving_data=self.payload.get("serving_data", ""))
        elif self.type_url == TYPE_URLS["quota_failure"] and PbQuotaFailure is not None:
            msg = PbQuotaFailure()
            for v in self.payload.get("violations", []):
                q = msg.violations.add()
                q.subject = v.get("subject", "")
                q.description = v.get("description", "")
        # Фоллбек: сырое Any
        if msg is None:
            any_pb.type_url = self.type_url
            any_pb.value = json.dumps(self.payload).encode("utf-8")
            return any_pb
        any_pb.Pack(msg)
        return any_pb


@dataclass
class EngineError(Exception):
    code: ErrorCode
    message: str
    details: t.List[ErrorDetail] = field(default_factory=list)
    public: bool = True  # если False — detail "обрезается" для клиента
    cause: t.Optional[BaseException] = None
    # контекст
    request_id: t.Optional[str] = None
    trace_id: t.Optional[str] = None
    data: t.Optional[t.Dict[str, t.Any]] = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    @property
    def http_status(self) -> int:
        return int(HTTP_MAP.get(self.code, HTTPStatus.INTERNAL_SERVER_ERROR))

    @property
    def category(self) -> ErrorCategory:
        return CATEGORY_MAP.get(self.code, ErrorCategory.UNKNOWN)

    def to_problem(self, instance: t.Optional[str] = None, locale: t.Optional[str] = None) -> t.Dict[str, t.Any]:
        """
        RFC7807 problem+json payload с расширениями.
        """
        title = self._title_for_code(self.code, locale)
        detail = self.message if self.public else self._generic_message(self.code, locale)
        problem = {
            "type": f"https://errors.{SERVICE_NAME}/{self.code}",
            "title": title,
            "status": self.http_status,
            "detail": detail,
            "instance": instance,
            "code": self.code,
            "category": self.category,
        }
        if self.request_id:
            problem["request_id"] = self.request_id
        if self.trace_id:
            problem["trace_id"] = self.trace_id
        # Публичные детали только если public=True
        if self.public and self.details:
            problem["details"] = [d.payload | {"@type": d.type_url} for d in self.details]
        return problem

    def to_grpc_status(self) -> t.Tuple[int, t.Optional[t.Any]]:
        """
        Возвращает (grpc_code, protobuf_status) при наличии зависимостей.
        """
        if grpc is None or PbStatus is None:  # pragma: no cover
            # grpc_code как int (fallback)
            code = GRPC_MAP.get(self.code) if GRPC_MAP else None
            return (int(code.value) if code is not None else 2, None)  # 2 = UNKNOWN
        code = GRPC_MAP.get(self.code, grpc.StatusCode.UNKNOWN)
        # Строим google.rpc.Status
        st = PbStatus(code=code.value[0] if hasattr(code, "value") else code.value, message=self.message)
        for d in self.details:
            any_pb = d.to_protobuf()
            if any_pb is not None:
                st.details.append(any_pb)
        return (code.value[0] if hasattr(code, "value") else code.value, st)

    @staticmethod
    def _title_for_code(code: ErrorCode, locale: t.Optional[str] = None) -> str:
        # i18n-хуки (упрощённо)
        titles = {
            ErrorCode.INVALID_ARGUMENT: "Invalid argument",
            ErrorCode.FAILED_PRECONDITION: "Failed precondition",
            ErrorCode.OUT_OF_RANGE: "Out of range",
            ErrorCode.UNAUTHENTICATED: "Unauthenticated",
            ErrorCode.PERMISSION_DENIED: "Forbidden",
            ErrorCode.NOT_FOUND: "Not found",
            ErrorCode.CONFLICT: "Conflict",
            ErrorCode.RESOURCE_EXHAUSTED: "Rate limit exceeded",
            ErrorCode.DEADLINE_EXCEEDED: "Deadline exceeded",
            ErrorCode.UNAVAILABLE: "Service unavailable",
            ErrorCode.NOT_IMPLEMENTED: "Not implemented",
            ErrorCode.INTERNAL: "Internal error",
            ErrorCode.UNKNOWN: "Unknown error",
        }
        return titles.get(code, "Error")

    @staticmethod
    def _generic_message(code: ErrorCode, locale: t.Optional[str] = None) -> str:
        generic = {
            ErrorCode.UNAUTHENTICATED: "Authentication required.",
            ErrorCode.PERMISSION_DENIED: "Access is forbidden.",
            ErrorCode.NOT_FOUND: "The requested resource was not found.",
            ErrorCode.RESOURCE_EXHAUSTED: "Too many requests.",
            ErrorCode.DEADLINE_EXCEEDED: "Request timeout exceeded.",
            ErrorCode.UNAVAILABLE: "Service is temporarily unavailable.",
            ErrorCode.INTERNAL: "An internal error occurred.",
        }
        return generic.get(code, "An error occurred.")


# =============================================================================
# Реестр ошибок и доменные фабрики
# =============================================================================

_ERROR_FACTORIES: t.Dict[str, t.Callable[..., EngineError]] = {}


def register_error(name: str):
    """
    Декоратор регистрации функции-фабрики доменной ошибки.
    Пример:
        @register_error("USER_NOT_FOUND")
        def user_not_found(user_id: str, **ctx): ...
    """
    def _wrap(fn: t.Callable[..., EngineError]):
        _ERROR_FACTORIES[name] = fn
        return fn
    return _wrap


def make_error(name: str, **kwargs) -> EngineError:
    if name not in _ERROR_FACTORIES:
        return EngineError(code=ErrorCode.UNKNOWN, message=name, public=False, data=kwargs)
    return _ERROR_FACTORIES[name](**kwargs)


# =============================================================================
# Утилиты построения деталей
# =============================================================================

def error_info(reason: str, domain: str = SERVICE_NAME, metadata: t.Optional[t.Dict[str, str]] = None) -> ErrorDetail:
    return ErrorDetail(type_url=TYPE_URLS["error_info"], payload={"reason": reason, "domain": domain, "metadata": metadata or {}})


def bad_request_field(field: str, description: str) -> ErrorDetail:
    return ErrorDetail(type_url=TYPE_URLS["bad_request"], payload={"field_violations": [{"field": field, "description": description}]})


def retry_info(delay_ms: int) -> ErrorDetail:
    return ErrorDetail(type_url=TYPE_URLS["retry_info"], payload={"retry_delay_ms": int(delay_ms)})


def request_info(request_id: str, serving_data: str = "") -> ErrorDetail:
    return ErrorDetail(type_url=TYPE_URLS["request_info"], payload={"request_id": request_id, "serving_data": serving_data})


# =============================================================================
# Конвертеры/маппинги исключений
# =============================================================================

def from_exception(exc: BaseException, request_id: t.Optional[str] = None) -> EngineError:
    """
    Нормализует произвольные исключения в EngineError.
    """
    if isinstance(exc, EngineError):
        if request_id and not exc.request_id:
            exc.request_id = request_id
        return exc

    # FastAPI/Starlette HTTPException (lazy import)
    try:
        from fastapi import HTTPException as FastHTTPException  # type: ignore
    except Exception:
        FastHTTPException = None  # type: ignore

    if FastHTTPException is not None and isinstance(exc, FastHTTPException):
        # Маппинг по статусу
        status_code = getattr(exc, "status_code", 500)
        detail = getattr(exc, "detail", "")
        code = _code_from_http_status(status_code)
        return EngineError(
            code=code,
            message=str(detail) or HTTPStatus(status_code).phrase,
            details=[],
            public=True,
            request_id=request_id,
        )

    # Таймауты/сети
    if isinstance(exc, TimeoutError):
        return EngineError(code=ErrorCode.DEADLINE_EXCEEDED, message="Timeout exceeded", details=[], public=True, request_id=request_id)

    # Фоллбек
    return EngineError(
        code=ErrorCode.INTERNAL,
        message=str(exc) or "Internal error",
        public=False,
        details=[error_info("INTERNAL_EXCEPTION"),],
        request_id=request_id,
    )


def _code_from_http_status(status_code: int) -> ErrorCode:
    rev = {int(v): k for k, v in HTTP_MAP.items()}
    return rev.get(int(status_code), ErrorCode.INTERNAL)


# =============================================================================
# FastAPI интеграция
# =============================================================================

def to_http_response(err: EngineError, instance: t.Optional[str] = None) -> JSONResponse:
    """
    Строит JSONResponse (problem+json) из EngineError.
    """
    payload = err.to_problem(instance=instance)
    headers = {"Content-Type": "application/problem+json"}
    # Retry-After для rate limit/timeout
    if err.code in (ErrorCode.RESOURCE_EXHAUSTED, ErrorCode.DEADLINE_EXCEEDED):
        # Поиск retry_info
        retry_ms = None
        for d in err.details:
            if d.type_url == TYPE_URLS["retry_info"]:
                retry_ms = int(d.payload.get("retry_delay_ms", 0))
                break
        if retry_ms is not None and retry_ms >= 0:
            headers["Retry-After"] = str(max(1, retry_ms // 1000))
    return JSONResponse(status_code=err.http_status, content=payload, headers=headers)


async def fastapi_exception_handler(request: Request, exc: BaseException):
    """
    Глобальный обработчик FastAPI (подключить через app.add_exception_handler(Exception, fastapi_exception_handler)).
    """
    request_id = getattr(request.state, "request_id", None)
    err = from_exception(exc, request_id=request_id)
    # Добавим request_info деталь
    if request_id:
        err.details.append(request_info(request_id))
    # instance — путь запроса
    instance = str(request.url)
    return to_http_response(err, instance=instance)


# =============================================================================
# Примеры доменных ошибок (реестр)
# =============================================================================

@register_error("USER_NOT_FOUND")
def _user_not_found(user_id: t.Union[str, int], **ctx) -> EngineError:
    return EngineError(
        code=ErrorCode.NOT_FOUND,
        message=f"User '{user_id}' not found",
        details=[error_info("USER_NOT_FOUND"),],
        public=True,
        data={"user_id": user_id, **ctx},
    )


@register_error("VALIDATION_FAILED")
def _validation_failed(violations: t.List[t.Dict[str, str]], **_) -> EngineError:
    return EngineError(
        code=ErrorCode.INVALID_ARGUMENT,
        message="Validation failed",
        details=[ErrorDetail(type_url=TYPE_URLS["bad_request"], payload={"field_violations": violations})],
        public=True,
    )


@register_error("RATE_LIMITED")
def _rate_limited(retry_ms: int = 1000, **_) -> EngineError:
    return EngineError(
        code=ErrorCode.RESOURCE_EXHAUSTED,
        message="Too many requests",
        details=[retry_info(retry_ms)],
        public=True,
    )


# =============================================================================
# Прямые фабрики для популярных ошибок
# =============================================================================

def unauthenticated(msg: str = "Authentication required") -> EngineError:
    return EngineError(code=ErrorCode.UNAUTHENTICATED, message=msg, details=[error_info("UNAUTHENTICATED")], public=True)


def forbidden(msg: str = "Forbidden") -> EngineError:
    return EngineError(code=ErrorCode.PERMISSION_DENIED, message=msg, details=[error_info("PERMISSION_DENIED")], public=True)


def not_found(msg: str = "Not found") -> EngineError:
    return EngineError(code=ErrorCode.NOT_FOUND, message=msg, details=[error_info("NOT_FOUND")], public=True)


def internal(msg: str = "Internal error", cause: t.Optional[BaseException] = None) -> EngineError:
    return EngineError(code=ErrorCode.INTERNAL, message=msg, details=[error_info("INTERNAL")], public=False, cause=cause)


# =============================================================================
# Преобразование google.rpc.Status -> EngineError (если protobuf доступен)
# =============================================================================

def from_google_status(pb_status: t.Any, request_id: t.Optional[str] = None) -> EngineError:
    """
    Конвертация google.rpc.Status в EngineError.
    """
    if PbStatus is None or not isinstance(pb_status, PbStatus):  # pragma: no cover
        # Фоллбек: попытка парсинга словаря
        code = ErrorCode.UNKNOWN
        msg = "Unknown"
        if isinstance(pb_status, dict):
            msg = str(pb_status.get("message", msg))
        return EngineError(code=code, message=msg, public=True, request_id=request_id)

    # Маппинг gRPC code -> ErrorCode
    code = _from_grpc_code(pb_status.code)
    details: t.List[ErrorDetail] = []
    for any_pb in pb_status.details:
        type_url = getattr(any_pb, "type_url", "")
        payload: t.Dict[str, t.Any] = {}
        try:
            if type_url == TYPE_URLS["error_info"] and PbErrorInfo is not None:
                msg = PbErrorInfo()
                any_pb.Unpack(msg)
                payload = {"reason": msg.reason, "domain": msg.domain, "metadata": dict(msg.metadata)}
            elif type_url == TYPE_URLS["bad_request"] and PbBadRequest is not None:
                msg = PbBadRequest()
                any_pb.Unpack(msg)
                payload = {"field_violations": [{"field": f.field, "description": f.description} for f in msg.field_violations]}
            elif type_url == TYPE_URLS["retry_info"] and PbRetryInfo is not None:
                msg = PbRetryInfo()
                any_pb.Unpack(msg)
                delay_ms = (msg.retry_delay.seconds or 0) * 1000 + (msg.retry_delay.nanos or 0) // 1_000_000
                payload = {"retry_delay_ms": delay_ms}
            elif type_url == TYPE_URLS["request_info"] and PbRequestInfo is not None:
                msg = PbRequestInfo()
                any_pb.Unpack(msg)
                payload = {"request_id": msg.request_id, "serving_data": msg.serving_data}
            else:
                # сырые данные
                payload = json.loads(any_pb.value.decode("utf-8")) if any_pb.value else {}
        except Exception:  # pragma: no cover
            payload = {}
        details.append(ErrorDetail(type_url=type_url, payload=payload))

    return EngineError(code=code, message=pb_status.message, details=details, public=True, request_id=request_id)


def _from_grpc_code(code_value: int) -> ErrorCode:
    # гранично достаточный маппинг
    mapping = {
        3: ErrorCode.INVALID_ARGUMENT,
        9: ErrorCode.FAILED_PRECONDITION,
        11: ErrorCode.OUT_OF_RANGE,
        7: ErrorCode.PERMISSION_DENIED,
        16: ErrorCode.UNAUTHENTICATED,
        5: ErrorCode.NOT_FOUND,
        10: ErrorCode.ABORTED if hasattr(ErrorCode, "ABORTED") else ErrorCode.CONFLICT,
        8: ErrorCode.RESOURCE_EXHAUSTED,
        4: ErrorCode.DEADLINE_EXCEEDED,
        14: ErrorCode.UNAVAILABLE,
        12: ErrorCode.NOT_IMPLEMENTED,
        13: ErrorCode.INTERNAL,
        2: ErrorCode.UNKNOWN,
    }
    return mapping.get(int(code_value), ErrorCode.UNKNOWN)


# =============================================================================
# Помощники для логирования ошибок
# =============================================================================

def error_to_log_record(err: EngineError) -> t.Dict[str, t.Any]:
    rec = {
        "code": err.code,
        "category": err.category,
        "message": err.message,
        "http": err.http_status,
        "public": err.public,
        "request_id": err.request_id,
        "trace_id": err.trace_id,
    }
    if not err.public:
        rec["stack"] = "".join(traceback.format_stack(limit=5))
    return rec
