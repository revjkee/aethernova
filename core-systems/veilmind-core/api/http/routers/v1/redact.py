# veilmind-core/api/http/routers/v1/redact.py
# -*- coding: utf-8 -*-
"""
Выполнение редактирования (redaction) чувствительных данных.
Особенности:
- Pydantic-схемы запроса/ответа
- Проверка Content-SHA256 целостности полезной нагрузки
- Поддержка Idempotency-Key (прозрачная эхо-передача)
- Безопасное логирование с редактированием секретов
- Опциональная интеграция OpenTelemetry (если установлен)
- Интерфейс сервиса редактирования + дефолтная реализация
- Стандартизированные ошибки без утечки секретов
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple, Union

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError, root_validator

# Опциональная телеметрия (без жесткой зависимости)
try:  # pragma: no cover
    from opentelemetry import trace
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None

router = APIRouter(prefix="/v1", tags=["redaction"])

# ---------------------------
# Безопасные логи и редактирование строк
# ---------------------------

_REDACT_MASK = "[REDACTED]"
_DENY_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token", "id_token",
    "authorization", "api_key", "apikey", "cookie", "set-cookie", "private_key",
    "client_secret", "db_password", "jwt", "otp", "session"
}
_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),  # JWT
    re.compile(r"\b\d{13,19}\b"),  # PAN
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),             # Email
    re.compile(r"(?i)\+?[0-9][0-9\-\s()]{7,}"),                                # Phone
    re.compile(r"(?i)\b(pwd|pass(word)?|secret|token|key)\b\s*[:=]\s*\S+"),    # k=v секрет
]
_ID_KEY_RX = re.compile(r"(?i)^(user_)?id$")

def _redact_text(s: str, max_len: int = 2048) -> str:
    out = s
    for rx in _PATTERNS:
        out = rx.sub(_REDACT_MASK, out)
    if len(out) > max_len:
        out = out[:max_len] + "...(truncated)"
    return out

def _safe_log_kv(k: str, v: str) -> str:
    k_low = k.lower()
    if k_low in _DENY_KEYS or k_low in {"authorization", "cookie", "set-cookie"}:
        return f"{k}={_REDACT_MASK}"
    return f"{k}={_redact_text(v, max_len=256)}"

# ---------------------------
# Модели запроса/ответа
# ---------------------------

class RedactRequest(BaseModel):
    payload: Any = Field(..., description="Произвольный JSON, подлежащий редактированию")
    ruleset_id: Optional[str] = Field(None, description="Идентификатор набора правил, если поддерживается")
    context: Optional[Dict[str, Any]] = Field(None, description="Контекст (RBAC/ABAC), не обязателен")
    profile: Optional[str] = Field(None, description="dev|staging|prod — профиль строгости")

    @root_validator(pre=True)
    def _limit_size(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Жесткое ограничение на размер сериализованного тела, чтобы избегать злоупотреблений
        try:
            enc = json.dumps(values.get("payload"), ensure_ascii=False).encode("utf-8")
            if len(enc) > 1_048_576:  # 1 MiB
                raise ValueError("payload too large")
        except Exception:
            # Если сериализация невозможна — все равно проверим общий размер
            raw = json.dumps(values, ensure_ascii=False).encode("utf-8")
            if len(raw) > 1_048_576:
                raise ValueError("request too large")
        return values


class RedactionAction(BaseModel):
    masked: int = 0
    tokenized: int = 0
    hashed: int = 0
    truncated: int = 0
    dropped: int = 0


class RedactResponse(BaseModel):
    payload: Any
    applied_rules: List[str]
    actions: RedactionAction
    classification: Optional[str] = None
    meta: Dict[str, Any]


class ErrorResponse(BaseModel):
    error: str
    request_id: str
    details: Optional[str] = None

# ---------------------------
# Интерфейс сервиса и дефолтная реализация
# ---------------------------

@dataclass
class RedactionResult:
    payload: Any
    applied_rules: List[str]
    actions: RedactionAction
    classification: Optional[str] = None


class RedactionService:
    def redact(self, payload: Any, *, ruleset_id: Optional[str], context: Optional[Dict[str, Any]], profile: Optional[str]) -> RedactionResult:
        raise NotImplementedError


class SimpleRedactionService(RedactionService):
    """
    Дефолтная безопасная реализация:
    - Маскирование значений по denylist-ключам
    - Замена секретов/PII в строках по паттернам
    - Усечение слишком длинных строк
    - Хэширование идентификаторов по ключам ^(user_)?id$
    Примечание: Токенизация не выполняется (требуется внешний провайдер).
    """
    MAX_STR_LEN = 2048

    def redact(self, payload: Any, *, ruleset_id: Optional[str], context: Optional[Dict[str, Any]], profile: Optional[str]) -> RedactionResult:
        actions = RedactionAction()
        applied: List[str] = []
        out = self._walk(payload, actions, applied, parent_key=None)
        # Простая эвристика классификации
        classification = "SENSITIVE" if actions.masked or actions.hashed or actions.tokenized else "INTERNAL"
        return RedactionResult(payload=out, applied_rules=sorted(set(applied)), actions=actions, classification=classification)

    def _walk(self, node: Any, actions: RedactionAction, applied: List[str], parent_key: Optional[str]) -> Any:
        if isinstance(node, dict):
            res: Dict[str, Any] = {}
            for k, v in node.items():
                kl = str(k).lower()
                if kl in _DENY_KEYS:
                    res[k] = _REDACT_MASK
                    actions.masked += 1
                    applied.append("denylist.keys.mask")
                    continue
                # Хэшируем ID-значения (строка/число)
                if _ID_KEY_RX.match(k) and isinstance(v, (str, int)):
                    h = hashlib.sha256(str(v).encode("utf-8")).hexdigest()
                    res[k] = h
                    actions.hashed += 1
                    applied.append("id.hash.sha256")
                    continue
                res[k] = self._walk(v, actions, applied, parent_key=k)
            return res
        if isinstance(node, list):
            return [self._walk(x, actions, applied, parent_key=parent_key) for x in node]
        if isinstance(node, str):
            red = node
            before = red
            for rx in _PATTERNS:
                red = rx.sub(_REDACT_MASK, red)
            if red != before:
                actions.masked += 1
                applied.append("patterns.mask")
            if len(red) > self.MAX_STR_LEN:
                red = red[: self.MAX_STR_LEN] + "...(truncated)"
                actions.truncated += 1
                applied.append("length.truncate")
            return red
        # Прочие типы возвращаем как есть
        return node

# ---------------------------
# Зависимости: аутентификация и сервис
# ---------------------------

_security = HTTPBearer(auto_error=False)

def _verify_token(creds: Optional[HTTPAuthorizationCredentials] = Depends(_security)) -> Optional[str]:
    # Базовая проверка Bearer-токена; расширьте по необходимости
    if creds is None or not creds.scheme.lower() == "bearer" or not creds.credentials:
        return None
    return creds.credentials

def get_redaction_service(request: Request) -> RedactionService:
    svc = getattr(request.app.state, "redaction_service", None)
    if isinstance(svc, RedactionService):
        return svc
    # Дефолт
    return SimpleRedactionService()

# ---------------------------
# Утилиты: Content-SHA256 и request_id
# ---------------------------

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _compute_json_sha256(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(raw)

# ---------------------------
# Обработчик POST /v1/redact
# ---------------------------

@router.post(
    "/redact",
    response_model=RedactResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Редактирование чувствительных данных",
    description="Принимает произвольный JSON и возвращает отредактированный JSON согласно политике.",
)
async def redact_endpoint(
    request: Request,
    body: RedactRequest = Body(...),
    authorization: Optional[str] = Header(None, convert_underscores=False),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    content_sha256: Optional[str] = Header(None, alias="Content-SHA256"),
    svc: RedactionService = Depends(get_redaction_service),
    bearer: Optional[str] = Depends(_verify_token),
):
    started = time.perf_counter()
    request_id = str(uuid.uuid4())

    # Аутентификация (минимальная). При необходимости замените на полноценный verifier.
    if authorization and not bearer:
        # Неверная схема или пустой токен
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ErrorResponse(error="unauthorized", request_id=request_id).dict(),
        )

    # Проверка целостности тела при наличии заголовка Content-SHA256
    if content_sha256:
        try:
            calc = _compute_json_sha256(body.payload)
            if calc.lower() != content_sha256.lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorResponse(
                        error="content_sha256_mismatch",
                        request_id=request_id,
                        details="Provided Content-SHA256 does not match payload",
                    ).dict(),
                )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorResponse(error="bad_request", request_id=request_id, details="Integrity check failed").dict(),
            )

    # Трассировка
    if _tracer is not None:  # pragma: no cover
        with _tracer.start_as_current_span("redact") as span:
            span.set_attribute("veilmind.request_id", request_id)
            span.set_attribute("veilmind.ruleset_id", body.ruleset_id or "")
            span.set_attribute("veilmind.profile", body.profile or "")
            span.set_attribute("http.idempotency_key", idempotency_key or "")
            # Не добавляем содержимое payload в span

            result = svc.redact(body.payload, ruleset_id=body.ruleset_id, context=body.context, profile=body.profile)
    else:
        result = svc.redact(body.payload, ruleset_id=body.ruleset_id, context=body.context, profile=body.profile)

    elapsed_ms = int((time.perf_counter() - started) * 1000)

    resp = RedactResponse(
        payload=result.payload,
        applied_rules=result.applied_rules,
        actions=result.actions,
        classification=result.classification,
        meta={
            "request_id": request_id,
            "processing_time_ms": elapsed_ms,
            "idempotency_key": idempotency_key,
            "version": 1,
        },
    )
    return resp

# ---------------------------
# Глобальные обработчики ошибок (локально для роутера)
# ---------------------------

@router.exception_handler(ValidationError)
async def _validation_exception_handler(_: Request, exc: ValidationError):
    rid = str(uuid.uuid4())
    return Response(
        content=ErrorResponse(error="validation_error", request_id=rid, details="invalid payload").json(),
        media_type="application/json",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )

@router.exception_handler(HTTPException)
async def _http_exception_handler(_: Request, exc: HTTPException):
    # Если detail уже структурирован — возвращаем как есть, иначе упакуем
    rid = str(uuid.uuid4())
    if isinstance(exc.detail, dict) and "error" in exc.detail and "request_id" in exc.detail:
        payload = exc.detail
    else:
        payload = ErrorResponse(error="http_error", request_id=rid, details=str(exc.detail) if exc.detail else None).dict()
    return Response(content=json.dumps(payload, ensure_ascii=False), media_type="application/json", status_code=exc.status_code)

@router.exception_handler(Exception)
async def _unhandled_exception_handler(_: Request, exc: Exception):
    rid = str(uuid.uuid4())
    # Не раскрываем подробности
    return Response(
        content=ErrorResponse(error="internal_error", request_id=rid).json(),
        media_type="application/json",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
