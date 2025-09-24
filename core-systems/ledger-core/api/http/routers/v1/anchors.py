from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, TypedDict, Union

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, NonNegativeInt, StrictBool, StrictInt, StrictStr, UUID4, root_validator, validator

# =============================================================================
# Контракты и утилиты
# =============================================================================

# Унифицированный формат ошибки, согласованный с schemas/proto/v1/error.proto
class Localized(BaseModel):
    locale: Optional[str] = None
    message: Optional[str] = None


class FieldViolation(BaseModel):
    field: StrictStr
    description: Optional[str] = None
    value: Optional[str] = None


class ErrorDetail(BaseModel):
    field_violation: Optional[FieldViolation] = None
    # Для краткости включены только популярные детали; при необходимости расширьте.


class ErrorPayload(BaseModel):
    code: StrictStr
    message: StrictStr
    correlation_id: Optional[str] = None
    severity: Optional[int] = 3  # SEVERITY_ERROR
    http_status: Optional[int] = None
    retryable: Optional[bool] = False
    details: Optional[List[ErrorDetail]] = None
    metadata: Optional[Dict[str, str]] = None
    localized: Optional[Localized] = None


def error_response(
    *,
    code: str,
    message: str,
    http_status: int,
    correlation_id: Optional[str],
    retryable: bool = False,
    details: Optional[List[ErrorDetail]] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    payload = ErrorPayload(
        code=code,
        message=message,
        http_status=http_status,
        correlation_id=correlation_id,
        retryable=retryable,
        details=details,
        metadata=metadata,
    ).dict(exclude_none=True)
    return JSONResponse(status_code=http_status, content=payload)


# Корреляция запроса
def get_correlation_id(x_request_id: Optional[str] = Header(default=None)) -> str:
    # Берём X-Request-ID, иначе генерируем псевдо-UUIDv4 (без внешних зависимостей)
    if x_request_id:
        return x_request_id
    # Быстрый псевдо‑uuid: timestamp + sha1(rand)
    n = str(time.time_ns()).encode("utf-8")
    h = hashlib.sha1(n).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# Базовые безопасные заголовки на ответ
def apply_security_headers(resp: Response) -> None:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")


# Rate-limit (заглушка; реально должен заполняться из лимитера/прокси)
def apply_rate_limit_headers(resp: Response, *, limit: int = 1000, remaining: int = 999, reset_epoch_s: Optional[int] = None) -> None:
    resp.headers["X-RateLimit-Limit"] = str(limit)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    if reset_epoch_s:
        resp.headers["X-RateLimit-Reset"] = str(reset_epoch_s)


# =============================================================================
# Модель домена Anchors
# =============================================================================

class AnchorStatus(str):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DELETED = "deleted"


class AnchorIn(BaseModel):
    # Вход при создании/обновлении
    name: StrictStr = Field(..., min_length=3, max_length=200)
    description: Optional[StrictStr] = Field(None, max_length=1000)
    status: StrictStr = Field(AnchorStatus.ACTIVE, regex="^(active|inactive)$")
    metadata: Optional[Dict[str, StrictStr]] = Field(default=None)

    @validator("metadata")
    def validate_meta(cls, v):
        if v and any(len(k) > 64 or len(str(val)) > 256 for k, val in v.items()):
            raise ValueError("metadata key<=64, value<=256")
        return v


class AnchorOut(BaseModel):
    id: UUID4
    name: StrictStr
    description: Optional[StrictStr] = None
    status: StrictStr
    metadata: Optional[Dict[str, str]] = None
    version: StrictInt = Field(..., ge=1)
    created_at: datetime
    updated_at: datetime

    class Config:
        json_encoders = {datetime: lambda dt: dt.astimezone(timezone.utc).isoformat()}


class ListResponse(BaseModel):
    data: List[AnchorOut]
    next_cursor: Optional[StrictStr] = None


# =============================================================================
# Репозиторий — абстракция (реализация подключается в зависимостях)
# =============================================================================

class RepositoryError(Exception):
    code: str = "INTERNAL"

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AnchorRecord(TypedDict):
    id: str
    name: str
    description: Optional[str]
    status: str
    metadata: Optional[Dict[str, str]]
    version: int
    created_at: datetime
    updated_at: datetime


class AnchorRepository(Protocol):
    async def get(self, anchor_id: str) -> Optional[AnchorRecord]:
        ...

    async def list(self, *, limit: int, cursor: Optional[str]) -> Tuple[List[AnchorRecord], Optional[str]]:
        ...

    async def create(self, *, data: AnchorIn, idem_key: Optional[str]) -> AnchorRecord:
        ...

    async def update(self, *, anchor_id: str, data: AnchorIn, expected_version: Optional[int]) -> AnchorRecord:
        ...

    async def delete(self, *, anchor_id: str, expected_version: Optional[int]) -> AnchorRecord:
        ...

    async def etag_of(self, record: AnchorRecord) -> str:
        ...


# Пример простого ETag: по id+version
def default_etag(record: AnchorRecord) -> str:
    s = f'{record["id"]}:{record["version"]}'
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# =============================================================================
# Зависимости (безопасность, репозиторий, идемпотентность)
# =============================================================================

class AuthContext(BaseModel):
    subject: StrictStr
    roles: List[StrictStr] = []
    # при необходимости: tenant_id, scopes и т.п.


async def require_auth(
    authorization: Optional[str] = Header(default=None),
    x_request_id: str = Depends(get_correlation_id),
) -> AuthContext:
    # Заглушка: в реальности — валидация JWT/OIDC и загрузка контекста
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return AuthContext(subject="user:unknown")


class IdempotencyCache(Protocol):
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        ...

    async def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 7200) -> None:
        ...


# Неблокирующий in-memory кэш идемпотентности (для примера; для прод — Redis)
class InMemoryIdemCache:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            exp, val = item
            if time.time() > exp:
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 7200) -> None:
        async with self._lock:
            self._store[key] = (time.time() + ttl_seconds, value)


# Провайдеры зависимостей. В реальном сервисе замените внедрением (DI) на ваши реализации.
IDEM_CACHE = InMemoryIdemCache()

async def get_repo() -> AnchorRepository:
    # Здесь должен быть ваш репозиторий (Postgres и т.д.). Мы ожидаем внедрение.
    raise RepositoryError("INTERNAL", "Repository dependency is not wired")


async def get_idem_cache() -> IdempotencyCache:
    return IDEM_CACHE


# =============================================================================
# Роутер
# =============================================================================

router = APIRouter(prefix="/api/v1/anchors", tags=["anchors"])

# ---------- Helpers ----------

def _parse_if_match(if_match: Optional[str]) -> Optional[int]:
    if not if_match:
        return None
    # Принимаем либо число, либо ETag в виде "W/\"<hex>\"" — здесь поддержим только версию как число
    try:
        return int(if_match.strip().strip('"'))
    except Exception:
        return None


def _set_common_headers(resp: Response, *, etag: Optional[str] = None, correlation_id: str) -> None:
    apply_security_headers(resp)
    apply_rate_limit_headers(resp)
    resp.headers.setdefault("X-Request-ID", correlation_id)
    if etag:
        resp.headers["ETag"] = f"\"{etag}\""


async def _audit(bg: BackgroundTasks, *, action: str, subject: str, resource_id: Optional[str], success: bool, extra: Dict[str, Any]) -> None:
    # Отправка записи аудита во внешний sink (фоновой таск)
    async def _send():
        # Здесь вы можете отправить запись в Kafka/OTel/event‑шину
        _ = action, subject, resource_id, success, extra
    bg.add_task(_send)


# ---------- Endpoints ----------

@router.get("", response_model=ListResponse, summary="List anchors (cursor-based)")
async def list_anchors(
    request: Request,
    response: Response,
    limit: NonNegativeInt = Query(50, ge=1, le=500),
    cursor: Optional[StrictStr] = Query(None),
    repo: AnchorRepository = Depends(get_repo),
    auth: AuthContext = Depends(require_auth),
    correlation_id: str = Depends(get_correlation_id),
):
    try:
        items, next_cursor = await repo.list(limit=limit, cursor=cursor)
        out = [AnchorOut(**r) for r in items]
        _set_common_headers(response, correlation_id=correlation_id)
        return ListResponse(data=out, next_cursor=next_cursor)
    except RepositoryError as e:
        return error_response(
            code=e.code or "INTERNAL",
            message=str(e),
            http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            correlation_id=correlation_id,
            retryable=True,
        )


@router.get("/{anchor_id}", response_model=AnchorOut, summary="Get anchor by id")
async def get_anchor(
    anchor_id: UUID4,
    request: Request,
    response: Response,
    repo: AnchorRepository = Depends(get_repo),
    auth: AuthContext = Depends(require_auth),
    correlation_id: str = Depends(get_correlation_id),
):
    try:
        rec = await repo.get(str(anchor_id))
        if not rec:
            return error_response(
                code="NOT_FOUND",
                message="anchor not found",
                http_status=status.HTTP_404_NOT_FOUND,
                correlation_id=correlation_id,
            )
        etag = await repo.etag_of(rec)
        _set_common_headers(response, etag=etag, correlation_id=correlation_id)
        return AnchorOut(**rec)
    except RepositoryError as e:
        return error_response(
            code=e.code or "INTERNAL",
            message=str(e),
            http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            correlation_id=correlation_id,
            retryable=True,
        )


@router.post("", response_model=AnchorOut, status_code=status.HTTP_201_CREATED, summary="Create anchor (idempotent)")
async def create_anchor(
    payload: AnchorIn,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    repo: AnchorRepository = Depends(get_repo),
    idem_cache: IdempotencyCache = Depends(get_idem_cache),
    auth: AuthContext = Depends(require_auth),
    correlation_id: str = Depends(get_correlation_id),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Идемпотентность: если ключ передан — пытаемся вернуть ранее сохраненный результат
    try:
        if idempotency_key:
            cached = await idem_cache.get(idempotency_key)
            if cached:
                # Восстанавливаем ответ
                resp_json = cached["json"]
                etag = cached.get("etag")
                _set_common_headers(response, etag=etag, correlation_id=correlation_id)
                response.status_code = cached.get("status", status.HTTP_201_CREATED)
                return resp_json

        rec = await repo.create(data=payload, idem_key=idempotency_key)
        etag = await repo.etag_of(rec)
        out = AnchorOut(**rec)
        _set_common_headers(response, etag=etag, correlation_id=correlation_id)

        # Кэшируем идемп. результат
        if idempotency_key:
            await idem_cache.set(
                idempotency_key,
                {"json": json.loads(out.json()), "etag": etag, "status": status.HTTP_201_CREATED},
                ttl_seconds=7200,
            )

        await _audit(background, action="anchors.create", subject=auth.subject, resource_id=rec["id"], success=True, extra={"cid": correlation_id})
        return out
    except RepositoryError as e:
        return error_response(
            code=e.code or "INTERNAL",
            message=str(e),
            http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            correlation_id=correlation_id,
            retryable=True,
        )


@router.put("/{anchor_id}", response_model=AnchorOut, summary="Update anchor (optimistic concurrency)")
async def update_anchor(
    anchor_id: UUID4,
    payload: AnchorIn,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    repo: AnchorRepository = Depends(get_repo),
    auth: AuthContext = Depends(require_auth),
    correlation_id: str = Depends(get_correlation_id),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    expected_version = _parse_if_match(if_match)
    try:
        rec = await repo.update(anchor_id=str(anchor_id), data=payload, expected_version=expected_version)
        etag = await repo.etag_of(rec)
        _set_common_headers(response, etag=etag, correlation_id=correlation_id)
        await _audit(background, action="anchors.update", subject=auth.subject, resource_id=rec["id"], success=True, extra={"cid": correlation_id})
        return AnchorOut(**rec)
    except RepositoryError as e:
        code = e.code or "INTERNAL"
        http_status = status.HTTP_500_INTERNAL_SERVER_ERROR
        if code == "CONFLICT":
            http_status = status.HTTP_412_PRECONDITION_FAILED if expected_version is not None else status.HTTP_409_CONFLICT
        elif code == "NOT_FOUND":
            http_status = status.HTTP_404_NOT_FOUND
        return error_response(
            code=code,
            message=str(e),
            http_status=http_status,
            correlation_id=correlation_id,
            retryable=(http_status >= 500),
        )


@router.delete("/{anchor_id}", response_model=AnchorOut, summary="Delete anchor (soft-delete, optimistic concurrency)")
async def delete_anchor(
    anchor_id: UUID4,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    repo: AnchorRepository = Depends(get_repo),
    auth: AuthContext = Depends(require_auth),
    correlation_id: str = Depends(get_correlation_id),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    expected_version = _parse_if_match(if_match)
    try:
        rec = await repo.delete(anchor_id=str(anchor_id), expected_version=expected_version)
        etag = await repo.etag_of(rec)
        _set_common_headers(response, etag=etag, correlation_id=correlation_id)
        await _audit(background, action="anchors.delete", subject=auth.subject, resource_id=rec["id"], success=True, extra={"cid": correlation_id})
        return AnchorOut(**rec)
    except RepositoryError as e:
        code = e.code or "INTERNAL"
        http_status = status.HTTP_500_INTERNAL_SERVER_ERROR
        if code == "CONFLICT":
            http_status = status.HTTP_412_PRECONDITION_FAILED if expected_version is not None else status.HTTP_409_CONFLICT
        elif code == "NOT_FOUND":
            http_status = status.HTTP_404_NOT_FOUND
        return error_response(
            code=code,
            message=str(e),
            http_status=http_status,
            correlation_id=correlation_id,
            retryable=(http_status >= 500),
        )
