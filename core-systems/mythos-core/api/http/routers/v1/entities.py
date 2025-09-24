# mythos-core/api/http/routers/v1/entities.py
# -*- coding: utf-8 -*-
"""
HTTP v1 Entities Router для Mythos Core.

Зависимости (минимум):
  - fastapi>=0.110  (pydantic v2)
  - starlette

Сервис доступа к данным инжектируется через app.state.entity_service
или через зависимость get_entity_service(). Контракты совпадают
по духу с proto/jsonschema из каталога schemas/.

Автор: Aethernova
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Mapping, Optional, Tuple

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ConfigDict, field_validator

logger = logging.getLogger("mythos.api.entities")

router = APIRouter(prefix="/v1/entities", tags=["entities"])

# ==========================
# МОДЕЛИ ДАННЫХ (Pydantic v2)
# ==========================


class RelationshipModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(alias="sourceId", min_length=1, max_length=256)
    target_id: str = Field(alias="targetId", min_length=1, max_length=256)
    direction: Literal["OUTBOUND", "INBOUND", "BIDIRECTIONAL"] = "OUTBOUND"
    weight: Optional[float] = Field(default=None)
    properties: Optional[Dict[str, Any]] = None

    @field_validator("weight")
    @classmethod
    def _weight_range(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return v
        # допускаем 0..1 и шире — точная шкала зависит от домена
        return v


class EntityModel(BaseModel):
    """
    Сущность для REST. Поля синхронизированы с proto/jsonschema.
    """
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str = Field(min_length=1, max_length=256)
    tenant_id: Optional[str] = Field(default=None, alias="tenantId")
    namespace: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    display_name: Optional[str] = Field(default=None, alias="displayName")
    description: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[int] = None
    etag: Optional[str] = None
    lifecycle: Optional[Literal["DRAFT", "ACTIVE", "DEPRECATED", "ARCHIVED", "DELETED"]] = None
    owner: Optional[str] = None
    created_at: Optional[str] = Field(default=None, alias="createdAt")
    updated_at: Optional[str] = Field(default=None, alias="updatedAt")
    deleted_at: Optional[str] = Field(default=None, alias="deletedAt")
    relationships: List[RelationshipModel] = Field(default_factory=list)
    external_refs: Dict[str, str] = Field(default_factory=dict, alias="externalRefs")


class FilterModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expr: str = Field(min_length=1)
    params: Dict[str, str] = Field(default_factory=dict)


class SortModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(min_length=1)
    direction: Literal["ASC", "DESC"] = "ASC"


class PageRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    page_size: int = Field(default=100, ge=1, le=1000)
    page_token: str = Field(default="")


class PageResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_size: Optional[int] = Field(default=None, ge=0)
    next_page_token: Optional[str] = None


class ListEntitiesRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filter: Optional[FilterModel] = None
    sort: List[SortModel] = Field(default_factory=list)
    page: PageRequestModel = Field(default_factory=PageRequestModel)

    # быстрые фильтры
    ids: Optional[List[str]] = None
    kind: Optional[str] = None
    namespace: Optional[str] = None
    owner: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None


class ListEntitiesResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entities: List[EntityModel]
    page: PageResponseModel


class BatchUpsertRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entities: List[EntityModel]
    validate_only: bool = False


class UpsertResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    status: Literal["UPSERT_CREATED", "UPSERT_UPDATED", "UPSERT_SKIPPED", "UPSERT_FAILED"]
    etag: Optional[str] = None
    error_message: Optional[str] = None


class BatchUpsertResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    results: List[UpsertResultModel]


class SearchRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1)
    filter: Optional[FilterModel] = None
    sort: List[SortModel] = Field(default_factory=list)
    page: PageRequestModel = Field(default_factory=PageRequestModel)


class SearchResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entities: List[EntityModel]
    page: PageResponseModel


class DeleteEntityResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    etag: Optional[str] = None
    deleted_at: Optional[str] = Field(default=None, alias="deletedAt")


class EntityEventModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ENTITY_ADDED", "ENTITY_MODIFIED", "ENTITY_REMOVED"]
    entity: EntityModel
    occurred_at: str = Field(alias="occurredAt")
    reason: Optional[str] = None


# ==========================
# ИНТЕРФЕЙС СЕРВИСА (DI)
# ==========================


class EntityServiceError(Exception):
    """Базовая ошибка доменного сервиса."""


class NotFoundError(EntityServiceError):
    pass


class ConflictError(EntityServiceError):
    """Конфликт версий/ETag/дубликаты."""


class PreconditionFailedError(EntityServiceError):
    """Несоответствие If-Match/условий."""


class RateLimitExceededError(EntityServiceError):
    pass


class ValidationFailedError(EntityServiceError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class EntityService:
    """
    Контракт доменного сервиса. Реализация должна обеспечить:
      - идемпотентность create/batch_upsert по Idempotency-Key (если передается);
      - генерацию и проверку ETag;
      - постраничные ответы;
      - поток событий для watch().
    """

    # CRUD
    async def create(self, entity: EntityModel, *, validate_only: bool, idem_key: Optional[str]) -> EntityModel: ...
    async def get(self, entity_id: str, *, view: Optional[str]) -> EntityModel: ...
    async def update(
        self,
        entity: EntityModel,
        *,
        update_mask: Optional[List[str]],
        allow_missing: bool,
        validate_only: bool,
        expected_etag: Optional[str],
    ) -> EntityModel: ...
    async def delete(
        self,
        entity_id: str,
        *,
        allow_missing: bool,
        expected_etag: Optional[str],
        hard_delete: bool,
    ) -> DeleteEntityResponseModel: ...

    # List/Search/Batch
    async def list(self, req: ListEntitiesRequestModel) -> ListEntitiesResponseModel: ...
    async def batch_upsert(self, req: BatchUpsertRequestModel, *, idem_key: Optional[str]) -> BatchUpsertResponseModel: ...
    async def search(self, req: SearchRequestModel) -> SearchResponseModel: ...

    # Watch (SSE)
    def watch(self, *, filter_expr: Optional[str], since: Optional[str]) -> AsyncIterator[EntityEventModel]: ...


# ==========================
# ЗАВИСИМОСТИ/DI
# ==========================


def get_entity_service(request: Request) -> EntityService:
    svc = getattr(request.app.state, "entity_service", None)
    if svc is None:
        # Разрешаем замену через Depends в тестах/контейнерах
        raise HTTPException(status_code=500, detail="Entity service is not configured")
    return svc


# ==========================
# УТИЛИТЫ HTTP
# ==========================


def _set_entity_etag(response: Response, entity: EntityModel) -> None:
    if entity.etag:
        response.headers["ETag"] = entity.etag


def _maybe_return_304(request: Request, response_model: EntityModel) -> Optional[Response]:
    """
    Возвращает 304, если If-None-Match совпал с ETag сущности.
    """
    inm = request.headers.get("if-none-match")
    if inm and response_model.etag and inm.strip() == response_model.etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    return None


def _json_response(payload: BaseModel, status_code: int = 200, headers: Optional[Mapping[str, str]] = None) -> JSONResponse:
    return JSONResponse(content=json.loads(payload.model_dump_json(by_alias=True)), status_code=status_code, headers=dict(headers or {}))


def _map_error(exc: EntityServiceError) -> HTTPException:
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc) or "Not found")
    if isinstance(exc, PreconditionFailedError):
        return HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail=str(exc) or "Precondition failed")
    if isinstance(exc, ConflictError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc) or "Conflict")
    if isinstance(exc, RateLimitExceededError):
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc) or "Rate limit exceeded")
    if isinstance(exc, ValidationFailedError):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"message": str(exc), "details": exc.details})
    logger.exception("Unhandled service error: %s", exc)
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error")


# ==========================
# ENDPOINTS
# ==========================


@router.post(
    "",
    response_model=EntityModel,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Created", "headers": {"ETag": {"description": "Entity version tag", "schema": {"type": "string"}}}},
        412: {"description": "Precondition failed"},
        409: {"description": "Conflict"},
        422: {"description": "Validation failed"},
    },
)
async def create_entity(
    request: Request,
    entity: EntityModel,
    validate_only: bool = Query(False, alias="validateOnly"),
    idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    """
    Создать сущность. Идемпотентность обеспечивается по Idempotency-Key (если задан).
    """
    try:
        created = await svc.create(entity, validate_only=validate_only, idem_key=idem_key)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    # ETag и 304
    resp_304 = _maybe_return_304(request, created)
    if resp_304:
        return resp_304  # type: ignore[return-value]
    headers = {}
    if created.etag:
        headers["ETag"] = created.etag
    return _json_response(created, status_code=status.HTTP_201_CREATED, headers=headers)


@router.get(
    "/{entity_id}",
    response_model=EntityModel,
    responses={200: {"headers": {"ETag": {"schema": {"type": "string"}}}}, 304: {"description": "Not modified"}, 404: {}},
)
async def get_entity(
    request: Request,
    entity_id: str = Path(..., min_length=1),
    view: Optional[str] = Query(None),
    svc: EntityService = Depends(get_entity_service),
) -> Response:
    try:
        entity = await svc.get(entity_id, view=view)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    # 304 If-None-Match
    resp_304 = _maybe_return_304(request, entity)
    if resp_304:
        return resp_304
    # ETag
    headers = {}
    if entity.etag:
        headers["ETag"] = entity.etag
    return _json_response(entity, headers=headers)


@router.patch(
    "/{entity_id}",
    response_model=EntityModel,
    responses={200: {"headers": {"ETag": {"schema": {"type": "string"}}}}, 404: {}, 409: {}, 412: {}, 422: {}},
)
async def update_entity(
    entity_id: str = Path(..., min_length=1),
    entity: EntityModel = ...,
    update_mask: Optional[str] = Query(None, alias="updateMask", description="Список полей через запятую"),
    allow_missing: bool = Query(False, alias="allowMissing"),
    validate_only: bool = Query(False, alias="validateOnly"),
    expected_etag: Optional[str] = Header(default=None, alias="If-Match"),
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    if entity.id and entity.id != entity_id:
        raise HTTPException(status_code=400, detail="Entity id in path and body must match")
    try:
        updated = await svc.update(
            entity,
            update_mask=[s.strip() for s in update_mask.split(",")] if update_mask else None,
            allow_missing=allow_missing,
            validate_only=validate_only,
            expected_etag=expected_etag,
        )
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    headers = {}
    if updated.etag:
        headers["ETag"] = updated.etag
    return _json_response(updated, headers=headers)


@router.delete(
    "/{entity_id}",
    response_model=DeleteEntityResponseModel,
    responses={200: {}, 404: {}, 412: {}},
)
async def delete_entity(
    entity_id: str = Path(..., min_length=1),
    allow_missing: bool = Query(False, alias="allowMissing"),
    hard_delete: bool = Query(False, alias="hardDelete"),
    expected_etag: Optional[str] = Header(default=None, alias="If-Match"),
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    try:
        result = await svc.delete(entity_id, allow_missing=allow_missing, expected_etag=expected_etag, hard_delete=hard_delete)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    return _json_response(result)


@router.post(
    ":list",
    response_model=ListEntitiesResponseModel,
    responses={200: {}},
)
async def list_entities(
    req: ListEntitiesRequestModel,
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    try:
        out = await svc.list(req)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    return _json_response(out)


@router.post(
    ":batchUpsert",
    response_model=BatchUpsertResponseModel,
    responses={200: {}, 422: {}},
)
async def batch_upsert_entities(
    req: BatchUpsertRequestModel,
    idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    try:
        out = await svc.batch_upsert(req, idem_key=idem_key)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    return _json_response(out)


@router.post(
    ":search",
    response_model=SearchResponseModel,
    responses={200: {}},
)
async def search_entities(
    req: SearchRequestModel,
    svc: EntityService = Depends(get_entity_service),
) -> JSONResponse:
    try:
        out = await svc.search(req)
    except EntityServiceError as e:
        raise _map_error(e)  # noqa: B904
    return _json_response(out)


@router.get(
    ":watch",
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def watch_entities(
    filter: Optional[str] = Query(None, alias="filter"),
    since: Optional[str] = Query(None, alias="since"),
    heartbeat_interval: float = Query(15.0, ge=1.0, le=120.0, description="Интервал heartbeat SSE"),
    svc: EntityService = Depends(get_entity_service),
) -> StreamingResponse:
    """
    Server-Sent Events поток изменений сущностей.

    Формат событий:
      data: {"type": "...", "entity": {...}, "occurredAt": "...", "reason": "..."}\n\n
    """

    async def _event_stream() -> AsyncIterator[bytes]:
        # Первый heartbeat — для быстрой проверки подключения фронтом/шлюзом
        yield b":ok\n\n"
        last_heartbeat = asyncio.get_event_loop().time()

        async for ev in svc.watch(filter_expr=filter, since=since):
            payload = json.dumps(json.loads(ev.model_dump_json(by_alias=True)), ensure_ascii=False).encode("utf-8")
            yield b"event: entity\n"
            yield b"data: " + payload + b"\n\n"

            # периодический heartbeat, чтобы не разрывались обратные прокси
            now = asyncio.get_event_loop().time()
            if now - last_heartbeat >= heartbeat_interval:
                yield b":heartbeat\n\n"
                last_heartbeat = now

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


# ==========================
# РЕГИСТРАЦИЯ ROUTER В ПРИЛОЖЕНИИ (пример)
# ==========================
# from fastapi import FastAPI
# app = FastAPI()
# app.include_router(router)
# app.state.entity_service = YourEntityServiceImpl(...)
#
# Для тестов можно инжектить зависимость get_entity_service через fastapi.Depends override.
