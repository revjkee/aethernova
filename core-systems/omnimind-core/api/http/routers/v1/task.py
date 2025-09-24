# ops/api/http/routers/v1/task.py
"""
Роутер задач v1 для omnimind-core.

Особенности:
- Строгие Pydantic v2 DTO и enum статусы.
- Пагинация: page/page_size и cursor/limit (взаимоисключающие режимы).
- Идемпотентность: заголовок 'Idempotency-Key' для POST.
- Конкурентный доступ: ETag по (id, updated_at), поддержка 'If-Match'/'If-None-Match'.
- Корреляция: заголовок 'X-Request-Id' переносится в ответ.
- Явные HTTP-статусы и схемы ошибок для OpenAPI.
- Аутентификация: зависимость get_current_user (Bearer), легко заменить на вашу.

Примечание:
- Абстракция TaskService определена как Protocol. Подставьте вашу реализацию
  через зависимости в DI-контейнере приложения.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Iterable, Optional, Protocol
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator, ConfigDict

router = APIRouter(
    prefix="/v1/tasks",
    tags=["tasks"],
    responses={
        401: {"description": "Unauthorized", "model": lambda: ApiError.example(401)},
        403: {"description": "Forbidden", "model": lambda: ApiError.example(403)},
        404: {"description": "Not Found", "model": lambda: ApiError.example(404)},
        412: {"description": "Precondition Failed (ETag mismatch)", "model": lambda: ApiError.example(412)},
        409: {"description": "Conflict (idempotency or state)", "model": lambda: ApiError.example(409)},
        422: {"description": "Validation Error", "model": lambda: ApiError.example(422)},
        429: {"description": "Too Many Requests", "model": lambda: ApiError.example(429)},
        500: {"description": "Internal Server Error", "model": lambda: ApiError.example(500)},
    },
)


# ==========================
# МОДЕЛИ ДАННЫХ
# ==========================

class TaskStatus(StrEnum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"


class TaskKind(StrEnum):
    inference = "inference"
    embedding = "embedding"
    indexing = "indexing"
    maintenance = "maintenance"
    generic = "generic"


class TaskCreate(BaseModel):
    """
    Запрос на создание задачи.
    """
    model_config = ConfigDict(extra="forbid")

    kind: TaskKind = Field(..., description="Тип задачи")
    payload: dict[str, Any] = Field(default_factory=dict, description="Аргументы задачи")
    priority: int = Field(100, ge=1, le=1000, description="Приоритет (меньше — выше)")
    queue: str = Field("default", min_length=1, max_length=64, description="Имя очереди")
    # Таймауты исполнения
    soft_timeout_sec: int = Field(60, ge=1, le=86_400)
    hard_timeout_sec: int = Field(120, ge=1, le=86_400)

    @field_validator("hard_timeout_sec")
    @classmethod
    def _hard_ge_soft(cls, v: int, info):
        soft = info.data.get("soft_timeout_sec", 60)
        if v < soft:
            raise ValueError("hard_timeout_sec must be >= soft_timeout_sec")
        return v


class TaskUpdate(BaseModel):
    """
    Частичное обновление (патч) задачи.
    Допустимо обновлять только незапущенные задачи (pending).
    """
    model_config = ConfigDict(extra="forbid")

    priority: Optional[int] = Field(None, ge=1, le=1000)
    queue: Optional[str] = Field(None, min_length=1, max_length=64)
    payload: Optional[dict[str, Any]] = None


class TaskDTO(BaseModel):
    """
    Полная модель задачи для ответа.
    """
    model_config = ConfigDict(extra="ignore")

    id: UUID
    kind: TaskKind
    status: TaskStatus
    priority: int
    queue: str
    payload: dict[str, Any] = Field(default_factory=dict)
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None

    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    # Версионный маркер для оптимистической блокировки (может совпадать с updated_at)
    version: int = Field(..., ge=0, description="Счетчик версий записи")

    def etag(self) -> str:
        """
        Строим стабильный ETag по id и updated_at/version.
        """
        updated = self.updated_at.astimezone(timezone.utc).isoformat()
        base = f"{self.id}:{self.version}:{updated}"
        return f"W/\"{hashlib.sha256(base.encode('utf-8')).hexdigest()}\""


class PageMeta(BaseModel):
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1, le=1000)
    total_items: int = Field(..., ge=0)
    total_pages: int = Field(..., ge=0)


class CursorMeta(BaseModel):
    next_cursor: Optional[str] = None
    has_more: bool = False


class TaskListResponse(BaseModel):
    items: list[TaskDTO]
    page: Optional[PageMeta] = None
    cursor: Optional[CursorMeta] = None


class ApiError(BaseModel):
    error: str
    code: int
    details: Optional[dict[str, Any]] = None

    @staticmethod
    def example(code: int = 400) -> "ApiError":  # для OpenAPI в заголовке router.responses
        return ApiError(error=HTTP_STATUS_TITLES.get(code, "Error"), code=code)


HTTP_STATUS_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    412: "Precondition Failed",
    415: "Unsupported Media Type",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
}

# ==========================
# ИСКЛЮЧЕНИЯ ДОМЕНА
# ==========================

class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class PreconditionFailed(Exception):
    pass


class ForbiddenError(Exception):
    pass


# ==========================
# СЕРВИСНЫЙ СЛОЙ (Protocol)
# ==========================

class TaskService(Protocol):
    async def create(
        self,
        *,
        data: TaskCreate,
        user_id: str,
        idempotency_key: Optional[str],
        request_id: Optional[str],
    ) -> TaskDTO: ...

    async def get(self, task_id: UUID, *, user_id: str) -> TaskDTO: ...

    async def list_page(
        self,
        *,
        user_id: str,
        status: Optional[TaskStatus],
        kind: Optional[TaskKind],
        queue: Optional[str],
        page: int,
        page_size: int,
        order_by: str,
        order: str,
    ) -> tuple[list[TaskDTO], int]: ...

    async def list_cursor(
        self,
        *,
        user_id: str,
        status: Optional[TaskStatus],
        kind: Optional[TaskKind],
        queue: Optional[str],
        cursor: Optional[str],
        limit: int,
        order_by: str,
        order: str,
    ) -> tuple[list[TaskDTO], Optional[str]]: ...

    async def update(
        self,
        task_id: UUID,
        *,
        user_id: str,
        patch: TaskUpdate,
        if_match: Optional[str],
    ) -> TaskDTO: ...

    async def delete(
        self,
        task_id: UUID,
        *,
        user_id: str,
        if_match: Optional[str],
        soft: bool,
    ) -> None: ...

    async def cancel(self, task_id: UUID, *, user_id: str, if_match: Optional[str]) -> TaskDTO: ...

    async def stream_logs(self, task_id: UUID, *, user_id: str) -> Iterable[bytes]: ...


# ==========================
# ЗАВИСИМОСТИ (замените на ваши)
# ==========================

class User(BaseModel):
    sub: str
    roles: list[str] = Field(default_factory=list)


async def get_current_user() -> User:
    """
    Заглушка авторизации. Замените на вашу реализацию (OAuth2/JWT).
    """
    # Внедрите проверку токена и атрибутов
    return User(sub="user-123", roles=["user"])


def get_task_service() -> TaskService:
    """
    Провайдер сервиса задач. Замените на фактическую реализацию/контейнер.
    """
    raise NotImplementedError("Provide TaskService via dependency injection")


# ==========================
# УТИЛИТЫ
# ==========================

def set_common_headers(resp: Response, *, request_id: Optional[str], etag: Optional[str] = None) -> None:
    if request_id:
        resp.headers["X-Request-Id"] = request_id
    if etag:
        resp.headers["ETag"] = etag


def validate_pagination_mode(
    page: Optional[int],
    page_size: Optional[int],
    cursor: Optional[str],
    limit: Optional[int],
) -> None:
    if (page or page_size) and (cursor or limit):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ApiError(error="Choose either page/page_size or cursor/limit", code=400).model_dump(),
        )
    if page and not page_size:
        raise HTTPException(status_code=400, detail=ApiError(error="page_size required", code=400).model_dump())
    if page_size and not page:
        raise HTTPException(status_code=400, detail=ApiError(error="page required", code=400).model_dump())


# ==========================
# ХЭНДЛЕРЫ
# ==========================

@router.post(
    "",
    response_model=TaskDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Создать задачу",
    responses={
        201: {"description": "Создано"},
        409: {"description": "Конфликт идемпотентности"},
    },
)
async def create_task(
    payload: TaskCreate,
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    idempotency_key: Annotated[Optional[str], Header(alias="Idempotency-Key")] = None,
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    """
    Создает задачу. При повторной отправке с тем же Idempotency-Key вернуть тот же результат.
    """
    try:
        dto = await service.create(
            data=payload,
            user_id=user.sub,
            idempotency_key=idempotency_key,
            request_id=request_id,
        )
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=ApiError(error=str(e), code=409).model_dump())
    except ForbiddenError as e:
        raise HTTPException(status_code=403, detail=ApiError(error=str(e), code=403).model_dump())

    set_common_headers(response, request_id=request_id, etag=dto.etag())
    return dto


@router.get(
    "/{task_id}",
    response_model=TaskDTO,
    summary="Получить задачу по идентификатору",
)
async def get_task(
    task_id: Annotated[UUID, Path()],
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
    if_none_match: Annotated[Optional[str], Header(alias="If-None-Match")] = None,
):
    """
    Возвращает задачу. Поддерживает условные GET по ETag (If-None-Match).
    """
    try:
        dto = await service.get(task_id, user_id=user.sub)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=ApiError(error="Task not found", code=404).model_dump())

    etag = dto.etag()
    if if_none_match and if_none_match == etag:
        # Ничего не изменилось
        response.status_code = status.HTTP_304_NOT_MODIFIED
        set_common_headers(response, request_id=request_id, etag=etag)
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)

    set_common_headers(response, request_id=request_id, etag=etag)
    return dto


@router.get(
    "",
    response_model=TaskListResponse,
    summary="Список задач (пагинация page или cursor)",
)
async def list_tasks(
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    # Фильтры
    status_eq: Annotated[Optional[TaskStatus], Query(alias="status")] = None,
    kind_eq: Annotated[Optional[TaskKind], Query(alias="kind")] = None,
    queue_eq: Annotated[Optional[str], Query(alias="queue", min_length=1, max_length=64)] = None,
    # Сортировка
    order_by: Annotated[str, Query()] = "created_at",
    order: Annotated[str, Query(pattern="^(asc|desc)$", description="asc|desc")] = "desc",
    # Page-пагинация
    page: Annotated[Optional[int], Query(ge=1)] = None,
    page_size: Annotated[Optional[int], Query(ge=1, le=1000)] = None,
    # Cursor-пагинация
    cursor: Annotated[Optional[str], Query()] = None,
    limit: Annotated[Optional[int], Query(ge=1, le=1000)] = None,
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    validate_pagination_mode(page, page_size, cursor, limit)

    if page and page_size:
        items, total = await service.list_page(
            user_id=user.sub,
            status=status_eq,
            kind=kind_eq,
            queue=queue_eq,
            page=page,
            page_size=page_size,
            order_by=order_by,
            order=order,
        )
        total_pages = (total + page_size - 1) // page_size if page_size else 0
        result = TaskListResponse(
            items=items,
            page=PageMeta(page=page, page_size=page_size, total_items=total, total_pages=total_pages),
            cursor=None,
        )
    else:
        items, next_cur = await service.list_cursor(
            user_id=user.sub,
            status=status_eq,
            kind=kind_eq,
            queue=queue_eq,
            cursor=cursor,
            limit=limit or 100,
            order_by=order_by,
            order=order,
        )
        result = TaskListResponse(items=items, page=None, cursor=CursorMeta(next_cursor=next_cur, has_more=bool(next_cur)))
        if next_cur:
            response.headers["X-Next-Cursor"] = next_cur

    set_common_headers(response, request_id=request_id, etag=None)
    return result


@router.patch(
    "/{task_id}",
    response_model=TaskDTO,
    summary="Частично обновить задачу (If-Match для оптимистической блокировки)",
    responses={412: {"description": "ETag mismatch"}})
async def patch_task(
    task_id: Annotated[UUID, Path()],
    patch: TaskUpdate,
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    try:
        dto = await service.update(task_id, user_id=user.sub, patch=patch, if_match=if_match)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=ApiError(error="Task not found", code=404).model_dump())
    except PreconditionFailed as e:
        raise HTTPException(status_code=412, detail=ApiError(error=str(e), code=412).model_dump())
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=ApiError(error=str(e), code=409).model_dump())
    except ForbiddenError as e:
        raise HTTPException(status_code=403, detail=ApiError(error=str(e), code=403).model_dump())

    set_common_headers(response, request_id=request_id, etag=dto.etag())
    return dto


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить задачу (soft по умолчанию, If-Match поддерживается)",
)
async def delete_task(
    task_id: Annotated[UUID, Path()],
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    soft: Annotated[bool, Query(description="Мягкое удаление (по умолчанию)", include_in_schema=True)] = True,
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    try:
        await service.delete(task_id, user_id=user.sub, if_match=if_match, soft=soft)
    except NotFoundError:
        # Идемпотентный DELETE: неуспех превращаем в 204
        response.status_code = status.HTTP_204_NO_CONTENT
        set_common_headers(response, request_id=request_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except PreconditionFailed as e:
        raise HTTPException(status_code=412, detail=ApiError(error=str(e), code=412).model_dump())
    except ForbiddenError as e:
        raise HTTPException(status_code=403, detail=ApiError(error=str(e), code=403).model_dump())

    set_common_headers(response, request_id=request_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{task_id}/cancel",
    response_model=TaskDTO,
    summary="Отменить выполнение задачи",
)
async def cancel_task(
    task_id: Annotated[UUID, Path()],
    response: Response,
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    try:
        dto = await service.cancel(task_id, user_id=user.sub, if_match=if_match)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=ApiError(error="Task not found", code=404).model_dump())
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=ApiError(error=str(e), code=409).model_dump())
    except PreconditionFailed as e:
        raise HTTPException(status_code=412, detail=ApiError(error=str(e), code=412).model_dump())
    except ForbiddenError as e:
        raise HTTPException(status_code=403, detail=ApiError(error=str(e), code=403).model_dump())

    set_common_headers(response, request_id=request_id, etag=dto.etag())
    return dto


@router.get(
    "/{task_id}/logs",
    summary="Стрим логов задачи (text/event-stream)",
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def stream_task_logs(
    task_id: Annotated[UUID, Path()],
    service: Annotated[TaskService, Depends(get_task_service)],
    user: Annotated[User, Depends(get_current_user)],
    request_id: Annotated[Optional[str], Header(alias="X-Request-Id")] = None,
):
    """
    Возвращает Server-Sent Events (SSE) поток строк логов.
    Каждая строка — уже сериализованная JSON-структура или текст.
    """
    try:
        iterator = await service.stream_logs(task_id, user_id=user.sub)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=ApiError(error="Task not found", code=404).model_dump())
    except ForbiddenError as e:
        raise HTTPException(status_code=403, detail=ApiError(error=str(e), code=403).model_dump())

    async def sse():
        # Простейший SSE-формат
        yield f"event: init\ndata: {json.dumps({'requestId': request_id})}\n\n"
        async for chunk in iterator:  # type: ignore[func-returns-value]
            # chunk может быть bytes или str; нормализуем
            if isinstance(chunk, bytes):
                data = chunk.decode("utf-8", errors="replace")
            else:
                data = str(chunk)
            yield f"data: {data}\n\n"

    return StreamingResponse(sse(), media_type="text/event-stream")
