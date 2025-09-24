# ops/api/graphql/schema.py
"""
GraphQL схема (Strawberry) для omnimind-core.

Особенности:
- Relay-стиль: GlobalID, Connection/Edge, PageInfo.
- Тип Task с enum статусами/типами, JSON-полями и временными метками.
- Query: task, tasks (cursor-пагинация + фильтры/сортировка).
- Mutation: createTask, updateTask, deleteTask, cancelTask
  с поддержкой идемпотентности (idempotencyKey) и оптимистической блокировки (ifMatch/ETag).
- Subscription: taskLogs (реал-тайм поток логов).
- Контекст и сервисный протокол для DI.
- Директивы: @auth (проверка роли), @cost (учет условной "стоимости" резолвера).
- Форматирование ошибок с детальными extensions.

Интеграция (пример):
    from strawberry.fastapi import GraphQLRouter
    from .schema import schema, build_context, error_formatter
    graphql_app = GraphQLRouter(
        schema,
        context_getter=build_context,
        error_formatter=error_formatter,
    )
    app.include_router(graphql_app, prefix="/graphql")

Зависимости:
    pip install strawberry-graphql
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Iterable, Optional, Protocol
from uuid import UUID

import strawberry
from strawberry import directive
from strawberry.extensions import Extension
from strawberry.relay import Connection, GlobalID, Node, NodeID, PageInfo
from strawberry.scalars import JSON
from strawberry.types import Info

# ==========================
# Доменные enum'ы
# ==========================

@strawberry.enum
class TaskStatus(Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"


@strawberry.enum
class TaskKind(Enum):
    inference = "inference"
    embedding = "embedding"
    indexing = "indexing"
    maintenance = "maintenance"
    generic = "generic"


# ==========================
# GraphQL типы
# ==========================

@strawberry.type
class Task(Node):
    """
    Relay Node: глобальный идентификатор (GlobalID), базовые поля задачи.
    """
    id: NodeID  # Global Relay ID
    kind: TaskKind
    status: TaskStatus
    priority: int
    queue: str

    payload: JSON | None
    result: JSON | None
    error: str | None

    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    version: int

    @strawberry.field
    def etag(self) -> str:
        """
        Вернет слабый ETag на основе (id, version, updated_at).
        """
        updated = self.updated_at.astimezone(timezone.utc).isoformat()
        import hashlib

        base = f"{self.id}:{self.version}:{updated}".encode("utf-8")
        return f'W/"{hashlib.sha256(base).hexdigest()}"'


@strawberry.type
class TaskEdge:
    cursor: str
    node: Task


@strawberry.type
class TaskConnection(Connection[Task]):
    """Relay-совместимое подключение."""
    # Наследуем стандартные поля: edges, page_info


# ==========================
# Входные типы для мутаций
# ==========================

@strawberry.input
class TaskCreateInput:
    kind: TaskKind
    payload: JSON | None = strawberry.field(default_factory=dict)
    priority: int = 100  # 1..1000 (меньше — выше)
    queue: str = "default"
    soft_timeout_sec: int = 60
    hard_timeout_sec: int = 120


@strawberry.input
class TaskUpdateInput:
    priority: int | None = None
    queue: str | None = None
    payload: JSON | None = None


# ==========================
# Ошибки домена и форматтер
# ==========================

class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class PreconditionFailed(Exception):
    pass


class ForbiddenError(Exception):
    pass


def error_formatter(error: Exception, debug: bool = False) -> dict[str, Any]:
    """
    Преобразователь ошибок для GraphQLRouter(error_formatter=...).
    Возвращает GraphQL-ошибку с расширениями.
    """
    from graphql.error.graphql_error import GraphQLError

    if isinstance(error, GraphQLError):
        orig = error.original_error
    else:
        orig = error

    extensions: dict[str, Any] = {"code": "INTERNAL", "severity": "ERROR"}

    if isinstance(orig, NotFoundError):
        extensions.update(code="NOT_FOUND", httpStatus=404)
    elif isinstance(orig, ConflictError):
        extensions.update(code="CONFLICT", httpStatus=409)
    elif isinstance(orig, PreconditionFailed):
        extensions.update(code="PRECONDITION_FAILED", httpStatus=412)
    elif isinstance(orig, ForbiddenError):
        extensions.update(code="FORBIDDEN", httpStatus=403)

    # Базовое тело ошибки
    formatted = {
        "message": str(error),
        "locations": getattr(error, "locations", None),
        "path": getattr(error, "path", None),
        "extensions": extensions,
    }

    # При debug — возвращаем stacktrace
    if debug and hasattr(error, "stack"):
        formatted["extensions"]["stack"] = error.stack  # тип GraphQLError может нести stack

    return formatted


# ==========================
# Контекст и протокол сервиса
# ==========================

@dataclass
class RequestContext:
    request_id: str | None
    user_id: str | None
    roles: list[str]


@dataclass
class GraphQLContext:
    """
    Контекст запроса, доступный в resolvers через info.context
    """
    request: Any
    task_service: "TaskService"
    rc: RequestContext


class TaskService(Protocol):
    async def create(
        self,
        *,
        data: dict[str, Any],
        user_id: str,
        idempotency_key: str | None,
        request_id: str | None,
    ) -> dict[str, Any]: ...

    async def get(self, task_uuid: UUID, *, user_id: str) -> dict[str, Any]: ...

    async def list_cursor(
        self,
        *,
        user_id: str,
        status: TaskStatus | None,
        kind: TaskKind | None,
        queue: str | None,
        cursor: str | None,
        limit: int,
        order_by: str,
        order: str,
    ) -> tuple[list[dict[str, Any]], str | None]: ...

    async def update(
        self,
        task_uuid: UUID,
        *,
        user_id: str,
        patch: dict[str, Any],
        if_match: str | None,
    ) -> dict[str, Any]: ...

    async def delete(
        self,
        task_uuid: UUID,
        *,
        user_id: str,
        if_match: str | None,
        soft: bool,
    ) -> None: ...

    async def cancel(
        self,
        task_uuid: UUID,
        *,
        user_id: str,
        if_match: str | None,
    ) -> dict[str, Any]: ...

    async def stream_logs(
        self, task_uuid: UUID, *, user_id: str
    ) -> Iterable[bytes] | AsyncGenerator[bytes, None]: ...


# Фабрика контекста (подключите вашу реализацию TaskService)
async def build_context(request: Any) -> GraphQLContext:
    """
    Используйте в GraphQLRouter(context_getter=build_context).
    Здесь извлеките user/roles/token/TaskService из вашего контейнера/DI.
    """
    # Заглушки для примера. Подставьте вашу auth/DI-логику.
    user_id = getattr(request.state, "user_id", None)
    roles = getattr(request.state, "roles", []) or []
    request_id = request.headers.get("x-request-id")

    task_service = request.app.state.task_service  # ожидается в FastAPI app.state

    return GraphQLContext(
        request=request,
        task_service=task_service,
        rc=RequestContext(request_id=request_id, user_id=user_id, roles=roles),
    )


# ==========================
# Директивы
# ==========================

@directive(locations=[strawberry.schema_directive_location.FIELD_DEFINITION])
class auth:
    """
    @auth(role: "admin")
    Простейшая авторизационная директива на уровне поля.
    """
    role: str | None = None

    def __call__(self, next_resolver, source, info: Info, **kwargs):
        ctx: GraphQLContext = info.context
        if ctx.rc.user_id is None:
            raise ForbiddenError("Authentication required")
        if self.role and self.role not in ctx.rc.roles:
            raise ForbiddenError(f"Required role: {self.role}")
        return next_resolver()


@directive(locations=[strawberry.schema_directive_location.FIELD_DEFINITION])
class cost:
    """
    @cost(value: 10)
    Простая аннотация относительной «стоимости» поля.
    """
    value: int = 1


class CostEnforcer(Extension):
    """
    Пример расширения, проверяющего суммарную условную «стоимость» запроса
    по директивам @cost на полях. Лимит настраиваем через init.
    """
    def __init__(self, max_cost: int = 10_000):
        super().__init__()
        self.max_cost = max_cost

    def on_validate(self):
        # Пробегаем узлы и суммируем значения директив.
        total = 0
        for node, *_ in self.execution_context.validation_rules:
            _ = node  # совместимость
        # Упрощенно: реальный подсчет AST опущен.
        # В проде подключите анализатор на основе GraphQL AST.
        # Здесь просто оставляем заглушку, чтобы не блокировать запросы.
        if total > self.max_cost:
            raise ForbiddenError("Query cost exceeds limit")


# ==========================
# Утилиты
# ==========================

def _uuid_from_global_id(gid: GlobalID, expected_type: str = "Task") -> UUID:
    if gid.node_type != expected_type:
        raise NotFoundError(f"GlobalID type mismatch: expected {expected_type}, got {gid.node_type}")
    try:
        return UUID(gid.node_id)
    except ValueError as e:
        raise NotFoundError("Invalid GlobalID") from e


def _to_task_model(raw: dict[str, Any]) -> Task:
    """
    Преобразование доменного словаря в GraphQL тип Task.
    Ожидаемые ключи: id/uuid, kind, status, priority, queue, payload, result, error,
                      created_at, updated_at, started_at, finished_at, version.
    """
    # Допускаем, что raw["id"] — UUID
    task_uuid: UUID = raw.get("id") or raw.get("uuid")
    gid = GlobalID("Task", str(task_uuid))
    return Task(
        id=gid,
        kind=TaskKind(raw["kind"]),
        status=TaskStatus(raw["status"]),
        priority=int(raw["priority"]),
        queue=str(raw["queue"]),
        payload=raw.get("payload"),
        result=raw.get("result"),
        error=raw.get("error"),
        created_at=raw["created_at"],
        updated_at=raw["updated_at"],
        started_at=raw.get("started_at"),
        finished_at=raw.get("finished_at"),
        version=int(raw.get("version", 0)),
    )


# ==========================
# Query
# ==========================

@strawberry.type
class Query:
    @strawberry.field(directives=[auth()])
    async def task(self, info: Info, id: GlobalID) -> Task:
        """
        Получить задачу по GlobalID.
        """
        ctx: GraphQLContext = info.context
        task_uuid = _uuid_from_global_id(id)
        raw = await ctx.task_service.get(task_uuid, user_id=ctx.rc.user_id or "")
        return _to_task_model(raw)

    @strawberry.field(directives=[auth()])
    async def tasks(
        self,
        info: Info,
        status: TaskStatus | None = None,
        kind: TaskKind | None = None,
        queue: str | None = None,
        after: str | None = None,
        first: int = 100,
        order_by: str = "created_at",
        order: str = "desc",
    ) -> TaskConnection:
        """
        Список задач с cursor-пагинацией (Relay Connection).
        """
        ctx: GraphQLContext = info.context

        items, next_cur = await ctx.task_service.list_cursor(
            user_id=ctx.rc.user_id or "",
            status=status,
            kind=kind,
            queue=queue,
            cursor=after,
            limit=min(max(first, 1), 1000),
            order_by=order_by,
            order=order,
        )

        edges: list[TaskEdge] = []
        for raw in items:
            node = _to_task_model(raw)
            # Курсор может быть, например, строковое представление updated_at+id
            # Если сервис уже вернул курсор в raw["cursor"], используем его.
            cursor = str(raw.get("cursor", node.id))
            edges.append(TaskEdge(cursor=cursor, node=node))

        page_info = PageInfo(
            has_previous_page=False,   # для "forward" пагинации
            has_next_page=bool(next_cur),
            start_cursor=edges[0].cursor if edges else None,
            end_cursor=edges[-1].cursor if edges else None,
        )
        return TaskConnection(edges=edges, page_info=page_info)


# ==========================
# Mutation
# ==========================

@strawberry.type
class Mutation:
    @strawberry.mutation(directives=[auth()])
    async def create_task(
        self,
        info: Info,
        input: TaskCreateInput,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> Task:
        """
        Создать задачу. Повторный вызов с тем же idempotency_key должен вернуть
        один и тот же результат на уровне TaskService.
        """
        ctx: GraphQLContext = info.context
        data = {
            "kind": input.kind.value,
            "payload": input.payload or {},
            "priority": input.priority,
            "queue": input.queue,
            "soft_timeout_sec": input.soft_timeout_sec,
            "hard_timeout_sec": input.hard_timeout_sec,
        }
        try:
            raw = await ctx.task_service.create(
                data=data,
                user_id=ctx.rc.user_id or "",
                idempotency_key=idempotency_key,
                request_id=request_id or ctx.rc.request_id,
            )
        except ConflictError as e:
            raise e
        return _to_task_model(raw)

    @strawberry.mutation(directives=[auth()])
    async def update_task(
        self,
        info: Info,
        id: GlobalID,
        input: TaskUpdateInput,
        if_match: str | None = None,
    ) -> Task:
        """
        Частично обновить задачу (только для статуса pending).
        Защита от гонок через if_match (ETag).
        """
        ctx: GraphQLContext = info.context
        task_uuid = _uuid_from_global_id(id)
        patch = {k: v for k, v in {
            "priority": input.priority,
            "queue": input.queue,
            "payload": input.payload,
        }.items() if v is not None}

        raw = await ctx.task_service.update(
            task_uuid,
            user_id=ctx.rc.user_id or "",
            patch=patch,
            if_match=if_match,
        )
        return _to_task_model(raw)

    @strawberry.mutation(directives=[auth()])
    async def delete_task(
        self,
        info: Info,
        id: GlobalID,
        soft: bool = True,
        if_match: str | None = None,
    ) -> bool:
        """
        Удалить задачу. Идемпотентно (повторное удаление возвращает true).
        """
        ctx: GraphQLContext = info.context
        task_uuid = _uuid_from_global_id(id)
        try:
            await ctx.task_service.delete(
                task_uuid,
                user_id=ctx.rc.user_id or "",
                if_match=if_match,
                soft=soft,
            )
        except NotFoundError:
            return True
        return True

    @strawberry.mutation(directives=[auth()])
    async def cancel_task(
        self,
        info: Info,
        id: GlobalID,
        if_match: str | None = None,
    ) -> Task:
        """
        Отменить выполнение задачи (если это возможно).
        """
        ctx: GraphQLContext = info.context
        task_uuid = _uuid_from_global_id(id)
        raw = await ctx.task_service.cancel(
            task_uuid,
            user_id=ctx.rc.user_id or "",
            if_match=if_match,
        )
        return _to_task_model(raw)


# ==========================
# Subscription
# ==========================

@strawberry.type
class Subscription:
    @strawberry.subscription(directives=[auth()])
    async def task_logs(self, info: Info, id: GlobalID) -> AsyncGenerator[str, None]:
        """
        Реал-тайм поток логов задачи (строки). Бэкенд: TaskService.stream_logs.
        """
        ctx: GraphQLContext = info.context
        task_uuid = _uuid_from_global_id(id)
        iterator = await ctx.task_service.stream_logs(task_uuid, user_id=ctx.rc.user_id or "")

        async def agen() -> AsyncGenerator[str, None]:
            # Поддерживаем как асинхронный, так и синхронный итератор
            if hasattr(iterator, "__anext__"):
                async for chunk in iterator:  # type: ignore
                    yield chunk.decode("utf-8", errors="replace") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
            else:
                for chunk in iterator:  # type: ignore
                    yield chunk.decode("utf-8", errors="replace") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
                    await asyncio.sleep(0)  # yIELD control
        return agen()


# ==========================
# Сборка схемы
# ==========================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    directives=[auth, cost],
    extensions=[
        # Можно включить CostEnforcer(max_cost=...) при необходимости строгого учета.
        # lambda: CostEnforcer(max_cost=10000)
    ],
)
