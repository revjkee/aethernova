# datafabric-core/api/graphql/schema.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import enum
import json
import math
import typing as t
import uuid

import strawberry
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig
from strawberry.permission import BasePermission
from strawberry.directive import DirectiveLocation
from strawberry.schema_directive import schema_directive
from strawberry.subscriptions import GRAPHQL_TRANSPORT_WS_PROTOCOL, GRAPHQL_WS_PROTOCOL
from strawberry.tools import create_type
from strawberry.dataloader import DataLoader

# ============================================================
# СКАЛЯРЫ
# ============================================================

@strawberry.scalar(description="RFC3339/ISO8601 datetime with timezone")
def DateTime(value: t.Union[str, dt.datetime]) -> dt.datetime:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except Exception:
        raise ValueError("Invalid DateTime format")

@strawberry.scalar(description="UUID v4")
def UUID(value: t.Union[str, uuid.UUID]) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        u = uuid.UUID(str(value))
        return u
    except Exception:
        raise ValueError("Invalid UUID")

@strawberry.scalar(description="Arbitrary JSON object")
def JSON(value: t.Any) -> t.Any:
    # strawberry уже сериализует dict/list, валидация минимальная
    try:
        json.dumps(value)
        return value
    except Exception:
        raise ValueError("Invalid JSON")

# ============================================================
# RBAC / ПРАВА ДОСТУПА
# ============================================================

class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    MAINTAINER = "MAINTAINER"
    USER = "USER"
    VIEWER = "VIEWER"

class RequireRoles(BasePermission):
    message = "Forbidden"

    def __init__(self, *roles: Role):
        self.roles = set(roles)

    def has_permission(self, source: t.Any, info: Info, **kwargs) -> bool:
        user = getattr(info.context, "user", None)
        if not user or not getattr(user, "roles", None):
            return False
        user_roles = set(Role(r) for r in user.roles)
        return not self.roles or bool(self.roles & user_roles)

# ============================================================
# УТИЛИТЫ NODE/RELAY
# ============================================================

def to_global_id(type_name: str, id_value: t.Union[str, uuid.UUID]) -> str:
    raw = f"{type_name}:{id_value}"
    return base64.urlsafe_b64encode(raw.encode()).decode()

def from_global_id(global_id: str) -> t.Tuple[str, str]:
    raw = base64.urlsafe_b64decode(global_id.encode()).decode()
    type_name, id_value = raw.split(":", 1)
    return type_name, id_value

@strawberry.interface(description="Relay Node interface")
class Node:
    id: strawberry.ID

# Relay-пагинация (Connection/Edge + PageInfo)
@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    start_cursor: t.Optional[str]
    end_cursor: t.Optional[str]

TNode = t.TypeVar("TNode")

@strawberry.type
class Edge(t.Generic[TNode]):
    cursor: str
    node: TNode

@strawberry.type
class Connection(t.Generic[TNode]):
    page_info: PageInfo
    edges: list[Edge[TNode]]
    total_count: int

# ============================================================
# КОНТЕКСТ / РЕПОЗИТОРИИ / ЗАГРУЗЧИКИ
# ============================================================

class UserCtx(t.TypedDict, total=False):
    id: str
    email: str
    roles: list[str]

class Settings(t.TypedDict, total=False):
    max_query_depth: int
    max_query_complexity: int

class DatasetRecord(t.TypedDict, total=False):
    id: str
    name: str
    description: t.Optional[str]
    created_at: str
    updated_at: str
    owner_id: str
    tags: list[str]
    metadata: t.Dict[str, t.Any]

class AssetRecord(t.TypedDict, total=False):
    id: str
    dataset_id: str
    uri: str
    checksum: str
    size_bytes: int
    created_at: str
    attributes: t.Dict[str, t.Any]

class AuditRecord(t.TypedDict, total=False):
    id: str
    actor_id: str
    action: str
    entity_type: str
    entity_id: str
    ts: str
    diff: t.Dict[str, t.Any]

# Протоколы репозиториев (интерфейсы)
class DatasetsRepo(t.Protocol):
    async def get_by_id(self, dataset_id: str) -> t.Optional[DatasetRecord]: ...
    async def list(
        self,
        *,
        search: t.Optional[str],
        tag_in: t.Optional[list[str]],
        owner_id: t.Optional[str],
        offset: int,
        limit: int,
        sort: t.Optional[str],
    ) -> tuple[list[DatasetRecord], int]: ...
    async def create(self, data: dict, actor_id: str) -> DatasetRecord: ...
    async def update(self, dataset_id: str, patch: dict, actor_id: str) -> DatasetRecord: ...
    async def delete(self, dataset_id: str, actor_id: str) -> bool: ...

class AssetsRepo(t.Protocol):
    async def batch_by_ids(self, ids: list[str]) -> list[AssetRecord]: ...
    async def list_by_dataset(
        self, dataset_id: str, offset: int, limit: int, sort: t.Optional[str]
    ) -> tuple[list[AssetRecord], int]: ...
    async def create(self, dataset_id: str, data: dict, actor_id: str) -> AssetRecord: ...

class AuditRepo(t.Protocol):
    async def list_for_entity(self, entity_type: str, entity_id: str, limit: int = 50) -> list[AuditRecord]: ...

class Context(t.Protocol):
    request: t.Any
    user: UserCtx
    settings: Settings
    datasets: DatasetsRepo
    assets: AssetsRepo
    audit: AuditRepo
    loaders: "Loaders"

class Loaders:
    def __init__(self, assets_repo: AssetsRepo):
        self.asset_by_id = DataLoader(self._batch_asset_by_id)
        self._assets_repo = assets_repo

    async def _batch_asset_by_id(self, keys: list[str]) -> list[t.Optional[AssetRecord]]:
        # Сохраняем порядок выдачи
        records = await self._assets_repo.batch_by_ids(keys)
        index = {r["id"]: r for r in records}
        return [index.get(k) for k in keys]

# ============================================================
# ДИРЕКТИВЫ / ОГРАНИЧЕНИЯ
# ============================================================

@schema_directive(locations=[DirectiveLocation.FIELD_DEFINITION])
class deprecated_reason:
    reason: str = strawberry.directive_field(default="Deprecated")

# ============================================================
# ДОМЕННЫЕ ТИПЫ
# ============================================================

@strawberry.type
class AuditEvent:
    id: strawberry.ID
    actor_id: UUID
    action: str
    entity_type: str
    entity_id: UUID
    ts: DateTime
    diff: JSON

    @staticmethod
    def from_record(r: AuditRecord) -> "AuditEvent":
        return AuditEvent(
            id=strawberry.ID(to_global_id("AuditEvent", r["id"])),
            actor_id=uuid.UUID(r["actor_id"]),
            action=r["action"],
            entity_type=r["entity_type"],
            entity_id=uuid.UUID(r["entity_id"]),
            ts=DateTime(r["ts"]),
            diff=r.get("diff", {}),
        )

@strawberry.type
class UserProfile(Node):
    id: strawberry.ID
    email: str
    roles: list[Role]

@strawberry.type
class Asset(Node):
    id: strawberry.ID
    dataset_id: UUID
    uri: str
    checksum: str
    size_bytes: int
    created_at: DateTime
    attributes: JSON

    @staticmethod
    def from_record(r: AssetRecord) -> "Asset":
        return Asset(
            id=strawberry.ID(to_global_id("Asset", r["id"])),
            dataset_id=uuid.UUID(r["dataset_id"]),
            uri=r["uri"],
            checksum=r["checksum"],
            size_bytes=int(r["size_bytes"]),
            created_at=DateTime(r["created_at"]),
            attributes=r.get("attributes", {}),
        )

@strawberry.type
class Dataset(Node):
    id: strawberry.ID
    name: str
    description: t.Optional[str]
    created_at: DateTime
    updated_at: DateTime
    owner_id: UUID
    tags: list[str]
    metadata: JSON

    # Отложенная загрузка активов
    @strawberry.field(permission_classes=[RequireRoles(Role.USER, Role.ADMIN, Role.MAINTAINER, Role.VIEWER)])
    async def assets(
        self,
        info: Info,
        first: int = 20,
        after: t.Optional[str] = None,
        sort: t.Optional[str] = "created_at:desc",
    ) -> Connection[Asset]:
        ctx: Context = info.context
        _, raw_id = from_global_id(self.id)
        offset = 0
        if after:
            try:
                offset = int(base64.b64decode(after).decode())
            except Exception:
                offset = 0
        first = max(1, min(first, 200))
        items, total = await ctx.assets.list_by_dataset(dataset_id=raw_id, offset=offset, limit=first, sort=sort)
        edges: list[Edge[Asset]] = []
        for idx, rec in enumerate(items, start=offset):
            edges.append(Edge(cursor=base64.b64encode(str(idx + 1).encode()).decode(), node=Asset.from_record(rec)))
        has_next = (offset + first) < total
        page_info = PageInfo(
            has_next_page=has_next,
            has_previous_page=offset > 0,
            start_cursor=edges[0].cursor if edges else None,
            end_cursor=edges[-1].cursor if edges else None,
        )
        return Connection(page_info=page_info, edges=edges, total_count=total)

    @staticmethod
    def from_record(r: DatasetRecord) -> "Dataset":
        return Dataset(
            id=strawberry.ID(to_global_id("Dataset", r["id"])),
            name=r["name"],
            description=r.get("description"),
            created_at=DateTime(r["created_at"]),
            updated_at=DateTime(r["updated_at"]),
            owner_id=uuid.UUID(r["owner_id"]),
            tags=r.get("tags", []),
            metadata=r.get("metadata", {}),
        )

# ============================================================
# ФИЛЬТРЫ / СОРТИРОВКИ / INPUTS
# ============================================================

@strawberry.input
class DatasetFilter:
    search: t.Optional[str] = None
    tag_in: t.Optional[list[str]] = None
    owner_id: t.Optional[UUID] = None

@strawberry.enum
class DatasetSort(str, enum.Enum):
    CREATED_AT_ASC = "created_at:asc"
    CREATED_AT_DESC = "created_at:desc"
    UPDATED_AT_ASC = "updated_at:asc"
    UPDATED_AT_DESC = "updated_at:desc"
    NAME_ASC = "name:asc"
    NAME_DESC = "name:desc"

@strawberry.input
class CreateDatasetInput:
    name: str
    description: t.Optional[str] = None
    tags: list[str] = dataclasses.field(default_factory=list)
    metadata: JSON = dataclasses.field(default_factory=dict)

@strawberry.input
class UpdateDatasetInput:
    id: strawberry.ID
    name: t.Optional[str] = None
    description: t.Optional[str] = None
    tags: t.Optional[list[str]] = None
    metadata: t.Optional[JSON] = None

@strawberry.type
class MutationResult:
    ok: bool
    error: t.Optional[str] = None

# ============================================================
# ОШИБКИ ДОМЕНА
# ============================================================

class NotFoundError(Exception): ...
class ConflictError(Exception): ...
class ForbiddenError(Exception): ...

# Глобальный перехват ошибок через расширение
class ErrorMaskingExtension(strawberry.extensions.Extension):
    def on_request_end(self):
        # Можно репортить ошибки в observability
        pass

    def on_execution_error(self, error: Exception):
        # Маскируем внутренние ошибки
        if isinstance(error, (NotFoundError, ConflictError, ForbiddenError, ValueError)):
            return error
        return ValueError("Internal error")

# Ограничители глубины/сложности
class MaxDepthExtension(strawberry.extensions.Extension):
    def __init__(self, max_depth: int = 10) -> None:
        super().__init__()
        self.max_depth = max_depth

    def on_validate(self):
        document = self.execution_context.graphql_document
        # Простая оценка глубины запроса
        def node_depth(node, depth=0):
            from graphql.language.ast import FieldNode, InlineFragmentNode, FragmentSpreadNode, OperationDefinitionNode

            if isinstance(node, OperationDefinitionNode):
                maxd = 0
                for s in node.selection_set.selections:
                    maxd = max(maxd, node_depth(s, 1))
                return maxd
            if isinstance(node, (FieldNode, InlineFragmentNode, FragmentSpreadNode)):
                if not getattr(node, "selection_set", None) or not node.selection_set:
                    return depth
                return max(node_depth(s, depth + 1) for s in node.selection_set.selections)
            return depth

        depths = [node_depth(defn) for defn in document.definitions]
        if any(d > self.max_depth for d in depths):
            raise ValueError(f"Query depth exceeds limit {self.max_depth}")

class ComplexityExtension(strawberry.extensions.Extension):
    def __init__(self, max_complexity: int = 5000) -> None:
        super().__init__()
        self.max_complexity = max_complexity

    def on_validate(self):
        # Упрощенная оценка сложности: поля * коэффициент
        document = self.execution_context.graphql_document
        count = 0

        def walk(node):
            nonlocal count
            selection_set = getattr(node, "selection_set", None)
            if selection_set and selection_set.selections:
                for s in selection_set.selections:
                    count += 1
                    walk(s)

        for d in document.definitions:
            walk(d)
        if count > self.max_complexity:
            raise ValueError(f"Query complexity exceeds limit {self.max_complexity}")

# ============================================================
# ЗАПРОСЫ
# ============================================================

@strawberry.type
class Query:

    @strawberry.field(permission_classes=[RequireRoles(Role.USER, Role.ADMIN, Role.MAINTAINER, Role.VIEWER)])
    async def me(self, info: Info) -> UserProfile:
        ctx: Context = info.context
        u = ctx.user
        return UserProfile(
            id=strawberry.ID(to_global_id("UserProfile", u["id"])),
            email=u["email"],
            roles=[Role(r) for r in u.get("roles", [])],
        )

    @strawberry.field(permission_classes=[RequireRoles(Role.USER, Role.VIEWER, Role.MAINTAINER, Role.ADMIN)])
    async def dataset(self, info: Info, id: strawberry.ID) -> t.Optional[Dataset]:
        ctx: Context = info.context
        _, raw_id = from_global_id(id)
        rec = await ctx.datasets.get_by_id(raw_id)
        if not rec:
            return None
        return Dataset.from_record(rec)

    @strawberry.field(permission_classes=[RequireRoles(Role.USER, Role.VIEWER, Role.MAINTAINER, Role.ADMIN)])
    async def datasets(
        self,
        info: Info,
        first: int = 20,
        after: t.Optional[str] = None,
        filter: t.Optional[DatasetFilter] = None,
        sort: t.Optional[DatasetSort] = DatasetSort.UPDATED_AT_DESC,
    ) -> Connection[Dataset]:
        ctx: Context = info.context
        offset = 0
        if after:
            try:
                offset = int(base64.b64decode(after).decode())
            except Exception:
                offset = 0
        first = max(1, min(first, 200))
        flt = filter or DatasetFilter()
        items, total = await ctx.datasets.list(
            search=flt.search,
            tag_in=flt.tag_in,
            owner_id=str(flt.owner_id) if flt.owner_id else None,
            offset=offset,
            limit=first,
            sort=sort.value if sort else None,
        )
        edges: list[Edge[Dataset]] = []
        for idx, rec in enumerate(items, start=offset):
            edges.append(Edge(cursor=base64.b64encode(str(idx + 1).encode()).decode(), node=Dataset.from_record(rec)))
        page_info = PageInfo(
            has_next_page=(offset + first) < total,
            has_previous_page=offset > 0,
            start_cursor=edges[0].cursor if edges else None,
            end_cursor=edges[-1].cursor if edges else None,
        )
        return Connection(page_info=page_info, edges=edges, total_count=total)

    @strawberry.field(permission_classes=[RequireRoles(Role.USER, Role.VIEWER, Role.MAINTAINER, Role.ADMIN)])
    async def audit_trail(
        self, info: Info, entity_type: str, entity_id: strawberry.ID, limit: int = 50
    ) -> list[AuditEvent]:
        ctx: Context = info.context
        _, raw_id = from_global_id(entity_id)
        recs = await ctx.audit.list_for_entity(entity_type=entity_type, entity_id=raw_id, limit=max(1, min(limit, 200)))
        return [AuditEvent.from_record(r) for r in recs]

# ============================================================
# МУТАЦИИ
# ============================================================

@strawberry.type
class Mutation:

    @strawberry.mutation(permission_classes=[RequireRoles(Role.ADMIN, Role.MAINTAINER, Role.USER)])
    async def create_dataset(self, info: Info, input: CreateDatasetInput) -> Dataset:
        ctx: Context = info.context
        actor_id = ctx.user["id"]
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        data = {
            "name": input.name,
            "description": input.description,
            "owner_id": actor_id,
            "tags": input.tags or [],
            "metadata": input.metadata or {},
            "created_at": now,
            "updated_at": now,
        }
        rec = await ctx.datasets.create(data, actor_id=actor_id)
        return Dataset.from_record(rec)

    @strawberry.mutation(permission_classes=[RequireRoles(Role.ADMIN, Role.MAINTAINER)])
    async def update_dataset(self, info: Info, input: UpdateDatasetInput) -> Dataset:
        ctx: Context = info.context
        _, raw_id = from_global_id(input.id)
        patch: dict[str, t.Any] = {}
        if input.name is not None:
            patch["name"] = input.name
        if input.description is not None:
            patch["description"] = input.description
        if input.tags is not None:
            patch["tags"] = input.tags
        if input.metadata is not None:
            patch["metadata"] = input.metadata
        patch["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        rec = await ctx.datasets.update(raw_id, patch, actor_id=ctx.user["id"])
        return Dataset.from_record(rec)

    @strawberry.mutation(permission_classes=[RequireRoles(Role.ADMIN)])
    async def delete_dataset(self, info: Info, id: strawberry.ID) -> MutationResult:
        ctx: Context = info.context
        _, raw_id = from_global_id(id)
        ok = await ctx.datasets.delete(raw_id, actor_id=ctx.user["id"])
        return MutationResult(ok=bool(ok), error=None if ok else "Delete failed")

    @strawberry.mutation(permission_classes=[RequireRoles(Role.ADMIN, Role.MAINTAINER, Role.USER)])
    async def add_asset(
        self,
        info: Info,
        dataset_id: strawberry.ID,
        uri: str,
        checksum: str,
        size_bytes: int,
        attributes: t.Optional[JSON] = None,
    ) -> Asset:
        ctx: Context = info.context
        _, raw_ds_id = from_global_id(dataset_id)
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        data = {
            "uri": uri,
            "checksum": checksum,
            "size_bytes": int(size_bytes),
            "attributes": attributes or {},
            "dataset_id": raw_ds_id,
            "created_at": now,
        }
        rec = await ctx.assets.create(dataset_id=raw_ds_id, data=data, actor_id=ctx.user["id"])
        return Asset.from_record(rec)

# ============================================================
# ПОДПИСКИ
# ============================================================

@strawberry.type
class Subscription:

    @strawberry.subscription(permission_classes=[RequireRoles(Role.USER, Role.MAINTAINER, Role.ADMIN)])
    async def system_tick(self, info: Info, interval_ms: int = 1000) -> DateTime:
        # heartbeat для клиентов/мониторинга
        interval_ms = max(100, min(interval_ms, 10_000))
        while True:
            await asyncio.sleep(interval_ms / 1000)
            yield dt.datetime.now(dt.timezone.utc)

# ============================================================
# СБОРКА СХЕМЫ
# ============================================================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
    extensions=[
        lambda: ErrorMaskingExtension(),
        lambda: MaxDepthExtension(max_depth=12),
        lambda: ComplexityExtension(max_complexity=4000),
    ],
    directives=[deprecated_reason],
)

# ============================================================
# ПРИМЕЧАНИЯ ПО ИНТЕГРАЦИИ (важно сохранить в файле)
# ============================================================
"""
Интеграция с FastAPI:

from fastapi import FastAPI, Request
from strawberry.fastapi import GraphQLRouter

# Предполагается реализация репозиториев (асинхронных) где-то в datafabric_core.repositories
from datafabric_core.repositories import datasets_repo, assets_repo, audit_repo

def build_context(request: Request):
    # user и settings берём из auth-мидлвари / конфигов
    user = getattr(request.state, "user", {"id": "00000000-0000-0000-0000-000000000000", "email": "anonymous@local", "roles": ["VIEWER"]})
    settings = {"max_query_depth": 12, "max_query_complexity": 4000}
    loaders = Loaders(assets_repo=assets_repo)
    return {"request": request, "user": user, "settings": settings, "datasets": datasets_repo, "assets": assets_repo, "audit": audit_repo, "loaders": loaders}

graphql_app = GraphQLRouter(
    schema,
    context_getter=build_context,
    subscriptions_protocols=[GRAPHQL_TRANSPORT_WS_PROTOCOL, GRAPHQL_WS_PROTOCOL],
)

app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")

Безопасность:
- Применить мидлварь аутентификации, которая заполняет request.state.user
- Защитить эндпоинт с помощью reverse proxy (CORS, rate limit)
- Настроить ограничения размера запроса и таймауты uvicorn

Тестирование:
- Создать фикстуры async репозиториев (pytest-asyncio)
- Мокаутить контекст и проверять RBAC, пагинацию, ноды/ID

"""
