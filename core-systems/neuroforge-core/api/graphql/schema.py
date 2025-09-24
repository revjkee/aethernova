# -*- coding: utf-8 -*-
"""
GraphQL schema (Strawberry) for neuroforge-core
Unverified: зависимости/интеграции к внешним сервисам являются шаблоном. I cannot verify this.

Зависимости (пример):
    pip install "strawberry-graphql[fastapi]" prometheus-client opentelemetry-api

Примечение:
- Использует Strawberry, Relay-совместимую модель и асинхронные DataLoader'ы.
- Предусмотрены расширения: маскирование ошибок, лимит глубины/стоимости, простая трассировка.
- Авторизация: проверка scope и вызов OPA (заглушка), row-level делегируется бекендам.

Как подключить к FastAPI:
    from strawberry.fastapi import GraphQLRouter
    from neuroforge_core.api.graphql.schema import schema, build_context

    graphql_app = GraphQLRouter(schema, context_getter=build_context)
    app.include_router(graphql_app, prefix="/api/graphql")
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
import math
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Callable, Dict, Iterable, List, Optional, Tuple

import strawberry
from strawberry.relay import Node, Connection, Edge, GlobalID
from strawberry import relay
from strawberry.types import Info
from strawberry.extensions import Extension
from strawberry.schema.config import StrawberryConfig

logger = logging.getLogger(__name__)

# =============================================================================
# Контекст выполнения и утилиты авторизации
# =============================================================================

@dataclass(slots=True)
class Principal:
    id: str
    scopes: List[str]
    tenant_id: Optional[str] = None

@dataclass(slots=True)
class Services:
    # Заглушки; замените на реальные клиенты (БД/GRPC/HTTP)
    dataset_svc: Any
    model_svc: Any
    event_bus: Any

@dataclass(slots=True)
class Context:
    principal: Principal
    services: Services
    request_id: str
    opa_client: Optional[Any] = None
    # прометей/метрики/трейсер могут прокидываться тут же

# Фабрика контекста (для FastAPI/Starlette)
async def build_context() -> Context:  # type: ignore[override]
    # В реальном коде извлеките из запросов user/scopes/tenant и провайдьте клиентов
    principal = Principal(id="anonymous", scopes=["public:read"])
    services = Services(dataset_svc=_DatasetService(), model_svc=_ModelService(), event_bus=_EventBus())
    return Context(principal=principal, services=services, request_id="req-unknown")

# Декоратор проверки scope
def require_scope(required: str):
    def deco(fn: Callable):
        async def wrapper(*args, **kwargs):
            info: Info = kwargs.get("info") or args[-1]
            ctx: Context = info.context
            if required not in (ctx.principal.scopes or []):
                raise ForbiddenError(f"missing scope: {required}")
            return await fn(*args, **kwargs)
        return wrapper
    return deco

# OPA-авторизация (заглушка). Возвращает True/False.
async def opa_allow(ctx: Context, package: str, rule: str, input_obj: dict) -> bool:
    if ctx.opa_client is None:
        return True  # fail-open по умолчанию
    try:
        return await ctx.opa_client.evaluate(package=package, rule=rule, input=input_obj)
    except Exception as e:
        logger.warning("OPA evaluation failed: %s", e)
        return True

# =============================================================================
# Ошибки и маскирование
# =============================================================================

class UserVisibleError(Exception):
    pass

class ForbiddenError(UserVisibleError):
    pass

class NotFoundError(UserVisibleError):
    pass

class ValidationError(UserVisibleError):
    pass

def mask_error(err: Exception) -> str:
    if isinstance(err, UserVisibleError):
        return str(err)
    return "Internal server error"

# =============================================================================
# DataLoader (асинхронные)
# =============================================================================

class DataLoader:
    """Минимальный батчер/кешер для асинхронных загрузок."""
    def __init__(self, batch_load_fn: Callable[[List[Any]], Any], ttl_s: float = 0.5) -> None:
        self._fn = batch_load_fn
        self._queue: List[Tuple[Any, asyncio.Future]] = []
        self._scheduled = False
        self._cache: Dict[Any, Tuple[float, Any]] = {}
        self._ttl = ttl_s

    async def load(self, key: Any) -> Any:
        # cache short-lived
        now = monotonic()
        cached = self._cache.get(key)
        if cached and now - cached[0] <= self._ttl:
            return cached[1]
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._queue.append((key, fut))
        if not self._scheduled:
            self._scheduled = True
            asyncio.get_running_loop().call_soon(asyncio.create_task, self._dispatch())
        return await fut

    async def _dispatch(self) -> None:
        await asyncio.sleep(0)  # собрать очередь
        items = self._queue
        self._queue = []
        self._scheduled = False
        keys = [k for k, _ in items]
        try:
            results = await self._fn(keys)
            result_map = {r["id"]: r for r in results}
            now = monotonic()
            for k, fut in items:
                val = result_map.get(k)
                if val is None:
                    fut.set_exception(NotFoundError(f"not found: {k}"))
                else:
                    self._cache[k] = (now, val)
                    fut.set_result(val)
        except Exception as e:
            for _, fut in items:
                fut.set_exception(e)

def monotonic() -> float:
    return asyncio.get_running_loop().time()

# =============================================================================
# Графовые типы/Enum/Scalar
# =============================================================================

@strawberry.enum
class WriteMode:
    APPEND = "append"
    UPSERT = "upsert"
    OVERWRITE = "overwrite"

@strawberry.enum
class ModelStage:
    DEVELOP = "develop"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"

@strawberry.type
class BuildInfo:
    service: str
    version: str
    revision: str

# Relay Node базовый
@strawberry.interface
class GQLNode(Node):
    @classmethod
    def resolve_node(cls, node_id: str, info: Info) -> Optional["GQLNode"]:
        # Глобальные ID: <typename>:<id_hex>
        try:
            typename, raw_id = node_id.split(":", 1)
        except Exception:
            return None
        if typename == "Dataset":
            return DatasetType.from_backend(raw_id, info)
        if typename == "Model":
            return ModelType.from_backend(raw_id, info)
        if typename == "ModelVersion":
            return ModelVersionType.from_backend(raw_id, info)
        return None

# ---------------- Dataset ----------------

@strawberry.type
class DatasetType(GQLNode):
    id: relay.GlobalID
    dataset_id: strawberry.ID
    title: str
    domain: str
    owner: str
    primary_key: List[str]
    write_mode: WriteMode
    created_at: dt.datetime
    updated_at: dt.datetime

    @classmethod
    def from_backend(cls, raw_id: str, info: Info) -> Optional["DatasetType"]:
        # Загрузка по одиночному ключу через сервис
        svc = info.context.services.dataset_svc
        data = svc._mem.get(raw_id)  # типовой mock; замените вызовом в БД
        if not data:
            return None
        return cls(
            id=relay.to_base64("Dataset", raw_id),
            dataset_id=strawberry.ID(raw_id),
            title=data["title"],
            domain=data["domain"],
            owner=data["owner"],
            primary_key=data["primary_key"],
            write_mode=WriteMode(data["write_mode"]),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

# ---------------- Model / ModelVersion ----------------

@strawberry.type
class ModelType(GQLNode):
    id: relay.GlobalID
    model_id: strawberry.ID
    name: str
    owner: str
    created_at: dt.datetime
    updated_at: dt.datetime

    @classmethod
    def from_backend(cls, raw_id: str, info: Info) -> Optional["ModelType"]:
        svc = info.context.services.model_svc
        data = svc._mem_models.get(raw_id)
        if not data:
            return None
        return cls(
            id=relay.to_base64("Model", raw_id),
            model_id=strawberry.ID(raw_id),
            name=data["name"],
            owner=data["owner"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

@strawberry.type
class ModelVersionType(GQLNode):
    id: relay.GlobalID
    version_id: strawberry.ID
    model: ModelType
    version: int
    stage: ModelStage
    created_at: dt.datetime

    @classmethod
    def from_backend(cls, raw_id: str, info: Info) -> Optional["ModelVersionType"]:
        svc = info.context.services.model_svc
        data = svc._mem_versions.get(raw_id)
        if not data:
            return None
        model = ModelType.from_backend(data["model_id"], info)
        return cls(
            id=relay.to_base64("ModelVersion", raw_id),
            version_id=strawberry.ID(raw_id),
            model=model,
            version=data["version"],
            stage=ModelStage(data["stage"]),
            created_at=data["created_at"],
        )

# =============================================================================
# Входные типы
# =============================================================================

@strawberry.input
class UpsertDatasetInput:
    dataset_id: strawberry.ID
    title: str
    domain: str
    owner: str
    primary_key: List[str]
    write_mode: WriteMode

@strawberry.type
class UpsertDatasetPayload:
    dataset: DatasetType

# =============================================================================
# Соединения (Relay)
# =============================================================================

@strawberry.type
class DatasetEdge(Edge[DatasetType]):
    pass

@strawberry.type
class DatasetConnection(Connection[DatasetType]):
    total_count: int

# =============================================================================
# Query
# =============================================================================

@strawberry.type
class Query:
    build_info: BuildInfo = strawberry.field(
        resolver=lambda: BuildInfo(service="neuroforge-core", version="0.0.0", revision="unknown")
    )

    node: Optional[GQLNode] = relay.node()

    @strawberry.field(description="Получить датасет по ID")
    @require_scope("df:read")
    async def dataset(self, info: Info, dataset_id: strawberry.ID) -> DatasetType:
        ctx: Context = info.context
        svc = ctx.services.dataset_svc
        data = await svc.get_dataset(str(dataset_id))
        allowed = await opa_allow(ctx, package="neuroforge.authz.datasets", rule="allow",
                                  input_obj={"dataset_id": str(dataset_id), "principal": ctx.principal.id})
        if not allowed:
            raise ForbiddenError("not allowed by policy")
        return DatasetType.from_backend(str(dataset_id), info)  # type: ignore

    @strawberry.field(description="Список датасетов с пагинацией")
    @require_scope("df:read")
    async def datasets(
        self,
        info: Info,
        first: int = 20,
        after: Optional[str] = None,
        domain: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> DatasetConnection:
        ctx: Context = info.context
        svc = ctx.services.dataset_svc
        start = _cursor_to_offset(after)
        rows, total = await svc.list_datasets(offset=start, limit=first, domain=domain, owner=owner)
        edges = [
            DatasetEdge(
                node=DatasetType.from_backend(r["id"], info),  # type: ignore
                cursor=_offset_to_cursor(start + i + 1),
            )
            for i, r in enumerate(rows)
        ]
        end_cursor = edges[-1].cursor if edges else None
        has_next = start + len(rows) < total
        return DatasetConnection(
            edges=edges, page_info=relay.PageInfo(has_next_page=has_next, has_previous_page=start > 0,
                                                  start_cursor=edges[0].cursor if edges else None,
                                                  end_cursor=end_cursor),
            total_count=total,
        )

    @strawberry.field(description="Получить модель по ID")
    @require_scope("ml:read")
    async def model(self, info: Info, model_id: strawberry.ID) -> ModelType:
        svc = info.context.services.model_svc
        m = await svc.get_model(str(model_id))
        if not m:
            raise NotFoundError("model not found")
        return ModelType.from_backend(str(model_id), info)  # type: ignore

# =============================================================================
# Mutations
# =============================================================================

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Создать/обновить датасет")
    @require_scope("df:write")
    async def upsert_dataset(self, info: Info, input: UpsertDatasetInput) -> UpsertDatasetPayload:
        ctx: Context = info.context
        svc = ctx.services.dataset_svc
        await svc.upsert_dataset(
            {
                "id": str(input.dataset_id),
                "title": input.title,
                "domain": input.domain,
                "owner": input.owner,
                "primary_key": input.primary_key,
                "write_mode": input.write_mode.value,
            }
        )
        ds = DatasetType.from_backend(str(input.dataset_id), info)
        assert ds is not None
        return UpsertDatasetPayload(dataset=ds)

# =============================================================================
# Subscriptions (пример)
# =============================================================================

@strawberry.type
class Subscription:
    @strawberry.subscription(description="События деплойментов моделей (пример)")
    async def deployment_events(self, info: Info) -> AsyncGenerator[str, None]:
        bus = info.context.services.event_bus
        async for evt in bus.stream("deployments"):
            yield json.dumps(evt)

# =============================================================================
# Расширения: маскирование ошибок, лимиты, трассировка
# =============================================================================

class MaskErrors(Extension):
    def on_request_end(self) -> None:
        if not self.execution_result:
            return
        errors = self.execution_result.errors or []
        for e in errors:
            if e and e.original_error:
                e.message = mask_error(e.original_error)

class DepthLimit(Extension):
    def __init__(self, max_depth: int = 12) -> None:
        super().__init__()
        self.max_depth = max_depth

    def on_validation_start(self):
        # Примитивная проверка глубины по AST (selectionSet глубина)
        def max_depth_of(selection, depth=0):
            if not hasattr(selection, "selection_set") or selection.selection_set is None:
                return depth
            return max([max_depth_of(s, depth + 1) for s in selection.selection_set.selections] + [depth])

        try:
            doc = self.execution_context.graphql_document
            depth = 0
            for d in doc.definitions:
                if hasattr(d, "selection_set") and d.selection_set:
                    depth = max(depth, max([max_depth_of(s) for s in d.selection_set.selections] or [0]))
            if depth > self.max_depth:
                raise ValidationError(f"query depth {depth} exceeds max {self.max_depth}")
        except UserVisibleError as e:
            # Превращаем в GraphQL ошибку
            raise e

class CostLimit(Extension):
    """
    Простая оценка «стоимости» запроса: суммирует стоимость полей.
    По умолчанию 1 на поле, для соединений умножаем на аргумент first (с кэпом).
    """
    def __init__(self, max_cost: int = 5000, first_cap: int = 100) -> None:
        super().__init__()
        self.max_cost = max_cost
        self.first_cap = first_cap

    def on_validation_start(self):
        doc = self.execution_context.graphql_document

        def field_cost(field_node) -> int:
            name = getattr(field_node.name, "value", "")
            args = {a.name.value: getattr(a.value, "value", None) for a in getattr(field_node, "arguments", [])}
            cost = 1
            if name in {"datasets"}:
                first = args.get("first")
                if isinstance(first, int):
                    cost += min(self.first_cap, max(1, first))
                else:
                    cost += 20
            return cost

        total = 0
        for defn in doc.definitions:
            sels = getattr(defn, "selection_set", None)
            if not sels:
                continue
            for s in sels.selections:
                total += self._walk_cost(s, field_cost)
        if total > self.max_cost:
            raise ValidationError(f"query cost {total} exceeds max {self.max_cost}")

    def _walk_cost(self, node, cost_fn) -> int:
        c = cost_fn(node)
        sels = getattr(node, "selection_set", None)
        if sels:
            c += sum(self._walk_cost(s, cost_fn) for s in sels.selections)
        return c

class SimpleTracing(Extension):
    """
    Лёгкая трассировка: логирование длительности запроса и операции.
    Замените на полноценный OTel extension при наличии.
    """
    def on_operation(self):
        self._t0 = monotonic()

    def on_request_end(self):
        t = (monotonic() - getattr(self, "_t0", monotonic())) * 1000.0
        op_name = getattr(self.execution_context, "operation_name", None)
        logger.info("GraphQL op=%s took=%.2fms", op_name or "<anonymous>", t)

# =============================================================================
# Вспомогательные функции для Relay cursors
# =============================================================================

def _offset_to_cursor(n: int) -> str:
    return "cursor:" + _b64(str(n))

def _cursor_to_offset(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        if cursor.startswith("cursor:"):
            n = int(_b64d(cursor.split(":", 1)[1]))
            return max(0, n)
    except Exception:
        return 0
    return 0

def _b64(s: str) -> str:
    return (s.encode("utf-8")).hex()

def _b64d(s: str) -> str:
    return bytes.fromhex(s).decode("utf-8")

# =============================================================================
# Сборка схемы
# =============================================================================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    extensions=[
        MaskErrors,
        DepthLimit,     # depth<=12
        CostLimit,      # cost<=5000
        SimpleTracing,  # простая трассировка
    ],
    config=StrawberryConfig(auto_camel_case=True),
)

# =============================================================================
# Ниже — минимальные mock-сервисы (замените реальными реализациями)
# =============================================================================

class _DatasetService:
    def __init__(self) -> None:
        now = dt.datetime.utcnow()
        self._mem: Dict[str, Dict[str, Any]] = {
            "users_v1": {
                "id": "users_v1", "title": "Users Master", "domain": "core", "owner": "data.platform@nf",
                "primary_key": ["user_id"], "write_mode": "upsert", "created_at": now, "updated_at": now
            }
        }

    async def get_dataset(self, ds_id: str) -> Dict[str, Any]:
        v = self._mem.get(ds_id)
        if not v:
            raise NotFoundError("dataset not found")
        return v

    async def list_datasets(self, offset: int, limit: int, domain: Optional[str], owner: Optional[str]) -> Tuple[List[Dict[str, Any]], int]:
        rows = list(self._mem.values())
        if domain:
            rows = [r for r in rows if r["domain"] == domain]
        if owner:
            rows = [r for r in rows if r["owner"] == owner]
        total = len(rows)
        return rows[offset: offset + limit], total

    async def upsert_dataset(self, d: Dict[str, Any]) -> None:
        d.setdefault("created_at", dt.datetime.utcnow())
        d["updated_at"] = dt.datetime.utcnow()
        self._mem[d["id"]] = d

class _ModelService:
    def __init__(self) -> None:
        now = dt.datetime.utcnow()
        self._mem_models = {
            "mdl_1": {"id": "mdl_1", "name": "recommendation", "owner": "ml@nf", "created_at": now, "updated_at": now}
        }
        self._mem_versions = {
            "mv_1": {"id": "mv_1", "model_id": "mdl_1", "version": 1, "stage": "staging", "created_at": now}
        }

    async def get_model(self, model_id: str) -> Dict[str, Any]:
        m = self._mem_models.get(model_id)
        if not m:
            raise NotFoundError("model not found")
        return m

class _EventBus:
    async def stream(self, topic: str) -> AsyncGenerator[Dict[str, Any], None]:
        # Демонстрационная генерация событий
        for i in range(3):
            yield {"topic": topic, "sequence": i, "ts": dt.datetime.utcnow().isoformat() + "Z"}
            await asyncio.sleep(0.1)
