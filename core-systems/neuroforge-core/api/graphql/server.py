# neuroforge-core/api/graphql/server.py
# Strawberry GraphQL сервер для Neuroforge Core.
# Особенности:
# - Интеграция с FastAPI (GraphQLRouter), AuthMiddleware (request.state.principal)
# - Типы Model/Version + connection-пагинация, запросы/мутации реестра
# - Проверка скоупов (models:read / models:write / models:admin)
# - ETag/If-Match и Idempotency-Key как аргументы мутаций
# - DataLoader для батчинга листинга версий по моделям
# - Расширения: лимит глубины/сложности, persisted queries, базовая телеметрия
# - Отключаемая интроспекция (ENV NF_GQL_INTROSPECTION=false)
# Зависимости: strawberry-graphql>=0.205, fastapi>=0.110, pydantic>=1.10

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import strawberry
from fastapi import APIRouter, Request
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig
from strawberry.dataloader import DataLoader
from graphql import GraphQLError, validate, visit, BREAK
from graphql.language import Visitor, ASTNode, FieldNode, FragmentSpreadNode, InlineFragmentNode, OperationDefinitionNode

# Попытка импорта сервисного слоя из REST-роутера (переиспользуем логику/хранилище)
try:
    # Абсолютный импорт, если проект установлен как пакет
    from api.http.routers.v1.registry import (
        IModelRegistryService,
        InMemoryRegistry,
        get_registry as _get_registry_default,
    )
except Exception:
    # Относительный импорт как запасной вариант
    try:
        from ..http.routers.v1.registry import (
            IModelRegistryService,
            InMemoryRegistry,
            get_registry as _get_registry_default,
        )
    except Exception:
        # Фолбэк: создаём локальный in-memory сервис (на случай автономного запуска)
        class IModelRegistryService:  # type: ignore
            ...

        class InMemoryRegistry:  # type: ignore
            def __init__(self) -> None:
                self._store: Dict[str, Any] = {}

        def _get_registry_default() -> IModelRegistryService:  # type: ignore
            return InMemoryRegistry()  # type: ignore


# =========================
# Утилиты и окружение
# =========================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _get_request_id(req: Request) -> str:
    return req.headers.get("x-request-id") or req.headers.get("x-correlation-id") or hashlib.sha1(
        f"{time.time_ns()}-{id(req)}".encode()
    ).hexdigest()[:16]

def _require_scope(info: Info, scope: str) -> None:
    principal = getattr(getattr(info.context, "request", None).state, "principal", None)
    has = getattr(principal, "has_scope", lambda s: False)
    if not has(scope):
        raise GraphQLError("PERMISSION_DENIED: missing scope", extensions={"code": "PERMISSION_DENIED"})

def _tenant(info: Info) -> Optional[str]:
    principal = getattr(getattr(info.context, "request", None).state, "principal", None)
    return getattr(principal, "tenant", None)

def _actor(info: Info) -> Optional[str]:
    principal = getattr(getattr(info.context, "request", None).state, "principal", None)
    return getattr(principal, "subject", None)

def _etag_header(info: Info) -> Optional[str]:
    return info.context.request.headers.get("if-match")

def _idem_key(info: Info) -> Optional[str]:
    return info.context.request.headers.get("idempotency-key") or info.context.request.headers.get("x-idempotency-key")

# =========================
# DataLoader'ы
# =========================

async def _batch_list_versions(
    keys: List[Tuple[str, Dict[str, Any]]], svc: IModelRegistryService, tenant: Optional[str]
) -> List[List[Dict[str, Any]]]:
    """Батчит list_versions по нескольким моделям.
    keys: [(model_id, {"page_size": int, "page_token": str|None, "stage": str|None, "order_by": str|None}), ...]
    Возвращает списки VersionOut.dict() для каждого ключа без next_token (только первая страница).
    """
    out: List[List[Dict[str, Any]]] = []
    for model_id, params in keys:
        page_size = int(params.get("page_size") or 50)
        page_token = params.get("page_token")
        stage = params.get("stage")
        order_by = params.get("order_by") or "update_time desc"
        try:
            items, _ = svc.list_versions(tenant, model_id, page_size, page_token, stage, order_by)
            out.append([i.dict() for i in items])  # type: ignore[attr-defined]
        except Exception:
            out.append([])
    return out

# =========================
# GraphQL типы/enum'ы
# =========================

@strawberry.enum
class Stage:
    DRAFT = "DRAFT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"

@strawberry.enum
class Framework:
    TENSORFLOW = "TENSORFLOW"
    PYTORCH = "PYTORCH"
    ONNX = "ONNX"
    XGBOOST = "XGBOOST"
    LLM = "LLM"

@strawberry.type
class PageInfo:
    has_next_page: bool
    next_page_token: Optional[str]

@strawberry.type
class Version:
    name: str
    model: str
    version: str
    artifact_uri: str
    checksum_sha256: Optional[str]
    size_bytes: Optional[int]
    framework: Framework
    framework_version: Optional[str]
    format: Optional[str]
    stage: Stage
    precision: Optional[str]
    accelerator: Optional[str]
    device_count: Optional[int]
    resource_spec: Optional[dict]
    parameters: dict
    metrics: dict
    model_card_uri: Optional[str]
    create_time: datetime
    update_time: datetime
    created_by: Optional[str]
    etag: str

@strawberry.type
class VersionEdge:
    node: Version

@strawberry.type
class VersionConnection:
    edges: List[VersionEdge]
    page_info: PageInfo

@strawberry.type
class Model:
    name: str
    model_id: str
    tenant_id: Optional[str]
    display_name: str
    description: Optional[str]
    labels: dict
    metadata: dict
    input_spec: Optional[dict]
    output_spec: Optional[dict]
    default_version: Optional[str]
    create_time: datetime
    update_time: datetime
    etag: str

    @strawberry.field
    async def versions(
        self,
        info: Info,
        page_size: int = 50,
        page_token: Optional[str] = None,
        stage: Optional[Stage] = None,
        order_by: Optional[str] = "update_time desc",
    ) -> VersionConnection:
        _require_scope(info, "models:read")
        ctx: GQLContext = info.context
        data = await ctx.version_loader.load((self.model_id, {
            "page_size": page_size,
            "page_token": page_token,
            "stage": stage.value if stage else None,
            "order_by": order_by,
        }))
        edges = [VersionEdge(node=Version(**row)) for row in data]
        # Простейшая pageInfo: DataLoader возвращает только первую страницу
        return VersionConnection(edges=edges, page_info=PageInfo(has_next_page=False, next_page_token=None))

@strawberry.type
class ModelEdge:
    node: Model

@strawberry.type
class ModelConnection:
    edges: List[ModelEdge]
    page_info: PageInfo

# ---------- Inputs ----------

@strawberry.input
class LabelSelectorInput:
    key: str
    value: str

@strawberry.input
class ModelCreateInput:
    model_id: str
    display_name: str
    description: Optional[str] = None
    labels: Optional[dict] = None
    metadata: Optional[dict] = None
    input_spec: Optional[dict] = None
    output_spec: Optional[dict] = None

@strawberry.input
class ModelUpdateInput:
    display_name: Optional[str] = None
    description: Optional[str] = None
    labels: Optional[dict] = None
    metadata: Optional[dict] = None
    input_spec: Optional[dict] = None
    output_spec: Optional[dict] = None
    default_version: Optional[str] = None

@strawberry.input
class VersionCreateInput:
    version: str
    artifact_uri: str
    checksum_sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    framework: Framework = Framework.ONNX
    framework_version: Optional[str] = None
    format: Optional[str] = None
    stage: Stage = Stage.DRAFT
    precision: Optional[str] = None
    accelerator: Optional[str] = None
    device_count: Optional[int] = 0
    resource_spec: Optional[dict] = None
    parameters: Optional[dict] = None
    metrics: Optional[dict] = None
    model_card_uri: Optional[str] = None

@strawberry.input
class VersionUpdateInput:
    stage: Optional[Stage] = None
    resource_spec: Optional[dict] = None
    parameters: Optional[dict] = None
    metrics: Optional[dict] = None
    model_card_uri: Optional[dict] = None
    precision: Optional[str] = None

# =========================
# Контекст и DI
# =========================

@dataclass
class GQLContext:
    request: Request
    svc: IModelRegistryService
    version_loader: DataLoader

async def _get_context(req: Request) -> GQLContext:
    svc: IModelRegistryService = _get_registry_default()
    tenant = getattr(getattr(req.state, "principal", None), "tenant", None)
    loader = DataLoader(lambda keys: _batch_list_versions(list(keys), svc, tenant))
    return GQLContext(request=req, svc=svc, version_loader=loader)

# =========================
# Query / Mutation
# =========================

@strawberry.type
class Query:
    @strawberry.field
    def model(self, info: Info, model_id: str) -> Optional[Model]:
        _require_scope(info, "models:read")
        svc: IModelRegistryService = info.context.svc
        try:
            out = svc.get_model(_tenant(info), model_id)
            return Model(**out.dict())  # type: ignore[attr-defined]
        except Exception as e:
            raise GraphQLError("NOT_FOUND", extensions={"code": "NOT_FOUND"}) from e

    @strawberry.field
    def models(
        self,
        info: Info,
        page_size: int = 50,
        page_token: Optional[str] = None,
        labels: Optional[List[LabelSelectorInput]] = None,
        order_by: Optional[str] = "update_time desc",
    ) -> ModelConnection:
        _require_scope(info, "models:read")
        svc: IModelRegistryService = info.context.svc
        selector = {l.key: l.value for l in (labels or [])}
        items, next_tok = svc.list_models(_tenant(info), page_size, page_token, selector, order_by)
        edges = [ModelEdge(node=Model(**i.dict())) for i in items]  # type: ignore[attr-defined]
        return ModelConnection(edges=edges, page_info=PageInfo(has_next_page=bool(next_tok), next_page_token=next_tok))

    @strawberry.field
    def version(self, info: Info, model_id: str, version: str) -> Optional[Version]:
        _require_scope(info, "models:read")
        svc: IModelRegistryService = info.context.svc
        try:
            out = svc.get_version(_tenant(info), model_id, version)
            return Version(**out.dict())  # type: ignore[attr-defined]
        except Exception as e:
            raise GraphQLError("NOT_FOUND", extensions={"code": "NOT_FOUND"}) from e

@strawberry.type
class Mutation:
    @strawberry.mutation
    def create_model(self, info: Info, input: ModelCreateInput) -> Model:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.create_model(_tenant(info), _to_pyd(input), _idem_key(info))
        return Model(**out.dict())  # type: ignore[attr-defined]

    @strawberry.mutation
    def update_model(self, info: Info, model_id: str, patch: ModelUpdateInput) -> Model:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.update_model(_tenant(info), model_id, _to_pyd(patch), _etag_header(info))
        return Model(**out.dict())  # type: ignore[attr-defined]

    @strawberry.mutation
    def delete_model(self, info: Info, model_id: str) -> bool:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        svc.delete_model(_tenant(info), model_id, _etag_header(info))
        return True

    @strawberry.mutation
    def set_default_version(self, info: Info, model_id: str, version: str) -> Model:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.set_default_version(_tenant(info), model_id, version, _etag_header(info))
        return Model(**out.dict())  # type: ignore[attr-defined]

    @strawberry.mutation
    def create_version(self, info: Info, model_id: str, input: VersionCreateInput) -> Version:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.create_version(_tenant(info), model_id, _to_pyd(input), _actor(info), _idem_key(info))
        return Version(**out.dict())  # type: ignore[attr-defined]

    @strawberry.mutation
    def update_version(self, info: Info, model_id: str, version: str, patch: VersionUpdateInput) -> Version:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.update_version(_tenant(info), model_id, version, _to_pyd(patch), _etag_header(info))
        return Version(**out.dict())  # type: ignore[attr-defined]

    @strawberry.mutation
    def delete_version(self, info: Info, model_id: str, version: str) -> bool:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        svc.delete_version(_tenant(info), model_id, version, _etag_header(info))
        return True

    @strawberry.mutation
    def promote_version(self, info: Info, model_id: str, version: str, target_stage: Stage) -> Version:
        _require_scope(info, "models:write")
        svc: IModelRegistryService = info.context.svc
        out = svc.promote_version(_tenant(info), model_id, version, target_stage.value, _etag_header(info))
        return Version(**out.dict())  # type: ignore[attr-defined]

def _to_pyd(obj: Any) -> Any:
    """Преобразование Strawberry input -> Pydantic моделей из REST-сервиса."""
    # REST-сервис использует Pydantic-модели, у которых есть .dict() и валидаторы.
    # Передадим обычный dict — Pydantic сам провалидирует.
    if hasattr(obj, "__dict__"):
        # strawberry.input -> dataclass-like
        return json.loads(json.dumps(obj.__dict__, default=str))
    return obj

# =========================
# Расширения (лимиты/персист/метки)
# =========================

class DepthLimitExtension(strawberry.extensions.BaseExtension):
    """Ограничение глубины запроса (NF_GQL_MAX_DEPTH, default 10)."""
    def __init__(self, execution_context):
        super().__init__(execution_context)
        self.max_depth = int(os.getenv("NF_GQL_MAX_DEPTH", "10"))

    def on_validation_start(self):
        doc = self.execution_context.graphql_document
        max_depth = 0

        def measure_depth(node: ASTNode, depth: int = 0) -> None:
            nonlocal max_depth
            if isinstance(node, FieldNode):
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            for child in getattr(node, "selection_set", []).selections if getattr(node, "selection_set", None) else []:
                measure_depth(child, depth)

        for d in doc.definitions:
            if isinstance(d, OperationDefinitionNode):
                measure_depth(d, 0)
        if max_depth > self.max_depth:
            raise GraphQLError(
                f"QUERY_DEPTH_EXCEEDED: {max_depth} > {self.max_depth}",
                extensions={"code": "QUERY_DEPTH_EXCEEDED"},
            )

class SimpleCostExtension(strawberry.extensions.BaseExtension):
    """Простой стоимостной лимит (NF_GQL_MAX_COST, default 5000). Каждое поле =1, connection поля = N (page_size)."""
    def __init__(self, execution_context):
        super().__init__(execution_context)
        self.max_cost = int(os.getenv("NF_GQL_MAX_COST", "5000"))
        self._cost = 0

    def on_validation_start(self):
        doc = self.execution_context.graphql_document

        def visit_field(node: FieldNode) -> int:
            cost = 1
            # эвристика page_size
            for arg in node.arguments or []:
                if arg.name.value in ("page_size", "first", "last"):
                    try:
                        val = int(getattr(arg.value, "value", 50))
                        cost += max(0, min(val, 1000))
                    except Exception:
                        cost += 50
            return cost

        total = 0
        for d in doc.definitions:
            if isinstance(d, OperationDefinitionNode):
                stack = [d]
                while stack:
                    n = stack.pop()
                    if isinstance(n, FieldNode):
                        total += visit_field(n)
                    sel = getattr(n, "selection_set", None)
                    if sel and sel.selections:
                        stack.extend(sel.selections)
        self._cost = total
        if total > self.max_cost:
            raise GraphQLError(
                f"QUERY_COST_EXCEEDED: {total} > {self.max_cost}",
                extensions={"code": "QUERY_COST_EXCEEDED"},
            )

class PersistedQueryExtension(strawberry.extensions.BaseExtension):
    """Поддержка persisted queries через заголовок X-Query-Hash (sha256) или queryId параметр.
       В проде стоит заменить на внешний KV. Здесь — in-memory TTL.
    """
    _store: Dict[str, Tuple[float, str]] = {}
    _ttl = int(os.getenv("NF_GQL_PQ_TTL_S", "3600"))

    def on_request_start(self):
        request = getattr(self.execution_context.context, "request", None)
        if not request:
            return
        qid = request.headers.get("x-query-hash") or request.query_params.get("queryId")
        if not qid:
            return
        # Если в запросе нет текста query — попытаемся подставить из хранилища
        if not self.execution_context.query and qid in self._store:
            ts, q = self._store[qid]
            if (time.time() - ts) <= self._ttl:
                self.execution_context.query = q
        # Если текст есть — (пере)сохраняем по хэшу
        if self.execution_context.query:
            h = hashlib.sha256(self.execution_context.query.encode()).hexdigest()
            if qid == h:
                self._store[qid] = (time.time(), self.execution_context.query)

class RequestTagExtension(strawberry.extensions.BaseExtension):
    """Добавляет request_id в extensions ответа."""
    def on_execute_end(self):
        req = getattr(self.execution_context.context, "request", None)
        rid = _get_request_id(req) if req else None
        if rid:
            self.execution_context.result.extensions = (self.execution_context.result.extensions or {})
            self.execution_context.result.extensions.update({"request_id": rid})

# =========================
# Сборка схемы и роутера
# =========================

def _error_formatter(error: GraphQLError, debug: bool = False) -> dict:
    code = "INTERNAL"
    if error.extensions and "code" in error.extensions:
        code = error.extensions["code"]
    msg = error.message
    return {"message": msg, "locations": error.locations, "path": error.path, "extensions": {"code": code}}

def build_graphql_router() -> APIRouter:
    schema = strawberry.Schema(
        query=Query,
        mutation=Mutation,
        config=StrawberryConfig(auto_camel_case=True),
    )

    # Интроспекция управляется переменной окружения
    allow_introspection = os.getenv("NF_GQL_INTROSPECTION", "true").lower() == "true"

    extensions = [
        DepthLimitExtension,
        SimpleCostExtension,
        PersistedQueryExtension,
        RequestTagExtension,
    ]

    graphql_app = GraphQLRouter(
        schema,
        context_getter=_get_context,
        graphiql=allow_introspection,
        # Strawberry сам выключит introspection на уровне валидации:
        allow_introspection=allow_introspection,
        extensions=extensions,
        error_formatter=_error_formatter,
    )

    router = APIRouter()
    router.include_router(graphql_app, prefix="/graphql")
    return router

# Экспорт по умолчанию
router = build_graphql_router()
