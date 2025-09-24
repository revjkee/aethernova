from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

import strawberry
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from graphql import (
    GraphQLError,
    ValidationRule,
    visit,
    parse,
    OperationDefinitionNode,
    FieldNode,
    FragmentSpreadNode,
    FragmentDefinitionNode,
    InlineFragmentNode,
)
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from strawberry.schema.extensions import SchemaExtension

# -----------------------------------------------------------------------------
# Конфигурация окружения
# -----------------------------------------------------------------------------
GQL_PATH = os.getenv("GRAPHQL_PATH", "/api/graphql")
ENABLE_PLAYGROUND = os.getenv("GRAPHQL_PLAYGROUND", "false").lower() == "true"
MAX_QUERY_DEPTH = int(os.getenv("GRAPHQL_MAX_DEPTH", "12"))
MAX_QUERY_COMPLEXITY = int(os.getenv("GRAPHQL_MAX_COMPLEXITY", "2000"))
REQUEST_TIMEOUT_SEC = float(os.getenv("GRAPHQL_REQUEST_TIMEOUT_SEC", "15.0"))
ALLOW_INTROSPECTION = os.getenv("GRAPHQL_ALLOW_INTROSPECTION", "false").lower() == "true"

# -----------------------------------------------------------------------------
# Унифицированные ошибки (совместимо с schemas/proto/v1/error.proto)
# -----------------------------------------------------------------------------
def error_payload(
    *,
    code: str,
    message: str,
    http_status: int,
    correlation_id: Optional[str],
    retryable: bool = False,
    details: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    payload = {
        "code": code,
        "message": message,
        "http_status": http_status,
        "correlation_id": correlation_id,
        "retryable": retryable,
    }
    if details:
        payload["details"] = details
    if metadata:
        payload["metadata"] = metadata
    return payload


class DomainError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400, retryable: bool = False, details=None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.retryable = retryable
        self.details = details or []


# -----------------------------------------------------------------------------
# Корреляция и безопасные заголовки
# -----------------------------------------------------------------------------
def secure_headers(resp: Response) -> None:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")


def rate_limit_headers(resp: Response, *, limit: int = 1000, remaining: int = 999, reset_epoch_s: Optional[int] = None) -> None:
    resp.headers["X-RateLimit-Limit"] = str(limit)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    if reset_epoch_s:
        resp.headers["X-RateLimit-Reset"] = str(reset_epoch_s)


async def correlation_id_dependency(x_request_id: Optional[str] = Header(default=None)) -> str:
    if x_request_id:
        return x_request_id
    n = str(time.time_ns()).encode("utf-8")
    h = hashlib.sha1(n).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# -----------------------------------------------------------------------------
# Аутентификация (заглушка; замените на вашу)
# -----------------------------------------------------------------------------
@dataclass
class AuthContext:
    subject: str
    roles: List[str]
    tenant_id: Optional[str] = None


async def auth_dependency(
    authorization: Optional[str] = Header(default=None),
    correlation_id: str = Depends(correlation_id_dependency),
) -> AuthContext:
    if not authorization or not authorization.lower().startswith("bearer "):
        # Для GraphQL отдаём GraphQLError позже через error_formatter; здесь бросаем HTTP 401 для health и т.п.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    # Разбор JWT/OIDC опущен: выдаём заглушку
    return AuthContext(subject="user:unknown", roles=["USER"])


# -----------------------------------------------------------------------------
# Persisted queries (APQ) — in‑memory/Redis‑like
# -----------------------------------------------------------------------------
class PersistedQueryCache:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, str]] = {}
        self._lock = asyncio.Lock()
        self._ttl = 60 * 60  # 1 час

    async def get(self, sha256: str) -> Optional[str]:
        async with self._lock:
            row = self._store.get(sha256)
            if not row:
                return None
            exp, q = row
            if time.time() > exp:
                self._store.pop(sha256, None)
                return None
            return q

    async def set(self, sha256: str, query: str) -> None:
        async with self._lock:
            self._store[sha256] = (time.time() + self._ttl, query)


APQ = PersistedQueryCache()


# -----------------------------------------------------------------------------
# Depth/Complexity лимиты
# -----------------------------------------------------------------------------
class DepthLimitRule(ValidationRule):
    def __init__(self, context):
        super().__init__(context)
        self.max_depth = MAX_QUERY_DEPTH
        self.current_depth = 0
        self.max_seen = 0

    def enter(self, node, key, parent, path, ancestors):
        if isinstance(node, (FieldNode, InlineFragmentNode, FragmentSpreadNode)):
            self.current_depth += 1
            self.max_seen = max(self.max_seen, self.current_depth)
            if self.max_seen > self.max_depth:
                self.context.report_error(GraphQLError(f"Query depth {self.max_seen} exceeds max {self.max_depth}"))
        return super().enter(node, key, parent, path, ancestors)

    def leave(self, node, key, parent, path, ancestors):
        if isinstance(node, (FieldNode, InlineFragmentNode, FragmentSpreadNode)):
            self.current_depth -= 1
        return super().leave(node, key, parent, path, ancestors)


def estimate_complexity(src: str) -> int:
    """
    Простейшая эвристика: суммарное число FieldNode.
    Для продакшена замените на полноценный visitor с весами.
    """
    try:
        doc = parse(src)
    except Exception:
        return 0
    counter = 0

    def _count(node):
        nonlocal counter
        if isinstance(node, FieldNode):
            counter += 1

    visit(doc, {"Field": _count})
    return counter


# -----------------------------------------------------------------------------
# DataLoader (микро‑реализация для батчинга)
# -----------------------------------------------------------------------------
class DataLoader:
    def __init__(self, batch_fn: Callable[[List[str]], Awaitable[List[Any]]], max_batch_size: int = 100):
        self.batch_fn = batch_fn
        self.max_batch_size = max_batch_size
        self._queue: List[Tuple[str, asyncio.Future]] = []
        self._scheduled = False

    async def load(self, key: str) -> Any:
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._queue.append((key, fut))
        if not self._scheduled:
            self._scheduled = True
            loop.call_soon(self._dispatch)
        return await fut

    def _dispatch(self):
        self._scheduled = False
        if not self._queue:
            return
        batch = self._queue[: self.max_batch_size]
        del self._queue[: self.max_batch_size]
        keys = [k for k, _ in batch]

        async def run():
            try:
                results = await self.batch_fn(keys)
                for (_, fut), val in zip(batch, results):
                    if not fut.done():
                        fut.set_result(val)
            except Exception as e:
                for _, fut in batch:
                    if not fut.done():
                        fut.set_exception(e)
        asyncio.create_task(run())


# -----------------------------------------------------------------------------
# Пример домена: Anchor (согласовано с REST‑версией)
# -----------------------------------------------------------------------------
@strawberry.type
class Anchor:
    id: strawberry.ID
    name: str
    description: Optional[str]
    status: str
    version: int
    created_at: datetime
    updated_at: datetime


@strawberry.type
class PageAnchors:
    data: List[Anchor]
    next_cursor: Optional[str]


# Заглушка репозитория — замените внедрением ваших реализаций
class AnchorRepo:
    async def list(self, *, limit: int, cursor: Optional[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        return [], None

    async def get_many(self, ids: List[str]) -> List[Optional[Dict[str, Any]]]:
        return [None for _ in ids]

    async def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        raise DomainError("NOT_IMPLEMENTED", "create not implemented", 501)

    async def update(self, anchor_id: str, data: Dict[str, Any], expected_version: Optional[int]) -> Dict[str, Any]:
        raise DomainError("NOT_IMPLEMENTED", "update not implemented", 501)


# -----------------------------------------------------------------------------
# Контекст запроса
# -----------------------------------------------------------------------------
@dataclass
class GQLContext:
    request: Request
    response: Response
    auth: AuthContext
    correlation_id: str
    anchor_repo: AnchorRepo
    loaders: Dict[str, DataLoader]


async def get_context(
    request: Request,
    response: Response,
    auth: AuthContext = Depends(auth_dependency),
    correlation_id: str = Depends(correlation_id_dependency),
) -> GQLContext:
    secure_headers(response)
    rate_limit_headers(response)
    response.headers.setdefault("X-Request-ID", correlation_id)
    repo = AnchorRepo()

    anchor_loader = DataLoader(repo.get_many)
    return GQLContext(
        request=request,
        response=response,
        auth=auth,
        correlation_id=correlation_id,
        anchor_repo=repo,
        loaders={"anchor": anchor_loader},
    )


# -----------------------------------------------------------------------------
# Расширения схемы: таймаут и простая трассировка
# -----------------------------------------------------------------------------
class TimeoutExtension(SchemaExtension):
    def on_operation(self):
        async def _wrap(next_):
            try:
                return await asyncio.wait_for(next_(), timeout=REQUEST_TIMEOUT_SEC)
            except asyncio.TimeoutError:
                raise DomainError("UPSTREAM_UNAVAILABLE", "operation timeout", http_status=504, retryable=True)

        return _wrap


class TraceExtension(SchemaExtension):
    def on_request_start(self):
        ctx: GQLContext = self.execution_context.context
        start = time.time()

        async def _wrap(next_):
            try:
                return await next_()
            finally:
                dur_ms = int((time.time() - start) * 1000)
                ctx.response.headers["X-GraphQL-Duration-ms"] = str(dur_ms)

        return _wrap


# -----------------------------------------------------------------------------
# Query/Mutation
# -----------------------------------------------------------------------------
@strawberry.type
class Query:
    @strawberry.field(description="Cursor‑based список якорей")
    async def anchors(self, info: Info, limit: int = 50, cursor: Optional[str] = None) -> PageAnchors:
        ctx: GQLContext = info.context
        if limit < 1 or limit > 500:
            raise DomainError("VALIDATION_FAILED", "limit must be between 1 and 500", 400)

        items, next_cursor = await ctx.anchor_repo.list(limit=limit, cursor=cursor)
        data = [
            Anchor(
                id=i["id"],
                name=i["name"],
                description=i.get("description"),
                status=i["status"],
                version=i["version"],
                created_at=i["created_at"].astimezone(timezone.utc),
                updated_at=i["updated_at"].astimezone(timezone.utc),
            )
            for i in items
        ]
        return PageAnchors(data=data, next_cursor=next_cursor)

    @strawberry.field(description="Получить якорь по id")
    async def anchor(self, info: Info, id: strawberry.ID) -> Optional[Anchor]:
        ctx: GQLContext = info.context
        rec = await ctx.loaders["anchor"].load(str(id))
        if not rec:
            return None
        return Anchor(
            id=rec["id"],
            name=rec["name"],
            description=rec.get("description"),
            status=rec["status"],
            version=rec["version"],
            created_at=rec["created_at"].astimezone(timezone.utc),
            updated_at=rec["updated_at"].astimezone(timezone.utc),
        )


@strawberry.input
class AnchorInput:
    name: str
    description: Optional[str] = None
    status: str = "active"


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Создать якорь")
    async def create_anchor(self, info: Info, input: AnchorInput, idempotency_key: Optional[str] = None) -> Anchor:
        ctx: GQLContext = info.context
        # В продакшене используйте Redis‑кэш для идемпотентности
        data = await ctx.anchor_repo.create({"name": input.name, "description": input.description, "status": input.status})
        return Anchor(
            id=data["id"],
            name=data["name"],
            description=data.get("description"),
            status=data["status"],
            version=data["version"],
            created_at=data["created_at"].astimezone(timezone.utc),
            updated_at=data["updated_at"].astimezone(timezone.utc),
        )


schema = strawberry.Schema(query=Query, mutation=Mutation, extensions=[TimeoutExtension, TraceExtension])

# -----------------------------------------------------------------------------
# Error formatter
# -----------------------------------------------------------------------------
def graphql_error_formatter(error: GraphQLError, debug: bool = False) -> Dict[str, Any]:
    # DomainError → унифицированный payload
    cid = None
    try:
        ctx: GQLContext = error.path and error.extensions and error.extensions.get("context")  # редко доступно
    except Exception:
        ctx = None
    if hasattr(error, "original_error") and isinstance(error.original_error, DomainError):
        e: DomainError = error.original_error
        return {
            "message": e.args[0],
            "extensions": {
                "code": e.code,
                "payload": error_payload(
                    code=e.code,
                    message=str(e),
                    http_status=e.http_status,
                    correlation_id=cid,
                    retryable=e.retryable,
                    details=e.details,
                ),
            },
        }

    # Прочие ошибки
    code = "INTERNAL" if not isinstance(error, GraphQLError) else "BAD_REQUEST"
    return {
        "message": str(error),
        "extensions": {
            "code": code,
            "payload": error_payload(
                code=code,
                message=str(error),
                http_status=500 if code == "INTERNAL" else 400,
                correlation_id=cid,
                retryable=(code == "INTERNAL"),
            ),
        },
    }


# -----------------------------------------------------------------------------
# APQ обработчик для FastAPI‑роутера (поддержка Apollo Persisted Queries)
# -----------------------------------------------------------------------------
async def apq_middleware(request: Request) -> Optional[Dict[str, Any]]:
    """
    Возвращает тело запроса для Strawberry, применяя APQ, либо None — если не APQ.
    Поддерживает:
      - extensions: { persistedQuery: { version: 1, sha256Hash } }
      - query + sha → кэширование
    """
    if request.method != "POST":
        return None
    try:
        body = await request.json()
    except Exception:
        return None

    extensions = body.get("extensions") if isinstance(body, dict) else None
    if not isinstance(extensions, dict):
        return None
    persisted = extensions.get("persistedQuery")
    if not isinstance(persisted, dict):
        return None
    sha = persisted.get("sha256Hash")
    if not isinstance(sha, str):
        return None

    query = body.get("query")
    if query:
        # Кэшируем
        await APQ.set(sha, query)
        return body

    # Попытка получить из кэша
    cached = await APQ.get(sha)
    if cached:
        body["query"] = cached
        return body

    # Соответствие спецификации: вернуть ошибку PersistedQueryNotFound
    raise HTTPException(
        status_code=200,
        detail={
            "errors": [
                {
                    "message": "PersistedQueryNotFound",
                    "extensions": {"code": "PERSISTED_QUERY_NOT_FOUND"},
                }
            ]
        },
    )


# -----------------------------------------------------------------------------
# Query validation hook
# -----------------------------------------------------------------------------
def validate_query_document(source: str) -> None:
    if not ALLOW_INTROSPECTION and ("__schema" in source or "__type" in source):
        raise DomainError("FORBIDDEN", "Introspection is disabled", http_status=403)

    depth_rule = DepthLimitRule
    # Грубая оценка сложности до парсинга (быстро) и после (точнее)
    complexity = estimate_complexity(source)
    if complexity > MAX_QUERY_COMPLEXITY:
        raise DomainError("BAD_REQUEST", f"Query complexity {complexity} exceeds max {MAX_QUERY_COMPLEXITY}", http_status=400)

    # Дополнительно можно прогнать custom ValidationRule в GraphQLRouter через параметр validation_rules


# -----------------------------------------------------------------------------
# FastAPI Router + GraphQLRouter
# -----------------------------------------------------------------------------
api_router = APIRouter()


@api_router.get(f"{GQL_PATH}/health", include_in_schema=False)
async def health() -> PlainTextResponse:
    return PlainTextResponse("ok", status_code=200)


@api_router.get(f"{GQL_PATH}/ready", include_in_schema=False)
async def ready() -> PlainTextResponse:
    return PlainTextResponse("ready", status_code=200)


class CustomGraphQLRouter(GraphQLRouter):
    async def get_context(self, request: Request, response: Response) -> Any:
        # Интеграция FastAPI Depends
        try:
            auth = await auth_dependency()  # может бросить 401
        except HTTPException as e:
            # Преобразуем в GraphQL‑ошибку в error_formatter
            raise e
        correlation_id = await correlation_id_dependency()
        return await get_context(request, response, auth=auth, correlation_id=correlation_id)

    async def process_request(self, request: Request, response: Response) -> Optional[Dict[str, Any]]:
        # APQ support и валидация
        body = await apq_middleware(request)
        if body and "query" in body and isinstance(body["query"], str):
            validate_query_document(body["query"])
        return body


graphql_app = CustomGraphQLRouter(
    schema,
    graphiql=ENABLE_PLAYGROUND,
    error_formatter=graphql_error_formatter,
    validation_rules=[DepthLimitRule],  # Дополнительно к ручной проверке
)

# Подвешиваем на основной роутер
api_router.include_router(graphql_app, prefix="")

# Экспортируем для использования в приложении FastAPI:
# from .server import api_router  ; app.include_router(api_router)
