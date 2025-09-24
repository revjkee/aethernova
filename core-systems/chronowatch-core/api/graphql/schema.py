# chronowatch-core/api/graphql/schema.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, TypeVar

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from strawberry.permission import BasePermission

# Optional extensions (graceful if missing)
try:
    from strawberry.extensions.tracing import OpenTelemetryExtension  # type: ignore
except Exception:  # pragma: no cover
    OpenTelemetryExtension = None  # type: ignore

try:
    from strawberry.extensions import QueryDepthLimiter  # type: ignore
except Exception:  # pragma: no cover
    QueryDepthLimiter = None  # type: ignore

try:
    from graphql import GraphQLError  # type: ignore
except Exception:  # pragma: no cover
    class GraphQLError(Exception):  # type: ignore
        pass

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logger = logging.getLogger("chronowatch.graphql")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(os.getenv("GRAPHQL_LOG_LEVEL", "INFO").upper())


# ------------------------------------------------------------------------------
# Helpers: global Relay ID
# ------------------------------------------------------------------------------
def to_global_id(typename: str, raw_id: str | int) -> strawberry.ID:
    payload = f"{typename}:{raw_id}".encode("utf-8")
    return strawberry.ID(base64.urlsafe_b64encode(payload).decode("ascii"))


def from_global_id(gid: strawberry.ID) -> Tuple[str, str]:
    try:
        decoded = base64.urlsafe_b64decode(str(gid)).decode("utf-8")
        typename, rid = decoded.split(":", 1)
        return typename, rid
    except Exception:
        raise GraphQLError("Invalid ID")


# ------------------------------------------------------------------------------
# Context & Services
# ------------------------------------------------------------------------------
@dataclass
class AuthIdentity:
    subject: str
    org_id: Optional[str] = None
    scopes: Tuple[str, ...] = ()
    roles: Tuple[str, ...] = ()
    auth_mode: str = "unknown"


class SlaService(Protocol):
    async def get(self, sla_id: str) -> Optional["SlaModel"]:
        ...

    async def list(
        self,
        *,
        first: int,
        after: Optional[str],
        owner: Optional[str],
        org_id: Optional[str],
        query: Optional[str],
    ) -> Tuple[List["SlaModel"], Optional[str]]:
        ...

    async def create(self, payload: "SlaInput", owner: str, org_id: Optional[str]) -> "SlaModel":
        ...

    async def update(self, sla_id: str, patch: "SlaPatch") -> "SlaModel":
        ...

    async def delete(self, sla_id: str) -> bool:
        ...

    async def evaluate(self, sla_id: str, as_of: Optional[datetime]) -> "EvaluationResultModel":
        ...


class NullSlaService:
    async def get(self, sla_id: str) -> Optional["SlaModel"]:
        return None

    async def list(
        self, *, first: int, after: Optional[str], owner: Optional[str], org_id: Optional[str], query: Optional[str]
    ) -> Tuple[List["SlaModel"], Optional[str]]:
        return [], None

    async def create(self, payload: "SlaInput", owner: str, org_id: Optional[str]) -> "SlaModel":
        raise GraphQLError("SLA service is not configured")

    async def update(self, sla_id: str, patch: "SlaPatch") -> "SlaModel":
        raise GraphQLError("SLA service is not configured")

    async def delete(self, sla_id: str) -> bool:
        raise GraphQLError("SLA service is not configured")

    async def evaluate(self, sla_id: str, as_of: Optional[datetime]) -> "EvaluationResultModel":
        raise GraphQLError("SLA service is not configured")


@dataclass
class Services:
    sla: SlaService = dataclasses.field(default_factory=NullSlaService)


@dataclass
class Context:
    request: Any
    auth: Optional[AuthIdentity]
    services: Services
    request_id: str


async def context_getter(request) -> Context:
    auth = getattr(request.state, "auth", None)
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or "unknown"
    # TODO: inject real Services here (e.g., from container)
    return Context(request=request, auth=auth, services=Services(), request_id=req_id)


# ------------------------------------------------------------------------------
# Permissions
# ------------------------------------------------------------------------------
class IsAuthenticated(BasePermission):
    message = "Authentication required"

    def has_permission(self, source: object, info: Info, **kwargs) -> bool:
        ctx: Context = info.context
        return ctx.auth is not None


class HasScopes(BasePermission):
    def __init__(self, *required: str) -> None:
        self.required = tuple(required)

    @property
    def message(self) -> str:
        return f"Missing required scopes: {', '.join(self.required)}"

    def has_permission(self, source: object, info: Info, **kwargs) -> bool:
        ctx: Context = info.context
        if not ctx.auth:
            return False
        return set(self.required).issubset(set(ctx.auth.scopes))


# ------------------------------------------------------------------------------
# DataLoader (anti N+1)
# ------------------------------------------------------------------------------
K = TypeVar("K")
V = TypeVar("V")


class DataLoader:
    def __init__(self, batch_load_fn: Callable[[List[K]], Awaitable[List[V]]], max_batch_size: int = 128) -> None:
        self.batch_load_fn = batch_load_fn
        self.max_batch_size = max_batch_size
        self._queue: List[Tuple[K, asyncio.Future[V]]] = []
        self._scheduled = False

    async def load(self, key: K) -> V:
        fut: asyncio.Future[V] = asyncio.get_event_loop().create_future()
        self._queue.append((key, fut))
        if not self._scheduled:
            self._scheduled = True
            asyncio.get_event_loop().call_soon(asyncio.create_task, self._dispatch())
        return await fut

    async def _dispatch(self) -> None:
        try:
            while self._queue:
                batch = self._queue[: self.max_batch_size]
                del self._queue[: self.max_batch_size]
                keys = [k for k, _ in batch]
                values = await self.batch_load_fn(keys)
                if len(values) != len(keys):
                    raise GraphQLError("Loader returned wrong batch size")
                for (_, fut), val in zip(batch, values):
                    if not fut.done():
                        fut.set_result(val)
        finally:
            self._scheduled = False


# ------------------------------------------------------------------------------
# GraphQL Types
# ------------------------------------------------------------------------------
DateTime = strawberry.scalar(
    datetime,
    serialize=lambda v: v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    parse_value=lambda v: datetime.fromisoformat(str(v).replace("Z", "+00:00")),
    description="RFC3339 timestamp",
)


@strawberry.interface(description="Relay Node interface")
class Node:
    id: strawberry.ID


@strawberry.type(description="Authenticated user")
class User(Node):
    id: strawberry.ID
    username: str
    org_id: Optional[str]
    roles: List[str]
    auth_mode: str

    @staticmethod
    def from_identity(identity: AuthIdentity) -> "User":
        raw_id = identity.subject or "unknown"
        return User(
            id=to_global_id("User", raw_id),
            username=identity.subject,
            org_id=identity.org_id,
            roles=list(identity.roles),
            auth_mode=identity.auth_mode,
        )


# --- SLA domain (aligned with proto) ---
@strawberry.enum
class SLIType:
    AVAILABILITY = "AVAILABILITY"
    LATENCY = "LATENCY"
    ERROR_RATE = "ERROR_RATE"
    THROUGHPUT = "THROUGHPUT"
    CUSTOM = "CUSTOM"


@strawberry.type
class SLOTarget:
    objective: float  # 0..1
    window: str       # e.g. "rolling:30d" or "calendar:MONTH"
    description: Optional[str] = None


@strawberry.type
class Sla(Node):
    id: strawberry.ID
    name: str
    display_name: str
    owner: str
    org_id: Optional[str]
    sli_type: SLIType
    labels: Dict[str, str]
    created_at: DateTime
    updated_at: DateTime


@strawberry.type
class EvaluationWindow:
    window: str
    attained_objective: float
    target_objective: float
    error_budget_remaining: float
    burn_rate: float
    breached: bool
    severity: str


@strawberry.type
class EvaluationResult:
    sla: Sla
    windows: List[EvaluationWindow]
    evaluated_at: DateTime


# Internal models (service boundary)
@dataclass
class SlaModel:
    id: str
    name: str
    display_name: str
    owner: str
    org_id: Optional[str]
    sli_type: str
    labels: Dict[str, str]
    created_at: datetime
    updated_at: datetime


@dataclass
class EvaluationResultModel:
    sla: SlaModel
    windows: List[EvaluationWindow]
    evaluated_at: datetime


# Mapping helpers
def map_sla(m: SlaModel) -> Sla:
    return Sla(
        id=to_global_id("Sla", m.id),
        name=m.name,
        display_name=m.display_name,
        owner=m.owner,
        org_id=m.org_id,
        sli_type=SLIType[m.sli_type] if m.sli_type in SLIType.__members__ else SLIType.CUSTOM,
        labels=m.labels,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


# Connection (Relay-like)
@strawberry.type
class PageInfo:
    has_next_page: bool
    end_cursor: Optional[str]


@strawberry.type
class SlaEdge:
    cursor: str
    node: Sla


@strawberry.type
class SlaConnection:
    edges: List[SlaEdge]
    page_info: PageInfo
    total_count: int


# Inputs
@strawberry.input
class SlaInput:
    name: str
    display_name: str
    sli_type: SLIType
    labels: Optional[Dict[str, str]] = None


@strawberry.input
class SlaPatch:
    display_name: Optional[str] = None
    labels: Optional[Dict[str, str]] = None


# ------------------------------------------------------------------------------
# Query & Mutation
# ------------------------------------------------------------------------------
@strawberry.type
class Query:
    @strawberry.field(description="Liveness probe")
    def health(self) -> str:
        return "ok"

    @strawberry.field(description="Current authenticated user", permission_classes=[IsAuthenticated])
    def me(self, info: Info) -> User:
        ctx: Context = info.context
        assert ctx.auth is not None
        return User.from_identity(ctx.auth)

    @strawberry.field(description="Fetch single SLA by ID", permission_classes=[IsAuthenticated])
    async def sla(self, info: Info, id: strawberry.ID) -> Optional[Sla]:
        ctx: Context = info.context
        _, rid = from_global_id(id)
        m = await ctx.services.sla.get(rid)
        return map_sla(m) if m else None

    @strawberry.field(description="List SLAs with cursor pagination", permission_classes=[IsAuthenticated])
    async def slas(
        self,
        info: Info,
        first: int = 20,
        after: Optional[str] = None,
        owner: Optional[str] = None,
        org_id: Optional[str] = None,
        query: Optional[str] = None,
    ) -> SlaConnection:
        ctx: Context = info.context
        first = max(1, min(first, 200))
        items, next_cursor = await ctx.services.sla.list(
            first=first, after=after, owner=owner, org_id=org_id, query=query
        )
        edges = [SlaEdge(cursor=to_global_id("cursor", m.id), node=map_sla(m)) for m in items]
        page_info = PageInfo(has_next_page=bool(next_cursor), end_cursor=next_cursor)
        total_count = len(items) + (1 if next_cursor else 0)  # hint; replace with exact if available
        return SlaConnection(edges=edges, page_info=page_info, total_count=total_count)

    @strawberry.field(description="Evaluate SLA", permission_classes=[IsAuthenticated])
    async def evaluate_sla(
        self, info: Info, id: strawberry.ID, as_of: Optional[DateTime] = None
    ) -> EvaluationResult:
        ctx: Context = info.context
        _, rid = from_global_id(id)
        result = await ctx.services.sla.evaluate(rid, as_of)
        return EvaluationResult(
            sla=map_sla(result.sla),
            windows=result.windows,
            evaluated_at=result.evaluated_at,
        )


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Create SLA", permission_classes=[IsAuthenticated, HasScopes("sla:write")])
    async def create_sla(self, info: Info, input: SlaInput) -> Sla:
        ctx: Context = info.context
        assert ctx.auth is not None
        model = await ctx.services.sla.create(
            payload=input, owner=ctx.auth.subject, org_id=ctx.auth.org_id
        )
        return map_sla(model)

    @strawberry.mutation(description="Update SLA", permission_classes=[IsAuthenticated, HasScopes("sla:write")])
    async def update_sla(self, info: Info, id: strawberry.ID, patch: SlaPatch) -> Sla:
        ctx: Context = info.context
        _, rid = from_global_id(id)
        model = await ctx.services.sla.update(rid, patch)
        return map_sla(model)

    @strawberry.mutation(description="Delete SLA", permission_classes=[IsAuthenticated, HasScopes("sla:write")])
    async def delete_sla(self, info: Info, id: strawberry.ID) -> bool:
        ctx: Context = info.context
        _, rid = from_global_id(id)
        return await ctx.services.sla.delete(rid)


schema = strawberry.Schema(Query, Mutation, types=[User, Sla])


# ------------------------------------------------------------------------------
# Error formatter (mask internals, attach request_id)
# ------------------------------------------------------------------------------
def error_formatter(error: GraphQLError, debug: bool = False) -> Dict[str, Any]:
    try:
        # Attach request id from context if available
        request_id = "unknown"
        try:
            ctx = error.path.context  # type: ignore[attr-defined]
        except Exception:
            ctx = None
        if hasattr(error, "original_error") and debug:
            logger.exception("GraphQL error", exc_info=error.original_error)
        message = str(error) if (debug or isinstance(error, GraphQLError)) else "Internal server error"
        formatted = {
            "message": message,
            "locations": [{"line": loc.line, "column": loc.column} for loc in (error.locations or [])],
            "path": error.path,
            "extensions": {
                "code": getattr(error, "extensions", {}).get("code", "INTERNAL_ERROR"),
                "request_id": getattr(getattr(getattr(error, "nodes", [None])[0], "context", None), "request_id", request_id),
            },
        }
        return formatted
    except Exception:
        # Last resort
        return {"message": "Internal server error", "extensions": {"code": "INTERNAL_ERROR"}}


# ------------------------------------------------------------------------------
# Router (mount into FastAPI)
# ------------------------------------------------------------------------------
extensions: List[Any] = []
if OpenTelemetryExtension is not None:
    extensions.append(OpenTelemetryExtension())
if QueryDepthLimiter is not None:
    max_depth = int(os.getenv("GRAPHQL_MAX_DEPTH", "15"))
    extensions.append(QueryDepthLimiter(max_depth=max_depth))

GRAPHQL_DEBUG = os.getenv("GRAPHQL_DEBUG", "false").lower() in ("1", "true", "yes")

router = GraphQLRouter(
    schema,
    graphiql=os.getenv("GRAPHQL_PLAYGROUND", "true").lower() in ("1", "true", "yes"),
    context_getter=context_getter,
    error_formatter=error_formatter,
    extensions=extensions,
)
