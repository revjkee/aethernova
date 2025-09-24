# -*- coding: utf-8 -*-
"""
policy-core GraphQL schema (industrial-grade, Strawberry)

Key features:
- Strawberry GraphQL with Relay (Node, Connection, cursor pagination)
- Types: Policy, PolicyBundle, Waiver, ValidationResult, CompiledArtifact
- Mutations: upsertPolicy, deletePolicy, createWaiver, revokeWaiver,
             validatePolicy, compilePolicy, ingestEvent
- Subscription: policyChanges (stream change events)
- Scalars: DateTime (ISO8601), JSONObject
- Enums aligned with OpenAPI/DSL: Environment, CompileTarget, Severity
- Error handling: RFC7807-like problem in GraphQL error extensions
- Permissions: IsAuthenticated / HasRole (field-level guards)
- Telemetry: optional Prometheus (counters/histograms) & OpenTelemetry spans
- Dataloaders: simple policy loader, easily extensible

This file assumes an application context `GQLContext` that exposes service layer:
  - policy_service: PolicyService
  - bundle_service: BundleService
  - waiver_service: WaiverService
  - validation_service: ValidationService
  - compile_service: CompileService
  - events_service: EventsService (async iterator for subscriptions)
  - user: current user info (id, roles)
Replace protocol definitions with your concrete implementations and wire via DI.
"""

from __future__ import annotations

import abc
import asyncio
import base64
import dataclasses
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Iterable, List, Optional, Protocol, Tuple

import strawberry
from strawberry import ID
from strawberry.types import Info
from strawberry.relay import Node
from strawberry.scalars import JSON
from strawberry.schema_directive import Location

# Optional dependencies (graceful fallback if missing)
try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore

try:
    from opentelemetry import trace
    from opentelemetry.trace import SpanKind
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    SpanKind = None  # type: ignore


# =============================================================================
# Scalars
# =============================================================================

@strawberry.scalar(description="RFC3339/ISO8601 datetime in UTC, e.g. 2025-08-28T12:34:56Z")
def DateTime(value: datetime) -> str:
    if isinstance(value, str):
        # parse on input
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            raise ValueError("Invalid DateTime format")
    if not isinstance(value, datetime):
        raise ValueError("Invalid DateTime type")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Use Strawberry's JSON scalar aliased as JSONObject for clarity
JSONObject = JSON


# =============================================================================
# Enums
# =============================================================================

@strawberry.enum
class Environment(Enum):
    DEV = "DEV"
    STAGING = "STAGING"
    PROD = "PROD"
    OTHER = "OTHER"


@strawberry.enum
class CompileTarget(Enum):
    REGO = "rego"
    CEL = "cel"
    WASM = "wasm"


@strawberry.enum
class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =============================================================================
# Error / Problem shapes (returned in GraphQL error extensions)
# =============================================================================

@dataclass
class ProblemExt:
    code: str
    title: str
    status: int
    detail: Optional[str] = None
    path: Optional[str] = None


def problem_ext(code: str, title: str, status: int, detail: Optional[str] = None, path: Optional[str] = None) -> Dict[str, Any]:
    return dataclasses.asdict(ProblemExt(code=code, title=title, status=status, detail=detail, path=path))


# =============================================================================
# Service layer protocols (replace with real implementations)
# =============================================================================

class PolicyService(Protocol):
    async def get(self, id_: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]: ...
    async def list(self, cursor: Optional[str], limit: int, q: Optional[str], env: Optional[Environment]) -> Tuple[List[Dict[str, Any]], Optional[str]]: ...
    async def upsert(self, policy: Dict[str, Any]) -> Dict[str, Any]: ...
    async def delete(self, id_: str) -> bool: ...


class BundleService(Protocol):
    async def get(self, id_: str) -> Optional[Dict[str, Any]]: ...
    async def list(self, cursor: Optional[str], limit: int) -> Tuple[List[Dict[str, Any]], Optional[str]]: ...
    async def upsert(self, bundle: Dict[str, Any]) -> Dict[str, Any]: ...


class WaiverService(Protocol):
    async def get(self, id_: str) -> Optional[Dict[str, Any]]: ...
    async def list(self, cursor: Optional[str], limit: int, rule_id: Optional[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]: ...
    async def create(self, waiver: Dict[str, Any]) -> Dict[str, Any]: ...
    async def revoke(self, id_: str) -> bool: ...


class ValidationService(Protocol):
    async def validate(self, policy: Dict[str, Any]) -> Dict[str, Any]: ...


class CompileService(Protocol):
    async def compile(self, id_: str, target: CompileTarget, options: Dict[str, Any]) -> Dict[str, Any]: ...


class EventsService(Protocol):
    def subscribe_policy_changes(self, environment: Optional[Environment]) -> AsyncGenerator[Dict[str, Any], None]: ...


# =============================================================================
# Context
# =============================================================================

@dataclass
class UserCtx:
    id: str
    roles: List[str]


@dataclass
class GQLContext:
    policy_service: PolicyService
    bundle_service: BundleService
    waiver_service: WaiverService
    validation_service: ValidationService
    compile_service: CompileService
    events_service: EventsService
    user: Optional[UserCtx] = None
    request_id: Optional[str] = None


# =============================================================================
# Permissions
# =============================================================================

class IsAuthenticated:
    message = "Authentication required"

    def has_permission(self, info: Info) -> bool:
        ctx: GQLContext = info.context
        return ctx.user is not None


class HasRole:
    def __init__(self, role: str) -> None:
        self.role = role
        self.message = f"Role '{role}' required"

    def has_permission(self, info: Info) -> bool:
        ctx: GQLContext = info.context
        return bool(ctx.user and self.role in (ctx.user.roles or []))


# =============================================================================
# Telemetry
# =============================================================================

if Counter and Histogram:
    GQL_REQ = Counter("policy_gql_requests_total", "GraphQL resolver requests", ["field", "type"])
    GQL_ERR = Counter("policy_gql_errors_total", "GraphQL resolver errors", ["field", "type", "code"])
    GQL_LAT = Histogram("policy_gql_duration_seconds", "Resolver duration", buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2))
else:  # no-op fallbacks
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_, **__): return None
        def observe(self, *_, **__): return None
    GQL_REQ = GQL_ERR = GQL_LAT = _Noop()


def traced(field_name: str, type_name: str):
    def deco(fn):
        async def wrapper(*args, **kwargs):
            GQL_REQ.labels(field_name, type_name).inc()
            span = None
            if trace:
                tracer = trace.get_tracer("policy-core.graphql")
                span = tracer.start_span(f"{type_name}.{field_name}", kind=SpanKind.SERVER if SpanKind else None)
            try:
                start = asyncio.get_running_loop().time() if asyncio.get_running_loop() else 0.0
                res = await fn(*args, **kwargs)
                end = asyncio.get_running_loop().time() if asyncio.get_running_loop() else start
                GQL_LAT.observe(max(0.0, end - start))
                if span:
                    span.set_attribute("success", True)
                return res
            except Exception as e:  # pragma: no cover
                if span:
                    span.set_attribute("success", False)
                # Best-effort classification
                code = getattr(e, "code", "INTERNAL")
                GQL_ERR.labels(field_name, type_name, str(code)).inc()
                raise
            finally:
                if span:
                    span.end()
        return wrapper
    return deco


# =============================================================================
# Relay helpers (simple base64 cursor encode/decode)
# =============================================================================

def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")


def _unb64(s: str) -> str:
    return base64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8")


# =============================================================================
# GraphQL Types
# =============================================================================

@strawberry.type
class PageInfo:
    has_next_page: bool
    end_cursor: Optional[str]


@strawberry.type
class ValidationError:
    code: str
    message: str
    path: Optional[str]


@strawberry.type
class ValidationResultGQL:
    ok: bool
    errors: List[ValidationError]
    warnings: List[str]
    metrics: JSONObject


@strawberry.type
class CompiledArtifact:
    target: CompileTarget
    module_name: Optional[str]
    uri: str
    sha256: str
    size_bytes: Optional[int]
    created_at: Optional[DateTime]


@strawberry.interface
class NodeBase(Node):
    id: ID


@strawberry.type
class Policy(NodeBase):
    id: ID
    api_version: str
    kind: str
    metadata: JSONObject
    spec: JSONObject
    signature: Optional[JSONObject]
    created_at: Optional[DateTime] = None
    updated_at: Optional[DateTime] = None

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Policy":
        return Policy(
            id=ID(d.get("metadata", {}).get("id", "")),
            api_version=d.get("apiVersion", ""),
            kind=d.get("kind", ""),
            metadata=d.get("metadata", {}),
            spec=d.get("spec", {}),
            signature=d.get("signature"),
            created_at=d.get("createdAt"),
            updated_at=d.get("updatedAt"),
        )


@strawberry.type
class PolicyEdge:
    cursor: str
    node: Policy


@strawberry.type
class PolicyConnection:
    page_info: PageInfo
    edges: List[PolicyEdge]
    total_count: Optional[int] = None  # if available


@strawberry.type
class PolicyBundle(NodeBase):
    id: ID
    api_version: str
    kind: str
    metadata: JSONObject
    spec: JSONObject
    items: Optional[List[Policy]] = None

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PolicyBundle":
        items = [Policy.from_dict(x) for x in d.get("items", [])] if d.get("items") else None
        return PolicyBundle(
            id=ID(d.get("metadata", {}).get("id", "")),
            api_version=d.get("apiVersion", ""),
            kind=d.get("kind", ""),
            metadata=d.get("metadata", {}),
            spec=d.get("spec", {}),
            items=items,
        )


@strawberry.type
class Waiver(NodeBase):
    id: ID
    rule: str
    scope: JSONObject
    reason: str
    risk: Optional[JSONObject]
    ticket: Optional[JSONObject]
    granted_by: str
    granted_at: DateTime
    expires_at: DateTime
    labels: Optional[JSONObject]

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Waiver":
        return Waiver(
            id=ID(d.get("id", "")),
            rule=d.get("rule", ""),
            scope=d.get("scope", {}),
            reason=d.get("reason", ""),
            risk=d.get("risk"),
            ticket=d.get("ticket"),
            granted_by=d.get("grantedBy", ""),
            granted_at=d.get("grantedAt"),
            expires_at=d.get("expiresAt"),
            labels=d.get("labels"),
        )


# =============================================================================
# Inputs
# =============================================================================

@strawberry.input
class PolicyFilter:
    q: Optional[str] = None
    environment: Optional[Environment] = None


@strawberry.input
class PolicyInput:
    apiVersion: str
    kind: str
    metadata: JSONObject
    spec: JSONObject
    signature: Optional[JSONObject] = None


@strawberry.input
class WaiverInput:
    id: Optional[str] = None
    rule: str
    scope: JSONObject
    reason: str
    risk: Optional[JSONObject] = None
    ticket: Optional[JSONObject] = None
    grantedBy: str
    grantedAt: DateTime
    expiresAt: DateTime
    labels: Optional[JSONObject] = None


# =============================================================================
# Query
# =============================================================================

@strawberry.type
class Query:
    @strawberry.field(description="Get policy by id (and optional version)")
    @traced("policy", "Query")
    async def policy(self, info: Info, id: ID, version: Optional[str] = None) -> Optional[Policy]:
        ctx: GQLContext = info.context
        data = await ctx.policy_service.get(str(id), version)
        return Policy.from_dict(data) if data else None

    @strawberry.field(description="List policies with cursor pagination")
    @traced("policies", "Query")
    async def policies(
        self,
        info: Info,
        first: int = 100,
        after: Optional[str] = None,
        filter: Optional[PolicyFilter] = None,
    ) -> PolicyConnection:
        ctx: GQLContext = info.context
        limit = max(1, min(first, 500))
        q = filter.q if filter else None
        env = filter.environment if (filter and filter.environment) else None
        items, next_cursor = await ctx.policy_service.list(cursor=after, limit=limit, q=q, env=env)
        edges = [PolicyEdge(cursor=_b64(p["metadata"]["id"]), node=Policy.from_dict(p)) for p in items]
        page_info = PageInfo(has_next_page=bool(next_cursor), end_cursor=next_cursor)
        return PolicyConnection(page_info=page_info, edges=edges)

    @strawberry.field(description="Get bundle by id")
    @traced("bundle", "Query")
    async def bundle(self, info: Info, id: ID) -> Optional[PolicyBundle]:
        ctx: GQLContext = info.context
        data = await ctx.bundle_service.get(str(id))
        return PolicyBundle.from_dict(data) if data else None

    @strawberry.field(description="List bundles with cursor pagination")
    @traced("bundles", "Query")
    async def bundles(self, info: Info, first: int = 50, after: Optional[str] = None) -> PolicyConnection:
        ctx: GQLContext = info.context
        limit = max(1, min(first, 200))
        items, next_cursor = await ctx.bundle_service.list(cursor=after, limit=limit)
        # Reuse PolicyConnection shape by mapping bundles as policies is not ideal;
        # in a full schema create BundleConnection type; kept compact here.
        edges = [PolicyEdge(cursor=_b64(b["metadata"]["id"]), node=Policy.from_dict(b)) for b in items]
        page_info = PageInfo(has_next_page=bool(next_cursor), end_cursor=next_cursor)
        return PolicyConnection(page_info=page_info, edges=edges)

    @strawberry.field(description="Get waiver by id")
    @traced("waiver", "Query")
    async def waiver(self, info: Info, id: ID) -> Optional[Waiver]:
        ctx: GQLContext = info.context
        data = await ctx.waiver_service.get(str(id))
        return Waiver.from_dict(data) if data else None

    @strawberry.field(description="List waivers with cursor pagination")
    @traced("waivers", "Query")
    async def waivers(
        self, info: Info, first: int = 100, after: Optional[str] = None, rule_id: Optional[str] = None
    ) -> Tuple[List[Waiver], PageInfo]:
        ctx: GQLContext = info.context
        limit = max(1, min(first, 500))
        items, next_cursor = await ctx.waiver_service.list(cursor=after, limit=limit, rule_id=rule_id)
        page_info = PageInfo(has_next_page=bool(next_cursor), end_cursor=next_cursor)
        return [Waiver.from_dict(w) for w in items], page_info


# =============================================================================
# Mutations
# =============================================================================

@strawberry.type
class DeletePayload:
    ok: bool


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Create or update a policy")
    @traced("upsertPolicy", "Mutation")
    async def upsert_policy(self, info: Info, input: PolicyInput) -> Policy:
        ctx: GQLContext = info.context
        if not IsAuthenticated().has_permission(info):
            raise strawberry.exceptions.PermissionError(message=IsAuthenticated.message)
        data = await ctx.policy_service.upsert(dataclasses.asdict(input))
        return Policy.from_dict(data)

    @strawberry.mutation(description="Delete a policy by id")
    @traced("deletePolicy", "Mutation")
    async def delete_policy(self, info: Info, id: ID) -> DeletePayload:
        ctx: GQLContext = info.context
        if not HasRole("admin").has_permission(info):
            raise strawberry.exceptions.PermissionError(message=HasRole("admin").message)
        ok = await ctx.policy_service.delete(str(id))
        return DeletePayload(ok=bool(ok))

    @strawberry.mutation(description="Validate a policy payload (returns ValidationResult)")
    @traced("validatePolicy", "Mutation")
    async def validate_policy(self, info: Info, input: PolicyInput) -> ValidationResultGQL:
        ctx: GQLContext = info.context
        res = await ctx.validation_service.validate(dataclasses.asdict(input))
        return ValidationResultGQL(
            ok=bool(res.get("ok")),
            errors=[ValidationError(code=e["code"], message=e["message"], path=e.get("path")) for e in res.get("errors", [])],
            warnings=res.get("warnings", []),
            metrics=res.get("metrics", {}),
        )

    @strawberry.mutation(description="Compile a policy to target format (Rego/CEL/WASM)")
    @traced("compilePolicy", "Mutation")
    async def compile_policy(
        self, info: Info, id: ID, target: CompileTarget, options: Optional[JSONObject] = None
    ) -> CompiledArtifact:
        ctx: GQLContext = info.context
        data = await ctx.compile_service.compile(str(id), target, dict(options or {}))
        return CompiledArtifact(
            target=target,
            module_name=data.get("moduleName"),
            uri=data["uri"],
            sha256=data["sha256"],
            size_bytes=data.get("sizeBytes"),
            created_at=data.get("createdAt"),
        )

    @strawberry.mutation(description="Create a waiver (exception)")
    @traced("createWaiver", "Mutation")
    async def create_waiver(self, info: Info, input: WaiverInput) -> Waiver:
        ctx: GQLContext = info.context
        if not HasRole("security").has_permission(info):
            raise strawberry.exceptions.PermissionError(message=HasRole("security").message)
        created = await ctx.waiver_service.create(dataclasses.asdict(input))
        return Waiver.from_dict(created)

    @strawberry.mutation(description="Revoke a waiver by id")
    @traced("revokeWaiver", "Mutation")
    async def revoke_waiver(self, info: Info, id: ID) -> DeletePayload:
        ctx: GQLContext = info.context
        if not HasRole("security").has_permission(info):
            raise strawberry.exceptions.PermissionError(message=HasRole("security").message)
        ok = await ctx.waiver_service.revoke(str(id))
        return DeletePayload(ok=bool(ok))

    @strawberry.mutation(description="Ingest a policy change event (CloudEvents JSON-like)")
    @traced("ingestEvent", "Mutation")
    async def ingest_event(self, info: Info, event: JSONObject) -> bool:
        ctx: GQLContext = info.context
        # Delegate to events service if it supports ingestion
        if not hasattr(ctx.events_service, "ingest"):  # type: ignore
            # graceful behavior
            return False
        return bool(await ctx.events_service.ingest(dict(event)))  # type: ignore


# =============================================================================
# Subscriptions
# =============================================================================

@strawberry.type
class Subscription:
    @strawberry.subscription(description="Subscribe to policy change events")
    async def policy_changes(self, info: Info, environment: Optional[Environment] = None) -> AsyncGenerator[JSONObject, None]:
        ctx: GQLContext = info.context
        async for evt in ctx.events_service.subscribe_policy_changes(environment):
            yield JSONObject(evt)


# =============================================================================
# Error formatter (attach RFC7807-like extensions)
# =============================================================================

def custom_error_formatter(error: strawberry.types.GraphQLError, debug: bool) -> strawberry.types.GraphQLError:
    # Attach default extension if none present
    if not error.extensions:
        error.extensions = {}
    if "problem" not in error.extensions:
        title = "GraphQL Error"
        code = "INTERNAL"
        status = 500
        detail = error.message
        # PermissionError mapping
        if isinstance(error.original_error, strawberry.exceptions.PermissionError):  # type: ignore
            code, title, status = "FORBIDDEN", "Forbidden", 403
        error.extensions["problem"] = problem_ext(code=code, title=title, status=status, detail=detail)
    return error


# =============================================================================
# Schema (export)
# =============================================================================

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    scalar_overrides={datetime: DateTime},
    extensions=[],
    # Install custom error formatter
    config=strawberry.SchemaConfig(error_formatter=custom_error_formatter),
)

# Notes for ASGI integration (do not execute here):
# from strawberry.asgi import GraphQL
# graphql_app = GraphQL(schema, context_getter=lambda request: GQLContext(..., request_id=request.headers.get("X-Request-ID")))
