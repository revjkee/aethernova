# File: security-core/api/graphql/server.py
# Industrial-grade GraphQL server for security-core (Secrets domain)
# Stack: FastAPI (as host), Ariadne (GraphQL), graphql-core
# Python: 3.10+
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import typing as t
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

# Ariadne / graphql-core
from ariadne import (
    QueryType,
    MutationType,
    make_executable_schema,
    ScalarType,
    load_schema_from_path,
    gql,
)
from ariadne.asgi import GraphQL
from graphql import (
    GraphQLError,
    ValidationRule,
    ASTValidationContext,
    OperationDefinitionNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    FieldNode,
    visit,
)

# ---------------------------
# Env toggles & constants
# ---------------------------

ENV = os.getenv("ENV", os.getenv("PYTHON_ENV", "production")).lower()
DEBUG = os.getenv("SECURITY_CORE_DEBUG", "").lower() in {"1", "true", "yes"} or ENV in {
    "dev",
    "development",
    "debug",
    "local",
}
GRAPHQL_INTROSPECTION = DEBUG or os.getenv("GRAPHQL_INTROSPECTION", "false").lower() in {"1", "true", "yes"}
GRAPHQL_PLAYGROUND = DEBUG or os.getenv("GRAPHQL_PLAYGROUND", "false").lower() in {"1", "true", "yes"}

MAX_QUERY_DEPTH = int(os.getenv("GRAPHQL_MAX_DEPTH", "10"))
MAX_QUERY_COST = int(os.getenv("GRAPHQL_MAX_COST", "5000"))

APQ_ENABLED = os.getenv("GRAPHQL_APQ", "false").lower() in {"1", "true", "yes"}

# ---------------------------
# Domain integration (Subject, SecretService)
# ---------------------------

class SecretState(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    SOFT_DELETED = "soft_deleted"


class SecretType(str, Enum):
    GENERIC = "generic"
    API_KEY = "api_key"
    CREDENTIALS = "credentials"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY_HANDLE = "private_key_handle"


@dataclass
class Subject:
    sub: str
    tenant_id: t.Optional[str]
    roles: list[str]
    scopes: list[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes

    def is_admin(self) -> bool:
        return "admin" in self.roles or "security.admin" in self.roles


# Prefer project dependencies if present
try:
    from security_core.api.http.dependencies import get_current_subject  # type: ignore
except Exception:  # pragma: no cover
    async def get_current_subject(request: Request) -> Subject:
        raise GraphQLError("Unauthorized")


class SecretVersionInfo(t.TypedDict, total=False):
    version_id: str
    created_at: datetime
    expires_at: t.Optional[datetime]
    enabled: bool
    checksum_sha256: t.Optional[str]


class SecretSummary(t.TypedDict, total=False):
    id: str
    name: str
    type: SecretType
    state: SecretState
    created_at: datetime
    updated_at: datetime
    tags: list[str]
    has_value: bool
    current_version_id: t.Optional[str]
    etag: t.Optional[str]


class SecretDetail(SecretSummary, total=False):
    value: t.Optional[str]
    metadata: dict[str, t.Any]
    versions: t.Optional[list[SecretVersionInfo]]


class Page(t.TypedDict, total=False):
    items: list[SecretSummary]
    next_page_token: t.Optional[str]


class SecretService:
    async def create_secret(self, subject: Subject, payload: dict) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def list_secrets(
        self,
        subject: Subject,
        *,
        name_contains: t.Optional[str],
        secret_type: t.Optional[SecretType],
        tag: t.Optional[str],
        state: t.Optional[SecretState],
        page_size: int,
        page_token: t.Optional[str],
    ) -> tuple[list[SecretSummary], t.Optional[str]]:  # pragma: no cover
        raise NotImplementedError

    async def get_secret(self, subject: Subject, secret_id: str, *, include_value: bool) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def get_versions(self, subject: Subject, secret_id: str) -> list[SecretVersionInfo]:  # pragma: no cover
        raise NotImplementedError

    async def rotate(self, subject: Subject, secret_id: str, payload: dict) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def update(self, subject: Subject, secret_id: str, payload: dict) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError

    async def delete(self, subject: Subject, secret_id: str, *, hard: bool) -> None:  # pragma: no cover
        raise NotImplementedError

    async def restore(self, subject: Subject, secret_id: str) -> SecretDetail:  # pragma: no cover
        raise NotImplementedError


try:
    from security_core.domain.secrets import get_secret_service  # type: ignore
except Exception:  # pragma: no cover
    async def get_secret_service() -> SecretService:
        raise GraphQLError("Service unavailable")


# ---------------------------
# Scalars
# ---------------------------

datetime_scalar = ScalarType("DateTime")
json_scalar = ScalarType("JSON")

@datetime_scalar.serializer
def serialize_datetime(value: datetime) -> str:
    return value.isoformat()

@datetime_scalar.value_parser
def parse_datetime_value(value: str) -> datetime:
    return datetime.fromisoformat(value)

@json_scalar.serializer
def serialize_json(value: t.Any) -> t.Any:
    return value

@json_scalar.value_parser
def parse_json_value(value: t.Any) -> t.Any:
    return value

# ---------------------------
# SDL (schema)
# ---------------------------

SDL = gql("""
scalar DateTime
scalar JSON

enum SecretState { ACTIVE DISABLED SOFT_DELETED }
enum SecretType { GENERIC API_KEY CREDENTIALS TOKEN CERTIFICATE PRIVATE_KEY_HANDLE }

type SecretVersionInfo {
  versionId: ID!
  createdAt: DateTime!
  expiresAt: DateTime
  enabled: Boolean!
  checksumSha256: String
}

type SecretSummary {
  id: ID!
  name: String!
  type: SecretType!
  state: SecretState!
  createdAt: DateTime!
  updatedAt: DateTime!
  tags: [String!]!
  hasValue: Boolean!
  currentVersionId: ID
  etag: String
}

type SecretDetail {
  id: ID!
  name: String!
  type: SecretType!
  state: SecretState!
  createdAt: DateTime!
  updatedAt: DateTime!
  tags: [String!]!
  hasValue: Boolean!
  currentVersionId: ID
  etag: String
  value: String
  metadata: JSON!
  versions: [SecretVersionInfo!]
}

input SecretsFilter {
  nameContains: String
  type: SecretType
  tag: String
  state: SecretState
}

type SecretsPage {
  items: [SecretSummary!]!
  nextPageToken: String
}

input SecretCreateInput {
  name: String!
  type: SecretType = GENERIC
  value: String
  tags: [String!]
  metadata: JSON
  ttlSeconds: Int
  rotationPeriodDays: Int
  allowReadOnce: Boolean = false
}

input SecretRotateInput {
  newValue: String
  versionMetadata: JSON
  expiresAt: DateTime
  enableNewVersion: Boolean = true
}

input SecretUpdateInput {
  name: String
  tags: [String!]
  metadata: JSON
  state: SecretState
  rotationPeriodDays: Int
}

type DeleteResult { ok: Boolean! }

type Query {
  secret(id: ID!, reveal: Boolean = false): SecretDetail!
  secrets(filter: SecretsFilter, pageSize: Int = 50, pageToken: String): SecretsPage!
  secretVersions(id: ID!): [SecretVersionInfo!]!
}

type Mutation {
  createSecret(input: SecretCreateInput!): SecretDetail!
  rotateSecret(id: ID!, input: SecretRotateInput!): SecretDetail!
  updateSecret(id: ID!, input: SecretUpdateInput!): SecretDetail!
  deleteSecret(id: ID!, hard: Boolean = false): DeleteResult!
  restoreSecret(id: ID!): SecretDetail!
}
""")

# ---------------------------
# Resolvers
# ---------------------------

query = QueryType()
mutation = MutationType()

def _compute_etag(summary: SecretSummary) -> str:
    base = f"{summary['id']}:{summary['updated_at'].isoformat()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

async def _require_scope(subject: Subject, scope: str) -> None:
    if not (subject.has_scope(scope) or subject.is_admin()):
        raise GraphQLError(f"Forbidden: missing scope {scope}")

@query.field("secrets")
async def resolve_secrets(*_, filter: t.Optional[dict] = None, pageSize: int = 50, pageToken: t.Optional[str] = None, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:read")
    svc: SecretService = ctx.svc
    name_contains = (filter or {}).get("nameContains")
    secret_type = (filter or {}).get("type")
    tag = (filter or {}).get("tag")
    state = (filter or {}).get("state")
    items, token = await svc.list_secrets(
        subject,
        name_contains=name_contains,
        secret_type=secret_type,
        tag=tag,
        state=state,
        page_size=pageSize,
        page_token=pageToken,
    )
    # normalize etag
    for s in items:
        s["etag"] = s.get("etag") or _compute_etag(s)
    return {"items": [_to_summary_gql(s) for s in items], "nextPageToken": token}

@query.field("secret")
async def resolve_secret(*_, id: str, reveal: bool = False, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:read")
    include_value = False
    if reveal:
        await _require_scope(subject, "secrets:read:value")
        include_value = True
    svc: SecretService = ctx.svc
    detail = await svc.get_secret(subject, id, include_value=include_value)
    return _to_detail_gql(detail, include_value)

@query.field("secretVersions")
async def resolve_secret_versions(*_, id: str, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:read")
    svc: SecretService = ctx.svc
    versions = await svc.get_versions(subject, id)
    return [_to_version_gql(v) for v in versions]

@mutation.field("createSecret")
async def resolve_create_secret(*_, input: dict, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:write")
    svc: SecretService = ctx.svc
    created = await svc.create_secret(subject, _create_payload_from_input(input))
    # never leak value on create unless caller has read:value
    include_value = subject.has_scope("secrets:read:value") or subject.is_admin()
    return _to_detail_gql(created, include_value=include_value)

@mutation.field("rotateSecret")
async def resolve_rotate_secret(*_, id: str, input: dict, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:write")
    svc: SecretService = ctx.svc
    rotated = await svc.rotate(subject, id, _rotate_payload_from_input(input))
    include_value = subject.has_scope("secrets:read:value") or subject.is_admin()
    return _to_detail_gql(rotated, include_value=include_value)

@mutation.field("updateSecret")
async def resolve_update_secret(*_, id: str, input: dict, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:write")
    svc: SecretService = ctx.svc
    updated = await svc.update(subject, id, _update_payload_from_input(input))
    return _to_detail_gql(updated, include_value=False)

@mutation.field("deleteSecret")
async def resolve_delete_secret(*_, id: str, hard: bool = False, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:write")
    if hard and not subject.is_admin():
        raise GraphQLError("Forbidden: hard delete requires admin")
    svc: SecretService = ctx.svc
    await svc.delete(subject, id, hard=hard)
    return {"ok": True}

@mutation.field("restoreSecret")
async def resolve_restore_secret(*_, id: str, **__):
    ctx = _ctx()
    subject: Subject = ctx.subject
    await _require_scope(subject, "secrets:write")
    svc: SecretService = ctx.svc
    restored = await svc.restore(subject, id)
    return _to_detail_gql(restored, include_value=False)

# ---------------------------
# Mapping helpers
# ---------------------------

def _to_summary_gql(s: SecretSummary) -> dict:
    return {
        "id": s["id"],
        "name": s["name"],
        "type": s["type"].name if isinstance(s["type"], Enum) else s["type"],
        "state": s["state"].name if isinstance(s["state"], Enum) else s["state"],
        "createdAt": s["created_at"],
        "updatedAt": s["updated_at"],
        "tags": s.get("tags", []),
        "hasValue": s.get("has_value", False),
        "currentVersionId": s.get("current_version_id"),
        "etag": s.get("etag"),
    }

def _to_detail_gql(d: SecretDetail, include_value: bool) -> dict:
    base = _to_summary_gql(d)
    base.update({
        "metadata": d.get("metadata", {}),
        "versions": [_to_version_gql(v) for v in d.get("versions", [])] if d.get("versions") else None,
        "value": d.get("value") if include_value else None,
    })
    return base

def _to_version_gql(v: SecretVersionInfo) -> dict:
    return {
        "versionId": v["version_id"],
        "createdAt": v["created_at"],
        "expiresAt": v.get("expires_at"),
        "enabled": v.get("enabled", True),
        "checksumSha256": v.get("checksum_sha256"),
    }

def _create_payload_from_input(i: dict) -> dict:
    return {
        "name": i["name"],
        "type": i.get("type", SecretType.GENERIC),
        "value": i.get("value"),
        "tags": i.get("tags") or [],
        "metadata": i.get("metadata") or {},
        "ttl_seconds": i.get("ttlSeconds"),
        "rotation_period_days": i.get("rotationPeriodDays"),
        "allow_read_once": i.get("allowReadOnce", False),
    }

def _rotate_payload_from_input(i: dict) -> dict:
    return {
        "new_value": i.get("newValue"),
        "version_metadata": i.get("versionMetadata") or {},
        "expires_at": i.get("expiresAt"),
        "enable_new_version": i.get("enableNewVersion", True),
    }

def _update_payload_from_input(i: dict) -> dict:
    return {
        "name": i.get("name"),
        "tags": i.get("tags"),
        "metadata": i.get("metadata"),
        "state": i.get("state"),
        "rotation_period_days": i.get("rotationPeriodDays"),
    }

# ---------------------------
# Context & DataLoaders
# ---------------------------

@dataclass
class GraphQLContext:
    request: Request
    subject: Subject
    svc: SecretService
    loaders: dict[str, t.Any]

# thread-local like holder (simple, because resolvers run in same task)
_ctx_var: asyncio.TaskLocal[GraphQLContext] = asyncio.TaskLocal()  # type: ignore[attr-defined]

def _ctx() -> GraphQLContext:
    ctx = getattr(_ctx_var, "value", None)
    if ctx is None:
        raise RuntimeError("GraphQL context is not initialized")
    return ctx

async def context_value_fn(request: Request) -> GraphQLContext:
    subject = await get_current_subject(request)  # raises if unauth
    svc = await get_secret_service()
    ctx = GraphQLContext(request=request, subject=subject, svc=svc, loaders={})
    _ctx_var.value = ctx  # set for resolvers
    return ctx

# ---------------------------
# Error formatting
# ---------------------------

def format_error_fn(err: GraphQLError) -> dict:
    # Map domain exceptions (SecurityCoreError) if present
    original = err.original_error
    is_debug = DEBUG
    extensions: dict[str, t.Any] = {"code": "INTERNAL_ERROR"}
    message = "Internal server error"

    if isinstance(original, GraphQLError):
        # unlikely, but normalize
        original = original.original_error

    # Try map common cases
    if original:
        name = type(original).__name__
        if name in {"AuthenticationError"}:
            extensions["code"] = "AUTH_FAILED"
            message = "Authentication failed"
        elif name in {"AuthorizationError"}:
            extensions["code"] = "FORBIDDEN"
            message = "Access denied"
        elif name in {"NotFoundError"}:
            extensions["code"] = "NOT_FOUND"
            message = "Resource not found"
        elif name in {"ConflictError"}:
            extensions["code"] = "CONFLICT"
            message = "Conflict"
        elif name in {"ValidationFailed", "ValueError"}:
            extensions["code"] = "VALIDATION_FAILED"
            message = "Validation failed"

    if is_debug:
        # expose full GraphQLError dict in debug
        payload = err.formatted
        payload["extensions"] = payload.get("extensions", {}) | extensions
        return payload

    # production: minimize leakage
    return {
        "message": message,
        "locations": err.locations,
        "path": err.path,
        "extensions": extensions,
    }

# ---------------------------
# Query depth & cost validation
# ---------------------------

class DepthLimitRule(ValidationRule):
    def __init__(self, context: ASTValidationContext, max_depth: int) -> None:
        super().__init__(context)
        self.max_depth = max_depth
        self.current_depth = 0
        self.max_seen = 0

    def enter_operation_definition(self, node: OperationDefinitionNode, *_):
        self.current_depth = 0
        self.max_seen = 0

    def enter_field(self, node: FieldNode, *_):
        self.current_depth += 1
        self.max_seen = max(self.max_seen, self.current_depth)
        if self.max_seen > self.max_depth:
            self.context.report_error(
                GraphQLError(f"Query is too deep: {self.max_seen} > {self.max_depth}", [node])
            )

    def leave_field(self, node: FieldNode, *_):
        self.current_depth -= 1


class CostLimitRule(ValidationRule):
    # naive cost model: each field cost=1; for list fields with pageSize arg multiplies by pageSize (default 50)
    def __init__(self, context: ASTValidationContext, max_cost: int) -> None:
        super().__init__(context)
        self.max_cost = max_cost
        self.cost = 0

    def enter_field(self, node: FieldNode, *_):
        field_cost = 1
        if node.arguments:
            for arg in node.arguments:
                if arg.name.value in {"pageSize", "first", "limit"}:
                    try:
                        # arg.value could be IntValue or Variable
                        if hasattr(arg.value, "value"):
                            field_cost *= int(arg.value.value)
                    except Exception:
                        pass
        self.cost += field_cost
        if self.cost > self.max_cost:
            self.context.report_error(
                GraphQLError(f"Query is too expensive: {self.cost} > {self.max_cost}", [node])
            )

# Factory that supplies both rules with configured limits
def validation_rules_fn(context: ASTValidationContext) -> list[ValidationRule]:
    return [
        DepthLimitRule(context, MAX_QUERY_DEPTH),
        CostLimitRule(context, MAX_QUERY_COST),
    ]

# ---------------------------
# APQ (Automatic Persisted Queries) skeleton (optional)
# ---------------------------

class APQStore:
    async def get(self, sha256: str) -> t.Optional[str]:  # pragma: no cover
        return None

    async def put(self, sha256: str, query: str) -> None:  # pragma: no cover
        return None

async def apq_middleware(request: Request, call_next):
    if not APQ_ENABLED:
        return await call_next(request)
    if request.method == "POST" and request.headers.get("content-type", "").startswith("application/json"):
        body = await request.body()
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return JSONResponse({"errors": [{"message": "Invalid JSON"}]}, status_code=400)

        ext = (payload.get("extensions") or {}).get("persistedQuery")
        if ext and ext.get("version") == 1:
            sha = ext.get("sha256Hash")
            store: APQStore = request.app.state.graphql_apq_store  # type: ignore[attr-defined]
            query = payload.get("query")
            if query:
                # register
                if hashlib.sha256(query.encode("utf-8")).hexdigest() != sha:
                    return JSONResponse({"errors": [{"message": "APQ hash mismatch"}]}, status_code=400)
                await store.put(sha, query)
            else:
                # lookup
                q = await store.get(sha)
                if not q:
                    return JSONResponse({"errors": [{"message": "PersistedQueryNotFound"}]}, status_code=200)
                payload["query"] = q
                scope = {"type": "http", "method": "POST", "path": request.url.path, "headers": request.scope.get("headers", [])}
                async def receive():
                    return {"type": "http.request", "body": json.dumps(payload).encode("utf-8")}
                request._receive = receive  # type: ignore
    return await call_next(request)

# ---------------------------
# Build schema & app
# ---------------------------

schema = make_executable_schema(
    SDL,
    [query, mutation, datetime_scalar, json_scalar],
)

def _extensions():
    # graphql-core expects callables; we pass validation rule factory through GraphQL constructor
    return None

def build_graphql_asgi() -> ASGIApp:
    return GraphQL(
        schema,
        debug=DEBUG,
        introspection=GRAPHQL_INTROSPECTION,
        context_value=context_value_fn,
        error_formatter=format_error_fn,
        validation_rules=validation_rules_fn,  # depth & cost
        extensions=_extensions(),
    )

# ---------------------------
# Mounting into FastAPI
# ---------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        # Basic hardening headers; adjust as needed
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

def mount_graphql(app: FastAPI, path: str = "/api/graphql") -> None:
    graphql_asgi = build_graphql_asgi()
    app.add_middleware(SecurityHeadersMiddleware)
    if APQ_ENABLED:
        app.middleware("http")(apq_middleware)
        app.state.graphql_apq_store = APQStore()  # type: ignore[attr-defined]
    app.mount(path, graphql_asgi)

# Optional: expose a convenience factory for external use
def get_graphql_app() -> ASGIApp:
    return build_graphql_asgi()
