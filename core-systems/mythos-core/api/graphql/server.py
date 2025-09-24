from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import typing as t
import uuid
from dataclasses import asdict
from functools import cached_property

import strawberry
from fastapi import FastAPI, Request, Response, status
from strawberry.fastapi import GraphQLRouter
from strawberry.schema.config import StrawberryConfig
from strawberry.types import Info

# graphql-core validation
from graphql import GraphQLError, DocumentNode, OperationDefinitionNode, FieldNode, visit
from graphql.validation import ValidationRule

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class Settings:
    def __init__(self) -> None:
        self.debug: bool = os.getenv("MYTHOS_GRAPHQL_DEBUG", "false").lower() == "true"
        self.enable_graphiql: bool = os.getenv("MYTHOS_GRAPHQL_GRAPHIQL", "false").lower() == "true"
        self.depth_limit: int = int(os.getenv("MYTHOS_GRAPHQL_MAX_DEPTH", "15"))
        self.field_limit: int = int(os.getenv("MYTHOS_GRAPHQL_MAX_FIELDS", "2000"))
        self.keepalive_sec: int = int(os.getenv("MYTHOS_GRAPHQL_WS_KEEPALIVE_SEC", "20"))
        self.idempotency_ttl_sec: int = int(os.getenv("MYTHOS_GRAPHQL_IDEMP_TTL_SEC", "86400"))
        self.apq_ttl_sec: int = int(os.getenv("MYTHOS_GRAPHQL_APQ_TTL_SEC", "86400"))
        self.path: str = os.getenv("MYTHOS_GRAPHQL_PATH", "/graphql")


settings = Settings()

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def gen_request_id() -> str:
    return str(uuid.uuid4())

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# Idempotency (for mutations) & APQ cache
# ---------------------------------------------------------------------------

class LruTtlCache:
    def __init__(self, maxsize: int = 10000) -> None:
        self._data: dict[str, tuple[bytes, float]] = {}
        self._order: list[str] = []
        self._max = maxsize
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> t.Optional[bytes]:
        async with self._lock:
            self._purge()
            if key in self._data:
                # move to tail
                self._order.remove(key)
                self._order.append(key)
                return self._data[key][0]
            return None

    async def set(self, key: str, value: bytes, ttl_sec: int) -> None:
        async with self._lock:
            self._purge()
            if key in self._data:
                self._order.remove(key)
            self._data[key] = (value, asyncio.get_event_loop().time() + ttl_sec)
            self._order.append(key)
            while len(self._order) > self._max:
                oldest = self._order.pop(0)
                self._data.pop(oldest, None)

    def _purge(self) -> None:
        now = asyncio.get_event_loop().time()
        for k in list(self._order):
            exp = self._data.get(k, (b"", 0.0))[1]
            if exp <= now:
                self._order.remove(k)
                self._data.pop(k, None)


idem_cache = LruTtlCache()
apq_cache = LruTtlCache()

# ---------------------------------------------------------------------------
# Service contracts (thin facade to your application layer)
# ---------------------------------------------------------------------------

# NOTE: ожидается, что FastAPI app.state.dialogue_service предоставит объект
# с методами create_dialogue, append_turn, get_dialogue, list_dialogues, stream_events
# интерфейс совместим с тем, что определён в REST-роутере.

# ---------------------------------------------------------------------------
# Domain GraphQL types (aligned with REST/Proto/SDK)
# ---------------------------------------------------------------------------

@strawberry.enum
class Actor:
    ACTOR_UNSPECIFIED = "ACTOR_UNSPECIFIED"
    ACTOR_USER = "ACTOR_USER"
    ACTOR_ASSISTANT = "ACTOR_ASSISTANT"
    ACTOR_SYSTEM = "ACTOR_SYSTEM"
    ACTOR_TOOL = "ACTOR_TOOL"


@strawberry.enum
class DialogueStatus:
    DIALOGUE_STATUS_UNSPECIFIED = "DIALOGUE_STATUS_UNSPECIFIED"
    DIALOGUE_OPEN = "DIALOGUE_OPEN"
    DIALOGUE_CLOSED = "DIALOGUE_CLOSED"
    DIALOGUE_ARCHIVED = "DIALOGUE_ARCHIVED"


@strawberry.enum
class ToolCallStatus:
    TOOL_CALL_STATUS_UNSPECIFIED = "TOOL_CALL_STATUS_UNSPECIFIED"
    TOOL_CALL_PENDING = "TOOL_CALL_PENDING"
    TOOL_CALL_SUCCESS = "TOOL_CALL_SUCCESS"
    TOOL_CALL_ERROR = "TOOL_CALL_ERROR"
    TOOL_CALL_TIMEOUT = "TOOL_CALL_TIMEOUT"
    TOOL_CALL_CANCELLED = "TOOL_CALL_CANCELLED"


@strawberry.enum
class Severity:
    SEVERITY_UNSPECIFIED = "SEVERITY_UNSPECIFIED"
    SEVERITY_LOW = "SEVERITY_LOW"
    SEVERITY_MEDIUM = "SEVERITY_MEDIUM"
    SEVERITY_HIGH = "SEVERITY_HIGH"
    SEVERITY_CRITICAL = "SEVERITY_CRITICAL"


@strawberry.type
class TokenUsage:
    prompt_tokens: t.Optional[int] = None
    completion_tokens: t.Optional[int] = None
    total_tokens: t.Optional[int] = None


@strawberry.type
class SafetyLabel:
    policy: str
    severity: Severity
    tags: t.Optional[list[str]] = None
    reason: t.Optional[str] = None
    details: t.Optional[dict[str, str]] = None


@strawberry.type
class Attachment:
    attachment_id: strawberry.ID
    filename: str
    mime_type: str
    size_bytes: int
    sha256_hex: t.Optional[str] = None
    uri: t.Optional[str] = None
    metadata: t.Optional[dict[str, t.Any]] = None


@strawberry.type
class ToolCall:
    call_id: strawberry.ID
    tool_name: str
    input: t.Optional[dict[str, t.Any]] = None
    output: t.Optional[dict[str, t.Any]] = None
    status: t.Optional[ToolCallStatus] = None
    latency: t.Optional[str] = None
    error_message: t.Optional[str] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.type
class Participant:
    participant_id: strawberry.ID
    display_name: str
    role: t.Optional[str] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.type
class Turn:
    turn_id: strawberry.ID
    actor: Actor
    created_at: dt.datetime
    parent_turn_id: t.Optional[strawberry.ID] = None
    text: t.Optional[str] = None
    data: t.Optional[dict[str, t.Any]] = None
    tool: t.Optional[ToolCall] = None
    attachments: t.Optional[list[Attachment]] = None
    safety: t.Optional[list[SafetyLabel]] = None
    usage: t.Optional[TokenUsage] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.type
class Dialogue:
    dialogue_id: strawberry.ID
    status: DialogueStatus
    title: t.Optional[str] = None
    participants: t.Optional[list[Participant]] = None
    created_at: dt.datetime
    updated_at: t.Optional[dt.datetime] = None
    last_turn_id: t.Optional[strawberry.ID] = None
    turns: t.Optional[list[Turn]] = None
    labels: t.Optional[dict[str, str]] = None
    usage_total: t.Optional[TokenUsage] = None


@strawberry.type
class PageTurns:
    turns: list[Turn]
    next_page_token: t.Optional[str] = None


@strawberry.type
class DialoguePage:
    dialogues: list[Dialogue]
    next_page_token: t.Optional[str] = None


# Inputs

@strawberry.input
class AttachmentInput:
    attachment_id: strawberry.ID
    filename: str
    mime_type: str
    size_bytes: int
    sha256_hex: t.Optional[str] = None
    uri: t.Optional[str] = None
    metadata: t.Optional[dict[str, t.Any]] = None


@strawberry.input
class ToolCallInput:
    call_id: strawberry.ID
    tool_name: str
    input: t.Optional[dict[str, t.Any]] = None
    output: t.Optional[dict[str, t.Any]] = None
    status: t.Optional[ToolCallStatus] = None
    latency: t.Optional[str] = None
    error_message: t.Optional[str] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.input
class ParticipantInput:
    participant_id: strawberry.ID
    display_name: str
    role: t.Optional[str] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.input
class TurnSeedInput:
    actor: Actor
    text: t.Optional[str] = None
    data: t.Optional[dict[str, t.Any]] = None
    tool: t.Optional[ToolCallInput] = None
    attachments: t.Optional[list[AttachmentInput]] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.input
class CreateDialogueInput:
    title: t.Optional[str] = None
    participants: t.Optional[list[ParticipantInput]] = None
    labels: t.Optional[dict[str, str]] = None
    seed_turn: t.Optional[TurnSeedInput] = None


@strawberry.input
class AppendTurnInput:
    actor: Actor
    text: t.Optional[str] = None
    data: t.Optional[dict[str, t.Any]] = None
    tool: t.Optional[ToolCallInput] = None
    attachments: t.Optional[list[AttachmentInput]] = None
    attributes: t.Optional[dict[str, str]] = None
    return_dialogue: t.Optional[bool] = False


# ---------------------------------------------------------------------------
# Context & auth
# ---------------------------------------------------------------------------

class Principal(strawberry.types.Info):
    sub: str
    roles: list[str]
    tenant: t.Optional[str]


class RequestContext:
    def __init__(self, request: Request, response: Response) -> None:
        self.request = request
        self.response = response

    @cached_property
    def request_id(self) -> str:
        rid = self.request.headers.get("x-request-id") or gen_request_id()
        self.response.headers["x-request-id"] = rid
        return rid

    async def principal(self) -> Principal:
        auth = self.request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise GraphQLError("Unauthorized")
        token = auth[7:].strip()
        if not token:
            raise GraphQLError("Unauthorized")
        # TODO: валидация токена и загрузка ролей/арендатора
        return Principal  # type: ignore


# ---------------------------------------------------------------------------
# Validation rules: depth limit and field count
# ---------------------------------------------------------------------------

def depth_limit_rule(max_depth: int) -> type[ValidationRule]:
    class DepthLimit(ValidationRule):
        def __init__(self, context) -> None:
            super().__init__(context)
            doc: DocumentNode = context.document
            for defn in doc.definitions:
                if isinstance(defn, OperationDefinitionNode):
                    d = _depth(defn.selection_set)
                    if d > max_depth:
                        context.report_error(
                            GraphQLError(f"Query depth {d} exceeds max {max_depth}", [defn])
                        )
    return DepthLimit

def field_limit_rule(max_fields: int) -> type[ValidationRule]:
    class FieldLimit(ValidationRule):
        def __init__(self, context) -> None:
            super().__init__(context)
            count = 0
            def visitor(node, *_):
                nonlocal count
                if isinstance(node, FieldNode):
                    count += 1
                return None
            visit(context.document, {"enter": visitor})
            if count > max_fields:
                context.report_error(GraphQLError(f"Query has {count} fields, limit is {max_fields}"))
    return FieldLimit

def _depth(sel, current: int = 0) -> int:
    if not sel or not getattr(sel, "selections", None):
        return current
    depths = []
    for s in sel.selections:
        if getattr(s, "selection_set", None):
            depths.append(_depth(s.selection_set, current + 1))
        else:
            depths.append(current + 1)
    return max(depths) if depths else current

# ---------------------------------------------------------------------------
# APQ (Automatic Persisted Queries) helper
# ---------------------------------------------------------------------------

async def resolve_apq(request: Request) -> t.Tuple[str | None, dict | None]:
    """
    Implements Apollo-style APQ handshake:
    extensions.persistedQuery = { version: 1, sha256Hash }
    POST with only hash => lookup; POST with query+hash => store.
    Returns (query, error) where error is GraphQL error dict if any.
    """
    if request.method != "POST":
        return None, None
    try:
        payload = await request.json()
    except Exception:
        return None, None

    ext = (payload or {}).get("extensions") or {}
    pq = ext.get("persistedQuery") if isinstance(ext, dict) else None
    if not pq or pq.get("version") != 1:
        return None, None

    provided_query: str | None = payload.get("query")
    sha: str = pq.get("sha256Hash", "")
    if not sha:
        return None, {"errors": [{"message": "APQ: missing sha256Hash"}]}
    key = f"apq:{sha}"

    if provided_query:
        if sha256_hex(provided_query) != sha:
            return None, {"errors": [{"message": "APQ: sha mismatch"}]}
        await apq_cache.set(key, provided_query.encode("utf-8"), settings.apq_ttl_sec)
        return provided_query, None

    cached = await apq_cache.get(key)
    if not cached:
        return None, {
            "errors": [{"message": "PersistedQueryNotFound"}],
            "data": None,
        }
    return cached.decode("utf-8"), None

# ---------------------------------------------------------------------------
# Root resolvers (Query/Mutation/Subscription)
# ---------------------------------------------------------------------------

@strawberry.type
class Query:
    @strawberry.field
    async def dialogue(
        self,
        info: Info,
        dialogue_id: strawberry.ID,
        include_turns: bool = False,
        page_size: t.Optional[int] = None,
        page_token: t.Optional[str] = None,
    ) -> t.Optional[Dialogue]:
        svc = info.context["dialogue_service"]
        principal = info.context["principal"]
        dlg, turns, _ = await svc.get_dialogue(
            principal, uuid.UUID(str(dialogue_id)), include_turns, page_size, page_token
        )
        if turns is not None:
            dlg.turns = turns  # type: ignore
        return dlg

    @strawberry.field
    async def list_dialogues(
        self,
        info: Info,
        page_size: int = 50,
        page_token: t.Optional[str] = None,
        status: t.Optional[DialogueStatus] = None,
        query: t.Optional[str] = None,
        label: t.Optional[dict[str, str]] = None,
    ) -> DialoguePage:
        svc = info.context["dialogue_service"]
        principal = info.context["principal"]
        items, next_token = await svc.list_dialogues(
            principal, page_size, page_token, status.value if status else None, label or {}, query
        )
        return DialoguePage(dialogues=items, next_page_token=next_token)


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def create_dialogue(
        self,
        info: Info,
        input: CreateDialogueInput,
    ) -> Dialogue:
        svc = info.context["dialogue_service"]
        principal = info.context["principal"]

        # Idempotency by header
        request: Request = info.context["request"]
        response: Response = info.context["response"]
        rid = info.context["request_id"]

        idem_key = request.headers.get("idempotency-key")
        if idem_key:
            cached = await idem_cache.get(f"idem:{idem_key}")
            if cached:
                # cached payload is serialized Dialogue
                data = json.loads(cached.decode("utf-8"))
                response.headers["x-request-id"] = data.get("_meta", {}).get("request_id", rid)
                return Dialogue(**data["dialogue"])  # type: ignore

        dlg = await svc.create_dialogue(principal, _to_rest(input))
        if idem_key:
            envelope = {"dialogue": asdict(dlg) if hasattr(dlg, "__dataclass_fields__") else _to_jsonable(dlg),
                        "_meta": {"request_id": rid}}
            await idem_cache.set(f"idem:{idem_key}", json.dumps(envelope, default=_json_dt).encode("utf-8"),
                                 settings.idempotency_ttl_sec)
        return dlg

    @strawberry.mutation
    async def append_turn(
        self,
        info: Info,
        dialogue_id: strawberry.ID,
        input: AppendTurnInput,
    ) -> Turn:
        svc = info.context["dialogue_service"]
        principal = info.context["principal"]
        result = await svc.append_turn(principal, uuid.UUID(str(dialogue_id)), _to_rest(input))
        return result.turn  # type: ignore


@strawberry.type
class DialogueCreated:
    dialogue: Dialogue


@strawberry.type
class TurnAppended:
    turn: Turn
    usage_total: t.Optional[TokenUsage] = None


@strawberry.type
class DialogueUpdated:
    status: t.Optional[DialogueStatus] = None
    title: t.Optional[str] = None
    labels: t.Optional[dict[str, str]] = None


@strawberry.type
class DialogueEvent:
    event_id: strawberry.ID
    created_at: dt.datetime
    dialogue_id: strawberry.ID
    dialogue_created: t.Optional[DialogueCreated] = None
    turn_appended: t.Optional[TurnAppended] = None
    dialogue_updated: t.Optional[DialogueUpdated] = None
    dialogue_closed: t.Optional[dict[str, t.Any]] = None
    dialogue_archived: t.Optional[dict[str, t.Any]] = None
    attributes: t.Optional[dict[str, str]] = None


@strawberry.type
class Subscription:
    @strawberry.subscription
    async def dialogue_events(
        self, info: Info, dialogue_id: strawberry.ID, from_event_id: t.Optional[strawberry.ID] = None
    ) -> t.AsyncGenerator[DialogueEvent, None]:
        svc = info.context["dialogue_service"]
        principal = info.context["principal"]
        async for ev in svc.stream_events(
            principal,
            uuid.UUID(str(dialogue_id)),
            uuid.UUID(str(from_event_id)) if from_event_id else None,
        ):
            yield ev  # already DialogueEvent-compatible

# ---------------------------------------------------------------------------
# Error formatter (uniform shape with request id)
# ---------------------------------------------------------------------------

def error_formatter(error: GraphQLError, debug: bool) -> dict:
    request_id = None
    try:
        ctx = error.path[0] if error.path else None  # not reliable
    except Exception:
        ctx = None
    ext = dict(error.extensions or {})
    # Attach request id from context if present
    if "request" in ext:
        request_id = ext["request"].headers.get("x-request-id")
    message = error.message if settings.debug or debug else "Internal error" if error.original_error else error.message
    return {
        "message": message,
        "path": error.path,
        "locations": [{"line": loc.line, "column": loc.column} for loc in (error.locations or [])],
        "extensions": {
            **ext,
            "code": ext.get("code", "INTERNAL_ERROR" if error.original_error else "BAD_REQUEST"),
            "request_id": request_id,
        },
    }

# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=True),
)

validation_rules = [
    depth_limit_rule(settings.depth_limit),
    field_limit_rule(settings.field_limit),
]

def _json_dt(o):
    if isinstance(o, (dt.datetime, dt.date)):
        return o.isoformat()
    return str(o)

def _to_rest(obj):
    # Convert strawberry input to plain dicts compatible with REST service
    if hasattr(obj, "__dict__"):
        d = {k: _to_rest(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
        return d
    if isinstance(obj, list):
        return [_to_rest(x) for x in obj]
    return obj

def _to_jsonable(obj):
    try:
        return json.loads(json.dumps(obj, default=_json_dt))
    except Exception:
        return obj

async def _get_context(request: Request, response: Response):
    # APQ resolution (only for POST)
    query, apq_error = await resolve_apq(request)
    if apq_error:
        response.status_code = status.HTTP_200_OK
        return {"apq_error": apq_error}  # GraphQLRouter вернёт это как payload
    # Attach request id
    rid = request.headers.get("x-request-id") or gen_request_id()
    response.headers["x-request-id"] = rid

    # Principal and service injection
    if not hasattr(request.app.state, "dialogue_service"):
        raise GraphQLError("Dialogue service is not configured", extensions={"code": "NOT_IMPLEMENTED"})
    principal = {"sub": "anonymous", "roles": ["viewer"]}  # TODO: replace with real auth
    return {
        "request": request,
        "response": response,
        "request_id": rid,
        "principal": principal,
        "dialogue_service": request.app.state.dialogue_service,
        "apq_query": query,
    }

class APQMiddleware:
    """
    ASGI middleware to inject APQ-retrieved query text into the GraphQL POST body.
    """
    def __init__(self, app, path: str):
        self.app = app
        self.path = path.rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "") != self.path or scope.get("method") != "POST":
            return await self.app(scope, receive, send)

        body = b""
        more_body = True
        while more_body:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                more_body = msg.get("more_body", False)
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            payload = {}
        # If context resolved APQ (we can't call it here), we re-compute if needed:
        ext = (payload.get("extensions") or {})
        pq = ext.get("persistedQuery") if isinstance(ext, dict) else None
        if pq and pq.get("version") == 1 and not payload.get("query"):
            sha = pq.get("sha256Hash")
            if sha:
                cached = await apq_cache.get(f"apq:{sha}")
                if cached:
                    payload["query"] = cached.decode("utf-8")
                    body = json.dumps(payload).encode("utf-8")
        await send({"type": "http.request", "body": body, "more_body": False})
        return

def get_graphql_router() -> GraphQLRouter:
    return GraphQLRouter(
        schema,
        graphiql=settings.enable_graphiql,
        context_getter=_get_context,
        subscriptions_enabled=True,
        subscription_keep_alive_interval=settings.keepalive_sec,
        validation_rules=validation_rules,
        debug=settings.debug,
        error_formatter=error_formatter,
    )

def install_graphql(app: FastAPI, path: str | None = None) -> None:
    path = (path or settings.path).rstrip("/")
    router = get_graphql_router()
    # APQ middleware in front of the GraphQL route
    app.add_middleware(APQMiddleware, path=path)
    app.include_router(router, prefix=path)

# Example usage:
# app = FastAPI()
# app.state.dialogue_service = YourDialogueServiceImpl(...)
# install_graphql(app, "/graphql")
