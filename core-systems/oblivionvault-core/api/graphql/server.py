# oblivionvault-core/api/graphql/server.py
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import strawberry
from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, constr
from strawberry.fastapi import GraphQLRouter
from strawberry.scalars import JSON
from strawberry.types import Info

# Опциональные зависимости (мягкие фичи)
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: F401
    OTEL_AVAILABLE = True
except Exception:
    OTEL_AVAILABLE = False

try:
    from strawberry.extensions.tracing.apollo import ApolloTracingExtension  # noqa: F401
    APOLLO_TRACING_AVAILABLE = True
except Exception:
    APOLLO_TRACING_AVAILABLE = False

# Логирование
logger = logging.getLogger("ovc.graphql")
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Конфигурация через переменные окружения
# -----------------------------------------------------------------------------
ENV = os.getenv("OVC_ENV", "staging")
GRAPHQL_DEBUG = os.getenv("OVC_GQL_DEBUG", "false").lower() == "true"
GRAPHQL_GRAPHIQL = os.getenv("OVC_GQL_GRAPHIQL", "false").lower() == "true" if ENV == "prod" else True
PERSISTED_PATH = os.getenv("OVC_GQL_PERSISTED_PATH")  # путь к JSON { sha256: "query" }
ALLOW_ONLY_PERSISTED = os.getenv("OVC_GQL_ALLOW_ONLY_PERSISTED", "false").lower() == "true"
MAX_QUERY_DEPTH = int(os.getenv("OVC_GQL_MAX_DEPTH", "15"))
MAX_COMPLEXITY = int(os.getenv("OVC_GQL_MAX_COMPLEXITY", "5000"))
ENABLE_SUBSCRIPTIONS = os.getenv("OVC_GQL_SUBSCRIPTIONS", "true").lower() == "true"

# -----------------------------------------------------------------------------
# Вспомогательные модели контекста и заголовков аудита
# -----------------------------------------------------------------------------
class AuditHeaders(BaseModel):
    x_request_id: Optional[UUID] = None
    x_idempotency_key: Optional[constr(min_length=8, max_length=100)] = None
    x_evidence_id: Optional[constr(max_length=200)] = None
    x_audit_user: Optional[constr(max_length=120)] = None
    x_audit_reason: Optional[constr(max_length=400)] = None
    x_scopes: List[str] = Field(default_factory=list)

async def get_audit_headers(
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    x_idempotency_key: Optional[str] = Header(default=None, alias="X-Idempotency-Key"),
    x_evidence_id: Optional[str] = Header(default=None, alias="X-Evidence-Id"),
    x_audit_user: Optional[str] = Header(default=None, alias="X-Audit-User"),
    x_audit_reason: Optional[str] = Header(default=None, alias="X-Audit-Reason"),
    x_scopes: Optional[str] = Header(default=None, alias="X-Scopes"),
) -> AuditHeaders:
    rid = None
    if x_request_id:
        try:
            rid = UUID(x_request_id)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid X-Request-Id (UUID expected)")
    scopes = [s.strip() for s in (x_scopes or "").split(",") if s and s.strip()]
    return AuditHeaders(
        x_request_id=rid,
        x_idempotency_key=x_idempotency_key,
        x_evidence_id=x_evidence_id,
        x_audit_user=x_audit_user,
        x_audit_reason=x_audit_reason,
        x_scopes=scopes,
    )

@dataclass
class GQLContext:
    request: Request
    audit: AuditHeaders
    pubsub: "PubSub"
    persisted_map: Dict[str, str]

# -----------------------------------------------------------------------------
# Репозиторий DSAR (простая in-memory реализация; замените на БД)
# -----------------------------------------------------------------------------
DSARStatus = strawberry.enum(
    "DSARStatus",
    [
        "received",
        "in_review",
        "info_requested",
        "verified",
        "fulfilled",
        "partially_fulfilled",
        "rejected",
        "closed",
    ],
)

# Соответствие REST-статусу (с дефисами) и GraphQL (с подчеркиваниями)
REST_TO_GQL = {
    "received": "received",
    "in-review": "in_review",
    "info-requested": "info_requested",
    "verified": "verified",
    "fulfilled": "fulfilled",
    "partially-fulfilled": "partially_fulfilled",
    "rejected": "rejected",
    "closed": "closed",
}
GQL_TO_REST = {v: k for k, v in REST_TO_GQL.items()}

class DSARRecord(BaseModel):
    id: UUID
    createdAt: datetime
    updatedAt: datetime
    status: str   # REST стиль: received | in-review | ...
    framework: Optional[str]
    payload: Dict[str, Any]

class DSARRepository:
    def __init__(self) -> None:
        self._by_id: Dict[UUID, DSARRecord] = {}
        self._idempotency: Dict[str, UUID] = {}

    def create(self, payload: Dict[str, Any], idemp: Optional[str]) -> DSARRecord:
        # Идемпотентность
        if idemp and idemp in self._idempotency:
            return self._by_id[self._idempotency[idemp]]
        now = datetime.now(timezone.utc)
        status_val = (payload.get("processing") or {}).get("status", "received")
        framework = (payload.get("jurisdiction") or {}).get("framework")
        rec = DSARRecord(
            id=uuid4(), createdAt=now, updatedAt=now,
            status=status_val, framework=framework, payload=payload
        )
        self._by_id[rec.id] = rec
        if idemp:
            self._idempotency[idemp] = rec.id
        return rec

    def get(self, id_: UUID) -> Optional[DSARRecord]:
        return self._by_id.get(id_)

    def list(
        self, *, status: Optional[str], framework: Optional[str],
        search: Optional[str], offset: int, limit: int
    ) -> Tuple[List[DSARRecord], int]:
        data = list(self._by_id.values())
        if status:
            data = [d for d in data if d.status == status]
        if framework:
            data = [d for d in data if (d.framework or "").lower() == framework.lower()]
        if search:
            s = search.lower()
            def hay(r: DSARRecord) -> str:
                emails = (r.payload.get("dataSubject", {}) or {}).get("emails", [])
                rtype = (r.payload.get("request", {}) or {}).get("requestType", "")
                return " ".join([str(r.id), str(r.payload.get("requestId", "")), " ".join(emails), rtype]).lower()
            data = [d for d in data if s in hay(d)]
        total = len(data)
        return data[offset: offset + limit], total

    def patch(self, id_: UUID, patch: Dict[str, Any]) -> Optional[DSARRecord]:
        rec = self._by_id.get(id_)
        if not rec:
            return None
        new_payload = rec.payload.copy()
        for k, v in patch.items():
            if isinstance(new_payload.get(k), dict) and isinstance(v, dict):
                new_payload[k] = {**new_payload[k], **v}
            else:
                new_payload[k] = v
        rec = DSARRecord(
            id=rec.id,
            createdAt=rec.createdAt,
            updatedAt=datetime.now(timezone.utc),
            status=(new_payload.get("processing") or {}).get("status", rec.status),
            framework=(new_payload.get("jurisdiction") or {}).get("framework"),
            payload=new_payload,
        )
        self._by_id[id_] = rec
        return rec

REPO = DSARRepository()

# -----------------------------------------------------------------------------
# PubSub для подписок (in-memory)
# -----------------------------------------------------------------------------
class PubSub:
    def __init__(self) -> None:
        self._topics: Dict[str, List[asyncio.Queue]] = {}

    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        for q in self._topics.get(topic, []):
            await q.put(payload)

    async def subscribe(self, topic: str) -> AsyncGenerator[Dict[str, Any], None]:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._topics.setdefault(topic, []).append(q)
        try:
            while True:
                msg = await q.get()
                yield msg
        finally:
            self._topics[topic].remove(q)

PUBSUB = PubSub()

# -----------------------------------------------------------------------------
# Валидация payload по JSON Schema (опционально)
# -----------------------------------------------------------------------------
def _load_dsar_schema() -> Optional[Dict[str, Any]]:
    path = os.path.join(os.getenv("OVC_REPO_ROOT", os.getcwd()), "schemas", "jsonschema", "v1", "dsar_request.schema.json")
    if not os.path.isfile(path):
        logger.warning("JSON Schema not found: %s", path)
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

try:
    from jsonschema import Draft202012Validator
    SCHEMA = _load_dsar_schema()
    SCHEMA_VALIDATOR = Draft202012Validator(SCHEMA) if SCHEMA else None
except Exception as e:
    logger.warning("jsonschema not available or invalid: %s", e)
    SCHEMA_VALIDATOR = None

def validate_payload(payload: Dict[str, Any]) -> List[str]:
    if not SCHEMA_VALIDATOR:
        return []
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in SCHEMA_VALIDATOR.iter_errors(payload)]

# -----------------------------------------------------------------------------
# Persisted Queries (allow-list)
# -----------------------------------------------------------------------------
def load_persisted_map() -> Dict[str, str]:
    if not PERSISTED_PATH or not os.path.isfile(PERSISTED_PATH):
        return {}
    with open(PERSISTED_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        logger.error("Persisted file must be a JSON object {sha256: query}")
        return {}
    return {str(k): str(v) for k, v in data.items()}

PERSISTED_MAP = load_persisted_map()

def sha256_of(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()

# -----------------------------------------------------------------------------
# Лимиты глубины и сложности
# -----------------------------------------------------------------------------
from graphql import visit, parse, Visitor, DocumentNode, FieldNode, FragmentSpreadNode, InlineFragmentNode

def calc_max_depth(doc: DocumentNode) -> int:
    max_depth = 0
    def _depth(selection_set, depth):
        nonlocal max_depth
        if not selection_set:
            max_depth = max(max_depth, depth)
            return
        for sel in selection_set.selections:
            if isinstance(sel, FieldNode):
                _depth(sel.selection_set, depth + 1)
            elif isinstance(sel, (InlineFragmentNode,)):
                _depth(sel.selection_set, depth + 1)
            elif isinstance(sel, FragmentSpreadNode):
                # Фрагменты будут развернуты ниже в визиторе — для простоты считаем +1
                max_depth = max(max_depth, depth + 1)
    for defn in doc.definitions:
        sel = getattr(defn, "selection_set", None)
        if sel:
            _depth(sel, 0)
    return max_depth

def calc_complexity(doc: DocumentNode) -> int:
    # Наивная метрика: 1 за поле, 5 за фрагмент/inline, суммирование
    score = 0
    def _walk(selection_set):
        nonlocal score
        if not selection_set:
            return
        for sel in selection_set.selections:
            if isinstance(sel, FieldNode):
                score += 1
                _walk(sel.selection_set)
            elif isinstance(sel, InlineFragmentNode):
                score += 5
                _walk(sel.selection_set)
            elif isinstance(sel, FragmentSpreadNode):
                score += 5
    for defn in doc.definitions:
        sel = getattr(defn, "selection_set", None)
        if sel:
            _walk(sel)
    return score

# -----------------------------------------------------------------------------
# Типы GraphQL
# -----------------------------------------------------------------------------
@strawberry.type
class DSARSummaryGQL:
    id: strawberry.ID
    requestId: UUID
    createdAt: datetime
    updatedAt: datetime
    framework: Optional[str]
    status: DSARStatus
    subjectEmail: Optional[str]
    subjectCountry: Optional[str]

    @staticmethod
    def from_record(r: DSARRecord) -> "DSARSummaryGQL":
        payload = r.payload
        emails = (payload.get("dataSubject", {}) or {}).get("emails", []) or []
        country = (payload.get("dataSubject", {}) or {}).get("countryOfResidence")
        return DSARSummaryGQL(
            id=str(r.id),
            requestId=UUID(payload.get("requestId", str(r.id))),
            createdAt=r.createdAt,
            updatedAt=r.updatedAt,
            framework=r.framework,
            status=DSARStatus(REST_TO_GQL.get(r.status, "received")),
            subjectEmail=emails[0] if emails else None,
            subjectCountry=country,
        )

@strawberry.type
class PageInfo:
    page: int
    pageSize: int
    total: int

@strawberry.type
class DSARConnection:
    items: List[DSARSummaryGQL]
    pageInfo: PageInfo

@strawberry.input
class DSARFilters:
    status: Optional[DSARStatus] = None
    framework: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    pageSize: int = 50

@strawberry.type
class MutationResult:
    ok: bool
    id: Optional[strawberry.ID] = None
    error: Optional[str] = None

@strawberry.type
class DSAREvent:
    id: strawberry.ID
    type: str
    at: datetime
    requestId: UUID
    status: DSARStatus

# -----------------------------------------------------------------------------
# Dataloaders (простая заглушка — для БД замените на батч-загрузку)
# -----------------------------------------------------------------------------
from strawberry.dataloader import DataLoader

async def _batch_load(ids: List[UUID]) -> List[Optional[DSARRecord]]:
    return [REPO.get(i) for i in ids]

# -----------------------------------------------------------------------------
# Query / Mutation / Subscription
# -----------------------------------------------------------------------------
@strawberry.type
class Query:
    @strawberry.field(description="Получить DSAR по ID")
    async def dsar(self, info: Info, id: strawberry.ID) -> Optional[DSARSummaryGQL]:
        rec = REPO.get(UUID(str(id)))
        return DSARSummaryGQL.from_record(rec) if rec else None

    @strawberry.field(description="Список DSAR с пагинацией и фильтрами")
    async def dsars(self, info: Info, filters: DSARFilters) -> DSARConnection:
        status_rest = GQL_TO_REST.get(filters.status.value, None) if filters.status else None
        items, total = REPO.list(
            status=status_rest,
            framework=filters.framework,
            search=filters.search,
            offset=(filters.page - 1) * filters.pageSize,
            limit=filters.pageSize,
        )
        return DSARConnection(
            items=[DSARSummaryGQL.from_record(r) for r in items],
            pageInfo=PageInfo(page=filters.page, pageSize=filters.pageSize, total=total),
        )

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Создать DSAR (payload соответствует JSON Schema)")
    async def create_dsar(self, info: Info, payload: JSON) -> MutationResult:
        ctx: GQLContext = info.context
        doc: Dict[str, Any] = dict(payload or {})
        now = datetime.now(timezone.utc).isoformat()
        doc.setdefault("schemaVersion", "1.0.0")
        doc.setdefault("createdAt", now)
        doc.setdefault("requestId", str(uuid4()))
        # Аудит-событие
        events = (doc.get("audit") or {}).get("events") or []
        events.append({
            "timestamp": now,
            "actor": ctx.audit.x_audit_user or "graphql",
            "action": "created",
            "note": ctx.audit.x_audit_reason,
            "statusSnapshot": (doc.get("processing") or {}).get("status", "received"),
        })
        doc.setdefault("audit", {}).setdefault("events", events)
        # Валидация
        errors = validate_payload(doc)
        if errors:
            return MutationResult(ok=False, error="; ".join(errors[:10]))
        rec = REPO.create(doc, ctx.audit.x_idempotency_key)
        # Публикуем событие (подписки)
        await ctx.pubsub.publish("dsar.events", {
            "id": str(rec.id),
            "type": "dsar.created",
            "at": rec.createdAt.isoformat(),
            "requestId": rec.payload.get("requestId"),
            "status": rec.status,
        })
        return MutationResult(ok=True, id=str(rec.id))

    @strawberry.mutation(description="Обновить processing (частично)")
    async def patch_processing(self, info: Info, id: strawberry.ID, processing: JSON) -> MutationResult:
        ctx: GQLContext = info.context
        rec = REPO.get(UUID(str(id)))
        if not rec:
            return MutationResult(ok=False, error="not found")
        # Аудит
        events = (rec.payload.get("audit") or {}).get("events") or []
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": ctx.audit.x_audit_user or "graphql",
            "action": "comment-added",
            "note": f"processing patch ({ctx.audit.x_audit_reason or 'n/a'})",
            "statusSnapshot": (processing or {}).get("status") or rec.status,
        })
        patched = REPO.patch(UUID(str(id)), {"processing": dict(processing or {}), "audit": {"events": events}})
        if not patched:
            return MutationResult(ok=False, error="conflict")
        errors = validate_payload(patched.payload)
        if errors:
            return MutationResult(ok=False, error="; ".join(errors[:10]))
        await ctx.pubsub.publish("dsar.events", {
            "id": str(patched.id),
            "type": "dsar.processing.patched",
            "at": patched.updatedAt.isoformat(),
            "requestId": patched.payload.get("requestId"),
            "status": patched.status,
        })
        return MutationResult(ok=True, id=str(patched.id))

    @strawberry.mutation(description="Обновить verification (частично)")
    async def patch_verification(self, info: Info, id: strawberry.ID, verification: JSON) -> MutationResult:
        ctx: GQLContext = info.context
        rec = REPO.get(UUID(str(id)))
        if not rec:
            return MutationResult(ok=False, error="not found")
        events = (rec.payload.get("audit") or {}).get("events") or []
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": ctx.audit.x_audit_user or "graphql",
            "action": "verified" if (verification or {}).get("status") == "verified" else "comment-added",
            "note": f"verification patch ({ctx.audit.x_audit_reason or 'n/a'})",
            "statusSnapshot": (rec.payload.get("processing") or {}).get("status"),
        })
        patched = REPO.patch(UUID(str(id)), {"verification": dict(verification or {}), "audit": {"events": events}})
        if not patched:
            return MutationResult(ok=False, error="conflict")
        errors = validate_payload(patched.payload)
        if errors:
            return MutationResult(ok=False, error="; ".join(errors[:10]))
        await ctx.pubsub.publish("dsar.events", {
            "id": str(patched.id),
            "type": "dsar.verification.patched",
            "at": patched.updatedAt.isoformat(),
            "requestId": patched.payload.get("requestId"),
            "status": patched.status,
        })
        return MutationResult(ok=True, id=str(patched.id))

    @strawberry.mutation(description="Добавить ссылки на вложения")
    async def add_attachments(self, info: Info, id: strawberry.ID, attachments: JSON) -> MutationResult:
        ctx: GQLContext = info.context
        rec = REPO.get(UUID(str(id)))
        if not rec:
            return MutationResult(ok=False, error="not found")
        cur = rec.payload.get("attachments") or []
        cur.extend(list(attachments or []))
        events = (rec.payload.get("audit") or {}).get("events") or []
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": ctx.audit.x_audit_user or "graphql",
            "action": "evidence-attached",
            "note": f"{len(list(attachments or []))} attachment(s) added",
            "statusSnapshot": (rec.payload.get("processing") or {}).get("status"),
        })
        patched = REPO.patch(UUID(str(id)), {"attachments": cur, "audit": {"events": events}})
        if not patched:
            return MutationResult(ok=False, error="conflict")
        errors = validate_payload(patched.payload)
        if errors:
            return MutationResult(ok=False, error="; ".join(errors[:10]))
        await ctx.pubsub.publish("dsar.events", {
            "id": str(patched.id),
            "type": "dsar.attachments.added",
            "at": patched.updatedAt.isoformat(),
            "requestId": patched.payload.get("requestId"),
            "status": patched.status,
        })
        return MutationResult(ok=True, id=str(patched.id))

    @strawberry.mutation(description="Закрыть DSAR")
    async def close_dsar(self, info: Info, id: strawberry.ID) -> MutationResult:
        ctx: GQLContext = info.context
        rec = REPO.get(UUID(str(id)))
        if not rec:
            return MutationResult(ok=False, error="not found")
        processing = (rec.payload.get("processing") or {}).copy()
        processing["status"] = "closed"
        events = (rec.payload.get("audit") or {}).get("events") or []
        events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": ctx.audit.x_audit_user or "graphql",
            "action": "closed",
            "note": ctx.audit.x_audit_reason,
            "statusSnapshot": "closed",
        })
        patched = REPO.patch(UUID(str(id)), {"processing": processing, "audit": {"events": events}})
        if not patched:
            return MutationResult(ok=False, error="conflict")
        await ctx.pubsub.publish("dsar.events", {
            "id": str(patched.id),
            "type": "dsar.closed",
            "at": patched.updatedAt.isoformat(),
            "requestId": patched.payload.get("requestId"),
            "status": patched.status,
        })
        return MutationResult(ok=True, id=str(patched.id))

@strawberry.type
class Subscription:
    @strawberry.subscription(description="События DSAR (created/updated/closed)")
    async def dsar_events(self, info: Info) -> AsyncGenerator[DSAREvent, None]:
        if not ENABLE_SUBSCRIPTIONS:
            # Завершаем без событий
            if False:
                yield  # pragma: no cover
            return
        async for msg in info.context.pubsub.subscribe("dsar.events"):
            yield DSAREvent(
                id=msg["id"],
                type=msg["type"],
                at=datetime.fromisoformat(msg["at"].replace("Z", "+00:00")),
                requestId=UUID(msg["requestId"]),
                status=DSARStatus(REST_TO_GQL.get(msg["status"], "received")),
            )

# -----------------------------------------------------------------------------
# Error masking и расширения
# -----------------------------------------------------------------------------
from strawberry.exceptions import StrawberryGraphQLError
from graphql.error import GraphQLError

def safe_error_formatter(error: GraphQLError, debug: bool) -> GraphQLError:
    # Не раскрываем внутренности в проде
    if GRAPHQL_DEBUG or debug:
        return error
    return GraphQLError(message="Internal server error")

class PersistedQueriesExtension(strawberry.extensions.BaseExtension):
    def __init__(self, *, persisted_map: Dict[str, str], allow_only: bool) -> None:
        super().__init__()
        self.persisted_map = persisted_map
        self.allow_only = allow_only

    def on_operation(self) -> None:  # type: ignore[override]
        query = self.execution_context.query
        if not query:
            return
        digest = sha256_of(query)
        if self.allow_only and digest not in self.persisted_map:
            raise GraphQLError("Query is not in persisted allow-list")
        # Можно логировать digest для аудита
        self.execution_context.context["query_sha256"] = digest  # type: ignore[index]

class LimitsExtension(strawberry.extensions.BaseExtension):
    def on_operation(self) -> None:  # type: ignore[override]
        parsed = self.execution_context.parsed_query
        if not parsed:
            return
        depth = calc_max_depth(parsed)
        if depth > MAX_QUERY_DEPTH:
            raise GraphQLError(f"Max query depth exceeded: {depth} > {MAX_QUERY_DEPTH}")
        complexity = calc_complexity(parsed)
        if complexity > MAX_COMPLEXITY:
            raise GraphQLError(f"Max query complexity exceeded: {complexity} > {MAX_COMPLEXITY}")

# -----------------------------------------------------------------------------
# Сборка схемы и роутера
# -----------------------------------------------------------------------------
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription if ENABLE_SUBSCRIPTIONS else None,
)

extensions: List[Any] = [LimitsExtension, PersistedQueriesExtension]
if APOLLO_TRACING_AVAILABLE and os.getenv("OVC_GQL_APOLLO_TRACING", "false").lower() == "true":
    extensions.append(ApolloTracingExtension)

async def get_context(request: Request, audit: AuditHeaders = Depends(get_audit_headers)) -> GQLContext:
    # Передаем persisted map и pubsub
    ctx = GQLContext(
        request=request,
        audit=audit,
        pubsub=PUBSUB,
        persisted_map=PERSISTED_MAP,
    )
    return ctx

graphql_app = GraphQLRouter(
    schema,
    graphiql=GRAPHQL_GRAPHIQL,
    debug=GRAPHQL_DEBUG,
    error_formatter=safe_error_formatter,
    context_getter=get_context,
    extensions=[
        lambda: LimitsExtension(),
        lambda: PersistedQueriesExtension(persisted_map=PERSISTED_MAP, allow_only=ALLOW_ONLY_PERSISTED),
        *( [ApolloTracingExtension] if (APOLLO_TRACING_AVAILABLE and os.getenv("OVC_GQL_APOLLO_TRACING", "false").lower() == "true") else [] )
    ],
    subscription_protocols=["graphql-ws"] if ENABLE_SUBSCRIPTIONS else [],
)

# Экспортируем роутер для включения в FastAPI-приложение:
router = graphql_app

"""
Как подключить:

# app.py
from fastapi import FastAPI
from api.graphql.server import router as graphql_router

app = FastAPI(title="OblivionVault Core")
app.include_router(graphql_router, prefix="/graphql")

Prod-рекомендации:
- Установить переменные:
  OVC_ENV=prod
  OVC_GQL_GRAPHIQL=false
  OVC_GQL_ALLOW_ONLY_PERSISTED=true
  OVC_GQL_PERSISTED_PATH=/app/configs/graphql/persisted.json
  OVC_GQL_MAX_DEPTH=15
  OVC_GQL_MAX_COMPLEXITY=5000
  OVC_GQL_APOLLO_TRACING=false
- Заменить DSARRepository на реализацию с БД (Postgres) и реальным PubSub (NATS/Kafka).
- Ограничить размеры запроса на уровне reverse-proxy и FastAPI (body size).
- Включить аутентификацию/авторизацию через Depends() и проверку scopes из X-Scopes или OAuth2.
"""
