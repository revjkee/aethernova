from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import strawberry
from strawberry.types import Info
from strawberry.scalars import JSON

# JSON Schema validation (strict)
from jsonschema import Draft202012Validator, ValidationError as JSONSchemaValidationError

# GraphQL error with extensions (graceful fallback)
try:
    from graphql import GraphQLError
except Exception:  # pragma: no cover
    class GraphQLError(Exception):  # type: ignore
        def __init__(self, message: str, extensions: Optional[dict] = None):
            super().__init__(message)
            self.extensions = extensions or {}

# Optional OpenTelemetry (works if installed)
try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except Exception:  # pragma: no cover
    trace = None
    Status = None
    StatusCode = None

logger = logging.getLogger("ov.gql")
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Security / Principal in context
# ------------------------------------------------------------------------------

@strawberry.enum
class Role(str):
    USER = "user"
    SECURITY = "security"
    DPO = "dpo"
    LEGAL = "legal"
    SRE = "sre"
    ADMIN = "admin"

@dataclass
class Principal:
    sub: str
    role: Role
    email: Optional[str] = None

def ctx_principal(info: Info) -> Principal:
    # Ожидается, что ASGI-слой положит principal в info.context["principal"].
    # Фолбэк — анонимный user (должен быть запрещён на gateway).
    p: Optional[Principal] = info.context.get("principal") if info and info.context else None
    return p or Principal(sub="anonymous", role=Role.USER, email=None)

def require_roles(info: Info, *allowed: Role) -> None:
    p = ctx_principal(info)
    if p.role not in allowed and p.role != Role.ADMIN:
        raise GraphQLError("forbidden", extensions={"code": "FORBIDDEN"})

# ------------------------------------------------------------------------------
# JSON Schema loading/validation (shared with REST)
# ------------------------------------------------------------------------------

SCHEMA_PATH = os.getenv(
    "OV_ERASURE_SCHEMA_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../schemas/jsonschema/v1/erasure_task.schema.json"),
)

FALLBACK_MIN_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": [
        "apiVersion", "kind", "id", "created_at",
        "requested_by", "method", "targets",
        "approvals", "audit", "verification",
        "legal_basis", "subject"
    ],
    "properties": {
        "apiVersion": {"const": "oblivionvault.io/v1"},
        "kind": {"const": "ErasureTask"},
        "id": {"type": "string"},
        "method": {
            "type": "object",
            "required": ["type"],
            "properties": {
                "type": {"enum": ["crypto-erase", "overwrite", "tombstone-delete", "remote-purge"]},
                "keyset_ref": {"type": "string"},
                "n_passes": {"type": "integer", "minimum": 1, "maximum": 10}
            }
        },
        "targets": {"type": "array", "minItems": 1},
        "approvals": {
            "type": "object",
            "required": ["required_approvals", "approvers"],
            "properties": {
                "required_approvals": {"type": "integer", "minimum": 1, "maximum": 10, "default": 2},
                "approvers": {"type": "array", "minItems": 1}
            }
        },
        "audit": {"type": "object", "required": ["correlation_id", "otlp_endpoint"]},
        "verification": {"type": "object", "required": ["mode"]},
        "legal_basis": {"type": "string"},
        "subject": {"type": "object"},
        "constraints": {"type": "object"},
        "schedule": {"type": "object"},
        "dry_run": {"type": "boolean"}
    },
    "additionalProperties": True
}

@lru_cache(maxsize=1)
def load_erasure_schema() -> Dict[str, Any]:
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
            Draft202012Validator.check_schema(schema)
            logger.info("Loaded erasure JSON Schema from %s", SCHEMA_PATH)
            return schema
    except Exception as e:
        logger.warning("Using fallback erasure JSON Schema: %s", e)
        Draft202012Validator.check_schema(FALLBACK_MIN_SCHEMA)
        return FALLBACK_MIN_SCHEMA

@lru_cache(maxsize=1)
def get_validator() -> Draft202012Validator:
    return Draft202012Validator(load_erasure_schema())

def validate_payload(payload: Dict[str, Any]) -> None:
    try:
        get_validator().validate(payload)
    except JSONSchemaValidationError as ve:
        raise GraphQLError(
            "erasure payload failed schema validation",
            extensions={"code": "UNPROCESSABLE_ENTITY", "error": ve.message, "path": list(ve.path)}
        )

# ------------------------------------------------------------------------------
# In-memory store (replace with DB / queue in production)
# ------------------------------------------------------------------------------

@strawberry.enum
class TaskStatus(str):
    CREATED = "created"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

@dataclass
class TaskRecord:
    id: str
    status: TaskStatus
    payload: Dict[str, Any]
    approvals_given: List[str]
    approvals_required: int
    created_at: datetime
    updated_at: datetime
    checksum_sha256: str
    batch_id: str

_TASKS: Dict[str, TaskRecord] = {}

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def sha256_payload(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

def new_batch_id() -> str:
    return str(uuid.uuid4())

def required_approvals(payload: Dict[str, Any]) -> int:
    try:
        return int(payload.get("approvals", {}).get("required_approvals", 2))
    except Exception:
        return 2

def legal_hold_override(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("constraints", {}).get("legal_hold_override", False))

def within_window(schedule: Optional[Dict[str, Any]]) -> bool:
    if not schedule or schedule.get("mode", "immediate") != "window":
        return True
    try:
        start = datetime.fromisoformat(schedule["window_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(schedule["window_end"].replace("Z", "+00:00"))
        return start <= now_utc() <= end
    except Exception:
        return False

# ------------------------------------------------------------------------------
# Rate limiting (simple token bucket per principal)
# ------------------------------------------------------------------------------

class SimpleLimiter:
    def __init__(self, capacity: int = 60, refill_per_sec: int = 20):
        self.capacity = capacity
        self.refill = refill_per_sec
        self.tokens: Dict[str, Tuple[float, float]] = {}

    def check(self, key: str) -> bool:
        t_now = time.monotonic()
        last_t, tok = self.tokens.get(key, (t_now, float(self.capacity)))
        tok = min(self.capacity, tok + (t_now - last_t) * self.refill)
        ok = tok >= 1.0
        tok = tok - 1.0 if ok else tok
        self.tokens[key] = (t_now, tok)
        return ok

_limiter = SimpleLimiter(capacity=80, refill_per_sec=30)

def rate_limit(info: Info) -> None:
    p = ctx_principal(info)
    key = f"{p.sub}:{p.role.value}"
    if not _limiter.check(key):
        raise GraphQLError("rate limit exceeded", extensions={"code": "TOO_MANY_REQUESTS"})

# ------------------------------------------------------------------------------
# OpenTelemetry helper
# ------------------------------------------------------------------------------

def otel_span(name: str):
    if trace is None:
        class _Nop:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def set_attribute(self, *a, **k): pass
            def set_status(self, *a, **k): pass
        return _Nop()
    tracer = trace.get_tracer("ov.gql")
    return tracer.start_as_current_span(name)

# ------------------------------------------------------------------------------
# Relay-style pagination helpers
# ------------------------------------------------------------------------------

def encode_cursor(dt: datetime) -> str:
    return base64.urlsafe_b64encode(dt.isoformat().encode()).decode()

def decode_cursor(cursor: str) -> datetime:
    return datetime.fromisoformat(base64.urlsafe_b64decode(cursor.encode()).decode())

@strawberry.type
class PageInfo:
    has_next_page: bool
    end_cursor: Optional[str]

@strawberry.type
class ErasureTask:
    id: strawberry.ID
    status: TaskStatus
    created_at: datetime
    updated_at: datetime
    approvals_given: List[str]
    approvals_required: int
    checksum_sha256: str
    batch_id: str
    payload: JSON

@strawberry.type
class ErasureTaskEdge:
    node: ErasureTask
    cursor: str

@strawberry.type
class ErasureTaskConnection:
    edges: List[ErasureTaskEdge]
    page_info: PageInfo
    total_count: int

def to_gql(rec: TaskRecord) -> ErasureTask:
    return ErasureTask(
        id=strawberry.ID(rec.id),
        status=rec.status,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        approvals_given=list(rec.approvals_given),
        approvals_required=rec.approvals_required,
        checksum_sha256=rec.checksum_sha256,
        batch_id=rec.batch_id,
        payload=rec.payload,
    )

# ------------------------------------------------------------------------------
# Queries
# ------------------------------------------------------------------------------

@strawberry.type
class Query:
    @strawberry.field(description="Проверка состояния GQL-сервиса")
    def health(self, info: Info) -> JSON:
        rate_limit(info)
        ok = True
        try:
            get_validator()
        except Exception:
            ok = False
        return {
            "schema_loaded": ok,
            "tasks_in_memory": len(_TASKS),
            "time": now_utc().isoformat(),
        }

    @strawberry.field(description="Получить задачу стирания по ID")
    def erasure_task(self, info: Info, id: strawberry.ID) -> ErasureTask:
        rate_limit(info)
        rec = _TASKS.get(str(id))
        if not rec:
            raise GraphQLError("task not found", extensions={"code": "NOT_FOUND"})
        return to_gql(rec)

    @strawberry.field(description="Список задач стирания с пагинацией (новые сначала)")
    def erasure_tasks(
        self,
        info: Info,
        status_eq: Optional[TaskStatus] = None,
        first: int = 50,
        after: Optional[str] = None,
    ) -> ErasureTaskConnection:
        rate_limit(info)
        first = max(1, min(200, first))
        items = list(_TASKS.values())
        if status_eq:
            items = [t for t in items if t.status == status_eq]
        # сортировка: новые сначала
        items.sort(key=lambda t: t.created_at, reverse=True)

        if after:
            try:
                after_dt = decode_cursor(after)
                items = [t for t in items if t.created_at < after_dt]
            except Exception:
                raise GraphQLError("bad cursor", extensions={"code": "BAD_REQUEST"})

        slice_ = items[:first]
        edges = [ErasureTaskEdge(node=to_gql(t), cursor=encode_cursor(t.created_at)) for t in slice_]
        end_cursor = edges[-1].cursor if edges else None
        has_next_page = len(items) > len(slice_)
        return ErasureTaskConnection(
            edges=edges,
            page_info=PageInfo(has_next_page=has_next_page, end_cursor=end_cursor),
            total_count=len(items),
        )

# ------------------------------------------------------------------------------
# Mutations
# ------------------------------------------------------------------------------

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Создать задачу стирания (валидация JSON Schema)")
    def create_erasure_task(self, info: Info, payload: JSON) -> ErasureTask:
        rate_limit(info)
        with otel_span("gql.erasure.create") as span:
            p = ctx_principal(info)
            # Автозаполнение обязательных полей
            payload.setdefault("requested_by", {"type": "user", "id": p.sub, "email": p.email})
            payload.setdefault("apiVersion", "oblivionvault.io/v1")
            payload.setdefault("kind", "ErasureTask")
            payload.setdefault("created_at", now_utc().isoformat())
            if not isinstance(payload.get("id"), str) or not payload["id"]:
                payload["id"] = str(uuid.uuid4())

            validate_payload(payload)

            req_appr = required_approvals(payload)
            if legal_hold_override(payload) and req_appr < 2:
                raise GraphQLError(
                    "legal_hold_override requires at least 2 approvals",
                    extensions={"code": "UNPROCESSABLE_ENTITY"},
                )

            task_id = payload["id"]
            if task_id in _TASKS:
                raise GraphQLError("task already exists", extensions={"code": "CONFLICT"})

            checksum = sha256_payload(payload)
            rec = TaskRecord(
                id=task_id,
                status=TaskStatus.CREATED,
                payload=payload,
                approvals_given=[],
                approvals_required=req_appr,
                created_at=now_utc(),
                updated_at=now_utc(),
                checksum_sha256=checksum,
                batch_id=new_batch_id(),
            )
            _TASKS[task_id] = rec
            if span:
                span.set_attribute("erasure.task_id", task_id)
            logger.info("AUDIT %s", json.dumps({"event": "created", "task_id": task_id, "by": p.sub}))
            return to_gql(rec)

    @strawberry.mutation(description="Одобрить задачу")
    def approve_erasure_task(self, info: Info, id: strawberry.ID) -> ErasureTask:
        rate_limit(info)
        require_roles(info, Role.SECURITY, Role.DPO, Role.LEGAL, Role.SRE, Role.ADMIN)
        p = ctx_principal(info)
        rec = _TASKS.get(str(id))
        if not rec:
            raise GraphQLError("task not found", extensions={"code": "NOT_FOUND"})
        if rec.status in (TaskStatus.REJECTED, TaskStatus.CANCELED, TaskStatus.COMPLETED, TaskStatus.FAILED):
            raise GraphQLError(f"cannot approve task in status {rec.status}", extensions={"code": "CONFLICT"})
        if p.sub not in rec.approvals_given:
            rec.approvals_given.append(p.sub)
            rec.updated_at = now_utc()
            if len(rec.approvals_given) >= rec.approvals_required:
                rec.status = TaskStatus.APPROVED
        logger.info("AUDIT %s", json.dumps({"event": "approved", "task_id": rec.id, "by": p.sub, "count": len(rec.approvals_given)}))
        return to_gql(rec)

    @strawberry.mutation(description="Отклонить задачу")
    def reject_erasure_task(self, info: Info, id: strawberry.ID) -> ErasureTask:
        rate_limit(info)
        require_roles(info, Role.SECURITY, Role.DPO, Role.LEGAL, Role.ADMIN)
        p = ctx_principal(info)
        rec = _TASKS.get(str(id))
        if not rec:
            raise GraphQLError("task not found", extensions={"code": "NOT_FOUND"})
        if rec.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELED):
            raise GraphQLError(f"cannot reject task in status {rec.status}", extensions={"code": "CONFLICT"})
        rec.status = TaskStatus.REJECTED
        rec.updated_at = now_utc()
        logger.info("AUDIT %s", json.dumps({"event": "rejected", "task_id": rec.id, "by": p.sub}))
        return to_gql(rec)

    @strawberry.mutation(description="Отменить задачу")
    def cancel_erasure_task(self, info: Info, id: strawberry.ID) -> ErasureTask:
        rate_limit(info)
        require_roles(info, Role.SECURITY, Role.DPO, Role.SRE, Role.ADMIN)
        p = ctx_principal(info)
        rec = _TASKS.get(str(id))
        if not rec:
            raise GraphQLError("task not found", extensions={"code": "NOT_FOUND"})
        if rec.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELED):
            return to_gql(rec)
        rec.status = TaskStatus.CANCELED
        rec.updated_at = now_utc()
        logger.info("AUDIT %s", json.dumps({"event": "canceled", "task_id": rec.id, "by": p.sub}))
        return to_gql(rec)

    @strawberry.mutation(description="Запустить задачу (background)")
    def run_erasure_task(self, info: Info, id: strawberry.ID) -> ErasureTask:
        rate_limit(info)
        require_roles(info, Role.SECURITY, Role.SRE, Role.ADMIN)
        p = ctx_principal(info)
        rec = _TASKS.get(str(id))
        if not rec:
            raise GraphQLError("task not found", extensions={"code": "NOT_FOUND"})
        if rec.status not in (TaskStatus.APPROVED, TaskStatus.CREATED):
            raise GraphQLError(f"cannot run task in status {rec.status}", extensions={"code": "CONFLICT"})
        if rec.status == TaskStatus.CREATED and p.role != Role.ADMIN:
            raise GraphQLError("not approved", extensions={"code": "FORBIDDEN"})
        if not within_window(rec.payload.get("schedule")):
            raise GraphQLError("outside of allowed schedule window", extensions={"code": "CONFLICT"})

        rec.status = TaskStatus.RUNNING
        rec.updated_at = now_utc()
        logger.info("AUDIT %s", json.dumps({"event": "started", "task_id": rec.id, "by": p.sub}))
        # Fire and forget (replace with queue/worker in prod)
        asyncio.create_task(_background_execute(rec.id, p))
        return to_gql(rec)

# ------------------------------------------------------------------------------
# Background execution stub (replace with executors)
# ------------------------------------------------------------------------------

async def _background_execute(task_id: str, principal: Principal) -> None:
    rec = _TASKS.get(task_id)
    if not rec:
        return
    with otel_span("gql.erasure.execute") as span:
        if span:
            try:
                span.set_attribute("erasure.task_id", rec.id)
                span.set_attribute("erasure.method", rec.payload.get("method", {}).get("type", "unknown"))
            except Exception:
                pass
        try:
            dry_run = bool(rec.payload.get("dry_run", False))
            method = (rec.payload.get("method") or {}).get("type", "unknown")
            targets = rec.payload.get("targets", [])
            concurrency = int(rec.payload.get("concurrency_limit", 25))
            concurrency = max(1, min(concurrency, 1000))

            sem = asyncio.Semaphore(concurrency)

            async def process_target(t: Dict[str, Any]) -> bool:
                async with sem:
                    await asyncio.sleep(0.01)  # simulate IO
                    # TODO: plug real erasure executors (crypto-erase/overwrite/etc.)
                    return True

            results = await asyncio.gather(*(process_target(t) for t in targets), return_exceptions=True)
            if any(isinstance(r, Exception) or r is False for r in results):
                rec.status = TaskStatus.FAILED
                rec.updated_at = now_utc()
                logger.info("AUDIT %s", json.dumps({"event": "failed", "task_id": rec.id, "dry_run": dry_run, "method": method}))
                if span and Status and StatusCode:
                    span.set_status(Status(StatusCode.ERROR))
                return

            rec.status = TaskStatus.COMPLETED
            rec.updated_at = now_utc()
            logger.info("AUDIT %s", json.dumps({"event": "completed", "task_id": rec.id, "dry_run": dry_run, "method": method}))
            if span and Status and StatusCode:
                span.set_status(Status(StatusCode.OK))
        except Exception as e:
            rec.status = TaskStatus.FAILED
            rec.updated_at = now_utc()
            logger.exception("Execution error for task %s: %s", task_id, e)
            logger.info("AUDIT %s", json.dumps({"event": "failed", "task_id": rec.id, "error": str(e)}))
            if span and Status and StatusCode:
                span.set_status(Status(StatusCode.ERROR))

# ------------------------------------------------------------------------------
# Strawberry schema export
# ------------------------------------------------------------------------------

schema = strawberry.Schema(query=Query, mutation=Mutation)

# Optional helper to mount into FastAPI if desired:
try:
    from strawberry.fastapi import GraphQLRouter  # type: ignore

    def get_graphql_router() -> GraphQLRouter:
        # Прокиньте principal в контекст через dependency/middleware FastAPI
        return GraphQLRouter(schema, context_getter=lambda request: {"principal": request.state.principal if hasattr(request.state, "principal") else None})
except Exception:
    # Без FastAPI — просто экспортируйте `schema`
    pass
