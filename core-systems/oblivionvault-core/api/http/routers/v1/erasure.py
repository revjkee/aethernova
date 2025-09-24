from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from jsonschema import Draft202012Validator, ValidationError as JSONSchemaValidationError

# Optional OpenTelemetry (graceful if not installed)
try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except Exception:  # pragma: no cover
    trace = None
    Status = None
    StatusCode = None

logger = logging.getLogger("ov.api.erasure")
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/v1/erasure", tags=["erasure"])

# ----------------------------
# Security / RBAC primitives
# ----------------------------

security = HTTPBearer(auto_error=False)

class Principal(BaseModel):
    sub: str
    role: Literal["user", "security", "dpo", "legal", "sre", "admin"] = "user"
    email: Optional[str] = None

def get_principal(
    request: Request, token: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Principal:
    """
    Simplified principal extraction.
    Production note:
      - integrate with your JWT middleware; validate audience/scope.
      - map roles from claims.
    """
    # Header overrides for service-to-service (mTLS or gateway enrichment)
    hdr_sub = request.headers.get("X-User-Id")
    hdr_role = request.headers.get("X-User-Role", "user")
    hdr_email = request.headers.get("X-User-Email")

    if hdr_sub:
        return Principal(sub=hdr_sub, role=hdr_role, email=hdr_email)

    if token and token.credentials:
        # WARNING: demo parse. Replace with real JWT validation.
        try:
            # Attempt to decode base64 payload part if JWT-like
            parts = token.credentials.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1] + "==="
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())
                return Principal(
                    sub=str(payload.get("sub") or "unknown"),
                    role=str(payload.get("role") or "user"),
                    email=str(payload.get("email") or ""),
                )
        except Exception:
            pass

    # Anonymous fallback (should be forbidden in gateways)
    return Principal(sub="anonymous", role="user")


def require_roles(*allowed: str):
    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role not in allowed and "admin" not in allowed and principal.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return principal
    return _dep


# ----------------------------
# JSON Schema loading/validation
# ----------------------------

SCHEMA_PATH = os.getenv(
    "OV_ERASURE_SCHEMA_PATH",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "../../../../schemas/jsonschema/v1/erasure_task.schema.json",
    ),
)

FALLBACK_MIN_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["apiVersion", "kind", "id", "created_at", "requested_by", "method", "targets", "approvals", "audit", "verification", "legal_basis", "subject"],
    "additionalProperties": True,
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
                "n_passes": {"type": "integer", "minimum": 1, "maximum": 10},
            },
        },
        "targets": {"type": "array", "minItems": 1},
        "approvals": {
            "type": "object",
            "required": ["required_approvals", "approvers"],
            "properties": {
                "required_approvals": {"type": "integer", "minimum": 1, "maximum": 10, "default": 2},
                "approvers": {"type": "array", "minItems": 1},
            },
        },
        "audit": {"type": "object", "required": ["correlation_id", "otlp_endpoint"]},
        "verification": {"type": "object", "required": ["mode"]},
        "legal_basis": {"type": "string"},
        "subject": {"type": "object"},
        "constraints": {"type": "object"},
        "schedule": {"type": "object"},
        "dry_run": {"type": "boolean"},
    },
}

@lru_cache(maxsize=1)
def _load_schema() -> Dict[str, Any]:
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
def _get_validator() -> Draft202012Validator:
    return Draft202012Validator(_load_schema())


def validate_task_payload(payload: Dict[str, Any]) -> None:
    try:
        _get_validator().validate(payload)
    except JSONSchemaValidationError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "erasure payload failed schema validation", "error": ve.message, "path": list(ve.path)},
        ) from ve

# ----------------------------
# Data models and memory store (replace with DB in production)
# ----------------------------

class TaskStatus(str):
    CREATED = "created"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

class TaskRecord(BaseModel):
    id: str
    status: Literal[
        TaskStatus.CREATED,
        TaskStatus.APPROVED,
        TaskStatus.REJECTED,
        TaskStatus.RUNNING,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELED,
    ] = TaskStatus.CREATED
    payload: Dict[str, Any]
    approvals_given: List[str] = Field(default_factory=list)
    approvals_required: int = 2
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checksum_sha256: str
    batch_id: str

# naive in-memory store (thread-safe enough for demo; replace with persistent DB)
_TASKS: Dict[str, TaskRecord] = {}

# ----------------------------
# Rate limiting (simple token bucket per principal)
# ----------------------------

class SimpleLimiter:
    def __init__(self, capacity: int = 30, refill_per_sec: int = 10):
        self.capacity = capacity
        self.refill = refill_per_sec
        self.tokens: Dict[str, Tuple[float, float]] = {}

    def check(self, key: str) -> bool:
        now = time.monotonic()
        t, tok = self.tokens.get(key, (now, float(self.capacity)))
        # refill
        tok = min(self.capacity, tok + (now - t) * self.refill)
        allowed = tok >= 1.0
        tok = tok - 1.0 if allowed else tok
        self.tokens[key] = (now, tok)
        return allowed

_limiter = SimpleLimiter(capacity=60, refill_per_sec=20)

def limit(dep: Principal = Depends(get_principal)) -> None:
    key = f"{dep.sub}:{dep.role}"
    if not _limiter.check(key):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")

# ----------------------------
# Helpers
# ----------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _hash_payload(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

def _new_batch_id() -> str:
    return str(uuid.uuid4())

def _within_window(schedule: Optional[Dict[str, Any]]) -> bool:
    if not schedule or schedule.get("mode", "immediate") != "window":
        return True
    try:
        tz = schedule.get("timezone", "UTC")
        start = datetime.fromisoformat(schedule["window_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(schedule["window_end"].replace("Z", "+00:00"))
        now = _now()
        # timezone-awareness simplified to UTC. Extend if needed.
        return start <= now <= end
    except Exception:
        return False

def _otel_span(name: str):
    if trace is None:
        class _Nop:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def set_attribute(self, *a, **k): pass
            def set_status(self, *a, **k): pass
        return _Nop()
    tracer = trace.get_tracer("ov.api.erasure")
    return tracer.start_as_current_span(name)

def _require_task(task_id: str) -> TaskRecord:
    rec = _TASKS.get(task_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
    return rec

def _required_approvals(payload: Dict[str, Any]) -> int:
    try:
        return int(payload.get("approvals", {}).get("required_approvals", 2))
    except Exception:
        return 2

def _legal_hold_override(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("constraints", {}).get("legal_hold_override", False))

async def _emit_audit(event: str, task: TaskRecord, principal: Principal, extra: Optional[Dict[str, Any]] = None) -> None:
    # production: send to OTLP or message bus
    msg = {
        "event": event,
        "task_id": task.id,
        "status": task.status,
        "principal": principal.sub,
        "role": principal.role,
        "time": _now().isoformat(),
        "extra": extra or {},
    }
    logger.info("AUDIT %s", json.dumps(msg, ensure_ascii=False))

# ----------------------------
# Pydantic response models
# ----------------------------

class TaskOut(BaseModel):
    id: str
    status: str
    created_at: datetime
    updated_at: datetime
    approvals_given: List[str]
    approvals_required: int
    checksum_sha256: str
    batch_id: str
    payload: Dict[str, Any]

class TaskListOut(BaseModel):
    items: List[TaskOut]
    total: int

# ----------------------------
# Endpoints
# ----------------------------

@router.post(
    "/tasks",
    response_model=TaskOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(limit)],
    summary="Create erasure task",
)
async def create_task(
    request: Request,
    principal: Principal = Depends(get_principal),
    payload: Dict[str, Any] = Body(..., embed=False),
):
    with _otel_span("erasure.create") as span:
        # inject requested_by if absent
        payload.setdefault("requested_by", {"type": "user", "id": principal.sub, "email": principal.email})
        payload.setdefault("apiVersion", "oblivionvault.io/v1")
        payload.setdefault("kind", "ErasureTask")
        payload.setdefault("created_at", _now().isoformat())

        # Generate UUID if id missing or invalid
        if not isinstance(payload.get("id"), str) or not payload["id"]:
            payload["id"] = str(uuid.uuid4())

        validate_task_payload(payload)

        # policy: legal_hold_override mandates >= 2 approvals
        req_appr = _required_approvals(payload)
        if _legal_hold_override(payload) and req_appr < 2:
            raise HTTPException(status_code=422, detail="legal_hold_override requires at least 2 approvals")

        task_id = payload["id"]
        if task_id in _TASKS:
            raise HTTPException(status_code=409, detail="task already exists")

        checksum = _hash_payload(payload)
        rec = TaskRecord(
            id=task_id,
            status=TaskStatus.CREATED,
            payload=payload,
            approvals_given=[],
            approvals_required=req_appr,
            checksum_sha256=checksum,
            batch_id=_new_batch_id(),
        )
        _TASKS[task_id] = rec
        span.set_attribute("erasure.task_id", task_id) if span else None
        await _emit_audit("created", rec, principal)
        return TaskOut(**rec.dict())


@router.get(
    "/tasks/{task_id}",
    response_model=TaskOut,
    dependencies=[Depends(limit)],
    summary="Get erasure task",
)
async def get_task(task_id: str = Path(..., min_length=1)):
    rec = _require_task(task_id)
    return TaskOut(**rec.dict())


@router.get(
    "/tasks",
    response_model=TaskListOut,
    dependencies=[Depends(limit)],
    summary="List erasure tasks",
)
async def list_tasks(
    status_eq: Optional[str] = Query(None),
    limit_q: int = Query(50, ge=1, le=500),
    offset_q: int = Query(0, ge=0),
):
    items = list(_TASKS.values())
    if status_eq:
        items = [t for t in items if t.status == status_eq]
    items.sort(key=lambda t: t.created_at, reverse=True)
    page = items[offset_q : offset_q + limit_q]
    return TaskListOut(items=[TaskOut(**p.dict()) for p in page], total=len(items))


@router.post(
    "/tasks/{task_id}/approve",
    response_model=TaskOut,
    dependencies=[Depends(limit)],
    summary="Approve erasure task",
)
async def approve_task(
    task_id: str,
    principal: Principal = Depends(require_roles("security", "dpo", "legal", "sre", "admin")),
):
    rec = _require_task(task_id)

    if rec.status in (TaskStatus.REJECTED, TaskStatus.CANCELED, TaskStatus.COMPLETED, TaskStatus.FAILED):
        raise HTTPException(status_code=409, detail=f"cannot approve task in status {rec.status}")

    if principal.sub in rec.approvals_given:
        return TaskOut(**rec.dict())

    rec.approvals_given.append(principal.sub)
    rec.updated_at = _now()
    if len(rec.approvals_given) >= rec.approvals_required:
        rec.status = TaskStatus.APPROVED
    await _emit_audit("approved", rec, principal, {"count": len(rec.approvals_given)})
    return TaskOut(**rec.dict())


@router.post(
    "/tasks/{task_id}/reject",
    response_model=TaskOut,
    dependencies=[Depends(limit)],
    summary="Reject erasure task",
)
async def reject_task(
    task_id: str,
    principal: Principal = Depends(require_roles("security", "dpo", "legal", "admin")),
):
    rec = _require_task(task_id)
    if rec.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELED):
        raise HTTPException(status_code=409, detail=f"cannot reject task in status {rec.status}")
    rec.status = TaskStatus.REJECTED
    rec.updated_at = _now()
    await _emit_audit("rejected", rec, principal)
    return TaskOut(**rec.dict())


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=TaskOut,
    dependencies=[Depends(limit)],
    summary="Cancel erasure task",
)
async def cancel_task(
    task_id: str,
    principal: Principal = Depends(require_roles("security", "dpo", "sre", "admin")),
):
    rec = _require_task(task_id)
    if rec.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELED):
        return TaskOut(**rec.dict())
    rec.status = TaskStatus.CANCELED
    rec.updated_at = _now()
    await _emit_audit("canceled", rec, principal)
    return TaskOut(**rec.dict())


@router.post(
    "/tasks/{task_id}/run",
    response_model=TaskOut,
    dependencies=[Depends(limit)],
    summary="Run erasure task (background)",
)
async def run_task(
    background: BackgroundTasks,
    task_id: str,
    principal: Principal = Depends(require_roles("security", "sre", "admin")),
):
    rec = _require_task(task_id)

    if rec.status not in (TaskStatus.APPROVED, TaskStatus.CREATED):
        raise HTTPException(status_code=409, detail=f"cannot run task in status {rec.status}")

    # If not approved yet, allow admin override only
    if rec.status == TaskStatus.CREATED and principal.role != "admin":
        raise HTTPException(status_code=403, detail="not approved")

    # Window check
    if not _within_window(rec.payload.get("schedule")):
        raise HTTPException(status_code=409, detail="outside of allowed schedule window")

    rec.status = TaskStatus.RUNNING
    rec.updated_at = _now()
    await _emit_audit("started", rec, principal)

    # Background execution stub; replace with real executor/queue
    background.add_task(_background_execute, rec.id, principal)
    return TaskOut(**rec.dict())


async def _background_execute(task_id: str, principal: Principal):
    rec = _require_task(task_id)
    with _otel_span("erasure.execute") as span:
        if span:
            span.set_attribute("erasure.task_id", rec.id)
            span.set_attribute("erasure.method", rec.payload.get("method", {}).get("type", "unknown"))
        try:
            # Simulate work respecting dry_run and rate limits
            dry_run = bool(rec.payload.get("dry_run", False))
            method = (rec.payload.get("method") or {}).get("type", "unknown")
            targets = rec.payload.get("targets", [])
            concurrency = int(rec.payload.get("concurrency_limit", 25))
            concurrency = max(1, min(concurrency, 1000))

            # Simple simulation loop
            sem = asyncio.Semaphore(concurrency)

            async def process_target(t: Dict[str, Any]):
                async with sem:
                    await asyncio.sleep(0.01)  # simulate latency
                    # Here: plug actual delete/crypto-erase/integration code
                    return True

            results = await asyncio.gather(*(process_target(t) for t in targets), return_exceptions=True)
            if any(isinstance(r, Exception) or r is False for r in results):
                rec.status = TaskStatus.FAILED
                rec.updated_at = _now()
                await _emit_audit("failed", rec, principal, {"dry_run": dry_run, "method": method})
                if span:
                    span.set_status(Status(StatusCode.ERROR) if Status else None)  # type: ignore
                return

            # Dry-run does not complete; marks as completed-simulated
            if dry_run:
                rec.status = TaskStatus.COMPLETED
            else:
                rec.status = TaskStatus.COMPLETED
            rec.updated_at = _now()
            await _emit_audit("completed", rec, principal, {"dry_run": dry_run, "method": method})
            if span:
                span.set_status(Status(StatusCode.OK) if Status else None)  # type: ignore
        except Exception as e:
            logger.exception("Execution error for task %s: %s", task_id, e)
            rec.status = TaskStatus.FAILED
            rec.updated_at = _now()
            await _emit_audit("failed", rec, principal, {"error": str(e)})
            if span:
                span.set_status(Status(StatusCode.ERROR) if Status else None)  # type: ignore


# ----------------------------
# Health/Introspection
# ----------------------------

class HealthOut(BaseModel):
    schema_loaded: bool
    tasks_in_memory: int
    time: str

@router.get("/health", response_model=HealthOut, include_in_schema=False)
async def health():
    try:
        _get_validator()
        ok = True
    except Exception:
        ok = False
    return HealthOut(schema_loaded=ok, tasks_in_memory=len(_TASKS), time=_now().isoformat())
