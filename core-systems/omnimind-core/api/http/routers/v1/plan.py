# ops/api/http/routers/v1/plan.py
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, HttpUrl, NonNegativeInt, PositiveInt, StrictBool, StrictInt, StrictStr, conint, constr, validator

# -----------------------------------------------------------------------------
# Error envelope (совместимо с omnimind.v1.Error в JSON-виде)
# -----------------------------------------------------------------------------

class ErrorCode(str, Enum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    INTERNAL = "INTERNAL"
    UNAVAILABLE = "UNAVAILABLE"

class RetryInfo(BaseModel):
    retry_after: Optional[str] = Field(default=None, description="ISO8601 duration или секунды")
    policy: Optional[str] = None
    max_attempts: Optional[int] = None

class ErrorEnvelope(BaseModel):
    code: ErrorCode
    http_status: Optional[int] = None
    message: str
    locale: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    domain: Optional[str] = "omnimind-core"
    reason: Optional[str] = None
    hints: Optional[List[str]] = None
    cause_chain: Optional[List[str]] = None
    details: Optional[List[Dict[str, Any]]] = None
    retry: Optional[RetryInfo] = None

def raise_enveloped(status_code: int, code: ErrorCode, message: str, request_id: Optional[str] = None, reason: Optional[str] = None, details: Optional[List[Dict[str, Any]]] = None) -> None:
    env = ErrorEnvelope(
        code=code,
        http_status=status_code,
        message=message,
        request_id=request_id,
        reason=reason,
        details=details or [],
    )
    # FastAPI автоматически сериализует content
    raise HTTPException(status_code=status_code, detail=json.loads(env.json()))

# -----------------------------------------------------------------------------
# Доменные модели плана
# -----------------------------------------------------------------------------

ETAG_FMT = 'W/"{version}"'

class PlanStatus(str, Enum):
    DRAFT = "DRAFT"
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"

class PlanStepAction(str, Enum):
    APPROVE = "APPROVE"
    APPLY = "APPLY"
    ROLLBACK = "ROLLBACK"
    HTTP = "HTTP"
    SHELL = "SHELL"
    K8S_APPLY = "K8S_APPLY"

class PlanStep(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: constr(min_length=1, max_length=120)
    action: PlanStepAction
    args: Dict[str, Any] = Field(default_factory=dict)
    continue_on_error: bool = Field(default=False)
    timeout_seconds: conint(ge=1, le=3600) = 300

class Plan(BaseModel):
    id: UUID
    name: constr(min_length=3, max_length=120)
    description: Optional[constr(max_length=1000)] = None
    labels: Dict[constr(regex=r"^[a-z0-9]([-a-z0-9./]{0,61}[a-z0-9])?$"), constr(max_length=253)] = Field(default_factory=dict)
    steps: List[PlanStep]
    status: PlanStatus = PlanStatus.DRAFT
    schedule_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    version: int = 1  # для оптимистичной блокировки

    @property
    def etag(self) -> str:
        return ETAG_FMT.format(version=self.version)

# -----------------------------------------------------------------------------
# DTO: запросы/ответы
# -----------------------------------------------------------------------------

class PlanCreate(BaseModel):
    name: constr(min_length=3, max_length=120)
    description: Optional[constr(max_length=1000)] = None
    labels: Optional[Dict[str, str]] = Field(default_factory=dict)
    steps: List[PlanStep]
    schedule_at: Optional[datetime] = None

class PlanPatch(BaseModel):
    name: Optional[constr(min_length=3, max_length=120)] = None
    description: Optional[constr(max_length=1000)] = None
    labels: Optional[Dict[str, str]] = None
    steps: Optional[List[PlanStep]] = None
    schedule_at: Optional[datetime] = None
    status: Optional[PlanStatus] = None

class PaginatedPlans(BaseModel):
    items: List[Plan]
    next_page_token: Optional[str] = None
    total: Optional[int] = None

# -----------------------------------------------------------------------------
# Сервисный слой (in-memory для демо; замените реальной реализацией в проде)
# -----------------------------------------------------------------------------

class PlanService:
    """In-memory реализация. Для продакшна создайте реализацию поверх БД + очереди."""
    def __init__(self) -> None:
        self._plans: Dict[UUID, Plan] = {}
        self._idemp: Dict[str, Tuple[str, str]] = {}  # key -> (scope, value)  scope: 'create'/'execute'
        self._runs: Dict[str, Dict[str, Any]] = {}    # run_id -> {'plan_id':..., 'status':...}

    def _require_existing(self, plan_id: UUID) -> Plan:
        if plan_id not in self._plans:
            raise KeyError("not_found")
        return self._plans[plan_id]

    def list(
        self,
        *,
        status_filter: Optional[PlanStatus],
        q: Optional[str],
        created_from: Optional[datetime],
        created_to: Optional[datetime],
        page_size: int,
        page_token: Optional[str],
    ) -> PaginatedPlans:
        # простая фильтрация
        items = list(self._plans.values())
        if status_filter:
            items = [p for p in items if p.status == status_filter]
        if q:
            ql = q.lower()
            items = [p for p in items if (ql in p.name.lower()) or (p.description and ql in p.description.lower())]
        if created_from:
            items = [p for p in items if p.created_at >= created_from]
        if created_to:
            items = [p for p in items if p.created_at <= created_to]
        items.sort(key=lambda p: (p.created_at, p.id), reverse=True)

        # пагинация по курсору: page_token = base64(id|created_at_ts)
        start = 0
        if page_token:
            try:
                decoded = base64.urlsafe_b64decode(page_token.encode()).decode()
                last_id, last_ts = decoded.split("|", 1)
                last_ts = float(last_ts)
                for i, p in enumerate(items):
                    if p.created_at.timestamp() < last_ts or (p.created_at.timestamp() == last_ts and str(p.id) == last_id):
                        start = i + 1
                        break
            except Exception:
                start = 0

        chunk = items[start : start + page_size]
        next_token = None
        if len(items) > start + page_size:
            last = chunk[-1]
            raw = f"{last.id}|{last.created_at.timestamp()}"
            next_token = base64.urlsafe_b64encode(raw.encode()).decode()

        return PaginatedPlans(items=chunk, next_page_token=next_token, total=None)

    def create(self, payload: PlanCreate, *, idem_key: Optional[str]) -> Plan:
        if idem_key:
            hit = self._idemp.get(idem_key)
            if hit and hit[0] == "create":
                # уже создавали — вернуть существующий
                plan_id = UUID(hit[1])
                return self._plans[plan_id]

        now = datetime.now(timezone.utc)
        plan_id = uuid4()
        plan = Plan(
            id=plan_id,
            name=payload.name,
            description=payload.description,
            labels=payload.labels or {},
            steps=payload.steps,
            schedule_at=payload.schedule_at,
            status=PlanStatus.SCHEDULED if payload.schedule_at else PlanStatus.DRAFT,
            created_at=now,
            updated_at=now,
            version=1,
        )
        self._plans[plan_id] = plan
        if idem_key:
            self._idemp[idem_key] = ("create", str(plan_id))
        return plan

    def get(self, plan_id: UUID) -> Plan:
        return self._require_existing(plan_id)

    def update(self, plan_id: UUID, patch: PlanPatch, *, if_match: Optional[str]) -> Plan:
        plan = self._require_existing(plan_id)

        # проверка ETag / If-Match
        if if_match:
            if if_match.strip() != plan.etag:
                raise ValueError("etag_mismatch")
        # простые правила статусов
        if plan.status in (PlanStatus.RUNNING, PlanStatus.SUCCEEDED, PlanStatus.FAILED, PlanStatus.CANCELED):
            # изменять контент разрешим только в DRAFT/SCHEDULED
            immutable_fields = {"steps", "name", "description", "labels", "schedule_at"}
            if any(getattr(patch, f) is not None for f in immutable_fields):
                raise RuntimeError("immutable_state")

        updated = plan.copy(deep=True)
        for field in ("name", "description", "labels", "steps", "schedule_at", "status"):
            val = getattr(patch, field)
            if val is not None:
                setattr(updated, field, val)

        updated.version = plan.version + 1
        updated.updated_at = datetime.now(timezone.utc)
        self._plans[plan_id] = updated
        return updated

    def delete(self, plan_id: UUID, *, if_match: Optional[str]) -> None:
        plan = self._require_existing(plan_id)
        if if_match and if_match.strip() != plan.etag:
            raise ValueError("etag_mismatch")
        if plan.status == PlanStatus.RUNNING:
            raise RuntimeError("cannot_delete_running")
        self._plans.pop(plan_id, None)

    def execute(self, plan_id: UUID, *, idem_key: Optional[str]) -> str:
        plan = self._require_existing(plan_id)
        if plan.status == PlanStatus.RUNNING:
            # уже запущено — вернем текущий run_id
            for run_id, meta in self._runs.items():
                if meta["plan_id"] == str(plan_id) and meta["status"] == "RUNNING":
                    return run_id

        if idem_key:
            hit = self._idemp.get(idem_key)
            if hit and hit[0] == "execute":
                return hit[1]

        run_id = f"run_{uuid4()}"
        self._runs[run_id] = {"plan_id": str(plan_id), "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat()}
        # обновим статус плана
        plan.status = PlanStatus.RUNNING
        plan.version += 1
        plan.updated_at = datetime.now(timezone.utc)
        self._plans[plan_id] = plan
        if idem_key:
            self._idemp[idem_key] = ("execute", run_id)
        return run_id

    def cancel(self, plan_id: UUID) -> None:
        plan = self._require_existing(plan_id)
        if plan.status != PlanStatus.RUNNING:
            raise RuntimeError("not_running")
        plan.status = PlanStatus.CANCELED
        plan.version += 1
        plan.updated_at = datetime.now(timezone.utc)
        self._plans[plan_id] = plan
        # пометим текущий run завершенным
        for run_id, meta in list(self._runs.items()):
            if meta["plan_id"] == str(plan_id) and meta["status"] == "RUNNING":
                meta["status"] = "CANCELED"
                meta["finished_at"] = datetime.now(timezone.utc).isoformat()

    def complete_run_for_demo(self, run_id: str, success: bool = True) -> None:
        meta = self._runs.get(run_id)
        if not meta:
            return
        meta["status"] = "SUCCEEDED" if success else "FAILED"
        meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        # синхронизируем статус плана
        pid = UUID(meta["plan_id"])
        if pid in self._plans:
            pl = self._plans[pid]
            pl.status = PlanStatus.SUCCEEDED if success else PlanStatus.FAILED
            pl.version += 1
            pl.updated_at = datetime.now(timezone.utc)

# DI-заготовка
_service_singleton = PlanService()
def get_plan_service() -> PlanService:
    return _service_singleton

# -----------------------------------------------------------------------------
# Утилиты
# -----------------------------------------------------------------------------

def ensure_request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id")
    return rid or f"req-{uuid4()}"

def parse_if_match(h: Optional[str]) -> Optional[str]:
    return h.strip() if h else None

def parse_idem_key(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    key = h.strip()
    # RFC idempotency-key обычно до ~128 символов
    if len(key) > 256:
        return None
    return key

# -----------------------------------------------------------------------------
# Router
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/v1/plans", tags=["plans"])

@router.get(
    "",
    response_model=PaginatedPlans,
    summary="Список планов с пагинацией и фильтрами",
)
async def list_plans(
    request: Request,
    response: Response,
    status_filter: Optional[PlanStatus] = Query(default=None, alias="status"),
    q: Optional[str] = Query(default=None, min_length=1, max_length=120),
    created_from: Optional[datetime] = Query(default=None),
    created_to: Optional[datetime] = Query(default=None),
    page_size: int = Query(default=50, ge=1, le=1000),
    page_token: Optional[str] = Query(default=None),
    svc: PlanService = Depends(get_plan_service),
):
    try:
        data = svc.list(
            status_filter=status_filter,
            q=q,
            created_from=created_from,
            created_to=created_to,
            page_size=page_size,
            page_token=page_token,
        )
        response.headers["x-request-id"] = ensure_request_id(request)
        return data
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", ensure_request_id(request), reason=type(e).__name__)

@router.post(
    "",
    response_model=Plan,
    status_code=status.HTTP_201_CREATED,
    summary="Создать план",
)
async def create_plan(
    request: Request,
    response: Response,
    payload: PlanCreate = Body(...),
    idempotency_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    idem = parse_idem_key(idempotency_key)
    try:
        plan = svc.create(payload, idem_key=idem)
        response.headers["ETag"] = plan.etag
        response.headers["x-request-id"] = rid
        return plan
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)

@router.get(
    "/{plan_id}",
    response_model=Plan,
    summary="Получить план по идентификатору",
)
async def get_plan(
    request: Request,
    response: Response,
    plan_id: UUID = Path(..., description="UUID плана"),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    try:
        plan = svc.get(plan_id)
        response.headers["ETag"] = plan.etag
        response.headers["x-request-id"] = rid
        return plan
    except KeyError:
        raise_enveloped(status.HTTP_404_NOT_FOUND, ErrorCode.NOT_FOUND, "Plan not found", rid)
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)

@router.patch(
    "/{plan_id}",
    response_model=Plan,
    summary="Частично обновить план (If-Match обязателен)",
)
async def patch_plan(
    request: Request,
    response: Response,
    plan_id: UUID = Path(...),
    patch: PlanPatch = Body(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    match = parse_if_match(if_match)
    if not match:
        raise_enveloped(status.HTTP_428_PRECONDITION_REQUIRED, ErrorCode.INVALID_ARGUMENT, "If-Match header is required", rid)
    try:
        plan = svc.update(plan_id, patch, if_match=match)
        response.headers["ETag"] = plan.etag
        response.headers["x-request-id"] = rid
        return plan
    except KeyError:
        raise_enveloped(status.HTTP_404_NOT_FOUND, ErrorCode.NOT_FOUND, "Plan not found", rid)
    except ValueError as ve:
        if str(ve) == "etag_mismatch":
            raise_enveloped(status.HTTP_412_PRECONDITION_FAILED, ErrorCode.CONFLICT, "ETag mismatch", rid, reason="etag_mismatch")
        raise_enveloped(status.HTTP_400_BAD_REQUEST, ErrorCode.INVALID_ARGUMENT, "Bad request", rid, reason=type(ve).__name__)
    except RuntimeError as rexc:
        if str(rexc) == "immutable_state":
            raise_enveloped(status.HTTP_409_CONFLICT, ErrorCode.CONFLICT, "Plan cannot be modified in current state", rid, reason="immutable_state")
        raise_enveloped(status.HTTP_400_BAD_REQUEST, ErrorCode.INVALID_ARGUMENT, "Bad request", rid, reason=type(rexc).__name__)
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)

@router.delete(
    "/{plan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить план (If-Match обязателен)",
)
async def delete_plan(
    request: Request,
    plan_id: UUID = Path(...),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    match = parse_if_match(if_match)
    if not match:
        raise_enveloped(status.HTTP_428_PRECONDITION_REQUIRED, ErrorCode.INVALID_ARGUMENT, "If-Match header is required", rid)
    try:
        svc.delete(plan_id, if_match=match)
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"x-request-id": rid})
    except KeyError:
        raise_enveloped(status.HTTP_404_NOT_FOUND, ErrorCode.NOT_FOUND, "Plan not found", rid)
    except ValueError as ve:
        if str(ve) == "etag_mismatch":
            raise_enveloped(status.HTTP_412_PRECONDITION_FAILED, ErrorCode.CONFLICT, "ETag mismatch", rid, reason="etag_mismatch")
        raise_enveloped(status.HTTP_400_BAD_REQUEST, ErrorCode.INVALID_ARGUMENT, "Bad request", rid)
    except RuntimeError as rexc:
        if str(rexc) == "cannot_delete_running":
            raise_enveloped(status.HTTP_409_CONFLICT, ErrorCode.CONFLICT, "Cannot delete running plan", rid, reason="cannot_delete_running")
        raise_enveloped(status.HTTP_400_BAD_REQUEST, ErrorCode.INVALID_ARGUMENT, "Bad request", rid)
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)

# ----------------------- Операции исполнения плана --------------------------

class ExecuteResponse(BaseModel):
    run_id: str
    status: str = "RUNNING"

@router.post(
    "/{plan_id}/execute",
    response_model=ExecuteResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Запустить выполнение плана",
)
async def execute_plan(
    request: Request,
    background: BackgroundTasks,
    plan_id: UUID = Path(...),
    idempotency_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
    dry_run: bool = Query(default=False, description="Если true — проверка валидности без выполнения"),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    try:
        if dry_run:
            # для примера просто проверим, что план существует
            svc.get(plan_id)
            return Response(
                status_code=status.HTTP_200_OK,
                content=json.dumps({"run_id": "dry-run", "status": "DRY_RUN_OK"}),
                media_type="application/json",
                headers={"x-request-id": rid},
            )

        run_id = svc.execute(plan_id, idem_key=parse_idem_key(idempotency_key))
        # имитация асинхронного завершения для демо
        async def _finish():
            await asyncio.sleep(1.5)
            svc.complete_run_for_demo(run_id, success=True)

        background.add_task(asyncio.create_task, _finish())
        return ExecuteResponse(run_id=run_id, status="RUNNING")
    except KeyError:
        raise_enveloped(status.HTTP_404_NOT_FOUND, ErrorCode.NOT_FOUND, "Plan not found", rid)
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)

@router.post(
    "/{plan_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Отменить выполнение плана",
)
async def cancel_plan(
    request: Request,
    plan_id: UUID = Path(...),
    svc: PlanService = Depends(get_plan_service),
):
    rid = ensure_request_id(request)
    try:
        svc.cancel(plan_id)
        return Response(status_code=status.HTTP_202_ACCEPTED, headers={"x-request-id": rid})
    except KeyError:
        raise_enveloped(status.HTTP_404_NOT_FOUND, ErrorCode.NOT_FOUND, "Plan not found", rid)
    except RuntimeError as rexc:
        if str(rexc) == "not_running":
            raise_enveloped(status.HTTP_409_CONFLICT, ErrorCode.CONFLICT, "Plan is not running", rid, reason="not_running")
        raise_enveloped(status.HTTP_400_BAD_REQUEST, ErrorCode.INVALID_ARGUMENT, "Bad request", rid)
    except Exception as e:
        raise_enveloped(status.HTTP_500_INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL, "Internal error", rid, reason=type(e).__name__)
