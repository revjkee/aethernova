# oblivionvault-core/api/http/routers/v1/requests.py
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Protocol, Tuple
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
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, constr, validator

# Опционально: pip install jsonschema
try:
    from jsonschema import Draft202012Validator, RefResolver, exceptions as js_exceptions
except Exception:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment]
    RefResolver = None  # type: ignore[assignment]
    js_exceptions = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ----------------------------- Problem Details ----------------------------- #

class Problem(BaseModel):
    type: Optional[str] = Field(default="about:blank")
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None
    traceId: Optional[str] = None


def problem_response(
    status_code: int,
    title: str,
    detail: Optional[str] = None,
    type_: str = "about:blank",
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=Problem(type=type_, title=title, status=status_code, detail=detail).dict(),
        media_type="application/problem+json",
    )


# ----------------------------- Headers / Context --------------------------- #

class AuditHeaders(BaseModel):
    x_request_id: Optional[UUID] = Field(default=None)
    x_idempotency_key: Optional[constr(min_length=8, max_length=100)] = Field(default=None)
    x_evidence_id: Optional[constr(max_length=200)] = Field(default=None)
    x_audit_user: Optional[constr(max_length=120)] = Field(default=None)
    x_audit_reason: Optional[constr(max_length=400)] = Field(default=None)


def get_audit_headers(
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    x_idempotency_key: Optional[str] = Header(default=None, alias="X-Idempotency-Key"),
    x_evidence_id: Optional[str] = Header(default=None, alias="X-Evidence-Id"),
    x_audit_user: Optional[str] = Header(default=None, alias="X-Audit-User"),
    x_audit_reason: Optional[str] = Header(default=None, alias="X-Audit-Reason"),
) -> AuditHeaders:
    try:
        rid = UUID(x_request_id) if x_request_id else None
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid X-Request-Id format (UUID expected)")
    return AuditHeaders(
        x_request_id=rid,
        x_idempotency_key=x_idempotency_key,
        x_evidence_id=x_evidence_id,
        x_audit_user=x_audit_user,
        x_audit_reason=x_audit_reason,
    )


# ----------------------------- Data models (thin) -------------------------- #
# Храним весь документ DSAR как payload: Dict[str, Any], но индексируем основные поля,
# чтобы быстро фильтровать и отображать списки.

DSARStatus = Literal[
    "received",
    "in-review",
    "info-requested",
    "verified",
    "fulfilled",
    "partially-fulfilled",
    "rejected",
    "closed",
]

class DSARSummary(BaseModel):
    id: UUID
    requestId: UUID
    createdAt: datetime
    updatedAt: datetime
    framework: Optional[str] = Field(description="GDPR/CCPA/…", default=None)
    status: DSARStatus
    subjectEmail: Optional[EmailStr] = None
    subjectCountry: Optional[constr(regex=r"^[A-Z]{2}$")] = None

class DSARRecord(BaseModel):
    id: UUID
    createdAt: datetime
    updatedAt: datetime
    status: DSARStatus
    framework: Optional[str]
    payload: Dict[str, Any]


# ----------------------------- Repository protocol ------------------------- #

class DSARRepository(Protocol):
    def create(self, record: DSARRecord, idempotency_key: Optional[str]) -> Tuple[DSARRecord, bool]:
        ...

    def get(self, record_id: UUID) -> Optional[DSARRecord]:
        ...

    def get_by_request_id(self, request_id: UUID) -> Optional[DSARRecord]:
        ...

    def list(
        self,
        *,
        status: Optional[DSARStatus],
        framework: Optional[str],
        search: Optional[str],
        created_from: Optional[datetime],
        created_to: Optional[datetime],
        offset: int,
        limit: int,
    ) -> Tuple[List[DSARRecord], int]:
        ...

    def update_payload(self, record_id: UUID, apply_patch: Dict[str, Any]) -> Optional[DSARRecord]:
        ...

    def put_payload(self, record_id: UUID, payload: Dict[str, Any]) -> Optional[DSARRecord]:
        ...

    def remember_idempotency(self, key: str, record_id: UUID) -> None:
        ...

    def get_idempotent(self, key: str) -> Optional[UUID]:
        ...


class InMemoryDSARRepository:
    def __init__(self) -> None:
        self._by_id: Dict[UUID, DSARRecord] = {}
        self._idempotency: Dict[str, UUID] = {}

    def create(self, record: DSARRecord, idempotency_key: Optional[str]) -> Tuple[DSARRecord, bool]:
        if idempotency_key:
            existed = self.get_idempotent(idempotency_key)
            if existed:
                # Возврат существующей записи
                return self._by_id[existed], True
            self.remember_idempotency(idempotency_key, record.id)
        self._by_id[record.id] = record
        return record, False

    def get(self, record_id: UUID) -> Optional[DSARRecord]:
        return self._by_id.get(record_id)

    def get_by_request_id(self, request_id: UUID) -> Optional[DSARRecord]:
        for r in self._by_id.values():
            if r.payload.get("requestId") == str(request_id):
                return r
        return None

    def list(
        self,
        *,
        status: Optional[DSARStatus],
        framework: Optional[str],
        search: Optional[str],
        created_from: Optional[datetime],
        created_to: Optional[datetime],
        offset: int,
        limit: int,
    ) -> Tuple[List[DSARRecord], int]:
        data = list(self._by_id.values())
        if status:
            data = [d for d in data if d.status == status]
        if framework:
            data = [d for d in data if (d.framework or "").lower() == framework.lower()]
        if created_from:
            data = [d for d in data if d.createdAt >= created_from]
        if created_to:
            data = [d for d in data if d.createdAt <= created_to]
        if search:
            s = search.lower()
            def hay(r: DSARRecord) -> str:
                subject_emails = r.payload.get("dataSubject", {}).get("emails", [])
                title = r.payload.get("request", {}).get("requestType", "")
                return " ".join([
                    json.dumps(r.payload, ensure_ascii=False).lower()[0:0],  # no heavy
                    " ".join(subject_emails).lower(),
                    str(title).lower(),
                    str(r.id),
                    str(r.payload.get("requestId", "")),
                ])
            data = [d for d in data if s in hay(d)]
        total = len(data)
        data = data[offset : offset + limit]
        return data, total

    def update_payload(self, record_id: UUID, apply_patch: Dict[str, Any]) -> Optional[DSARRecord]:
        rec = self._by_id.get(record_id)
        if not rec:
            return None
        # простое глубокое слияние по верхним ключам
        payload = rec.payload.copy()
        for k, v in apply_patch.items():
            if isinstance(v, dict) and isinstance(payload.get(k), dict):
                payload[k] = {**payload.get(k, {}), **v}
            else:
                payload[k] = v
        return self.put_payload(record_id, payload)

    def put_payload(self, record_id: UUID, payload: Dict[str, Any]) -> Optional[DSARRecord]:
        rec = self._by_id.get(record_id)
        if not rec:
            return None
        status_value = (
            payload.get("processing", {}).get("status")
            or rec.status
        )
        framework = (payload.get("jurisdiction", {}) or {}).get("framework")
        rec = DSARRecord(
            id=rec.id,
            createdAt=rec.createdAt,
            updatedAt=datetime.now(timezone.utc),
            status=status_value,  # type: ignore[assignment]
            framework=framework,
            payload=payload,
        )
        self._by_id[record_id] = rec
        return rec

    def remember_idempotency(self, key: str, record_id: UUID) -> None:
        self._idempotency[key] = record_id

    def get_idempotent(self, key: str) -> Optional[UUID]:
        return self._idempotency.get(key)


# ----------------------------- JSON Schema validation ---------------------- #

def load_dsar_schema() -> Optional[Dict[str, Any]]:
    """
    Загружаем schemas/jsonschema/v1/dsar_request.schema.json, если доступно.
    Если jsonschema отсутствует — пропускаем строгую валидацию.
    """
    root = os.getenv("OVC_REPO_ROOT", os.getcwd())
    schema_path = os.path.join(
        root, "schemas", "jsonschema", "v1", "dsar_request.schema.json"
    )
    if not os.path.isfile(schema_path):
        logger.warning("DSAR JSON Schema not found at %s; skipping strict validation", schema_path)
        return None
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_against_schema(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if Draft202012Validator is None:
        # Библиотека не установлена — мягкий режим
        return errors
    schema = load_dsar_schema()
    if not schema:
        return errors
    try:
        validator = Draft202012Validator(schema)
        for err in validator.iter_errors(payload):
            path = "/".join([str(p) for p in err.path])
            errors.append(f"{path or '<root>'}: {err.message}")
    except js_exceptions.SchemaError as e:  # type: ignore[attr-defined]
        logger.error("Invalid DSAR JSON Schema: %s", e)
        errors.append(f"Schema error: {e}")
    return errors


# ----------------------------- DTOs for partial updates -------------------- #

class ProcessingPatch(BaseModel):
    status: Optional[DSARStatus] = None
    dueDate: Optional[datetime] = None
    extended: Optional[bool] = None
    extensionReason: Optional[constr(max_length=2000)] = None
    extensionNotifiedAt: Optional[datetime] = None
    rejectionReasons: Optional[List[
        Literal[
            "identity-not-verified",
            "manifestly-unfounded",
            "excessive",
            "legal-exemption",
            "data-not-found",
            "duplicate-request",
            "other",
        ]
    ]] = None
    slaMinutes: Optional[int] = Field(default=None, ge=1, le=43200)

class VerificationPatch(BaseModel):
    method: Optional[
        Literal[
            "email-otp",
            "sms-otp",
            "knowledge-based",
            "document",
            "in-person",
            "bankid",
            "eidas",
            "other",
        ]
    ] = None
    status: Optional[Literal["pending", "verified", "failed"]] = None
    verifiedAt: Optional[datetime] = None
    attempts: Optional[int] = Field(default=None, ge=0, le=10)
    notes: Optional[constr(max_length=2000)] = None

class AttachmentRef(BaseModel):
    id: UUID
    name: constr(min_length=1, max_length=200)
    mimeType: Literal["application/pdf", "image/jpeg", "image/png", "image/heic", "application/zip"]
    sizeBytes: int = Field(ge=1, le=50 * 1024 * 1024)
    uri: constr(min_length=1)
    hash: Optional[constr(regex=r"^[A-Fa-f0-9]{64,128}$")] = None

class AddAttachmentsIn(BaseModel):
    attachments: List[AttachmentRef]

class AuditEventIn(BaseModel):
    timestamp: datetime
    actor: constr(min_length=1, max_length=120)
    action: Literal[
        "created",
        "verified",
        "comment-added",
        "evidence-attached",
        "export-started",
        "export-complete",
        "erasure-initiated",
        "erasure-complete",
        "response-sent",
        "closed",
    ]
    note: Optional[constr(max_length=2000)] = None
    statusSnapshot: Optional[DSARStatus] = None


# ----------------------------- Router & dependencies ----------------------- #

router = APIRouter(prefix="/v1/requests", tags=["DSAR Requests"])

# Подмените на вашу реализацию репозитория через DI контейнер
REPO: DSARRepository = InMemoryDSARRepository()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _summarize(record: DSARRecord) -> DSARSummary:
    payload = record.payload
    emails = (payload.get("dataSubject", {}) or {}).get("emails", []) or []
    country = (payload.get("dataSubject", {}) or {}).get("countryOfResidence")
    return DSARSummary(
        id=record.id,
        requestId=UUID(payload.get("requestId")) if payload.get("requestId") else record.id,
        createdAt=record.createdAt,
        updatedAt=record.updatedAt,
        framework=record.framework,
        status=record.status,
        subjectEmail=emails[0] if emails else None,
        subjectCountry=country,
    )


# --------------------------------- Endpoints ------------------------------- #

@router.get(
    "",
    response_model=Dict[str, Any],
    summary="Список DSAR-запросов (пагинация/фильтры)",
)
def list_requests(
    status_: Optional[DSARStatus] = Query(default=None, alias="status"),
    framework: Optional[str] = Query(default=None, description="GDPR/CCPA/..."),
    search: Optional[str] = Query(default=None, description="по email/типу/ID"),
    created_from: Optional[datetime] = Query(default=None),
    created_to: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=50, ge=1, le=500),
):
    offset = (page - 1) * pageSize
    items, total = REPO.list(
        status=status_,
        framework=framework,
        search=search,
        created_from=created_from,
        created_to=created_to,
        offset=offset,
        limit=pageSize,
    )
    return {
        "items": [_summarize(r).dict() for r in items],
        "pageInfo": {"page": page, "pageSize": pageSize, "total": total},
    }


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=Dict[str, Any],
    summary="Создать DSAR-запрос (идемпотентно)",
)
def create_request(
    payload: Dict[str, Any] = Body(..., description="Полный документ DSAR"),
    audit: AuditHeaders = Depends(get_audit_headers),
    background: BackgroundTasks = None,  # type: ignore[assignment]
):
    # Добавляем базовые поля, если они отсутствуют
    now = _now().isoformat()
    payload.setdefault("schemaVersion", "1.0.0")
    payload.setdefault("createdAt", now)
    payload.setdefault("requestId", str(uuid4()))
    # Вставляем начальную аудит-событие
    audit_event = {
        "timestamp": now,
        "actor": audit.x_audit_user or "system",
        "action": "created",
        "note": audit.x_audit_reason,
        "statusSnapshot": (payload.get("processing") or {}).get("status", "received"),
    }
    payload.setdefault("audit", {}).setdefault("events", []).append(audit_event)

    # Валидация по JSON Schema
    errors = validate_against_schema(payload)
    if errors:
        return problem_response(
            status_code=422,
            title="Validation failed against DSAR schema",
            detail="; ".join(errors[:10]),
        )

    # Индексация основных полей
    status_val: DSARStatus = (payload.get("processing") or {}).get("status", "received")  # type: ignore[assignment]
    framework = (payload.get("jurisdiction") or {}).get("framework")

    record = DSARRecord(
        id=uuid4(),
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
        status=status_val,
        framework=framework,
        payload=payload,
    )
    saved, reused = REPO.create(record, audit.x_idempotency_key)
    if reused:
        logger.info("Idempotent replay, key=%s record=%s", audit.x_idempotency_key, saved.id)
    # Хук для фона: связать с evidence (если указан X-Evidence-Id)
    if audit.x_evidence_id and background:
        background.add_task(
            logger.info,
            "Evidence link: %s -> %s",
            audit.x_evidence_id,
            saved.payload.get("requestId"),
        )
    # Ответ
    return {
        "id": str(saved.id),
        "requestId": saved.payload.get("requestId"),
        "createdAt": saved.createdAt.isoformat(),
        "status": saved.status,
        "framework": saved.framework,
        "links": {
            "self": f"/v1/requests/{saved.id}",
        },
    }


@router.get(
    "/{id}",
    response_model=Dict[str, Any],
    summary="Получить DSAR-запрос",
)
def get_request(
    id: UUID = Path(..., description="ID записи DSAR"),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    return {
        "summary": _summarize(rec).dict(),
        "payload": rec.payload,
    }


@router.patch(
    "/{id}/processing",
    response_model=Dict[str, Any],
    summary="Частичное обновление processing",
)
def patch_processing(
    id: UUID,
    patch: ProcessingPatch,
    audit: AuditHeaders = Depends(get_audit_headers),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    apply_patch = {"processing": {k: v for k, v in patch.dict(exclude_unset=True).items()}}
    # Добавим аудит-событие
    events = (rec.payload.get("audit") or {}).get("events") or []
    events.append(
        {
            "timestamp": _now().isoformat(),
            "actor": audit.x_audit_user or "system",
            "action": "comment-added",
            "note": f"processing patch by API ({audit.x_audit_reason or 'n/a'})",
            "statusSnapshot": apply_patch["processing"].get("status", rec.status),
        }
    )
    apply_patch["audit"] = {"events": events}
    new_rec = REPO.update_payload(id, apply_patch)
    if not new_rec:
        return problem_response(409, "Conflict", "Failed to update processing")
    # Проверка схемы (опционально)
    errors = validate_against_schema(new_rec.payload)
    if errors:
        return problem_response(422, "Validation failed after patch", "; ".join(errors[:10]))
    return {"summary": _summarize(new_rec).dict()}


@router.patch(
    "/{id}/verification",
    response_model=Dict[str, Any],
    summary="Частичное обновление verification",
)
def patch_verification(
    id: UUID,
    patch: VerificationPatch,
    audit: AuditHeaders = Depends(get_audit_headers),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    apply_patch = {"verification": {k: v for k, v in patch.dict(exclude_unset=True).items()}}
    events = (rec.payload.get("audit") or {}).get("events") or []
    events.append(
        {
            "timestamp": _now().isoformat(),
            "actor": audit.x_audit_user or "system",
            "action": "verified" if patch.status == "verified" else "comment-added",
            "note": f"verification patch ({audit.x_audit_reason or 'n/a'})",
            "statusSnapshot": (rec.payload.get("processing") or {}).get("status"),
        }
    )
    apply_patch["audit"] = {"events": events}
    new_rec = REPO.update_payload(id, apply_patch)
    if not new_rec:
        return problem_response(409, "Conflict", "Failed to update verification")
    errors = validate_against_schema(new_rec.payload)
    if errors:
        return problem_response(422, "Validation failed after patch", "; ".join(errors[:10]))
    return {"summary": _summarize(new_rec).dict()}


@router.post(
    "/{id}/attachments",
    response_model=Dict[str, Any],
    summary="Добавить ссылки на вложения (метаданные)",
)
def add_attachments(
    id: UUID,
    req: AddAttachmentsIn,
    audit: AuditHeaders = Depends(get_audit_headers),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    attachments = (rec.payload.get("attachments") or [])
    attachments.extend([a.dict() for a in req.attachments])
    apply_patch = {"attachments": attachments}
    # Аудит
    events = (rec.payload.get("audit") or {}).get("events") or []
    events.append(
        {
            "timestamp": _now().isoformat(),
            "actor": audit.x_audit_user or "system",
            "action": "evidence-attached",
            "note": f"{len(req.attachments)} attachment(s) added",
            "statusSnapshot": (rec.payload.get("processing") or {}).get("status"),
        }
    )
    apply_patch["audit"] = {"events": events}
    new_rec = REPO.update_payload(id, apply_patch)
    if not new_rec:
        return problem_response(409, "Conflict", "Failed to add attachments")
    errors = validate_against_schema(new_rec.payload)
    if errors:
        return problem_response(422, "Validation failed after patch", "; ".join(errors[:10]))
    return {"summary": _summarize(new_rec).dict(), "attachments": new_rec.payload.get("attachments", [])}


@router.post(
    "/{id}/events",
    status_code=204,
    summary="Добавить кастомное аудит-событие",
)
def add_event(
    id: UUID,
    evt: AuditEventIn,
    audit: AuditHeaders = Depends(get_audit_headers),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    events = (rec.payload.get("audit") or {}).get("events") or []
    events.append(
        {
            "timestamp": evt.timestamp.isoformat(),
            "actor": evt.actor,
            "action": evt.action,
            "note": evt.note,
            "statusSnapshot": evt.statusSnapshot,
        }
    )
    apply_patch = {"audit": {"events": events}}
    new_rec = REPO.update_payload(id, apply_patch)
    if not new_rec:
        return problem_response(409, "Conflict", "Failed to append audit event")
    return JSONResponse(status_code=204, content=None)


@router.post(
    "/{id}/close",
    response_model=Dict[str, Any],
    summary="Закрыть DSAR (status=closed)",
)
def close_request(
    id: UUID,
    audit: AuditHeaders = Depends(get_audit_headers),
):
    rec = REPO.get(id)
    if not rec:
        return problem_response(404, "Not Found", f"DSAR record {id} not found")
    processing = (rec.payload.get("processing") or {}).copy()
    processing["status"] = "closed"
    events = (rec.payload.get("audit") or {}).get("events") or []
    events.append(
        {
            "timestamp": _now().isoformat(),
            "actor": audit.x_audit_user or "system",
            "action": "closed",
            "note": audit.x_audit_reason,
            "statusSnapshot": "closed",
        }
    )
    new_rec = REPO.update_payload(id, {"processing": processing, "audit": {"events": events}})
    if not new_rec:
        return problem_response(409, "Conflict", "Failed to close DSAR")
    errors = validate_against_schema(new_rec.payload)
    if errors:
        return problem_response(422, "Validation failed after close", "; ".join(errors[:10]))
    return {"summary": _summarize(new_rec).dict()}
