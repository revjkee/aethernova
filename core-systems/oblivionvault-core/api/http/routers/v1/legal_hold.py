# oblivionvault-core/api/http/routers/v1/legal_hold.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional, Tuple

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Query,
    Response,
    status,
)
from pydantic import BaseModel, EmailStr, Field, computed_field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/legal-holds", tags=["legal-holds"])


# --------------------------- Helpers ---------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_ulid_like() -> str:
    # Упрощенный генератор ULID-подобного идентификатора на базе времени.
    # В проде используйте ulid-py/uuid7.
    now = int(utcnow().timestamp() * 1000)
    rand = base64.urlsafe_b64encode(now.to_bytes(8, "big")).decode().rstrip("=")
    return f"01{rand}Z"  # просто стабильный префикс для сортировки


def make_etag(version: int) -> str:
    return f'W/"{version}"'


def parse_if_match(if_match: Optional[str]) -> Optional[str]:
    if not if_match:
        return None
    return if_match.strip()


def b64_cursor(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(token: Optional[str]) -> Dict[str, Any]:
    if not token:
        return {}
    pad = "=" * (-len(token) % 4)
    data = base64.urlsafe_b64decode(token + pad)
    return json.loads(data.decode())


# --------------------------- Domain models ---------------------------

class Labels(BaseModel):
    __root__: Dict[str, str] = Field(default_factory=dict)

    def dict(self, *args, **kwargs):
        return self.__root__


class Actor(BaseModel):
    id: str = Field(..., min_length=1, max_length=256)
    type: str = Field(..., pattern="^(user|service|system)$")
    email: Optional[EmailStr] = None
    display_name: Optional[str] = Field(default=None, max_length=256)


class Webhook(BaseModel):
    url: str = Field(..., description="URI", min_length=1, max_length=2048)
    method: str = Field("POST", pattern="^(POST|PUT|PATCH)$")
    secret_header: str = Field(default="X-Signature", max_length=64)
    secret_value_env: Optional[str] = Field(default=None, max_length=128)
    timeouts_connect_ms: int = Field(default=3000, ge=1, le=60000)
    timeouts_read_ms: int = Field(default=5000, ge=1, le=120000)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    retry_backoff_ms: int = Field(default=2000, ge=0, le=60000)


class NotificationTarget(BaseModel):
    channel: str = Field(..., pattern="^(email|slack|webhook)$")
    email: Optional[EmailStr] = None
    slack_webhook: Optional[str] = None
    webhook: Optional[Webhook] = None

    @field_validator("email")
    @classmethod
    def require_email_if_channel_email(cls, v, info):
        channel = info.data.get("channel")
        if channel == "email" and not v:
            raise ValueError("email is required when channel=email")
        return v

    @field_validator("slack_webhook")
    @classmethod
    def require_slack_if_channel_slack(cls, v, info):
        channel = info.data.get("channel")
        if channel == "slack" and not v:
            raise ValueError("slack_webhook is required when channel=slack")
        return v

    @field_validator("webhook")
    @classmethod
    def require_wh_if_channel_webhook(cls, v, info):
        channel = info.data.get("channel")
        if channel == "webhook" and not v:
            raise ValueError("webhook is required when channel=webhook")
        return v


class ApprovalStep(BaseModel):
    role: str = Field(..., max_length=128)
    status: str = Field(..., pattern="^(pending|approved|rejected)$")
    comment: Optional[str] = Field(default=None, max_length=2000)
    timestamp: Optional[datetime] = None
    assignee: Optional[Actor] = None


class Subject(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4000)
    jurisdictions: List[str] = Field(default_factory=list)
    legal_matter: Optional[Dict[str, str]] = None
    labels: Optional[Labels] = None


class Effective(BaseModel):
    indefinite: bool = False
    activated_at: datetime
    expires_at: Optional[datetime] = None
    tz: str = Field(default="UTC", min_length=1, max_length=64)
    grace_period: Optional[str] = Field(
        default=None,
        description="ISO 8601 duration, e.g. P7D or PT24H",
        pattern=r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$",
    )

    @field_validator("expires_at")
    @classmethod
    def check_expires_if_not_indefinite(cls, v, info):
        indefinite = info.data.get("indefinite", False)
        if not indefinite and v is None:
            raise ValueError("expires_at is required when indefinite=false")
        if indefinite and v is not None:
            raise ValueError("expires_at must be omitted when indefinite=true")
        return v


class Compliance(BaseModel):
    prevent_delete: bool = True
    prevent_update: bool = True
    copy_on_write: bool = True
    versioning_required: bool = True
    immutable_storage: bool = False
    allow_read: bool = True
    exceptions: List[str] = Field(default_factory=list)


class ReleaseInfo(BaseModel):
    released_at: datetime
    released_by: Actor
    reason: Optional[str] = Field(default=None, max_length=2000)
    superseded_by: Optional[str] = None


class LegalHoldBase(BaseModel):
    schema_version: str = Field(default="1.0.0", pattern=r"^\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]+)?$")
    external_ref: Optional[str] = Field(default=None, max_length=256)
    type: str = Field(..., pattern="^(litigation|investigation|regulatory|preservation_order|other)$")
    status: str = Field(..., pattern="^(draft|active|released|superseded)$")
    subject: Subject
    scope: Dict[str, Any]  # режимы all/objects/tags/prefixes/query из JSONSchema
    effective: Effective
    compliance: Compliance
    custodians: List[Actor] = Field(default_factory=list)
    approvals_required: int = Field(default=2, ge=1, le=10)
    approvals: List[ApprovalStep] = Field(default_factory=list)
    notifications_recipients: List[NotificationTarget] = Field(default_factory=list)
    notifications_triggers: List[str] = Field(
        default_factory=lambda: ["on_apply", "on_violation"],
    )
    webhooks: List[Webhook] = Field(default_factory=list)
    labels: Optional[Labels] = None
    extensions: Optional[Dict[str, Any]] = None


class LegalHoldCreate(LegalHoldBase):
    status: str = Field(default="active", pattern="^(draft|active)$")  # создаем только draft|active


class LegalHoldUpdate(BaseModel):
    # Частичное обновление
    external_ref: Optional[str] = Field(default=None, max_length=256)
    status: Optional[str] = Field(default=None, pattern="^(draft|active|released|superseded)$")
    subject: Optional[Subject] = None
    scope: Optional[Dict[str, Any]] = None
    effective: Optional[Effective] = None
    compliance: Optional[Compliance] = None
    custodians: Optional[List[Actor]] = None
    approvals_required: Optional[int] = Field(default=None, ge=1, le=10)
    approvals: Optional[List[ApprovalStep]] = None
    notifications_recipients: Optional[List[NotificationTarget]] = None
    notifications_triggers: Optional[List[str]] = None
    webhooks: Optional[List[Webhook]] = None
    labels: Optional[Labels] = None
    extensions: Optional[Dict[str, Any]] = None
    release: Optional[ReleaseInfo] = None  # разрешаем вместе со статусом released


class AuditEvent(BaseModel):
    at: datetime
    actor: Actor
    action: str = Field(..., pattern="^[a-z_]+$")
    details: Dict[str, Any] = Field(default_factory=dict)


class LegalHold(LegalHoldBase):
    hold_id: str
    created_at: datetime
    updated_at: datetime
    etag: str
    version: int
    release: Optional[ReleaseInfo] = None
    created_by: Optional[Actor] = None
    updated_by: Optional[Actor] = None
    audit: List[AuditEvent] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_active(self) -> bool:
        return self.status == "active"


class PageInfo(BaseModel):
    next_page_token: Optional[str] = None
    total_count: int


class ListResponse(BaseModel):
    items: List[LegalHold]
    page_info: PageInfo


# --------------------------- Repository (in-memory, async) ---------------------------

class LegalHoldRepository:
    async def create(self, item: LegalHold) -> LegalHold: ...
    async def get(self, hold_id: str) -> Optional[LegalHold]: ...
    async def update(self, item: LegalHold) -> LegalHold: ...
    async def delete(self, hold_id: str) -> None: ...
    async def list(self, limit: int, cursor: Optional[str]) -> Tuple[List[LegalHold], Optional[str], int]: ...
    async def append_audit(self, hold_id: str, event: AuditEvent) -> None: ...
    async def get_audit(self, hold_id: str) -> List[AuditEvent]: ...
    async def resolve_idempotency(self, key: str) -> Optional[str]: ...
    async def save_idempotency(self, key: str, hold_id: str) -> None: ...


class InMemoryLegalHoldRepo(LegalHoldRepository):
    def __init__(self):
        self._items: Dict[str, LegalHold] = {}
        self._audits: Dict[str, List[AuditEvent]] = {}
        self._idem: Dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def create(self, item: LegalHold) -> LegalHold:
        async with self._lock:
            self._items[item.hold_id] = item
            self._audits.setdefault(item.hold_id, [])
            return item

    async def get(self, hold_id: str) -> Optional[LegalHold]:
        return self._items.get(hold_id)

    async def update(self, item: LegalHold) -> LegalHold:
        async with self._lock:
            if item.hold_id not in self._items:
                raise KeyError("not found")
            self._items[item.hold_id] = item
            return item

    async def delete(self, hold_id: str) -> None:
        async with self._lock:
            self._items.pop(hold_id, None)
            self._audits.pop(hold_id, None)

    async def list(self, limit: int, cursor: Optional[str]) -> Tuple[List[LegalHold], Optional[str], int]:
        items = sorted(self._items.values(), key=lambda x: (x.created_at, x.hold_id))
        start_at = 0
        cur = decode_cursor(cursor)
        if "created_at" in cur and "hold_id" in cur:
            for i, it in enumerate(items):
                if it.created_at.isoformat() == cur["created_at"] and it.hold_id == cur["hold_id"]:
                    start_at = i + 1
                    break
        window = items[start_at : start_at + limit]
        next_token = None
        if start_at + limit < len(items):
            last = window[-1]
            next_token = b64_cursor({"created_at": last.created_at.isoformat(), "hold_id": last.hold_id})
        return window, next_token, len(items)

    async def append_audit(self, hold_id: str, event: AuditEvent) -> None:
        async with self._lock:
            self._audits.setdefault(hold_id, []).append(event)
            if hold_id in self._items:
                obj = self._items[hold_id]
                obj.audit = self._audits[hold_id]
                self._items[hold_id] = obj

    async def get_audit(self, hold_id: str) -> List[AuditEvent]:
        return list(self._audits.get(hold_id, []))

    async def resolve_idempotency(self, key: str) -> Optional[str]:
        return self._idem.get(key)

    async def save_idempotency(self, key: str, hold_id: str) -> None:
        async with self._lock:
            self._idem[key] = hold_id


_repo_singleton = InMemoryLegalHoldRepo()


async def get_repo() -> LegalHoldRepository:
    # В проде внедрите реализацию, работающую с БД.
    return _repo_singleton


# --------------------------- Security (placeholder) ---------------------------

async def get_current_actor(authorization: Annotated[Optional[str], Header()] = None) -> Actor:
    # В проде проверьте JWT RS256 и извлеките subject/claims.
    if not authorization:
        return Actor(id="svc:unknown", type="service")
    return Actor(id="svc:api", type="service")


# --------------------------- Validators and transitions ---------------------------

def ensure_status_transition(old: str, new: str) -> None:
    allowed = {
        "draft": {"draft", "active", "released", "superseded"},
        "active": {"active", "released", "superseded"},
        "released": {"released", "superseded"},
        "superseded": {"superseded"},
    }
    if new not in allowed.get(old, set()):
        raise HTTPException(status_code=400, detail=f"invalid status transition {old} -> {new}")


def ensure_release_payload(new_status: Optional[str], release: Optional[ReleaseInfo]) -> None:
    if new_status == "released" and not release:
        raise HTTPException(status_code=400, detail="release info required for status=released")


# --------------------------- Routes ---------------------------

@router.post("", status_code=status.HTTP_201_CREATED, response_model=LegalHold)
async def create_legal_hold(
    resp: Response,
    payload: Annotated[LegalHoldCreate, Body(..., embed=False)],
    repo: LegalHoldRepository = Depends(get_repo),
    actor: Actor = Depends(get_current_actor),
    idempotency_key: Annotated[Optional[str], Header(convert_underscores=False)] = None,
):
    # Idempotency
    if idempotency_key:
        existing_id = await repo.resolve_idempotency(idempotency_key)
        if existing_id:
            existing = await repo.get(existing_id)
            if existing:
                resp.headers["ETag"] = existing.etag
                return existing

    hold_id = make_ulid_like()
    now = utcnow()
    item = LegalHold(
        hold_id=hold_id,
        created_at=now,
        updated_at=now,
        etag=make_etag(1),
        version=1,
        created_by=actor,
        updated_by=actor,
        audit=[],
        **payload.model_dump(),
    )

    # Если создаем released|superseded — запрет (через модель ограничили).
    # Валидация effective уже выполнена в модели.

    await repo.create(item)
    await repo.append_audit(
        hold_id,
        AuditEvent(at=utcnow(), actor=actor, action="create", details={"status": item.status}),
    )

    if idempotency_key:
        await repo.save_idempotency(idempotency_key, hold_id)

    resp.headers["ETag"] = item.etag
    logger.info("legal_hold_created", extra={"hold_id": hold_id, "status": item.status})
    return item


@router.get("/{hold_id}", response_model=LegalHold)
async def get_legal_hold(
    hold_id: str,
    resp: Response,
    repo: LegalHoldRepository = Depends(get_repo),
):
    item = await repo.get(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    resp.headers["ETag"] = item.etag
    return item


@router.get("", response_model=ListResponse)
async def list_legal_holds(
    limit: int = Query(50, ge=1, le=200),
    page_token: Optional[str] = Query(None, alias="page_token"),
    repo: LegalHoldRepository = Depends(get_repo),
):
    items, next_token, total = await repo.list(limit=limit, cursor=page_token)
    return ListResponse(items=items, page_info=PageInfo(next_page_token=next_token, total_count=total))


@router.patch("/{hold_id}", response_model=LegalHold)
async def update_legal_hold(
    hold_id: str,
    resp: Response,
    payload: Annotated[LegalHoldUpdate, Body(..., embed=False)],
    repo: LegalHoldRepository = Depends(get_repo),
    actor: Actor = Depends(get_current_actor),
    if_match: Annotated[Optional[str], Header(convert_underscores=False)] = None,
):
    item = await repo.get(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")

    # Optimistic locking
    if if_match:
        if parse_if_match(if_match) != item.etag:
            raise HTTPException(status_code=412, detail="etag mismatch")

    # Status transitions and release checks
    new_status = payload.status or item.status
    ensure_status_transition(item.status, new_status)
    ensure_release_payload(payload.status, payload.release)

    data = item.model_dump()
    patch = payload.model_dump(exclude_unset=True)
    data.update(patch)

    # Валидацию Effective выполнит Pydantic при реконструкции
    updated = LegalHold(**data)
    updated.version = item.version + 1
    updated.etag = make_etag(updated.version)
    updated.updated_at = utcnow()
    updated.updated_by = actor
    await repo.update(updated)

    await repo.append_audit(
        hold_id,
        AuditEvent(at=utcnow(), actor=actor, action="update", details={"fields": list(patch.keys())}),
    )

    resp.headers["ETag"] = updated.etag
    logger.info(
        "legal_hold_updated",
        extra={"hold_id": hold_id, "version": updated.version, "status": updated.status},
    )
    return updated


@router.post("/{hold_id}/release", response_model=LegalHold)
async def release_legal_hold(
    hold_id: str,
    resp: Response,
    release: Annotated[ReleaseInfo, Body(..., embed=False)],
    repo: LegalHoldRepository = Depends(get_repo),
    actor: Actor = Depends(get_current_actor),
    if_match: Annotated[Optional[str], Header(convert_underscores=False)] = None,
):
    item = await repo.get(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")

    if if_match and parse_if_match(if_match) != item.etag:
        raise HTTPException(status_code=412, detail="etag mismatch")

    if item.status in {"released", "superseded"}:
        raise HTTPException(status_code=409, detail="already released or superseded")

    # Apply release
    item.status = "released"
    item.release = release
    item.version += 1
    item.etag = make_etag(item.version)
    item.updated_at = utcnow()
    item.updated_by = actor

    await repo.update(item)
    await repo.append_audit(
        hold_id, AuditEvent(at=utcnow(), actor=actor, action="release", details={})
    )

    resp.headers["ETag"] = item.etag
    logger.info("legal_hold_released", extra={"hold_id": hold_id})
    return item


@router.delete("/{hold_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_legal_hold(
    hold_id: str,
    repo: LegalHoldRepository = Depends(get_repo),
    actor: Actor = Depends(get_current_actor),
    if_match: Annotated[Optional[str], Header(convert_underscores=False)] = None,
):
    item = await repo.get(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")

    if if_match and parse_if_match(if_match) != item.etag:
        raise HTTPException(status_code=412, detail="etag mismatch")

    # Удалять разрешим только draft или released
    if item.status not in {"draft", "released"}:
        raise HTTPException(status_code=409, detail="cannot delete in current status")

    await repo.delete(hold_id)
    logger.info("legal_hold_deleted", extra={"hold_id": hold_id, "by": actor.id})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{hold_id}/audit", response_model=List[AuditEvent])
async def get_audit_trail(
    hold_id: str,
    repo: LegalHoldRepository = Depends(get_repo),
):
    item = await repo.get(hold_id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    return await repo.get_audit(hold_id)
