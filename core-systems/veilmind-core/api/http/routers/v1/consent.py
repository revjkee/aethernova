# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query, Body
from pydantic import BaseModel, Field, validator, root_validator

# ------------------------------------------------------------------------------
# Вспомогательные утилиты
# ------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _to_epoch_s(dt: datetime) -> int:
    return int(dt.timestamp())

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _require_security(request: Request) -> Any:
    sc = getattr(request.state, "security", None)
    if sc is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return sc

def _extract_tenant_subject(request: Request) -> Tuple[Optional[str], Optional[str]]:
    sc = _require_security(request)
    return getattr(sc, "tenant", None), getattr(sc, "subject", None)

def _client_ip(request: Request) -> Optional[str]:
    h = request.headers
    xff = h.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None

# ------------------------------------------------------------------------------
# Доменные типы и схемы
# ------------------------------------------------------------------------------

SEMVER_RE = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$"

class ConsentAction(str):
    GRANT = "grant"
    WITHDRAW = "withdraw"

class ConsentEventIn(BaseModel):
    policy_id: str = Field(..., min_length=1, max_length=200, description="Идентификатор политики согласия")
    policy_version: str = Field(..., regex=SEMVER_RE, description="Версия политики (semver)")
    action: str = Field(..., regex="^(grant|withdraw)$")
    scopes: List[str] = Field(default_factory=list, description="Допустимые области использования данных")
    purposes: List[str] = Field(default_factory=list, description="Цели обработки")
    subject_id: Optional[str] = Field(None, description="Идентификатор субъекта (если иной, чем из токена)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Произвольные метаданные клиента")
    occurred_at: Optional[datetime] = Field(None, description="Момент события; если не задан — серверное UTC now")
    proof: Optional[Dict[str, Any]] = Field(default=None, description="Опциональное крипто‑подтверждение (JWS/HMAC)")

    @validator("scopes", "purposes", each_item=True)
    def _items_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("empty item not allowed")
        return v.strip()

class ConsentEventOut(BaseModel):
    id: str
    tenant: Optional[str]
    subject_id: str
    policy_id: str
    policy_version: str
    action: str
    scopes: List[str]
    purposes: List[str]
    occurred_at: datetime
    received_at: datetime
    request_ip: Optional[str]
    user_agent: Optional[str]
    metadata: Dict[str, Any] = {}
    proof: Optional[Dict[str, Any]] = None
    chain_prev: Optional[str] = None
    chain_hash: str

class ConsentStatusOut(BaseModel):
    tenant: Optional[str]
    subject_id: str
    policy_id: str
    effective: bool
    last_action: str
    policy_version: str
    occurred_at: datetime

class PageMeta(BaseModel):
    next_cursor: Optional[str] = None
    limit: int

class ConsentEventListOut(BaseModel):
    items: List[ConsentEventOut]
    page: PageMeta

# ------------------------------------------------------------------------------
# Интерфейсы репозитория и провайдера политики
# ------------------------------------------------------------------------------

@dataclass
class ConsentEvent:
    id: str
    tenant: Optional[str]
    subject_id: str
    policy_id: str
    policy_version: str
    action: str
    scopes: Tuple[str, ...]
    purposes: Tuple[str, ...]
    occurred_at: datetime
    received_at: datetime
    request_ip: Optional[str]
    user_agent: Optional[str]
    metadata: Dict[str, Any]
    proof: Optional[Dict[str, Any]]
    chain_prev: Optional[str]
    chain_hash: str
    idempotency_key: Optional[str] = None

class ConsentRepository:
    async def save_event(self, ev: ConsentEvent) -> ConsentEvent:
        raise NotImplementedError

    async def get_event(self, tenant: Optional[str], ev_id: str) -> Optional[ConsentEvent]:
        raise NotImplementedError

    async def find_latest(self, tenant: Optional[str], subject_id: str, policy_id: str) -> Optional[ConsentEvent]:
        raise NotImplementedError

    async def list_events(
        self,
        tenant: Optional[str],
        subject_id: Optional[str],
        policy_id: Optional[str],
        limit: int,
        cursor: Optional[str],
        order_asc: bool = False,
    ) -> Tuple[List[ConsentEvent], Optional[str]]:
        raise NotImplementedError

    async def get_by_idempotency(self, tenant: Optional[str], key: str) -> Optional[ConsentEvent]:
        raise NotImplementedError

class ConsentPolicyProvider:
    async def is_known(self, tenant: Optional[str], policy_id: str, version: str) -> bool:
        """Проверка существования/поддержки политики указанной версии (можно реализовать через БД/ConfigMap)."""
        return True

# ------------------------------------------------------------------------------
# In-memory реализация (референс/по умолчанию, не для продакшн)
# ------------------------------------------------------------------------------

class InMemoryConsentRepository(ConsentRepository):
    def __init__(self) -> None:
        # Ключи: (tenant,'events') → список; (tenant,'by_id') → dict; (tenant,'idem') → dict
        self._events: Dict[str, List[ConsentEvent]] = {}
        self._by_id: Dict[str, Dict[str, ConsentEvent]] = {}
        self._idem: Dict[str, Dict[str, ConsentEvent]] = {}

    def _tkey(self, tenant: Optional[str]) -> str:
        return tenant or "__global__"

    async def save_event(self, ev: ConsentEvent) -> ConsentEvent:
        tk = self._tkey(ev.tenant)
        self._events.setdefault(tk, []).append(ev)
        self._by_id.setdefault(tk, {})[ev.id] = ev
        if ev.idempotency_key:
            self._idem.setdefault(tk, {})[ev.idempotency_key] = ev
        return ev

    async def get_event(self, tenant: Optional[str], ev_id: str) -> Optional[ConsentEvent]:
        return self._by_id.get(self._tkey(tenant), {}).get(ev_id)

    async def find_latest(self, tenant: Optional[str], subject_id: str, policy_id: str) -> Optional[ConsentEvent]:
        for ev in reversed(self._events.get(self._tkey(tenant), [])):
            if ev.subject_id == subject_id and ev.policy_id == policy_id:
                return ev
        return None

    async def list_events(
        self,
        tenant: Optional[str],
        subject_id: Optional[str],
        policy_id: Optional[str],
        limit: int,
        cursor: Optional[str],
        order_asc: bool = False,
    ) -> Tuple[List[ConsentEvent], Optional[str]]:
        data = self._events.get(self._tkey(tenant), [])
        if subject_id:
            data = [e for e in data if e.subject_id == subject_id]
        if policy_id:
            data = [e for e in data if e.policy_id == policy_id]
        data_sorted = sorted(data, key=lambda e: e.received_at, reverse=not order_asc)

        start = 0
        if cursor:
            try:
                ts, eid = cursor.split(":", 1)
                ts_i = int(ts)
                # находим позицию после курсора
                def after(e: ConsentEvent) -> bool:
                    if int(e.received_at.timestamp()) == ts_i:
                        return e.id > eid
                    return int(e.received_at.timestamp()) < ts_i if not order_asc else int(e.received_at.timestamp()) > ts_i
                for idx, e in enumerate(data_sorted):
                    if after(e):
                        start = idx
                        break
            except Exception:
                start = 0

        items = data_sorted[start : start + limit]
        next_cursor = None
        if len(items) == limit:
            last = items[-1]
            next_cursor = f"{int(last.received_at.timestamp())}:{last.id}"
        return items, next_cursor

    async def get_by_idempotency(self, tenant: Optional[str], key: str) -> Optional[ConsentEvent]:
        return self._idem.get(self._tkey(tenant), {}).get(key)

# ------------------------------------------------------------------------------
# DI (замените провайдеры в приложении на реальные)
# ------------------------------------------------------------------------------

_repo_singleton: ConsentRepository = InMemoryConsentRepository()
_policy_singleton: ConsentPolicyProvider = ConsentPolicyProvider()

async def get_repo() -> ConsentRepository:
    return _repo_singleton

async def get_policy_provider() -> ConsentPolicyProvider:
    return _policy_singleton

# ------------------------------------------------------------------------------
# Хеш‑цепочка аудита (tamper‑evident)
# ------------------------------------------------------------------------------

def _chain_next(prev_hash: Optional[str], event_payload: Dict[str, Any]) -> str:
    """
    Хеш‑цепочка: H = sha256( prev || sha256(canonical_json(event)) )
    """
    canonical = json.dumps(event_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    inner = hashlib.sha256(canonical).digest()
    if prev_hash:
        data = base64.b64decode(prev_hash + "==") + inner
    else:
        data = inner
    return _b64url(hashlib.sha256(data).digest())

# ------------------------------------------------------------------------------
# Роутер
# ------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/consent", tags=["consent"])

# --- Создание события согласия/отзыва --------------------------------------------------------

@router.post("/records", response_model=ConsentEventOut, status_code=status.HTTP_201_CREATED)
async def create_consent_event(
    request: Request,
    response: Response,
    payload: ConsentEventIn = Body(...),
    repo: ConsentRepository = Depends(get_repo),
    policy: ConsentPolicyProvider = Depends(get_policy_provider),
    idem_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    tenant, subject_from_token = _extract_tenant_subject(request)
    subject = payload.subject_id or subject_from_token
    if not subject:
        raise HTTPException(status_code=400, detail="subject is required (token or body)")

    # Идемпотентность
    if idem_key:
        existing = await repo.get_by_idempotency(tenant, idem_key)
        if existing:
            # Возврат существующего результата
            dto = _to_out(existing)
            _set_entity_headers(response, dto)
            response.status_code = status.HTTP_200_OK
            return dto

    # Валидация политики/версии
    known = await policy.is_known(tenant, payload.policy_id, payload.policy_version)
    if not known:
        raise HTTPException(status_code=400, detail="unknown policy_id or policy_version")

    occurred_at = payload.occurred_at or _utc_now()
    received_at = _utc_now()
    req_ip = _client_ip(request)
    ua = request.headers.get("user-agent")

    # chain_prev = хеш последнего события для этого субъекта+политики (в границах арендатора)
    last = await repo.find_latest(tenant, subject, payload.policy_id)
    chain_prev = last.chain_hash if last else None

    ev = ConsentEvent(
        id=str(uuid.uuid4()),
        tenant=tenant,
        subject_id=subject,
        policy_id=payload.policy_id,
        policy_version=payload.policy_version,
        action=payload.action,
        scopes=tuple(payload.scopes or []),
        purposes=tuple(payload.purposes or []),
        occurred_at=occurred_at,
        received_at=received_at,
        request_ip=req_ip,
        user_agent=ua,
        metadata=payload.metadata or {},
        proof=payload.proof,
        chain_prev=chain_prev,
        chain_hash=_chain_next(chain_prev, {
            "tenant": tenant,
            "subject_id": subject,
            "policy_id": payload.policy_id,
            "policy_version": payload.policy_version,
            "action": payload.action,
            "occurred_at": _to_epoch_s(occurred_at),
            "received_at": _to_epoch_s(received_at),
        }),
        idempotency_key=idem_key,
    )

    saved = await repo.save_event(ev)
    out = _to_out(saved)
    _set_entity_headers(response, out)
    return out

# --- Получение записи -----------------------------------------------------------------------

@router.get("/records/{record_id}", response_model=ConsentEventOut)
async def get_consent_event(
    record_id: str,
    request: Request,
    response: Response,
    repo: ConsentRepository = Depends(get_repo),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    tenant, _ = _extract_tenant_subject(request)
    ev = await repo.get_event(tenant, record_id)
    if not ev:
        raise HTTPException(status_code=404, detail="record not found")
    dto = _to_out(ev)
    etag = _etag_of(dto)
    if if_none_match and if_none_match == etag:
        response.status_code = status.HTTP_304_NOT_MODIFIED
        return Response(status_code=status.HTTP_304_NOT_MODIFIED)
    _set_entity_headers(response, dto)
    return dto

# --- Статус согласия ------------------------------------------------------------------------

@router.get("/status", response_model=ConsentStatusOut)
async def get_consent_status(
    request: Request,
    policy_id: str = Query(..., min_length=1),
    subject_id: Optional[str] = Query(None, description="Если не задан — берем из токена"),
    repo: ConsentRepository = Depends(get_repo),
):
    tenant, subj_from_token = _extract_tenant_subject(request)
    subject = subject_id or subj_from_token
    if not subject:
        raise HTTPException(status_code=400, detail="subject is required")
    last = await repo.find_latest(tenant, subject, policy_id)
    if not last:
        return ConsentStatusOut(
            tenant=tenant,
            subject_id=subject,
            policy_id=policy_id,
            effective=False,
            last_action="none",
            policy_version="0.0.0",
            occurred_at=_utc_now(),
        )
    return ConsentStatusOut(
        tenant=tenant,
        subject_id=subject,
        policy_id=policy_id,
        effective=(last.action == ConsentAction.GRANT),
        last_action=last.action,
        policy_version=last.policy_version,
        occurred_at=last.occurred_at,
    )

# --- Листинг событий ------------------------------------------------------------------------

@router.get("/records", response_model=ConsentEventListOut)
async def list_consent_events(
    request: Request,
    repo: ConsentRepository = Depends(get_repo),
    subject_id: Optional[str] = Query(None),
    policy_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    cursor: Optional[str] = Query(None),
    order_asc: bool = Query(False),
):
    tenant, _ = _extract_tenant_subject(request)
    items, next_cursor = await repo.list_events(tenant, subject_id, policy_id, limit, cursor, order_asc)
    return ConsentEventListOut(
        items=[_to_out(e) for e in items],
        page=PageMeta(next_cursor=next_cursor, limit=limit),
    )

# --- Экспорт аудита -------------------------------------------------------------------------

@router.get("/export", response_class=Response)
async def export_consent_audit(
    request: Request,
    repo: ConsentRepository = Depends(get_repo),
    subject_id: Optional[str] = Query(None),
    policy_id: Optional[str] = Query(None),
    limit: int = Query(1000, ge=1, le=10000),
    cursor: Optional[str] = Query(None),
):
    tenant, subj_from_token = _extract_tenant_subject(request)
    subject = subject_id or subj_from_token
    if not subject:
        raise HTTPException(status_code=400, detail="subject is required")

    items, next_cursor = await repo.list_events(tenant, subject, policy_id, limit, cursor, order_asc=True)
    payload = {
        "exported_at": _utc_now().isoformat(),
        "tenant": tenant,
        "subject_id": subject,
        "policy_id": policy_id,
        "next_cursor": next_cursor,
        "items": [ _to_out(e).dict() for e in items ],
    }
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    etag = f'W/"{_sha256_hex(data)}"'
    headers = {
        "Content-Type": "application/json",
        "Content-Disposition": f'attachment; filename="consent-audit-{subject}.json"',
        "ETag": etag,
    }
    return Response(content=data, media_type="application/json", headers=headers)

# ------------------------------------------------------------------------------
# Вспомогательные функции представления/заголовки
# ------------------------------------------------------------------------------

def _to_out(ev: ConsentEvent) -> ConsentEventOut:
    return ConsentEventOut(
        id=ev.id,
        tenant=ev.tenant,
        subject_id=ev.subject_id,
        policy_id=ev.policy_id,
        policy_version=ev.policy_version,
        action=ev.action,
        scopes=list(ev.scopes),
        purposes=list(ev.purposes),
        occurred_at=ev.occurred_at,
        received_at=ev.received_at,
        request_ip=ev.request_ip,
        user_agent=ev.user_agent,
        metadata=ev.metadata or {},
        proof=ev.proof,
        chain_prev=ev.chain_prev,
        chain_hash=ev.chain_hash,
    )

def _etag_of(dto: BaseModel) -> str:
    payload = json.dumps(dto.dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f'W/"{_sha256_hex(payload)}"'

def _set_entity_headers(response: Response, dto: BaseModel) -> None:
    response.headers["ETag"] = _etag_of(dto)
    response.headers.setdefault("Cache-Control", "no-store")
    # Канареечный заголовок, не несущий секретов
    response.headers.setdefault("X-Consent-Record", "true")

# ------------------------------------------------------------------------------
# Примечания по интеграции
# ------------------------------------------------------------------------------
# 1) Подключите роутер в основном приложении:
#    from veilmind_core.api.http.routers.v1.consent import router as consent_router
#    app.include_router(consent_router)
#
# 2) Замените InMemoryConsentRepository на БД-реализацию (Postgres/MySQL),
#    реализовав интерфейс ConsentRepository и подменив get_repo() через Depends.
#
# 3) Безопасность: роутер рассчитывает на AuthMiddleware, который
#    помещает SecurityContext в request.state.security (см. middleware/auth.py).
#
# 4) Идемпотентность: при повторной отправке того же запроса с одним
#    и тем же заголовком Idempotency-Key возвращается та же запись (200 OK).
