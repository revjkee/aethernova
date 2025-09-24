# security-core/api/http/routers/v1/self_inhibitor.py
# Industrial Self-Inhibitor / Kill-Switch Router (FastAPI, async)
from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from pydantic import BaseModel, Field, NonNegativeInt, StrictBool, StrictInt, StrictStr, conint, constr, root_validator, validator

logger = logging.getLogger("security_core.self_inhibitor")
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/v1/self-inhibitor", tags=["self-inhibitor"])

# =========================
# Configuration (ENV)
# =========================

ADMIN_HMAC_SECRET = os.getenv("SECURITY_CORE_ADMIN_HMAC_SECRET", "").encode("utf-8")
ALLOW_UNPROTECTED_CMDS = os.getenv("SECURITY_CORE_ALLOW_UNPROTECTED_CMDS", "false").lower() == "true"
STATE_PATH = os.getenv("SECURITY_CORE_INHIBITOR_STATE_PATH", "").strip()
WEBHOOK_URL = os.getenv("SECURITY_CORE_INHIBITOR_WEBHOOK", "").strip()
TIME_SKEW_SEC = int(os.getenv("SECURITY_CORE_ADMIN_SIG_SKEW_SEC", "60"))
NONCE_TTL_SEC = int(os.getenv("SECURITY_CORE_ADMIN_NONCE_TTL", "300"))
DEFAULT_ARM_TTL_SEC = int(os.getenv("SECURITY_CORE_DEFAULT_ARM_TTL", "300"))
DEFAULT_TRIGGER_TTL_SEC = int(os.getenv("SECURITY_CORE_DEFAULT_TRIGGER_TTL", "900"))
RUNTIME_ENV = os.getenv("RUNTIME_ENV", "prod")

# =========================
# Domain
# =========================

class Scope(str, Enum):
    API_READONLY = "api_readonly"               # только чтение API
    BLOCK_WRITES = "block_writes"               # запрет mutating операций (write/delete)
    FREEZE_DEPLOY = "freeze_deploy"             # стоп промоушена/деплоев
    FREEZE_ARTIFACT_PROMOTION = "freeze_artifacts"  # стоп продвижения артефактов
    BLOCK_EGRESS = "block_egress"               # запрет внешнего исходящего трафика
    QUARANTINE = "quarantine"                   # карантин ворклоадов
    REVOKE_SHORT_TOKENS = "revoke_short_tokens" # отзыв краткоживущих токенов
    PAUSE_JOBS = "pause_jobs"                   # пауза фоновых задач/джобов
    THROTTLE = "throttle"                       # деградация RPS/лимиты

DEFAULT_SCOPES: List[Scope] = [
    Scope.BLOCK_WRITES, Scope.FREEZE_DEPLOY, Scope.FREEZE_ARTIFACT_PROMOTION,
]

# =========================
# Models
# =========================

TenantId = constr(strip_whitespace=True, min_length=1, max_length=128)

class SignatureParts(BaseModel):
    version: StrictStr = "v1"
    ts: conint(ge=0) = Field(..., description="UNIX seconds")
    nonce: StrictStr = Field(..., min_length=8, max_length=128)
    sig_hex: StrictStr = Field(..., min_length=32, max_length=256)

    @validator("version")
    def _v1_only(cls, v):
        if v != "v1":
            raise ValueError("unsupported signature version")
        return v

class ArmRequest(BaseModel):
    code_phrase: StrictStr = Field(..., min_length=6, max_length=256)
    ttl_seconds: conint(ge=30, le=86400) = DEFAULT_ARM_TTL_SEC
    reason: StrictStr = Field(..., min_length=3, max_length=4096)
    tenant: Optional[TenantId] = None
    dry_run: StrictBool = False

class TriggerRequest(BaseModel):
    scopes: List[Scope] = Field(default_factory=lambda: list(DEFAULT_SCOPES))
    ttl_seconds: conint(ge=60, le=172800) = DEFAULT_TRIGGER_TTL_SEC
    reason: StrictStr = Field(..., min_length=3, max_length=4096)
    tenant: Optional[TenantId] = None
    dry_run: StrictBool = False
    code_phrase: Optional[StrictStr] = Field(None, min_length=6, max_length=256)

class DisarmRequest(BaseModel):
    code_phrase: StrictStr = Field(..., min_length=6, max_length=256)
    force: StrictBool = False
    reason: Optional[StrictStr] = Field(None, min_length=3, max_length=4096)

class HeartbeatRequest(BaseModel):
    component: StrictStr = Field(..., min_length=2, max_length=128)
    status: StrictStr = Field(..., min_length=2, max_length=64)
    message: Optional[StrictStr] = Field(None, max_length=1024)

class DecisionQuery(BaseModel):
    action: StrictStr = Field(..., min_length=2, max_length=64) # read/write/delete/deploy/etc.
    resource_type: Optional[StrictStr] = Field(None, max_length=128)
    tenant: Optional[TenantId] = None

class SelfInhibitorState(BaseModel):
    policy_id: StrictStr = "self-inhibitor"
    armed: StrictBool = False
    armed_until: Optional[int] = None  # epoch seconds
    enabled: StrictBool = False
    scopes: List[Scope] = Field(default_factory=list)
    reason: Optional[StrictStr] = None
    initiated_by: Optional[StrictStr] = None
    tenant: Optional[TenantId] = None
    created_at: int = Field(default_factory=lambda: int(time.time()))
    updated_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    env: StrictStr = RUNTIME_ENV
    event_id: Optional[StrictStr] = None

# =========================
# In-memory state + nonce store
# =========================

_state = SelfInhibitorState()
_nonce_store: Dict[str, float] = {}
_state_lock = asyncio.Lock()
_nonce_lock = asyncio.Lock()
_expiry_task: Optional[asyncio.Task] = None

# =========================
# Utilities: Signatures, Nonce, Persistence, Webhook
# =========================

def _parse_signature(header_value: str) -> SignatureParts:
    """
    X-Sec-Admin-Signature: v1:ts:nonce:sighex
    """
    try:
        version, ts_str, nonce, sig_hex = header_value.split(":", 3)
        return SignatureParts(version=version, ts=int(ts_str), nonce=nonce, sig_hex=sig_hex)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature header")

async def _check_nonce(nonce: str, ts: int) -> None:
    now = time.time()
    if abs(now - ts) > TIME_SKEW_SEC:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="timestamp skew")
    async with _nonce_lock:
        # purge expired
        for n, exp in list(_nonce_store.items()):
            if exp < now:
                _nonce_store.pop(n, None)
        if nonce in _nonce_store:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="replay detected")
        _nonce_store[nonce] = now + NONCE_TTL_SEC

def _calc_sig(ts: int, nonce: str, body_bytes: bytes) -> str:
    mac = hmac.new(ADMIN_HMAC_SECRET, digestmod=hashlib.sha256)
    mac.update(str(ts).encode("utf-8"))
    mac.update(b".")
    mac.update(nonce.encode("utf-8"))
    mac.update(b".")
    mac.update(body_bytes)
    return mac.hexdigest()

async def _verify_signature(request: Request, header_value: Optional[str]) -> None:
    if ADMIN_HMAC_SECRET and len(ADMIN_HMAC_SECRET) >= 32:
        if not header_value:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing signature")
        parts = _parse_signature(header_value)
        body = await request.body()
        expected = _calc_sig(parts.ts, parts.nonce, body)
        if not hmac.compare_digest(expected, parts.sig_hex):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bad signature")
        await _check_nonce(parts.nonce, parts.ts)
    else:
        if not ALLOW_UNPROTECTED_CMDS:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="hmac not configured")

def _persist_state() -> None:
    if not STATE_PATH:
        return
    try:
        Path(STATE_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(_state.dict(), f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("failed to persist self-inhibitor state")

def _load_state() -> None:
    global _state
    if not STATE_PATH:
        return
    p = Path(STATE_PATH)
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            _state = SelfInhibitorState(**raw)
            logger.info("self-inhibitor state loaded from %s", STATE_PATH)
        except Exception:
            logger.exception("failed to load self-inhibitor state")

async def _post_webhook(event: str, payload: Dict[str, Any]) -> None:
    if not WEBHOOK_URL:
        return
    data = {"event": event, "ts": int(time.time()), "self_inhibitor": _state.dict(), "payload": payload}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(WEBHOOK_URL, json=data)
    except Exception:
        logger.warning("webhook post failed", exc_info=True)

# =========================
# Background expiry task
# =========================

async def _expiry_watcher():
    try:
        while True:
            await asyncio.sleep(1.0)
            async with _state_lock:
                if _state.enabled and _state.expires_at and time.time() >= _state.expires_at:
                    logger.warning("self-inhibitor expired; auto-disarm")
                    _state.enabled = False
                    _state.scopes = []
                    _state.reason = (_state.reason or "") + " | auto-disarm (TTL reached)"
                    _state.updated_at = int(time.time())
                    _state.expires_at = None
                    _state.armed = False
                    _state.armed_until = None
                    _persist_state()
                    await _post_webhook("auto_disarm", {})
                elif _state.armed and _state.armed_until and time.time() >= _state.armed_until:
                    _state.armed = False
                    _state.armed_until = None
                    _state.updated_at = int(time.time())
                    _persist_state()
                    await _post_webhook("arm_expired", {})
    except asyncio.CancelledError:
        return
    except Exception:
        logger.exception("expiry watcher crashed; restarting")
        asyncio.create_task(_expiry_watcher())

def _ensure_task():
    global _expiry_task
    if _expiry_task is None or _expiry_task.done():
        _expiry_task = asyncio.create_task(_expiry_watcher())

# =========================
# Auth dependency
# =========================

async def require_admin_sig(request: Request, x_sec_admin_signature: Optional[str] = Header(None)):
    await _verify_signature(request, x_sec_admin_signature)

# =========================
# Decision helper
# =========================

def _decision(action: str, scopes: List[Scope]) -> bool:
    """
    Returns True if action is allowed under current scopes, False if must be inhibited.
    Deny-by-default for mutating operations if scopes enforce it.
    """
    a = action.lower()
    s = set(scopes)
    if Scope.API_READONLY in s and a in {"write", "delete", "update", "patch"}:
        return False
    if Scope.BLOCK_WRITES in s and a in {"write", "delete", "update", "patch", "produce"}:
        return False
    if Scope.FREEZE_DEPLOY in s and a in {"deploy", "promote", "rollback"}:
        return False
    if Scope.FREEZE_ARTIFACT_PROMOTION in s and a in {"promote_artifact", "release"}:
        return False
    if Scope.BLOCK_EGRESS in s and a in {"egress", "call_external"}:
        return False
    if Scope.QUARANTINE in s and a in {"schedule_pod", "start_instance"}:
        return False
    if Scope.PAUSE_JOBS in s and a in {"start_job", "schedule_job"}:
        return False
    # throttle/revoke_short_tokens управляются интеграциями, но само действие не запрещают
    return True

# =========================
# Endpoints
# =========================

@router.on_event("startup")
async def _startup():
    _load_state()
    _ensure_task()

@router.get("/status", response_model=SelfInhibitorState, status_code=status.HTTP_200_OK)
async def status_endpoint() -> SelfInhibitorState:
    return _state

@router.post("/arm", dependencies=[Depends(require_admin_sig)], response_model=SelfInhibitorState, status_code=status.HTTP_200_OK)
async def arm(req: ArmRequest) -> SelfInhibitorState:
    async with _state_lock:
        now = int(time.time())
        if req.dry_run:
            tmp = _state.copy(deep=True)
            tmp.armed = True
            tmp.armed_until = now + req.ttl_seconds
            tmp.reason = f"[DRY RUN] {req.reason}"
            return tmp
        _state.armed = True
        _state.armed_until = now + req.ttl_seconds
        _state.updated_at = now
        _state.reason = req.reason
        _state.initiated_by = "admin"
        _state.tenant = req.tenant
        _persist_state()
    logger.warning("self-inhibitor ARMED until=%s", _state.armed_until)
    await _post_webhook("armed", {"ttl_seconds": req.ttl_seconds})
    return _state

@router.post("/trigger", dependencies=[Depends(require_admin_sig)], response_model=SelfInhibitorState, status_code=status.HTTP_200_OK)
async def trigger(req: TriggerRequest) -> SelfInhibitorState:
    async with _state_lock:
        now = int(time.time())
        if not _state.armed or (_state.armed_until and now > _state.armed_until):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="not armed or arm expired")
        if req.dry_run:
            tmp = _state.copy(deep=True)
            tmp.enabled = True
            tmp.scopes = list(req.scopes)
            tmp.expires_at = now + req.ttl_seconds
            tmp.reason = f"[DRY RUN] {req.reason}"
            return tmp
        _state.enabled = True
        _state.scopes = list(req.scopes)
        _state.reason = req.reason
        _state.initiated_by = "admin"
        _state.updated_at = now
        _state.expires_at = now + req.ttl_seconds
        _state.event_id = str(uuid.uuid4())
        _persist_state()
    logger.critical(
        "self-inhibitor TRIGGERED scopes=%s ttl=%s event=%s",
        ",".join([s.value for s in _state.scopes]),
        req.ttl_seconds,
        _state.event_id,
    )
    _ensure_task()
    await _post_webhook("triggered", {"scopes": [s.value for s in req.scopes], "ttl_seconds": req.ttl_seconds})
    return _state

@router.post("/disarm", dependencies=[Depends(require_admin_sig)], response_model=SelfInhibitorState, status_code=status.HTTP_200_OK)
async def disarm(req: DisarmRequest) -> SelfInhibitorState:
    async with _state_lock:
        now = int(time.time())
        if req.force:
            # полная очистка
            _state.armed = False
            _state.armed_until = None
            _state.enabled = False
            _state.scopes = []
            _state.expires_at = None
            _state.reason = req.reason or "force disarm"
            _state.updated_at = now
            _state.event_id = None
        else:
            _state.armed = False
            _state.armed_until = None
            if _state.enabled:
                _state.enabled = False
                _state.scopes = []
                _state.expires_at = None
            _state.reason = req.reason or "disarm"
            _state.updated_at = now
        _persist_state()
    logger.warning("self-inhibitor DISARMED force=%s", req.force)
    await _post_webhook("disarmed", {"force": req.force})
    return _state

@router.get("/decision", status_code=status.HTTP_200_OK)
async def decision(action: str, resource_type: Optional[str] = None) -> Dict[str, Any]:
    allowed = _decision(action, _state.scopes if _state.enabled else [])
    return {
        "allowed": bool(allowed),
        "enabled": bool(_state.enabled),
        "scopes": [s.value for s in _state.scopes],
        "reason": _state.reason,
        "env": _state.env,
        "event_id": _state.event_id,
    }

@router.post("/heartbeat", status_code=status.HTTP_200_OK)
async def heartbeat(payload: HeartbeatRequest) -> Dict[str, Any]:
    logger.info("heartbeat component=%s status=%s msg=%s", payload.component, payload.status, payload.message)
    return {"ok": True, "ts": int(time.time())}

# =========================
# Safe helpers to be imported by other modules
# =========================

def is_inhibitor_enabled() -> bool:
    return _state.enabled

def scopes() -> List[str]:
    return [s.value for s in _state.scopes]

def decision_for(action: str) -> bool:
    return _decision(action, _state.scopes if _state.enabled else [])

# =========================
# Notes
# =========================
# 1) Для подключений к шлюзам/Ingress можно читать /status или кешировать is_inhibitor_enabled()
#    и реализовывать middleware, который переводит API в read-only при scopes API_READONLY/BLOCK_WRITES.
# 2) Для CI/CD: проверять /decision?action=deploy|promote перед промоушеном.
# 3) Для токенов: включать интеграцию, которая при REVOKE_SHORT_TOKENS отзывает/сужает TTL.
# 4) HMAC: сгенерируйте секрет длиной >= 32 байт и передавайте заголовок:
#    X-Sec-Admin-Signature: v1:{ts_unix}:{nonce}:{hex(hmac_sha256(ts + "." + nonce + "." + body))}
# 5) Персистентность: установите SECURITY_CORE_INHIBITOR_STATE_PATH для переживания рестартов.
