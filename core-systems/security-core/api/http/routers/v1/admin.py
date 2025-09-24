# security-core/api/http/routers/v1/admin.py
"""
Admin v1 router for security-core

Features:
- Strict async FastAPI router under /v1/admin
- Dual security: mTLS (via proxy headers) + OAuth2 scopes (Bearer)
- Role/Scope guard, least-privilege per endpoint
- Idempotency-Key support with in-memory TTL LRU cache
- Structured logging, RFC7807 errors
- Audit emission for every mutating admin action
- Safe background tasks for long-running ops (rotate keys, compaction)
- No sync DB calls; ready for DI of service backends

Env knobs (examples):
- AUTH_JWT_HS256_SECRET: optional HMAC secret for local JWT validation
- DEV_FAKE_TOKEN: optional opaque token for dev-only auth
- MTLS_HEADER_VERIFY: header name indicating client cert verification (default: "x-client-verify")
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# -------------------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------------------

logger = logging.getLogger("security_core.admin")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -------------------------------------------------------------------------------------
# RFC 7807 Problem Details
# -------------------------------------------------------------------------------------


class Problem(BaseModel):
    type: str = Field(default="about:blank")
    title: str
    status: int
    detail: Optional[str] = None
    instance: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    def to_response(self) -> JSONResponse:
        payload = self.model_dump()
        # compatibility: include arbitrary additional keys as top-level
        extra = payload.pop("extra", {})
        payload.update(extra)
        return JSONResponse(status_code=self.status, content=payload)


def problem(
    status_code: int,
    title: str,
    detail: Optional[str] = None,
    type_: str = "about:blank",
    instance: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    return Problem(
        type=type_, title=title, status=status_code, detail=detail, instance=instance, extra=extra or {}
    ).to_response()


# -------------------------------------------------------------------------------------
# Security primitives
# -------------------------------------------------------------------------------------

class SecurityContext(BaseModel):
    subject: str
    scopes: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    mtls_verified: bool = False
    token_id: Optional[str] = None

    def require_scopes(self, required: Iterable[str]) -> None:
        missing = [s for s in required if s not in self.scopes]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing scopes: {','.join(missing)}",
            )

    def require_roles_any(self, roles_any: Iterable[str]) -> None:
        if not set(roles_any).intersection(self.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing any role in: {','.join(roles_any)}",
            )


async def _decode_token(token: str) -> Dict[str, Any]:
    """
    Best-effort bearer token decoding:
    - If PyJWT is available and AUTH_JWT_HS256_SECRET is set, validate HS256 JWT.
    - Else accept DEV_FAKE_TOKEN and parse scopes/roles from a base64 json payload after a dot.
      Example: DEV_FAKE_TOKEN.scopes-roles, where suffix is base64url({"scopes":["admin"],"roles":["SECURITY_ADMIN"],"sub":"dev"})
    """
    try:
        import jwt  # type: ignore
    except Exception:
        jwt = None

    secret = os.getenv("AUTH_JWT_HS256_SECRET")
    dev_token = os.getenv("DEV_FAKE_TOKEN")

    if jwt and secret:
        try:
            claims = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
            return claims
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"invalid token: {e}")

    if dev_token and token.startswith(dev_token):
        parts = token.split(".", 1)
        if len(parts) == 2:
            try:
                raw = parts[1].encode()
                # base64url without padding
                padding = b"=" * (-len(raw) % 4)
                data = json.loads(base64.urlsafe_b64decode(raw + padding).decode())
                return data
            except Exception:
                return {"sub": "dev", "scopes": ["admin"], "roles": ["SECURITY_ADMIN"]}
        return {"sub": "dev", "scopes": ["admin"], "roles": ["SECURITY_ADMIN"]}

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


async def current_security(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    mtls_verify: Optional[str] = Header(default=None, alias=os.getenv("MTLS_HEADER_VERIFY", "x-client-verify")),
    client_dn: Optional[str] = Header(default=None, alias=os.getenv("MTLS_HEADER_DN", "x-client-dn")),
) -> SecurityContext:
    # Check mTLS via reverse proxy headers
    mtls_ok = (mtls_verify or "").upper() == "SUCCESS"

    # Parse bearer token
    scopes: List[str] = []
    roles: List[str] = []
    subject = "anonymous"
    token_id = None

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        claims = await _decode_token(token)
        subject = str(claims.get("sub") or claims.get("client_id") or "unknown")
        scopes = sorted(set(sum([str(claims.get("scope", "")).split(), claims.get("scopes", [])], [])))
        roles = list(claims.get("roles", []))
        token_id = claims.get("jti")

    if not scopes and not mtls_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")

    ctx = SecurityContext(
        subject=subject,
        scopes=scopes,
        roles=roles,
        mtls_verified=mtls_ok,
        token_id=token_id,
    )
    request.state.security = ctx
    return ctx


# -------------------------------------------------------------------------------------
# Idempotency cache (in-memory TTL LRU)
# -------------------------------------------------------------------------------------

class _IdemRecord(BaseModel):
    key: str
    created_at: float
    ttl: int
    response_payload: Optional[Dict[str, Any]] = None
    status_code: int = 202


class IdempotencyCache:
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._store: Dict[str, _IdemRecord] = {}
        self._lock = asyncio.Lock()

    async def check_or_put(
        self, key: str, ttl_seconds: int = 3600
    ) -> Tuple[bool, Optional[_IdemRecord]]:
        now = time.time()
        async with self._lock:
            # purge expired
            expired = [k for k, v in self._store.items() if (now - v.created_at) > v.ttl]
            for k in expired:
                self._store.pop(k, None)
            rec = self._store.get(key)
            if rec:
                return True, rec
            if len(self._store) >= self.capacity:
                # simple LRU-ish drop: remove oldest
                oldest = min(self._store.values(), key=lambda r: r.created_at)
                self._store.pop(oldest.key, None)
            rec = _IdemRecord(key=key, created_at=now, ttl=ttl_seconds)
            self._store[key] = rec
            return False, rec

    async def set_response(self, key: str, status_code: int, payload: Dict[str, Any]) -> None:
        async with self._lock:
            if key in self._store:
                self._store[key].status_code = status_code
                self._store[key].response_payload = payload


IDEM_CACHE = IdempotencyCache()


async def idempotency_guard(idem_key: Optional[str] = Header(default=None, alias="Idempotency-Key")) -> Optional[_IdemRecord]:
    if not idem_key:
        return None
    exists, rec = await IDEM_CACHE.check_or_put(idem_key)
    if exists and rec and rec.response_payload is not None:
        raise HTTPException(status_code=rec.status_code, detail=rec.response_payload)  # short-circuit repeat
    return rec


# -------------------------------------------------------------------------------------
# Service interfaces (to be bound via DI at app startup)
# -------------------------------------------------------------------------------------

class AuditEmitter:
    async def emit(self, event: Dict[str, Any]) -> None:
        logger.info("audit.emit %s", json.dumps(event, ensure_ascii=False))


class PolicyEngine:
    async def reload(self) -> Dict[str, Any]:
        await asyncio.sleep(0)  # placeholder for I/O
        return {"policy_id": "default", "version": "latest", "reloaded_at": datetime.now(timezone.utc).isoformat()}


class RetentionManager:
    async def set_policy(self, ttl_seconds: int, policy_id: Optional[str]) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return {"ttl_seconds": ttl_seconds, "policy_id": policy_id, "applied_at": datetime.now(timezone.utc).isoformat()}


class IngestController:
    _frozen: bool = False
    _reason: Optional[str] = None

    async def freeze(self, reason: str) -> Dict[str, Any]:
        self._frozen = True
        self._reason = reason
        return {"frozen": True, "reason": reason}

    async def unfreeze(self) -> Dict[str, Any]:
        self._frozen = False
        self._reason = None
        return {"frozen": False}


class KmsManager:
    async def rotate_key(self, key_alias: str, provider_id: Optional[str], dry_run: bool) -> str:
        await asyncio.sleep(0)
        # return job id
        return f"job-{uuid.uuid4()}"


class ConfigManager:
    async def reload(self) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return {"reloaded_at": datetime.now(timezone.utc).isoformat()}


class MaintenanceManager:
    async def compact(self) -> str:
        await asyncio.sleep(0)
        return f"job-{uuid.uuid4()}"


class ServiceRegistry:
    audit: AuditEmitter
    policy: PolicyEngine
    retention: RetentionManager
    ingest: IngestController
    kms: KmsManager
    config: ConfigManager
    maint: MaintenanceManager

    def __init__(self) -> None:
        self.audit = AuditEmitter()
        self.policy = PolicyEngine()
        self.retention = RetentionManager()
        self.ingest = IngestController()
        self.kms = KmsManager()
        self.config = ConfigManager()
        self.maint = MaintenanceManager()


REGISTRY = ServiceRegistry()


# -------------------------------------------------------------------------------------
# Request/Response models
# -------------------------------------------------------------------------------------

class OperationAck(BaseModel):
    operation_id: str
    accepted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "accepted"


class RuntimeInfo(BaseModel):
    service: str = "security-core"
    version: str = os.getenv("SECURITY_CORE_VERSION", "dev")
    commit: Optional[str] = os.getenv("SECURITY_CORE_COMMIT")
    pid: int = os.getpid()
    started_at: Optional[str] = os.getenv("PROCESS_STARTED_AT")
    uptime_seconds: int
    node: str = os.uname().nodename if hasattr(os, "uname") else "unknown"
    region: Optional[str] = os.getenv("REGION")
    cluster: Optional[str] = os.getenv("CLUSTER")
    # Safe subset of env for diagnostics
    env_safe: Dict[str, str] = Field(default_factory=dict)

    @staticmethod
    def now_with_uptime() -> "RuntimeInfo":
        started = float(os.getenv("PROCESS_STARTED_TS", str(time.time())))
        uptime = int(time.time() - started)
        env_whitelist = ["REGION", "CLUSTER", "ENV", "SECURITY_CORE_VERSION"]
        return RuntimeInfo(
            uptime_seconds=uptime,
            env_safe={k: v for k, v in os.environ.items() if k in env_whitelist},
        )


class FreezeRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=256)


class RetentionUpdateRequest(BaseModel):
    ttl_seconds: int = Field(ge=3600, le=10 * 365 * 24 * 3600)  # 1h .. 10y
    policy_id: Optional[str] = None


class KeyRotateRequest(BaseModel):
    key_alias: str = Field(min_length=2, max_length=128)
    provider_id: Optional[str] = Field(default=None, max_length=128)
    dry_run: bool = False


class EmptyBody(BaseModel):
    pass


# -------------------------------------------------------------------------------------
# Router
# -------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/admin", tags=["Admin"])


async def _emit_admin_audit(ctx: SecurityContext, action: str, details: Dict[str, Any]) -> None:
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "API_CALL",
        "action": action,
        "outcome": "SUCCESS",
        "severity": "INFO",
        "category": "admin",
        "actor": {
            "type": "HUMAN" if "SECURITY_ADMIN" in ctx.roles else "SERVICE",
            "actor_id": ctx.subject,
            "roles": ctx.roles,
        },
        "target": {"resource": {"type": "admin", "id": action, "name": action}},
        "details": details,
        "tags": ["admin", "security-core"],
    }
    try:
        await REGISTRY.audit.emit(event)
    except Exception as e:
        logger.error("audit emission failed: %s", e)


@router.get("/runtime", response_model=RuntimeInfo, summary="Runtime info")
async def runtime_info(_: SecurityContext = Depends(current_security)) -> RuntimeInfo:
    return RuntimeInfo.now_with_uptime()


@router.post(
    "/policy/reload",
    response_model=OperationAck,
    summary="Reload authorization policies",
)
async def policy_reload(
    bg: BackgroundTasks,
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin", "audit:admin"])
    ctx.require_roles_any(["SECURITY_ADMIN", "PLATFORM_ADMIN"])

    # short async op
    result = await REGISTRY.policy.reload()
    op_id = f"policy-reload-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "status": "accepted", "accepted_at": datetime.now(timezone.utc).isoformat(), "result": result}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "policy_reload", "result": result})
    return OperationAck(operation_id=op_id)


@router.post(
    "/audit/pipeline/freeze",
    response_model=OperationAck,
    summary="Freeze audit ingestion pipeline",
)
async def audit_freeze(
    body: FreezeRequest,
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin", "audit:admin"])
    ctx.require_roles_any(["SECURITY_ADMIN"])

    result = await REGISTRY.ingest.freeze(body.reason)
    op_id = f"audit-freeze-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "result": result}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "audit_freeze", "reason": body.reason})
    return OperationAck(operation_id=op_id)


@router.post(
    "/audit/pipeline/unfreeze",
    response_model=OperationAck,
    summary="Unfreeze audit ingestion pipeline",
)
async def audit_unfreeze(
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin", "audit:admin"])
    ctx.require_roles_any(["SECURITY_ADMIN"])

    result = await REGISTRY.ingest.unfreeze()
    op_id = f"audit-unfreeze-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "result": result}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "audit_unfreeze"})
    return OperationAck(operation_id=op_id)


@router.post(
    "/retention",
    response_model=Dict[str, Any],
    summary="Update retention policy",
)
async def retention_update(
    body: RetentionUpdateRequest,
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin", "audit:admin"])
    ctx.require_roles_any(["SECURITY_ADMIN", "DATA_STEWARD"])

    result = await REGISTRY.retention.set_policy(ttl_seconds=body.ttl_seconds, policy_id=body.policy_id)
    op_id = f"retention-{uuid.uuid4()}"
    response = {"operation_id": op_id, "status": "accepted", "result": result}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, response)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "retention_update", "params": body.model_dump()})
    return response


@router.post(
    "/keys/rotate",
    response_model=OperationAck,
    summary="Rotate KMS/HSM key by alias",
)
async def keys_rotate(
    body: KeyRotateRequest,
    bg: BackgroundTasks,
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin", "ca:admin"])
    ctx.require_roles_any(["SECURITY_ADMIN", "KMS_ADMIN"])

    async def _rotate() -> str:
        return await REGISTRY.kms.rotate_key(body.key_alias, body.provider_id, body.dry_run)

    # Run as background task to avoid long HTTP wait
    async def _task_wrapper() -> None:
        try:
            job_id = await _rotate()
            logger.info("key rotation started job_id=%s alias=%s dry=%s", job_id, body.key_alias, body.dry_run)
        except Exception as e:
            logger.exception("key rotation failed: %s", e)

    # FastAPI BackgroundTasks expects sync callables; run the async fn
    def _run_async_task() -> None:
        asyncio.get_event_loop().create_task(_task_wrapper())

    bg.add_task(_run_async_task)
    op_id = f"key-rotate-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "status": "accepted"}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "keys_rotate", "alias": body.key_alias, "dry_run": body.dry_run})
    return OperationAck(operation_id=op_id)


@router.post(
    "/config/reload",
    response_model=OperationAck,
    summary="Reload runtime configuration",
)
async def config_reload(
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin"])
    ctx.require_roles_any(["PLATFORM_ADMIN", "SECURITY_ADMIN"])

    result = await REGISTRY.config.reload()
    op_id = f"config-reload-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "status": "accepted", "result": result}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "config_reload", "result": result})
    return OperationAck(operation_id=op_id)


@router.post(
    "/maintenance/compact",
    response_model=OperationAck,
    summary="Trigger storage compaction",
)
async def maintenance_compact(
    bg: BackgroundTasks,
    idem: Optional[_IdemRecord] = Depends(idempotency_guard),
    ctx: SecurityContext = Depends(current_security),
):
    ctx.require_scopes(["admin"])
    ctx.require_roles_any(["PLATFORM_ADMIN", "SECURITY_ADMIN"])

    async def _compact() -> str:
        return await REGISTRY.maint.compact()

    async def _task_wrapper() -> None:
        try:
            job_id = await _compact()
            logger.info("compaction started job_id=%s", job_id)
        except Exception as e:
            logger.exception("compaction failed: %s", e)

    def _run_async_task() -> None:
        asyncio.get_event_loop().create_task(_task_wrapper())

    bg.add_task(_run_async_task)
    op_id = f"compact-{uuid.uuid4()}"
    payload = {"operation_id": op_id, "status": "accepted"}

    if idem:
        await IDEM_CACHE.set_response(idem.key, 202, payload)

    await _emit_admin_audit(ctx, "UPDATE", {"operation": "maintenance_compact"})
    return OperationAck(operation_id=op_id)


# -------------------------------------------------------------------------------------
# Exception handlers (optional hardening)
# -------------------------------------------------------------------------------------

@router.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    logger.warning("HTTPException rid=%s path=%s status=%s detail=%s", rid, request.url.path, exc.status_code, exc.detail)
    if isinstance(exc.detail, dict):
        # when idempotency short-circuits with stored payload
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return problem(status_code=exc.status_code, title="HTTP Error", detail=str(exc.detail), instance=rid)


@router.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    logger.exception("Unhandled error rid=%s path=%s", rid, request.url.path)
    return problem(status_code=500, title="Internal Server Error", detail="unexpected error", instance=rid)
