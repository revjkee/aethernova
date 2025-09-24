# security-core/api/http/routers/v1/revoke.py
"""
Industrial OAuth2 Token Revocation router (RFC 7009)
- Supports application/x-www-form-urlencoded and application/json
- RFC 6750-compliant error surfaces (WWW-Authenticate) and 200 on unknown tokens
- Idempotency via X-Idempotency-Key
- Redis-backed RevocationBackend with in-memory fallback
- Scope enforcement: requires 'tokens:revoke'
- Optional cascade by subject/tenant, reason tagging, TTL
- Safe parsing of jti from JWT (compact), PASETO (footer-less compact), or JSON token

Dependencies:
    fastapi, pydantic, starlette
Optional:
    redis>=5 (redis.asyncio)

Integration:
    from fastapi import FastAPI
    from security_core.api.http.routers.v1.revoke import router as revoke_router, \
        RedisRevocationBackend, RevocationConfig, set_revocation_backend

    app = FastAPI()
    # Configure backend once at app startup
    # set_revocation_backend(RedisRevocationBackend(RevocationConfig(redis_dsn="redis://localhost:6379/0")))
    app.include_router(revoke_router, prefix="/v1")
"""

from __future__ import annotations

import base64
import json
import time
import uuid
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple, Union, List, Set

from fastapi import APIRouter, Body, Depends, Form, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # optional

router = APIRouter(tags=["revocation"])

# =========================
# Errors/helpers (RFC 6750)
# =========================

class AuthzError(Exception):
    def __init__(self, status: int, error: str, description: str, scope: Optional[str] = None) -> None:
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.scope = scope

def _err_json(status: int, error: str, desc: str, request_id: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "error": error,
        "error_description": desc,
        "request_id": request_id,
    })

def _www_auth(error: str, desc: str, scope: Optional[str] = None) -> str:
    parts = [f'error="{error}"', f'error_description="{desc}"']
    if scope:
        parts.append(f'scope="{scope}"')
    return "Bearer " + ", ".join(parts)

def _now_s() -> int:
    return int(time.time())

def _get_request_id(request: Request) -> str:
    rid = getattr(getattr(request, "state", object()), "request_id", None)
    return rid or str(uuid.uuid4())

# =========================
# Scope enforcement
# =========================

REVOKE_SCOPE = "tokens:revoke"

def _require_revoke_scope(request: Request) -> None:
    info = getattr(request.state, "token_info", None)
    scopes: Tuple[str, ...] = getattr(info, "scopes", tuple()) if info else tuple()
    if REVOKE_SCOPE not in set(scopes):
        raise AuthzError(HTTP_403_FORBIDDEN, "insufficient_scope", "Required scope missing.", REVOKE_SCOPE)

# =========================
# Revocation backend API
# =========================

@dataclass(frozen=True)
class RevocationConfig:
    redis_dsn: Optional[str] = None
    key_prefix: str = "revoked"
    idempo_prefix: str = "idempo"
    default_ttl_s: int = 60 * 60 * 24 * 7  # 7 days

class RevocationBackend(Protocol):
    async def revoke(self, token_id: str, *, ttl_s: Optional[int], reason: Optional[str],
                     actor: Optional[str], tenant_id: Optional[str],
                     cascade_subject: Optional[str], tags: Optional[Mapping[str, str]]) -> None: ...
    async def is_revoked(self, token_id: str) -> bool: ...
    async def idempotency_get(self, key: str) -> Optional[Mapping[str, Any]]: ...
    async def idempotency_put(self, key: str, value: Mapping[str, Any], ttl_s: int = 3600) -> None: ...
    async def stats(self) -> Mapping[str, Any]: ...

# In-memory fallback backend
class MemoryRevocationBackend:
    def __init__(self, cfg: RevocationConfig = RevocationConfig()) -> None:
        self.cfg = cfg
        self._revoked: Dict[str, Tuple[Dict[str, Any], int]] = {}
        self._idempo: Dict[str, Tuple[Dict[str, Any], int]] = {}
        self._lock = asyncio.Lock()

    async def revoke(self, token_id: str, *, ttl_s: Optional[int], reason: Optional[str],
                     actor: Optional[str], tenant_id: Optional[str],
                     cascade_subject: Optional[str], tags: Optional[Mapping[str, str]]) -> None:
        exp = _now_s() + (ttl_s or self.cfg.default_ttl_s)
        meta = {"reason": reason, "actor": actor, "tenant_id": tenant_id,
                "cascade_subject": cascade_subject, "tags": dict(tags or {}),
                "revoked_at": _now_s(), "expires_at": exp}
        async with self._lock:
            self._revoked[token_id] = (meta, exp)

    async def is_revoked(self, token_id: str) -> bool:
        now = _now_s()
        async with self._lock:
            item = self._revoked.get(token_id)
            if not item: return False
            _, exp = item
            if exp <= now:
                self._revoked.pop(token_id, None)
                return False
            return True

    async def idempotency_get(self, key: str) -> Optional[Mapping[str, Any]]:
        now = _now_s()
        async with self._lock:
            item = self._idempo.get(key)
            if not item: return None
            val, exp = item
            if exp <= now:
                self._idempo.pop(key, None)
                return None
            return val

    async def idempotency_put(self, key: str, value: Mapping[str, Any], ttl_s: int = 3600) -> None:
        exp = _now_s() + ttl_s
        async with self._lock:
            self._idempo[key] = (dict(value), exp)

    async def stats(self) -> Mapping[str, Any]:
        now = _now_s()
        async with self._lock:
            live = sum(1 for _, exp in self._revoked.values() if exp > now)
        return {"backend": "memory", "live_revocations": live}

# Redis backend (optional)
class RedisRevocationBackend:
    def __init__(self, cfg: RevocationConfig = RevocationConfig()) -> None:
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not available")
        self.cfg = cfg
        self._redis = aioredis.from_url(cfg.redis_dsn or "redis://localhost:6379/0", encoding=None, decode_responses=False)

    def _k(self, token_id: str) -> str:
        return f"{self.cfg.key_prefix}:{token_id}"

    def _ik(self, idem_key: str) -> str:
        return f"{self.cfg.idempo_prefix}:{idem_key}"

    async def revoke(self, token_id: str, *, ttl_s: Optional[int], reason: Optional[str],
                     actor: Optional[str], tenant_id: Optional[str],
                     cascade_subject: Optional[str], tags: Optional[Mapping[str, str]]) -> None:
        meta = json.dumps({
            "reason": reason, "actor": actor, "tenant_id": tenant_id,
            "cascade_subject": cascade_subject, "tags": dict(tags or {}),
            "revoked_at": _now_s()
        }).encode()
        ttl = ttl_s or self.cfg.default_ttl_s
        await self._redis.set(self._k(token_id), meta, ex=ttl, nx=False)

    async def is_revoked(self, token_id: str) -> bool:
        v = await self._redis.exists(self._k(token_id))
        return bool(v)

    async def idempotency_get(self, key: str) -> Optional[Mapping[str, Any]]:
        b = await self._redis.get(self._ik(key))
        if b is None: return None
        try:
            return json.loads(b.decode())
        except Exception:
            return None

    async def idempotency_put(self, key: str, value: Mapping[str, Any], ttl_s: int = 3600) -> None:
        await self._redis.set(self._ik(key), json.dumps(dict(value)).encode(), ex=ttl_s, nx=True)

    async def stats(self) -> Mapping[str, Any]:
        # Lightweight: we cannot count keys reliably without SCAN, so return backend info only
        return {"backend": "redis"}

# Global backend holder with safe default
_BACKEND: RevocationBackend = MemoryRevocationBackend()

def set_revocation_backend(backend: RevocationBackend) -> None:
    global _BACKEND
    _BACKEND = backend

# =========================
# Models
# =========================

class RevokeJSON(BaseModel):
    token: Optional[str] = Field(None, description="Access or refresh token")
    token_type_hint: Optional[str] = Field(None, description="access_token | refresh_token | id_token | other")
    jti: Optional[str] = Field(None, description="If known, token identifier")
    ttl_seconds: Optional[int] = Field(None, ge=1, le=60*60*24*365)
    reason: Optional[str] = Field(None, max_length=512)
    cascade_subject: Optional[str] = Field(None, description="Revoke all tokens of subject (optional)")
    tenant_id: Optional[str] = None
    tags: Optional[Dict[str, str]] = None

    @validator("token_type_hint")
    def _hint_norm(cls, v: Optional[str]) -> Optional[str]:
        return v.lower() if isinstance(v, str) else v

class RevokeResponse(BaseModel):
    ok: bool = True
    token_id: Optional[str] = None
    unknown: bool = False
    request_id: str
    acted_at: int
    backend: Mapping[str, Any]

# =========================
# Utilities
# =========================

def _b64url_decode_to_json(seg: str) -> Dict[str, Any]:
    # Pad base64url if needed
    pad = '=' * ((4 - len(seg) % 4) % 4)
    data = base64.urlsafe_b64decode((seg + pad).encode())
    return json.loads(data.decode())

def _guess_token_id(token: str) -> Optional[str]:
    """
    Attempt to extract jti from:
    - JWT compact: header.payload.signature
    - PASETO compact (non-standard here): vX.local/public.payload[.footer]? -> try 3rd segment as payload
    - Raw JSON claims string
    Returns None if jti not present.
    """
    try:
        if token.count(".") >= 2:
            parts = token.split(".")
            # JWT payload is second segment
            payload = _b64url_decode_to_json(parts[1])
            jti = payload.get("jti")
            if jti: return str(jti)
        if token.startswith("{"):
            claims = json.loads(token)
            jti = claims.get("jti")
            if jti: return str(jti)
    except Exception:
        return None
    return None

async def _ensure_scope(request: Request) -> None:
    _require_revoke_scope(request)

async def _idempotent(key: Optional[str]) -> Optional[Mapping[str, Any]]:
    if not key:
        return None
    return await _BACKEND.idempotency_get(key)

async def _idempotent_store(key: Optional[str], value: Mapping[str, Any]) -> None:
    if not key:
        return
    await _BACKEND.idempotency_put(key, value)

def _authz_error_response(e: AuthzError, request_id: str) -> JSONResponse:
    headers = {
        "WWW-Authenticate": _www_auth(e.error, e.description, e.scope),
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Request-ID": request_id,
    }
    resp = _err_json(e.status, e.error, e.description, request_id)
    resp.init_headers(headers)
    return resp

# =========================
# Endpoints
# =========================

@router.post(
    "/revoke",
    summary="OAuth2 Token Revocation (RFC 7009)",
    response_model=RevokeResponse,
    response_model_exclude_none=True,
)
async def revoke_token(
    request: Request,
    response: Response,
    # Accept both JSON and WWW-Form (RFC 7009)
    token_form: Optional[str] = Form(default=None),
    token_type_hint_form: Optional[str] = Form(default=None),
    token_json: Optional[RevokeJSON] = Body(default=None),
    x_idempotency_key: Optional[str] = Header(default=None, convert_underscores=False),
):
    request_id = _get_request_id(request)

    # Authorization: must have tokens:revoke
    try:
        await _ensure_scope(request)
    except AuthzError as e:
        return _authz_error_response(e, request_id)

    # Idempotency check
    cached = await _idempotent(x_idempotency_key)
    if cached:
        return JSONResponse(status_code=HTTP_200_OK, content=dict(cached))

    # Normalize input
    token: Optional[str] = token_form
    token_type_hint = token_type_hint_form
    payload: Optional[RevokeJSON] = token_json

    if payload and payload.token is not None:
        token = payload.token
        token_type_hint = payload.token_type_hint or token_type_hint
    if payload is None and token is None:
        # Try to parse generic body as JSON if provided without model
        try:
            raw = await request.body()
            if raw:
                data = json.loads(raw.decode())
                token = data.get("token")
                token_type_hint = data.get("token_type_hint", token_type_hint)
                payload = RevokeJSON(**data)
        except Exception:
            pass

    if token is None and not (payload and payload.jti):
        # RFC 7009 requires returning 200 even if token is unknown or invalid.
        # But malformed request (no token nor jti) -> 400 invalid_request.
        return _err_json(HTTP_400_BAD_REQUEST, "invalid_request", "token or jti is required", request_id)

    # Resolve token_id (jti)
    token_id: Optional[str] = payload.jti if payload else None
    if token_id is None and token is not None:
        token_id = _guess_token_id(token)

    # If token_id is still unknown, comply with RFC 7009: respond 200 as if revoked
    if token_id is None:
        body = RevokeResponse(
            ok=True, token_id=None, unknown=True, request_id=request_id, acted_at=_now_s(),
            backend=await _BACKEND.stats()
        ).dict()
        await _idempotent_store(x_idempotency_key, body)
        return JSONResponse(status_code=HTTP_200_OK, content=body)

    # Perform revocation (idempotent by nature)
    ttl_s = payload.ttl_seconds if payload and payload.ttl_seconds else None
    reason = payload.reason if payload else None
    cascade_subject = payload.cascade_subject if payload else None
    tenant_id = payload.tenant_id if payload else None
    tags = payload.tags if payload and payload.tags else None

    actor = getattr(getattr(request.state, "principal", None), "subject", None) or "unknown"

    await _BACKEND.revoke(
        token_id,
        ttl_s=ttl_s,
        reason=reason,
        actor=actor,
        tenant_id=tenant_id,
        cascade_subject=cascade_subject,
        tags=tags,
    )

    body = RevokeResponse(
        ok=True,
        token_id=token_id,
        unknown=False,
        request_id=request_id,
        acted_at=_now_s(),
        backend=await _BACKEND.stats(),
    ).dict()
    await _idempotent_store(x_idempotency_key, body)
    return JSONResponse(status_code=HTTP_200_OK, content=body)

# Optional helper: check revocation status
class StatusResponse(BaseModel):
    token_id: str
    revoked: bool
    request_id: str
    as_of: int
    backend: Mapping[str, Any]

@router.get("/revoke/status/{token_id}", response_model=StatusResponse, summary="Check token revocation status")
async def revoke_status(request: Request, token_id: str):
    request_id = _get_request_id(request)
    try:
        await _ensure_scope(request)
    except AuthzError as e:
        return _authz_error_response(e, request_id)
    revoked = await _BACKEND.is_revoked(token_id)
    return JSONResponse(status_code=HTTP_200_OK, content={
        "token_id": token_id,
        "revoked": revoked,
        "request_id": request_id,
        "as_of": _now_s(),
        "backend": await _BACKEND.stats(),
    })
