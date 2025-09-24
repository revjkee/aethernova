# file: security-core/api/http/routers/v1/tokens.py
from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, constr, validator

logger = logging.getLogger("security_core.tokens")

router = APIRouter(prefix="/auth/v1", tags=["auth-tokens"])

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime | None) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _redact_token(value: Optional[str]) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-3:]

def _ensure_request_id(request_id: Optional[str]) -> str:
    try:
        uuid.UUID(str(request_id))
        return str(request_id)
    except Exception:
        return str(uuid.uuid4())

# -----------------------------------------------------------------------------
# Domain enums & models (compatible with SDK / proto semantics)
# -----------------------------------------------------------------------------

class TokenType(str, Enum):
    ACCESS = "ACCESS"
    REFRESH = "REFRESH"
    ID = "ID"
    SESSION = "SESSION"

class AuthMethod(str, Enum):
    PASSWORD = "PASSWORD"
    TOTP = "TOTP"
    WEBAUTHN = "WEBAUTHN"
    SMS_OTP = "SMS_OTP"
    EMAIL_OTP = "EMAIL_OTP"
    MAGIC_LINK = "MAGIC_LINK"
    OAUTH2_OIDC = "OAUTH2_OIDC"
    SAML2 = "SAML2"
    RECOVERY = "RECOVERY"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ApiError(BaseModel):
    code: Optional[str] = None
    message: str
    correlation_id: Optional[str] = Field(default=None, alias="correlation_id")

class Principal(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    external_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    phone_e164: Optional[str] = None
    display_name: Optional[str] = None
    roles: list[str] = []
    disabled: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    attributes: Dict[str, str] = {}

class Device(BaseModel):
    id: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    model: Optional[str] = None
    user_agent: Optional[str] = None
    fingerprint: Optional[str] = None
    trusted: Optional[bool] = None
    compliant: Optional[bool] = None
    attested: Optional[bool] = None
    attestation_provider: Optional[str] = None
    created_at: Optional[str] = None
    last_seen_at: Optional[str] = None

class RiskSignals(BaseModel):
    level: Optional[RiskLevel] = None
    score: Optional[float] = None
    reason: Optional[str] = None
    anomalies: list[str] = []
    ip_address: Optional[str] = None
    geoip_country: Optional[str] = None
    geoip_city: Optional[str] = None
    via_proxy: Optional[bool] = None
    via_tor: Optional[bool] = None
    velocity_exceeded: Optional[bool] = None
    historical_ips: list[str] = []

class ClientContext(BaseModel):
    request_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    locale: Optional[str] = None
    timezone: Optional[str] = None
    device: Optional[Device] = None
    headers: Optional[Dict[str, Any]] = None
    extra: Optional[Dict[str, Any]] = None

class Token(BaseModel):
    id: Optional[str] = None
    type: TokenType
    alg: Optional[str] = None
    key_id: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    audience: list[str] = []
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    not_before: Optional[str] = None
    scopes: list[str] = []
    client_id: Optional[str] = None
    session_id: Optional[str] = None
    claims: Dict[str, Any] = {}
    jwt_compact: Optional[str] = None
    paseto: Optional[str] = None
    opaque: Optional[str] = None

class Session(BaseModel):
    id: str
    principal_id: str
    methods: list[AuthMethod] = []
    device: Optional[Device] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None
    risk: Optional[RiskSignals] = None
    revoked: bool = False
    revoke_reason: Optional[str] = None
    created_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    expires_at: Optional[str] = None
    access_token_id: Optional[str] = None
    refresh_token_id: Optional[str] = None

class AuthSuccess(BaseModel):
    principal: Principal
    session: Session
    access_token: Token
    refresh_token: Token
    id_token_issued: Optional[bool] = None
    id_token: Optional[Token] = None

# -----------------------------------------------------------------------------
# Request / Response models (HTTP wire)
# -----------------------------------------------------------------------------

class RefreshAccessTokenIn(BaseModel):
    refresh_token: constr(min_length=20, max_length=8192)
    context: Optional[ClientContext] = None

class RefreshAccessTokenOut(BaseModel):
    success: AuthSuccess

class IntrospectTokenIn(BaseModel):
    token: constr(min_length=20, max_length=8192)
    assumed_type: Optional[TokenType] = None
    context: Optional[ClientContext] = None

class IntrospectTokenOut(BaseModel):
    active: bool
    token: Optional[Token] = None
    principal: Optional[Principal] = None
    session: Optional[Session] = None
    risk: Optional[RiskSignals] = None
    evaluated_at: Optional[str] = None

class RevokeTokenIn(BaseModel):
    token: constr(min_length=20, max_length=8192)
    type: TokenType = Field(default=TokenType.REFRESH)
    reason: Optional[str] = None
    context: Optional[ClientContext] = None

class RevokeTokenOut(BaseModel):
    revoked: bool

# -----------------------------------------------------------------------------
# Token service abstraction + dev mock
# -----------------------------------------------------------------------------

class TokenService:
    """Abstract token service; replace with real implementation via DI."""
    async def refresh_access_token(self, refresh_token: str, context: ClientContext | None) -> AuthSuccess:
        raise NotImplementedError

    async def introspect(self, token: str, assumed_type: TokenType | None, context: ClientContext | None) -> IntrospectTokenOut:
        raise NotImplementedError

    async def revoke(self, token: str, ttype: TokenType, reason: Optional[str], context: ClientContext | None) -> bool:
        raise NotImplementedError

class _InMemoryTokenService(TokenService):
    """DEV‑only mock for local runs: SECURITY_CORE_DEV_MOCK=1."""
    def __init__(self) -> None:
        self._refresh_store: Dict[str, Tuple[str, datetime, str]] = {}  # refresh -> (principal_id, exp, session_id)
        self._access_store: Dict[str, Tuple[str, datetime, str]] = {}   # access -> (principal_id, exp, session_id)

        # seed demo token
        principal_id = "demo-user"
        session_id = str(uuid.uuid4())
        refresh = self._mk_token()
        access = self._mk_token()
        now = _now_utc()
        self._refresh_store[refresh] = (principal_id, now + timedelta(days=7), session_id)
        self._access_store[access] = (principal_id, now + timedelta(minutes=15), session_id)
        self._seed = {"refresh": refresh, "access": access, "session": session_id, "principal": principal_id}

    @staticmethod
    def _mk_token() -> str:
        return uuid.uuid4().hex + uuid.uuid4().hex

    async def refresh_access_token(self, refresh_token: str, context: ClientContext | None) -> AuthSuccess:
        now = _now_utc()
        rec = self._refresh_store.get(refresh_token)
        if not rec:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "invalid refresh_token"})
        principal_id, exp, session_id = rec
        if exp < now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"message": "refresh_token expired"})

        new_access = self._mk_token()
        new_refresh = self._mk_token()  # rotate
        self._access_store[new_access] = (principal_id, now + timedelta(minutes=15), session_id)
        self._refresh_store[new_refresh] = (principal_id, now + timedelta(days=7), session_id)
        # revoke old refresh
        self._refresh_store.pop(refresh_token, None)

        principal = Principal(id=principal_id, username="demo", display_name="Demo User", created_at=_iso(now))
        session = Session(
            id=session_id,
            principal_id=principal_id,
            methods=[AuthMethod.PASSWORD],
            ip_address=context.ip_address if context else None,
            user_agent=context.user_agent if context else None,
            created_at=_iso(now),
            expires_at=_iso(now + timedelta(days=7)),
            access_token_id=new_access[:16],
            refresh_token_id=new_refresh[:16],
        )
        access_token = Token(
            id=new_access[:16],
            type=TokenType.ACCESS,
            issuer="aethernova://auth",
            subject=principal_id,
            issued_at=_iso(now),
            expires_at=_iso(now + timedelta(minutes=15)),
            jwt_compact=new_access,
            session_id=session_id,
        )
        refresh_token_model = Token(
            id=new_refresh[:16],
            type=TokenType.REFRESH,
            issuer="aethernova://auth",
            subject=principal_id,
            issued_at=_iso(now),
            expires_at=_iso(now + timedelta(days=7)),
            opaque=new_refresh,
            session_id=session_id,
        )
        return AuthSuccess(
            principal=principal,
            session=session,
            access_token=access_token,
            refresh_token=refresh_token_model,
            id_token_issued=False,
        )

    async def introspect(self, token: str, assumed_type: TokenType | None, context: ClientContext | None) -> IntrospectTokenOut:
        now = _now_utc()
        store = self._access_store if assumed_type in (TokenType.ACCESS, None) else self._refresh_store
        rec = store.get(token)
        if not rec:
            # try the other store if no assumed_type
            if assumed_type is None:
                rec = self._refresh_store.get(token)
                if not rec:
                    return IntrospectTokenOut(active=False, evaluated_at=_iso(now))
                ttype = TokenType.REFRESH
            else:
                return IntrospectTokenOut(active=False, evaluated_at=_iso(now))
        else:
            ttype = TokenType.ACCESS if store is self._access_store else TokenType.REFRESH

        principal_id, exp, session_id = rec
        active = exp > now

        tok = Token(
            id=token[:16],
            type=ttype,
            issuer="aethernova://auth",
            subject=principal_id,
            issued_at=_iso(now - timedelta(minutes=1)),
            expires_at=_iso(exp),
            jwt_compact=token if ttype == TokenType.ACCESS else None,
            opaque=token if ttype == TokenType.REFRESH else None,
            session_id=session_id,
        )
        principal = Principal(id=principal_id, username="demo")
        session = Session(id=session_id, principal_id=principal_id, created_at=_iso(now - timedelta(minutes=1)))
        return IntrospectTokenOut(active=active, token=tok, principal=principal, session=session, evaluated_at=_iso(now))

    async def revoke(self, token: str, ttype: TokenType, reason: Optional[str], context: ClientContext | None) -> bool:
        if ttype == TokenType.REFRESH:
            removed = self._refresh_store.pop(token, None)
            return removed is not None
        if ttype == TokenType.ACCESS:
            removed = self._access_store.pop(token, None)
            return removed is not None
        # ID/SESSION revocation not modelled in mock
        return False

# -----------------------------------------------------------------------------
# Dependencies / DI
# -----------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_service() -> TokenService:
    if os.getenv("SECURITY_CORE_DEV_MOCK") == "1":
        logger.warning("Using DEV in-memory TokenService mock. Do not use in production.")
        return _InMemoryTokenService()
    # In production wire your real implementation here
    # Example: return RealTokenService(...)
    raise RuntimeError("TokenService is not configured. Set SECURITY_CORE_DEV_MOCK=1 for local runs.")

async def get_token_service() -> TokenService:
    return _get_service()

# -----------------------------------------------------------------------------
# Context & headers dependencies
# -----------------------------------------------------------------------------

async def get_client_context(request: Request, x_request_id: Optional[str] = Header(default=None)) -> Tuple[ClientContext, str]:
    req_id = _ensure_request_id(x_request_id)
    ua = request.headers.get("user-agent")
    tz = request.headers.get("x-timezone")
    ip = request.client.host if request.client else None
    ctx = ClientContext(
        request_id=req_id,
        ip_address=ip,
        user_agent=ua,
        timezone=tz,
        headers={"x-forwarded-for": request.headers.get("x-forwarded-for")} if request.headers.get("x-forwarded-for") else None,
    )
    return ctx, req_id

def _no_store_headers(resp: Response) -> None:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"

# -----------------------------------------------------------------------------
# Idempotency (in-memory, per-process; replace with Redis in prod)
# -----------------------------------------------------------------------------

class _IdemCache:
    def __init__(self, ttl_sec: int = 600) -> None:
        self.ttl = ttl_sec
        self._store: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get_or_set(self, key: str, value_builder: callable[[], Dict[str, Any]]) -> Tuple[Dict[str, Any], bool]:
        now = time.time()
        # cleanup
        expired = [k for k, (t, _) in self._store.items() if now - t > self.ttl]
        for k in expired:
            self._store.pop(k, None)
        if key in self._store:
            return self._store[key][1], True
        val = value_builder()
        self._store[key] = (now, val)
        return val, False

_idem = _IdemCache(ttl_sec=900)

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@router.post(
    "/token:refresh",
    response_model=RefreshAccessTokenOut,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token (rotates refresh)",
)
async def token_refresh(
    payload: RefreshAccessTokenIn,
    response: Response,
    service: TokenService = Depends(get_token_service),
    ctx_pair: Tuple[ClientContext, str] = Depends(get_client_context),
):
    ctx, req_id = ctx_pair
    # prefer client-provided context if passed, but keep request_id
    req_ctx = payload.context or ClientContext()
    req_ctx.request_id = req_id
    try:
        result = await service.refresh_access_token(payload.refresh_token, req_ctx)
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.info(
            "token.refresh.ok",
            extra={
                "req_id": req_id,
                "session_id": result.session.id,
                "principal_id": result.principal.id,
                "access": _redact_token(result.access_token.jwt_compact or result.access_token.paseto or result.access_token.opaque),
                "refresh": _redact_token(result.refresh_token.jwt_compact or result.refresh_token.paseto or result.refresh_token.opaque),
            },
        )
        return RefreshAccessTokenOut(success=result)
    except HTTPException as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
        detail["correlation_id"] = req_id
        logger.warning("token.refresh.fail", extra={"req_id": req_id, "error": detail.get("message")})
        raise HTTPException(status_code=e.status_code, detail=detail)
    except Exception as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.exception("token.refresh.error", extra={"req_id": req_id})
        raise HTTPException(status_code=500, detail={"message": "internal error", "correlation_id": req_id})

@router.post(
    "/token:introspect",
    response_model=IntrospectTokenOut,
    status_code=status.HTTP_200_OK,
    summary="Introspect token (access/refresh)",
)
async def token_introspect(
    payload: IntrospectTokenIn,
    response: Response,
    service: TokenService = Depends(get_token_service),
    ctx_pair: Tuple[ClientContext, str] = Depends(get_client_context),
):
    ctx, req_id = ctx_pair
    req_ctx = payload.context or ClientContext()
    req_ctx.request_id = req_id
    try:
        res = await service.introspect(payload.token, payload.assumed_type, req_ctx)
        res.evaluated_at = res.evaluated_at or _iso(_now_utc())
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.info(
            "token.introspect",
            extra={
                "req_id": req_id,
                "active": res.active,
                "type": res.token.type if res.token else None,
                "token": _redact_token(res.token.jwt_compact or res.token.paseto or res.token.opaque) if res.token else "",
            },
        )
        return res
    except HTTPException as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
        detail["correlation_id"] = req_id
        logger.warning("token.introspect.fail", extra={"req_id": req_id, "error": detail.get("message")})
        raise HTTPException(status_code=e.status_code, detail=detail)
    except Exception as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.exception("token.introspect.error", extra={"req_id": req_id})
        raise HTTPException(status_code=500, detail={"message": "internal error", "correlation_id": req_id})

@router.post(
    "/token:revoke",
    response_model=RevokeTokenOut,
    status_code=status.HTTP_200_OK,
    summary="Revoke token (access/refresh)",
)
async def token_revoke(
    payload: RevokeTokenIn,
    response: Response,
    service: TokenService = Depends(get_token_service),
    ctx_pair: Tuple[ClientContext, str] = Depends(get_client_context),
    idempotency_key: Optional[str] = Header(default=None, convert_underscores=False, alias="Idempotency-Key"),
):
    ctx, req_id = ctx_pair
    req_ctx = payload.context or ClientContext()
    req_ctx.request_id = req_id

    # Idempotency: cache by key + token + type
    cache_key = None
    if idempotency_key:
        cache_key = f"revoke:{payload.type}:{payload.token}:{idempotency_key}"
        cached, hit = _idem.get_or_set(cache_key, lambda: {"revoked": None, "ts": time.time()})
        if hit and cached["revoked"] is not None:
            response.headers["X-Request-Id"] = req_id
            _no_store_headers(response)
            logger.info("token.revoke.idempotent", extra={"req_id": req_id, "hit": True})
            return RevokeTokenOut(revoked=bool(cached["revoked"]))

    try:
        revoked = await service.revoke(payload.token, payload.type, payload.reason, req_ctx)
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.info(
            "token.revoke",
            extra={
                "req_id": req_id,
                "type": payload.type,
                "token": _redact_token(payload.token),
                "revoked": revoked,
                "reason": payload.reason or "",
            },
        )
        if cache_key:
            _idem.get_or_set(cache_key, lambda: {"revoked": revoked, "ts": time.time()})
        return RevokeTokenOut(revoked=revoked)
    except HTTPException as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
        detail["correlation_id"] = req_id
        logger.warning("token.revoke.fail", extra={"req_id": req_id, "error": detail.get("message")})
        raise HTTPException(status_code=e.status_code, detail=detail)
    except Exception as e:
        response.headers["X-Request-Id"] = req_id
        _no_store_headers(response)
        logger.exception("token.revoke.error", extra={"req_id": req_id})
        raise HTTPException(status_code=500, detail={"message": "internal error", "correlation_id": req_id})
