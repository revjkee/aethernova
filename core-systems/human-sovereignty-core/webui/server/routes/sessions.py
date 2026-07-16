# human-sovereignty-core/webui/server/routes/sessions.py
from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, StrictBool, StrictStr, constr


router = APIRouter(tags=["sessions"])


# ============================
# Security configuration
# ============================

@dataclass(frozen=True, slots=True)
class SessionSecurityConfig:
    """
    Centralized security knobs for sessions routes.

    Important:
    - If you use cookie_mode=True, enforce CSRF checks on state-changing routes.
    - If you use Authorization header (bearer tokens) for access token, CSRF is not required.
    """

    cookie_mode: bool = True

    access_cookie_name: str = "hsc_access"
    refresh_cookie_name: str = "hsc_refresh"
    csrf_cookie_name: str = "hsc_csrf"
    csrf_header_name: str = "x-csrf-token"

    cookie_path: str = "/"
    cookie_samesite: str = "lax"  # lax|strict|none
    cookie_secure: bool = True
    cookie_httponly_access: bool = True
    cookie_httponly_refresh: bool = True

    csrf_cookie_httponly: bool = False

    access_cookie_max_age_seconds: int = 900
    refresh_cookie_max_age_seconds: int = 2592000

    issue_access_token_in_body: bool = False
    issue_refresh_token_in_body: bool = False

    require_csrf_for_refresh: bool = True
    require_csrf_for_logout: bool = True

    allow_refresh_in_body: bool = True

    # Hard bounds for payload safety
    max_identifier_len: int = 256
    max_password_len: int = 512

    # Timing protection
    min_login_processing_ms: int = 250


def get_session_security_config() -> SessionSecurityConfig:
    """
    Dependency injection point. Replace in app wiring if needed.
    No side effects, no env reads here by design.
    """
    return SessionSecurityConfig()


# ============================
# Models
# ============================

IdentifierStr = constr(strip_whitespace=True, min_length=1, max_length=256)
PasswordStr = constr(strip_whitespace=False, min_length=1, max_length=512)


class LoginRequest(BaseModel):
    identifier: IdentifierStr = Field(..., description="Username or email or external id")
    password: PasswordStr = Field(..., description="User secret")
    remember_me: StrictBool = Field(False, description="Optional hint to extend refresh TTL")


class TokenPair(BaseModel):
    access_token: StrictStr
    refresh_token: StrictStr
    token_type: StrictStr = "bearer"
    expires_in: int


class LoginResponse(BaseModel):
    ok: StrictBool = True
    subject_id: StrictStr
    session_id: StrictStr
    tokens: Optional[TokenPair] = None


class RefreshRequest(BaseModel):
    refresh_token: Optional[StrictStr] = Field(None, description="Refresh token (optional if cookie_mode)")
    rotate: StrictBool = Field(True, description="Rotate refresh token (recommended)")


class RefreshResponse(BaseModel):
    ok: StrictBool = True
    session_id: StrictStr
    tokens: Optional[TokenPair] = None


class LogoutResponse(BaseModel):
    ok: StrictBool = True


# ============================
# Interfaces
# ============================

class AuthService(Protocol):
    """
    Contract for authentication and session issuance.

    Implementations must:
    - Verify credentials securely
    - Issue access and refresh tokens
    - Persist refresh token state (hash, jti, session binding)
    - Support refresh rotation
    - Revoke refresh token(s) on logout
    """

    def authenticate_password(self, *, identifier: str, password: str, request_ctx: Mapping[str, Any]) -> Dict[str, str]:
        """
        Returns dict with keys:
        - subject_id
        - session_id
        """
        ...

    def issue_tokens(
        self,
        *,
        subject_id: str,
        session_id: str,
        remember_me: bool,
        request_ctx: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Returns dict with keys:
        - access_token (str)
        - refresh_token (str)
        - access_expires_in (int seconds)
        - refresh_expires_in (int seconds)
        """
        ...

    def refresh_tokens(
        self,
        *,
        refresh_token: str,
        rotate: bool,
        request_ctx: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Returns dict with keys:
        - session_id (str)
        - access_token (str)
        - refresh_token (str, if rotate True)
        - access_expires_in (int seconds)
        - refresh_expires_in (int seconds, if rotate True)
        """
        ...

    def revoke_session(
        self,
        *,
        refresh_token: Optional[str],
        session_id: Optional[str],
        request_ctx: Mapping[str, Any],
    ) -> None:
        """
        Revokes refresh token and/or session.
        """
        ...


class RateLimiter(Protocol):
    def hit(self, *, key: str, limit: int, window_seconds: int) -> None:
        """
        Must raise an exception on limit exceeded.
        """
        ...


class Auditor(Protocol):
    def emit(self, *, event: str, data: Mapping[str, Any]) -> None:
        """
        Must be non-throwing or throw only on fatal configuration.
        """
        ...


# ============================
# Default dependency stubs
# ============================

def get_auth_service() -> AuthService:
    raise RuntimeError("AuthService dependency is not wired")


def get_rate_limiter() -> Optional[RateLimiter]:
    return None


def get_auditor() -> Optional[Auditor]:
    return None


# ============================
# Helpers
# ============================

def _now_ms() -> int:
    return int(time.time() * 1000)


def _sleep_until_min_duration(start_ms: int, min_ms: int) -> None:
    elapsed = _now_ms() - start_ms
    remaining = min_ms - elapsed
    if remaining > 0:
        time.sleep(remaining / 1000.0)


def _client_ip(request: Request) -> str:
    # Prefer trusted proxy handling in gateway; this is best-effort.
    return request.client.host if request.client else "unknown"


def _build_request_ctx(request: Request) -> Dict[str, Any]:
    return {
        "ip": _client_ip(request),
        "ua": request.headers.get("user-agent", ""),
        "request_id": request.headers.get("x-request-id", ""),
        "origin": request.headers.get("origin", ""),
        "referer": request.headers.get("referer", ""),
    }


def _set_cookie(
    response: Response,
    *,
    name: str,
    value: str,
    cfg: SessionSecurityConfig,
    max_age: int,
    httponly: bool,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        expires=max_age,
        path=cfg.cookie_path,
        secure=cfg.cookie_secure,
        httponly=httponly,
        samesite=cfg.cookie_samesite,
    )


def _clear_cookie(response: Response, *, name: str, cfg: SessionSecurityConfig) -> None:
    response.delete_cookie(
        key=name,
        path=cfg.cookie_path,
        samesite=cfg.cookie_samesite,
    )


def _new_csrf_token() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _require_csrf(
    *,
    cfg: SessionSecurityConfig,
    csrf_cookie_value: Optional[str],
    csrf_header_value: Optional[str],
) -> None:
    if not cfg.cookie_mode:
        return

    if not csrf_cookie_value or not csrf_header_value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    if not secrets.compare_digest(csrf_cookie_value, csrf_header_value):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch")


def _safe_raise_auth_failed() -> None:
    # Unified response to avoid user enumeration.
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def _rate_limit_or_429(
    limiter: Optional[RateLimiter],
    *,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    if limiter is None:
        return
    try:
        limiter.hit(key=key, limit=limit, window_seconds=window_seconds)
    except Exception:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


# ============================
# Routes
# ============================

@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    cfg: SessionSecurityConfig = Depends(get_session_security_config),
    auth: AuthService = Depends(get_auth_service),
    limiter: Optional[RateLimiter] = Depends(get_rate_limiter),
    auditor: Optional[Auditor] = Depends(get_auditor),
) -> LoginResponse:
    start_ms = _now_ms()

    ctx = _build_request_ctx(request)

    # Rate limits
    ip = ctx.get("ip", "unknown")
    _rate_limit_or_429(limiter, key=f"login:ip:{ip}", limit=20, window_seconds=60)
    _rate_limit_or_429(limiter, key=f"login:id:{payload.identifier}", limit=10, window_seconds=300)

    try:
        result = auth.authenticate_password(
            identifier=payload.identifier,
            password=payload.password,
            request_ctx=ctx,
        )
        subject_id = result["subject_id"]
        session_id = result["session_id"]
    except HTTPException:
        _sleep_until_min_duration(start_ms, cfg.min_login_processing_ms)
        raise
    except Exception:
        # Do not leak details. Maintain consistent timing.
        _sleep_until_min_duration(start_ms, cfg.min_login_processing_ms)
        _safe_raise_auth_failed()

    try:
        tokens = auth.issue_tokens(
            subject_id=subject_id,
            session_id=session_id,
            remember_me=bool(payload.remember_me),
            request_ctx=ctx,
        )
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token issuance failed")

    access_token = str(tokens.get("access_token", ""))
    refresh_token = str(tokens.get("refresh_token", ""))
    access_expires_in = int(tokens.get("access_expires_in", cfg.access_cookie_max_age_seconds))
    refresh_expires_in = int(tokens.get("refresh_expires_in", cfg.refresh_cookie_max_age_seconds))

    if not access_token or not refresh_token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token issuance failed")

    # Cookie mode
    if cfg.cookie_mode:
        _set_cookie(
            response,
            name=cfg.access_cookie_name,
            value=access_token,
            cfg=cfg,
            max_age=min(access_expires_in, cfg.access_cookie_max_age_seconds),
            httponly=cfg.cookie_httponly_access,
        )
        _set_cookie(
            response,
            name=cfg.refresh_cookie_name,
            value=refresh_token,
            cfg=cfg,
            max_age=min(refresh_expires_in, cfg.refresh_cookie_max_age_seconds),
            httponly=cfg.cookie_httponly_refresh,
        )

        csrf = _new_csrf_token()
        _set_cookie(
            response,
            name=cfg.csrf_cookie_name,
            value=csrf,
            cfg=cfg,
            max_age=min(refresh_expires_in, cfg.refresh_cookie_max_age_seconds),
            httponly=cfg.csrf_cookie_httponly,
        )

    # Optional body tokens
    tokens_out: Optional[TokenPair] = None
    if cfg.issue_access_token_in_body or cfg.issue_refresh_token_in_body:
        tokens_out = TokenPair(
            access_token=access_token if cfg.issue_access_token_in_body else "",
            refresh_token=refresh_token if cfg.issue_refresh_token_in_body else "",
            expires_in=access_expires_in,
        )

    if auditor is not None:
        try:
            auditor.emit(
                event="sessions.login",
                data={
                    "subject_id": subject_id,
                    "session_id": session_id,
                    "ip": ip,
                    "cookie_mode": cfg.cookie_mode,
                },
            )
        except Exception:
            pass

    _sleep_until_min_duration(start_ms, cfg.min_login_processing_ms)

    return LoginResponse(ok=True, subject_id=subject_id, session_id=session_id, tokens=tokens_out)


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    cfg: SessionSecurityConfig = Depends(get_session_security_config),
    auth: AuthService = Depends(get_auth_service),
    limiter: Optional[RateLimiter] = Depends(get_rate_limiter),
    auditor: Optional[Auditor] = Depends(get_auditor),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> RefreshResponse:
    ctx = _build_request_ctx(request)
    ip = ctx.get("ip", "unknown")

    _rate_limit_or_429(limiter, key=f"refresh:ip:{ip}", limit=60, window_seconds=60)

    csrf_cookie = request.cookies.get(cfg.csrf_cookie_name)
    if cfg.cookie_mode and cfg.require_csrf_for_refresh:
        header_val = x_csrf_token or request.headers.get(cfg.csrf_header_name)
        _require_csrf(cfg=cfg, csrf_cookie_value=csrf_cookie, csrf_header_value=header_val)

    refresh_token = ""
    if cfg.cookie_mode:
        refresh_token = request.cookies.get(cfg.refresh_cookie_name, "")
    if not refresh_token and cfg.allow_refresh_in_body and payload.refresh_token:
        refresh_token = payload.refresh_token

    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    try:
        out = auth.refresh_tokens(
            refresh_token=refresh_token,
            rotate=bool(payload.rotate),
            request_ctx=ctx,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    session_id = str(out.get("session_id", ""))
    access_token = str(out.get("access_token", ""))
    new_refresh_token = str(out.get("refresh_token", "")) if bool(payload.rotate) else ""

    access_expires_in = int(out.get("access_expires_in", cfg.access_cookie_max_age_seconds))
    refresh_expires_in = int(out.get("refresh_expires_in", cfg.refresh_cookie_max_age_seconds))

    if not session_id or not access_token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Refresh failed")

    if cfg.cookie_mode:
        _set_cookie(
            response,
            name=cfg.access_cookie_name,
            value=access_token,
            cfg=cfg,
            max_age=min(access_expires_in, cfg.access_cookie_max_age_seconds),
            httponly=cfg.cookie_httponly_access,
        )
        if bool(payload.rotate):
            if not new_refresh_token:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Refresh rotation failed")
            _set_cookie(
                response,
                name=cfg.refresh_cookie_name,
                value=new_refresh_token,
                cfg=cfg,
                max_age=min(refresh_expires_in, cfg.refresh_cookie_max_age_seconds),
                httponly=cfg.cookie_httponly_refresh,
            )
            csrf = _new_csrf_token()
            _set_cookie(
                response,
                name=cfg.csrf_cookie_name,
                value=csrf,
                cfg=cfg,
                max_age=min(refresh_expires_in, cfg.refresh_cookie_max_age_seconds),
                httponly=cfg.csrf_cookie_httponly,
            )

    tokens_out: Optional[TokenPair] = None
    if cfg.issue_access_token_in_body or cfg.issue_refresh_token_in_body:
        tokens_out = TokenPair(
            access_token=access_token if cfg.issue_access_token_in_body else "",
            refresh_token=(new_refresh_token if bool(payload.rotate) else refresh_token) if cfg.issue_refresh_token_in_body else "",
            expires_in=access_expires_in,
        )

    if auditor is not None:
        try:
            auditor.emit(
                event="sessions.refresh",
                data={
                    "session_id": session_id,
                    "ip": ip,
                    "rotated": bool(payload.rotate),
                    "cookie_mode": cfg.cookie_mode,
                },
            )
        except Exception:
            pass

    return RefreshResponse(ok=True, session_id=session_id, tokens=tokens_out)


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    response: Response,
    cfg: SessionSecurityConfig = Depends(get_session_security_config),
    auth: AuthService = Depends(get_auth_service),
    limiter: Optional[RateLimiter] = Depends(get_rate_limiter),
    auditor: Optional[Auditor] = Depends(get_auditor),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> LogoutResponse:
    ctx = _build_request_ctx(request)
    ip = ctx.get("ip", "unknown")
    _rate_limit_or_429(limiter, key=f"logout:ip:{ip}", limit=120, window_seconds=60)

    csrf_cookie = request.cookies.get(cfg.csrf_cookie_name)
    if cfg.cookie_mode and cfg.require_csrf_for_logout:
        header_val = x_csrf_token or request.headers.get(cfg.csrf_header_name)
        _require_csrf(cfg=cfg, csrf_cookie_value=csrf_cookie, csrf_header_value=header_val)

    refresh_token = request.cookies.get(cfg.refresh_cookie_name) if cfg.cookie_mode else None
    session_id = None

    try:
        auth.revoke_session(refresh_token=refresh_token, session_id=session_id, request_ctx=ctx)
    except Exception:
        # Logout should be idempotent and not leak state.
        pass

    if cfg.cookie_mode:
        _clear_cookie(response, name=cfg.access_cookie_name, cfg=cfg)
        _clear_cookie(response, name=cfg.refresh_cookie_name, cfg=cfg)
        _clear_cookie(response, name=cfg.csrf_cookie_name, cfg=cfg)

    if auditor is not None:
        try:
            auditor.emit(event="sessions.logout", data={"ip": ip, "cookie_mode": cfg.cookie_mode})
        except Exception:
            pass

    return LogoutResponse(ok=True)
