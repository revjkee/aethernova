# agent_mash/legacy/scripts_archive/experiments/auth_prototype_v0.py
"""
Industrial Auth Prototype v0 (single-file, legacy/experiments)

Features:
- FastAPI service
- SQLite storage (users, refresh sessions)
- Password hashing: bcrypt
- JWT access tokens: HS256
- Refresh token rotation with one-time-use refresh tokens
- Basic IP rate limiting for login endpoint
- Audit logging (JSON-like structured logs)
- Strict configuration via env vars

Dependencies (install explicitly):
  pip install fastapi uvicorn pydantic pydantic-settings python-jose passlib[bcrypt]

Run:
  python auth_prototype_v0.py

Env vars:
  AUTH_BIND_HOST=127.0.0.1
  AUTH_BIND_PORT=8000
  AUTH_DB_PATH=/absolute/path/to/auth_prototype.sqlite3
  AUTH_JWT_SECRET=change_me_to_64+_random_chars
  AUTH_ACCESS_TTL_SECONDS=900
  AUTH_REFRESH_TTL_SECONDS=1209600
  AUTH_ISSUER=aethernova-auth
  AUTH_AUDIENCE=aethernova-clients
  AUTH_LOG_LEVEL=INFO
  AUTH_LOGIN_RL_WINDOW_SECONDS=60
  AUTH_LOGIN_RL_MAX_REQUESTS=10

Security notes:
- This is a prototype. For production: add mTLS, MFA/WebAuthn, device binding, risk signals,
  better rate-limits (redis), secrets management, structured audit sink, and key rotation (kid).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import uvicorn


# ----------------------------
# Configuration
# ----------------------------

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", extra="ignore")

    bind_host: str = "127.0.0.1"
    bind_port: int = 8000

    db_path: str = "/mnt/data/auth_prototype.sqlite3"

    jwt_secret: str = "change_me"
    jwt_algorithm: str = "HS256"
    issuer: str = "aethernova-auth"
    audience: str = "aethernova-clients"

    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 60 * 60 * 24 * 14

    log_level: str = "INFO"

    login_rl_window_seconds: int = 60
    login_rl_max_requests: int = 10


settings = Settings()

if not settings.jwt_secret or settings.jwt_secret == "change_me":
    # Prototype safety: fail fast if secret not set properly.
    # This is not a speculation; it is an explicit guardrail.
    raise RuntimeError("AUTH_JWT_SECRET must be set to a strong secret (not 'change_me').")


# ----------------------------
# Logging (structured)
# ----------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _log(event: str, **fields: Any) -> None:
    payload = {
        "ts": _utc_now().isoformat(),
        "event": event,
        **fields,
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ----------------------------
# Crypto helpers
# ----------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def generate_refresh_token() -> str:
    # 32 bytes is a standard strong token size for session secrets.
    return _b64url(secrets.token_bytes(32))


# ----------------------------
# Database
# ----------------------------

DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT NULL,
  used_at TEXT NULL,
  ip TEXT NULL,
  user_agent TEXT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user_id ON refresh_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_expires_at ON refresh_sessions(expires_at);
"""

@dataclass
class DB:
    conn: sqlite3.Connection

def _db_connect() -> DB:
    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return DB(conn=conn)

def _db_init(db: DB) -> None:
    db.conn.executescript(DDL)
    db.conn.commit()

db = _db_connect()
_db_init(db)


# ----------------------------
# Rate limiting (in-memory, prototype)
# ----------------------------

class InMemoryRateLimiter:
    def __init__(self, window_seconds: int, max_requests: int) -> None:
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._buckets: Dict[str, Tuple[float, int]] = {}

    def check(self, key: str) -> bool:
        now = time.monotonic()
        start, count = self._buckets.get(key, (now, 0))

        if (now - start) > self.window_seconds:
            start, count = now, 0

        count += 1
        self._buckets[key] = (start, count)
        return count <= self.max_requests

rl_login = InMemoryRateLimiter(settings.login_rl_window_seconds, settings.login_rl_max_requests)


# ----------------------------
# Models
# ----------------------------

class ErrorOut(BaseModel):
    code: str
    message: str

class HealthOut(BaseModel):
    status: str = "ok"
    service: str = "auth_prototype_v0"
    time_utc: str

class RegisterIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$")
    password: str = Field(..., min_length=8, max_length=256)

class LoginIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str

class RefreshIn(BaseModel):
    refresh_token: str = Field(..., min_length=20, max_length=400)

class MeOut(BaseModel):
    user_id: int
    username: str
    role: str
    is_active: bool


# ----------------------------
# JWT
# ----------------------------

def create_access_token(*, subject: str, user_id: int, role: str) -> Tuple[str, int]:
    ttl = int(settings.access_ttl_seconds)
    now = _utc_now()
    exp = now + timedelta(seconds=ttl)

    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": subject,
        "uid": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "typ": "access",
    }

    token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, ttl

def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.issuer,
            audience=settings.audience,
            options={"require_exp": True, "require_iat": True},
        )
        if claims.get("typ") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token type")
        return claims
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")


# ----------------------------
# Storage operations
# ----------------------------

def _user_get_by_username(username: str) -> Optional[sqlite3.Row]:
    cur = db.conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def _user_create(username: str, password_hash: str, role: str = "user") -> int:
    now = _utc_now().isoformat()
    cur = db.conn.execute(
        "INSERT INTO users(username, password_hash, role, created_at, updated_at) VALUES(?,?,?,?,?)",
        (username, password_hash, role, now, now),
    )
    db.conn.commit()
    return int(cur.lastrowid)

def _refresh_session_create(
    *,
    user_id: int,
    refresh_token: str,
    expires_at: datetime,
    ip: Optional[str],
    user_agent: Optional[str],
) -> None:
    now = _utc_now().isoformat()
    exp = expires_at.isoformat()
    r_hash = _sha256_hex(refresh_token)
    db.conn.execute(
        """
        INSERT INTO refresh_sessions(user_id, refresh_token_hash, created_at, expires_at, ip, user_agent)
        VALUES(?,?,?,?,?,?)
        """,
        (user_id, r_hash, now, exp, ip, user_agent),
    )
    db.conn.commit()

def _refresh_session_get_by_token(refresh_token: str) -> Optional[sqlite3.Row]:
    r_hash = _sha256_hex(refresh_token)
    cur = db.conn.execute(
        "SELECT * FROM refresh_sessions WHERE refresh_token_hash = ?",
        (r_hash,),
    )
    return cur.fetchone()

def _refresh_session_mark_used(session_id: int) -> None:
    now = _utc_now().isoformat()
    db.conn.execute("UPDATE refresh_sessions SET used_at = ? WHERE id = ?", (now, session_id))
    db.conn.commit()

def _refresh_session_revoke(session_id: int) -> None:
    now = _utc_now().isoformat()
    db.conn.execute("UPDATE refresh_sessions SET revoked_at = ? WHERE id = ?", (now, session_id))
    db.conn.commit()

def _refresh_session_is_valid(row: sqlite3.Row) -> Tuple[bool, str]:
    if row["revoked_at"] is not None:
        return False, "revoked"
    if row["used_at"] is not None:
        return False, "used"
    try:
        exp = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False, "invalid expires_at"
    if _utc_now() >= exp:
        return False, "expired"
    return True, "ok"


# ----------------------------
# Auth dependencies
# ----------------------------

def _extract_bearer(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return auth.split(" ", 1)[1].strip()

def current_user(request: Request) -> MeOut:
    token = _extract_bearer(request)
    claims = decode_access_token(token)
    uid = claims.get("uid")
    username = claims.get("sub")
    role = claims.get("role")
    if not isinstance(uid, int) or not isinstance(username, str) or not isinstance(role, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token claims")

    row = _user_get_by_username(username)
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found")
    if int(row["id"]) != uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token/user mismatch")
    if int(row["is_active"]) != 1:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user inactive")

    return MeOut(
        user_id=int(row["id"]),
        username=str(row["username"]),
        role=str(row["role"]),
        is_active=int(row["is_active"]) == 1,
    )


# ----------------------------
# FastAPI app
# ----------------------------

app = FastAPI(title="auth_prototype_v0", version="0.1.0")


@app.exception_handler(HTTPException)
async def http_exc_handler(_: Request, exc: HTTPException) -> JSONResponse:
    code = "HTTP_ERROR"
    if exc.status_code == 401:
        code = "UNAUTHORIZED"
    elif exc.status_code == 403:
        code = "FORBIDDEN"
    elif exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code == 429:
        code = "RATE_LIMITED"
    elif exc.status_code == 400:
        code = "BAD_REQUEST"

    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorOut(code=code, message=str(exc.detail)).model_dump(),
    )


@app.get("/health", response_model=HealthOut)
async def health() -> HealthOut:
    return HealthOut(time_utc=_utc_now().isoformat())


@app.post("/auth/register", response_model=MeOut, status_code=201)
async def register(payload: RegisterIn, request: Request) -> MeOut:
    existing = _user_get_by_username(payload.username)
    if existing is not None:
        raise HTTPException(status_code=400, detail="username already exists")

    pw_hash = hash_password(payload.password)
    uid = _user_create(payload.username, pw_hash, role="user")

    _log(
        "auth.register",
        user_id=uid,
        username=payload.username,
        ip=_client_ip(request),
        ua=_user_agent(request),
    )

    return MeOut(user_id=uid, username=payload.username, role="user", is_active=True)


@app.post("/auth/login", response_model=TokenOut)
async def login(payload: LoginIn, request: Request) -> TokenOut:
    ip = _client_ip(request)
    if not rl_login.check(ip):
        _log("auth.login.ratelimited", username=payload.username, ip=ip, ua=_user_agent(request))
        raise HTTPException(status_code=429, detail="too many attempts")

    row = _user_get_by_username(payload.username)
    if row is None:
        _log("auth.login.failed", username=payload.username, reason="user_not_found", ip=ip, ua=_user_agent(request))
        raise HTTPException(status_code=401, detail="invalid credentials")

    if int(row["is_active"]) != 1:
        _log("auth.login.failed", username=payload.username, reason="user_inactive", ip=ip, ua=_user_agent(request))
        raise HTTPException(status_code=403, detail="user inactive")

    if not verify_password(payload.password, str(row["password_hash"])):
        _log("auth.login.failed", username=payload.username, reason="bad_password", ip=ip, ua=_user_agent(request))
        raise HTTPException(status_code=401, detail="invalid credentials")

    user_id = int(row["id"])
    role = str(row["role"])

    access, ttl = create_access_token(subject=payload.username, user_id=user_id, role=role)
    refresh = generate_refresh_token()
    refresh_exp = _utc_now() + timedelta(seconds=int(settings.refresh_ttl_seconds))

    _refresh_session_create(
        user_id=user_id,
        refresh_token=refresh,
        expires_at=refresh_exp,
        ip=ip,
        user_agent=_user_agent(request),
    )

    _log("auth.login.success", user_id=user_id, username=payload.username, ip=ip, ua=_user_agent(request))

    return TokenOut(access_token=access, expires_in=ttl, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenOut)
async def refresh(payload: RefreshIn, request: Request) -> TokenOut:
    row = _refresh_session_get_by_token(payload.refresh_token)
    if row is None:
        _log("auth.refresh.failed", reason="session_not_found", ip=_client_ip(request), ua=_user_agent(request))
        raise HTTPException(status_code=401, detail="invalid refresh token")

    ok, reason = _refresh_session_is_valid(row)
    if not ok:
        _log("auth.refresh.failed", reason=reason, session_id=int(row["id"]), ip=_client_ip(request), ua=_user_agent(request))
        raise HTTPException(status_code=401, detail="invalid refresh token")

    user_id = int(row["user_id"])
    # Fetch current user snapshot
    cur = db.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    u = cur.fetchone()
    if u is None:
        _log("auth.refresh.failed", reason="user_missing", user_id=user_id, ip=_client_ip(request), ua=_user_agent(request))
        raise HTTPException(status_code=401, detail="invalid refresh token")

    if int(u["is_active"]) != 1:
        _log("auth.refresh.failed", reason="user_inactive", user_id=user_id, ip=_client_ip(request), ua=_user_agent(request))
        raise HTTPException(status_code=403, detail="user inactive")

    username = str(u["username"])
    role = str(u["role"])

    # Rotation: mark old token as used and issue new refresh token.
    _refresh_session_mark_used(int(row["id"]))

    access, ttl = create_access_token(subject=username, user_id=user_id, role=role)

    new_refresh = generate_refresh_token()
    refresh_exp = _utc_now() + timedelta(seconds=int(settings.refresh_ttl_seconds))

    _refresh_session_create(
        user_id=user_id,
        refresh_token=new_refresh,
        expires_at=refresh_exp,
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )

    _log("auth.refresh.success", user_id=user_id, username=username, ip=_client_ip(request), ua=_user_agent(request))

    return TokenOut(access_token=access, expires_in=ttl, refresh_token=new_refresh)


@app.post("/auth/logout", status_code=204)
async def logout(payload: RefreshIn, request: Request) -> None:
    row = _refresh_session_get_by_token(payload.refresh_token)
    if row is None:
        return
    _refresh_session_revoke(int(row["id"]))
    _log("auth.logout", session_id=int(row["id"]), ip=_client_ip(request), ua=_user_agent(request))


@app.get("/auth/me", response_model=MeOut)
async def me(user: MeOut = Depends(current_user)) -> MeOut:
    return user


# ----------------------------
# Request helpers
# ----------------------------

def _client_ip(request: Request) -> str:
    # Prototype: trust direct connection. For production behind proxy: validate X-Forwarded-For safely.
    host = request.client.host if request.client else "unknown"
    return str(host)

def _user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "")[:256]


# ----------------------------
# Entrypoint
# ----------------------------

def main() -> None:
    _log(
        "service.start",
        bind_host=settings.bind_host,
        bind_port=settings.bind_port,
        db_path=settings.db_path,
        issuer=settings.issuer,
        audience=settings.audience,
        access_ttl_seconds=settings.access_ttl_seconds,
        refresh_ttl_seconds=settings.refresh_ttl_seconds,
    )
    uvicorn.run(
        "auth_prototype_v0:app",
        host=settings.bind_host,
        port=int(settings.bind_port),
        log_level=settings.log_level.lower(),
        reload=False,
        access_log=False,
    )

if __name__ == "__main__":
    main()
