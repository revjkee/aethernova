# -*- coding: utf-8 -*-
"""
security-core HTTP router: AuthN + MFA (v1)
Индустриальная реализация:
- FastAPI APIRouter с маршрутами: /login, /refresh, /logout,
  /mfa/totp/enroll, /mfa/totp/verify, /mfa/backup-codes/generate, /mfa/backup-codes/verify,
  /introspect.
- Сессии на безопасных HTTP-only куки: SID (доступ) + RID (refresh) + DID (device).
- Pre-session для step-up MFA: пароль пройден, но MFA не подтвержден → ограниченная кука PSID.
- TOTP по RFC 6238 (SHA-1 по умолчанию), без внешних библиотек.
- Backup codes с PBKDF2-хешированием.
- CSRF: double-submit cookie + X-CSRF-Token.
- Rate limit: in-memory, поминутные ведра (IP и user).
- Password hashing: PBKDF2-HMAC-SHA256, пер-пользовательская соль.
- Risk score: базовый, учитывает новый девайс, отсутствие MFA, частые ошибки.
- Device binding: DID cookie (стаб), продакшен — из MDM/UA fingerprint.
Замените InMemory* на Redis/SQL/KV в проде.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Константы и политика
# ---------------------------------------------------------------------------

SESSION_COOKIE = "sid"
REFRESH_COOKIE = "rid"
PREFLIGHT_COOKIE = "psid"  # pre-session до MFA
DEVICE_COOKIE = "did"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

ACCESS_TTL = timedelta(minutes=15)
REFRESH_TTL = timedelta(days=30)
PREFLIGHT_TTL = timedelta(minutes=5)

COOKIE_DOMAIN = None  # подставьте ваш домен, например ".example.org"
COOKIE_SECURE = True
COOKIE_SAMESITE = "lax"  # "strict" для особо критичных интерфейсов

TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_ALGO = "SHA1"  # "SHA1" | "SHA256" при необходимости

MAX_LOGIN_ATTEMPTS_WINDOW = 300  # 5 минут окно брут-форса

# Risk thresholds
RISK_MEDIUM = 40
RISK_HIGH = 70

# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _b32_random_secret(length: int = 20) -> str:
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")

def _hmac_sha(algo: str, key: bytes, msg: bytes) -> bytes:
    algo = algo.upper()
    if algo == "SHA1":
        return hmac.new(key, msg, hashlib.sha1).digest()
    if algo == "SHA256":
        return hmac.new(key, msg, hashlib.sha256).digest()
    raise ValueError("Unsupported TOTP algo")

def _pbkdf2_sha256(password: str, salt: bytes, iters: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen)

def _safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

def _gen_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)

def _int_to_bytes(i: int) -> bytes:
    return struct.pack(">Q", i)

def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _set_cookie(resp: Response, key: str, val: str, ttl: timedelta, http_only: bool = True) -> None:
    resp.set_cookie(
        key=key,
        value=val,
        max_age=int(ttl.total_seconds()),
        secure=COOKIE_SECURE,
        httponly=http_only,
        samesite=COOKIE_SAMESITE,
        domain=COOKIE_DOMAIN,
        path="/",
    )

def _del_cookie(resp: Response, key: str) -> None:
    resp.delete_cookie(key=key, domain=COOKIE_DOMAIN, path="/")

# ---------------------------------------------------------------------------
# TOTP RFC 6238 (без внешних зависимостей)
# ---------------------------------------------------------------------------

def totp_at(secret_b32: str, ts: int, period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS, algo: str = TOTP_ALGO) -> int:
    # normalize base32 with padding
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)
    counter = ts // period
    h = _hmac_sha(algo, key, _int_to_bytes(counter))
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return code_int

def totp_verify(secret_b32: str, code: str, now_ts: Optional[int] = None, skew: int = 1, period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS, algo: str = TOTP_ALGO) -> bool:
    if not code.isdigit():
        return False
    now_ts = now_ts or int(time.time())
    for w in range(-skew, skew + 1):
        valid = f"{totp_at(secret_b32, now_ts + (w * period), period, digits, algo):0{digits}d}"
        if _safe_compare(valid, code):
            return True
    return False

def totp_otpauth_uri(issuer: str, account: str, secret_b32: str, period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS, algo: str = TOTP_ALGO) -> str:
    from urllib.parse import quote
    label = f"{quote(issuer)}:{quote(account)}"
    params = f"secret={secret_b32}&issuer={quote(issuer)}&period={period}&digits={digits}&algorithm={algo}"
    return f"otpauth://totp/{label}?{params}"

# ---------------------------------------------------------------------------
# Модели запросов/ответов
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None  # для step-up при наличии
    csrf_token: Optional[str] = None

class LoginResponse(BaseModel):
    user_id: str
    step_up: Optional[str] = None
    methods: Optional[List[str]] = None

class RefreshRequest(BaseModel):
    csrf_token: str

class IntrospectRequest(BaseModel):
    token: Optional[str] = None  # опционально для сторонних клиентов

class IntrospectResponse(BaseModel):
    active: bool
    user_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    device_id: Optional[str] = None

class EnrollTotpRequest(BaseModel):
    issuer: str = Field(default="ExampleCorp")
    account_name: Optional[str] = None

class EnrollTotpResponse(BaseModel):
    secret_b32: str
    otpauth_uri: str

class VerifyTotpRequest(BaseModel):
    code: str

class BackupCodesResponse(BaseModel):
    codes: List[str]

class VerifyBackupCodeRequest(BaseModel):
    code: str

# ---------------------------------------------------------------------------
# In-memory реализации. Продакшен: заменить на Redis/DB/KV.
# ---------------------------------------------------------------------------

class InMemoryUserStore:
    def __init__(self) -> None:
        # admin:admin по умолчанию (для демо)
        salt = os.urandom(16)
        self._users: Dict[str, Dict[str, Any]] = {
            "admin": {
                "id": "u-1",
                "salt": salt,
                "pwd": _pbkdf2_sha256("admin", salt),
                "mfa": {
                    "totp_secret": None,
                    "backup_hashes": set(),  # pbkdf2 hashes
                },
                "locked_until": 0.0,
                "fail_count_window": [],
            }
        }

    def get(self, username: str) -> Optional[Dict[str, Any]]:
        return self._users.get(username)

    def verify_password(self, username: str, password: str) -> bool:
        u = self.get(username)
        if not u:
            return False
        if time.time() < u["locked_until"]:
            return False
        hashed = _pbkdf2_sha256(password, u["salt"])
        ok = hmac.compare_digest(hashed, u["pwd"])
        # простая защита/брут
        now = time.time()
        window = [t for t in u["fail_count_window"] if now - t <= MAX_LOGIN_ATTEMPTS_WINDOW]
        u["fail_count_window"] = window
        if ok:
            u["fail_count_window"] = []
        else:
            window.append(now)
            if len(window) >= 10:
                u["locked_until"] = now + 600  # 10 минут блок
        return ok

    def set_totp_secret(self, user_id: str, username: str, secret_b32: str) -> None:
        u = self.get(username)
        if u and u["id"] == user_id:
            u["mfa"]["totp_secret"] = secret_b32

    def get_totp_secret(self, user_id: str, username: str) -> Optional[str]:
        u = self.get(username)
        if u and u["id"] == user_id:
            return u["mfa"]["totp_secret"]
        return None

    def set_backup_codes(self, user_id: str, username: str, code_hashes: List[str]) -> None:
        u = self.get(username)
        if u and u["id"] == user_id:
            u["mfa"]["backup_hashes"] = set(code_hashes)

    def use_backup_code(self, user_id: str, username: str, code: str) -> bool:
        u = self.get(username)
        if not u or u["id"] != user_id:
            return False
        hashed = _base64url(_pbkdf2_sha256(code, b"backup-pepper", iters=120_000, dklen=32))
        if hashed in u["mfa"]["backup_hashes"]:
            u["mfa"]["backup_hashes"].remove(hashed)  # одноразовый
            return True
        return False

class InMemorySessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}   # sid → record
        self._refresh: Dict[str, str] = {}               # rid → sid
        self._pre: Dict[str, Dict[str, Any]] = {}        # psid → record

    def create_pre_session(self, user_id: str, username: str, device_id: str) -> str:
        psid = _gen_token(18)
        self._pre[psid] = {
            "user_id": user_id,
            "username": username,
            "device_id": device_id,
            "exp": time.time() + PREFLIGHT_TTL.total_seconds(),
        }
        return psid

    def get_pre_session(self, psid: str) -> Optional[Dict[str, Any]]:
        rec = self._pre.get(psid)
        if not rec:
            return None
        if time.time() > rec["exp"]:
            self._pre.pop(psid, None)
            return None
        return rec

    def upgrade_to_full(self, psid: str) -> Tuple[str, str]:
        rec = self._pre.pop(psid, None)
        if not rec:
            raise KeyError("invalid pre-session")
        return self.create_session(rec["user_id"], rec["username"], rec["device_id"])

    def create_session(self, user_id: str, username: str, device_id: str) -> Tuple[str, str]:
        sid = _gen_token(24)
        rid = _gen_token(28)
        now = time.time()
        self._sessions[sid] = {
            "user_id": user_id,
            "username": username,
            "device_id": device_id,
            "exp": now + ACCESS_TTL.total_seconds(),
        }
        self._refresh[rid] = sid
        return sid, rid

    def touch(self, sid: str) -> bool:
        rec = self._sessions.get(sid)
        if not rec:
            return False
        rec["exp"] = time.time() + ACCESS_TTL.total_seconds()
        return True

    def get(self, sid: str) -> Optional[Dict[str, Any]]:
        rec = self._sessions.get(sid)
        if not rec:
            return None
        if time.time() > rec["exp"]:
            self._sessions.pop(sid, None)
            return None
        return rec

    def refresh(self, rid: str) -> Tuple[Optional[str], Optional[str]]:
        sid = self._refresh.get(rid)
        if not sid:
            return None, None
        # rotate
        new_sid = _gen_token(24)
        new_rid = _gen_token(28)
        rec = self._sessions.pop(sid, None)
        if not rec:
            # refresh без активной сессии — аннулировать
            self._refresh.pop(rid, None)
            return None, None
        rec["exp"] = time.time() + ACCESS_TTL.total_seconds()
        self._sessions[new_sid] = rec
        self._refresh.pop(rid, None)
        self._refresh[new_rid] = new_sid
        return new_sid, new_rid

    def revoke(self, sid: Optional[str], rid: Optional[str]) -> None:
        if sid and sid in self._sessions:
            self._sessions.pop(sid, None)
            # убрать все refresh, указывающие на sid
            doomed = [r for r, s in self._refresh.items() if s == sid]
            for r in doomed:
                self._refresh.pop(r, None)
        if rid and rid in self._refresh:
            sid2 = self._refresh.pop(rid, None)
            if sid2:
                self._sessions.pop(sid2, None)

class InMemoryRateLimiter:
    def __init__(self, max_per_min_ip: int = 60, max_per_min_user: int = 30) -> None:
        self.ip_bucket: Dict[int, int] = {}
        self.user_bucket: Dict[Tuple[str, int], int] = {}
        self.max_ip = max_per_min_ip
        self.max_user = max_per_min_user

    def allow(self, ip: str, username: Optional[str] = None) -> bool:
        now_min = int(time.time() // 60)
        # IP
        self.ip_bucket[now_min] = self.ip_bucket.get(now_min, 0) + 1
        if self.ip_bucket[now_min] > self.max_ip:
            return False
        # user
        if username:
            key = (username, now_min)
            self.user_bucket[key] = self.user_bucket.get(key, 0) + 1
            if self.user_bucket[key] > self.max_user:
                return False
        return True

# ---------------------------------------------------------------------------
# Зависимости/синглтоны
# ---------------------------------------------------------------------------

USER_STORE = InMemoryUserStore()
SESSIONS = InMemorySessionStore()
RATELIM = InMemoryRateLimiter()

router = APIRouter(prefix="/v1/authn", tags=["authn"])

# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

def _ensure_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or not _safe_compare(cookie, header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF check failed")

def _issue_csrf(resp: Response) -> str:
    token = _gen_token(16)
    _set_cookie(resp, CSRF_COOKIE, token, ttl=ACCESS_TTL, http_only=False)
    return token

# ---------------------------------------------------------------------------
# Risk оценка (упрощенная)
# ---------------------------------------------------------------------------

def _risk_score(request: Request, user: Dict[str, Any], has_mfa: bool) -> int:
    score = 0
    if not request.cookies.get(DEVICE_COOKIE):
        score += 25  # новый девайс
    if not has_mfa:
        score += 25
    # частые ошибки в окне
    fails = len([t for t in user.get("fail_count_window", []) if time.time() - t <= MAX_LOGIN_ATTEMPTS_WINDOW])
    if fails >= 5:
        score += 20
    # небезопасный UA признак (настоящее — через UA/ASN/Geo репутацию)
    ua = request.headers.get("user-agent", "")
    if "python-requests" in ua.lower():
        score += 10
    return score

# ---------------------------------------------------------------------------
# Маршруты
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
def login(req: Request, resp: Response, body: LoginRequest) -> LoginResponse:
    client_ip = req.client.host if req.client else "0.0.0.0"
    if not RATELIM.allow(client_ip, body.username):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    user = USER_STORE.get(body.username)
    if not user or not USER_STORE.verify_password(body.username, body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    did = req.cookies.get(DEVICE_COOKIE) or _gen_token(12)
    has_mfa = bool(USER_STORE.get_totp_secret(user["id"], body.username)) or bool(user["mfa"]["backup_hashes"])
    score = _risk_score(req, user, has_mfa)

    # Step-up MFA требование по риску или включенной MFA
    need_mfa = score >= RISK_MEDIUM or has_mfa

    # Если MFA нужна, но одноразовый код не передан или неверен → pre-session
    if need_mfa:
        if body.otp:
            secret = USER_STORE.get_totp_secret(user["id"], body.username)
            if secret and totp_verify(secret, body.otp):
                # Успешно, выдаем полную сессию
                sid, rid = SESSIONS.create_session(user["id"], body.username, did)
                _set_cookie(resp, DEVICE_COOKIE, did, ttl=REFRESH_TTL, http_only=False)
                _set_cookie(resp, SESSION_COOKIE, sid, ttl=ACCESS_TTL, http_only=True)
                _set_cookie(resp, REFRESH_COOKIE, rid, ttl=REFRESH_TTL, http_only=True)
                csrf = _issue_csrf(resp)
                return LoginResponse(user_id=user["id"])
            else:
                # пробуем резервный код
                if USER_STORE.use_backup_code(user["id"], body.username, body.otp):
                    sid, rid = SESSIONS.create_session(user["id"], body.username, did)
                    _set_cookie(resp, DEVICE_COOKIE, did, ttl=REFRESH_TTL, http_only=False)
                    _set_cookie(resp, SESSION_COOKIE, sid, ttl=ACCESS_TTL, http_only=True)
                    _set_cookie(resp, REFRESH_COOKIE, rid, ttl=REFRESH_TTL, http_only=True)
                    csrf = _issue_csrf(resp)
                    return LoginResponse(user_id=user["id"])
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA required")
        else:
            # выдаем pre-session для завершения шагом MFA
            psid = SESSIONS.create_pre_session(user["id"], body.username, did)
            _set_cookie(resp, DEVICE_COOKIE, did, ttl=REFRESH_TTL, http_only=False)
            _set_cookie(resp, PREFLIGHT_COOKIE, psid, ttl=PREFLIGHT_TTL, http_only=True)
            csrf = _issue_csrf(resp)
            return LoginResponse(user_id=user["id"], step_up="mfa_required", methods=["totp", "backup_codes"])

    # MFA не нужна — выдаем сессию
    sid, rid = SESSIONS.create_session(user["id"], body.username, did)
    _set_cookie(resp, DEVICE_COOKIE, did, ttl=REFRESH_TTL, http_only=False)
    _set_cookie(resp, SESSION_COOKIE, sid, ttl=ACCESS_TTL, http_only=True)
    _set_cookie(resp, REFRESH_COOKIE, rid, ttl=REFRESH_TTL, http_only=True)
    csrf = _issue_csrf(resp)
    return LoginResponse(user_id=user["id"])

@router.post("/refresh", response_model=LoginResponse)
def refresh(req: Request, resp: Response, body: RefreshRequest) -> LoginResponse:
    _ensure_csrf(req)
    rid = req.cookies.get(REFRESH_COOKIE)
    if not rid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh cookie")
    sid_new, rid_new = SESSIONS.refresh(rid)
    if not sid_new or not rid_new:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    _set_cookie(resp, SESSION_COOKIE, sid_new, ttl=ACCESS_TTL, http_only=True)
    _set_cookie(resp, REFRESH_COOKIE, rid_new, ttl=REFRESH_TTL, http_only=True)
    SESSIONS.touch(sid_new)
    # возвращаем user_id для удобства клиентов
    rec = SESSIONS.get(sid_new)
    csrf = _issue_csrf(resp)
    return LoginResponse(user_id=rec["user_id"] if rec else "unknown")

@router.post("/logout")
def logout(req: Request, resp: Response) -> Dict[str, str]:
    sid = req.cookies.get(SESSION_COOKIE)
    rid = req.cookies.get(REFRESH_COOKIE)
    SESSIONS.revoke(sid, rid)
    _del_cookie(resp, SESSION_COOKIE)
    _del_cookie(resp, REFRESH_COOKIE)
    _del_cookie(resp, PREFLIGHT_COOKIE)
    _del_cookie(resp, CSRF_COOKIE)
    return {"status": "ok"}

# ------------------ MFA: TOTP ------------------

@router.post("/mfa/totp/enroll", response_model=EnrollTotpResponse)
def mfa_totp_enroll(req: Request, resp: Response, body: EnrollTotpRequest) -> EnrollTotpResponse:
    # Требуем pre-session или полную сессию
    psid = req.cookies.get(PREFLIGHT_COOKIE)
    sid = req.cookies.get(SESSION_COOKIE)
    user_id = None
    username = None

    if sid:
        rec = SESSIONS.get(sid)
        if not rec:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
        user_id, username = rec["user_id"], rec["username"]
    elif psid:
        rec = SESSIONS.get_pre_session(psid)
        if not rec:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Pre-session expired")
        user_id, username = rec["user_id"], rec["username"]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session")

    secret = _b32_random_secret()
    account = body.account_name or username
    uri = totp_otpauth_uri(body.issuer, account, secret, period=TOTP_PERIOD, digits=TOTP_DIGITS, algo=TOTP_ALGO)
    USER_STORE.set_totp_secret(user_id, username, secret)
    return EnrollTotpResponse(secret_b32=secret, otpauth_uri=uri)

@router.post("/mfa/totp/verify")
def mfa_totp_verify(req: Request, resp: Response, body: VerifyTotpRequest) -> Dict[str, str]:
    psid = req.cookies.get(PREFLIGHT_COOKIE)
    if not psid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pre-session")
    pre = SESSIONS.get_pre_session(psid)
    if not pre:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Pre-session expired")
    secret = USER_STORE.get_totp_secret(pre["user_id"], pre["username"])
    if not secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TOTP not enrolled")
    if not totp_verify(secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    # Upgrade до полной сессии
    sid, rid = SESSIONS.upgrade_to_full(psid)
    _del_cookie(resp, PREFLIGHT_COOKIE)
    _set_cookie(resp, SESSION_COOKIE, sid, ttl=ACCESS_TTL, http_only=True)
    _set_cookie(resp, REFRESH_COOKIE, rid, ttl=REFRESH_TTL, http_only=True)
    csrf = _issue_csrf(resp)
    return {"status": "ok"}

# ------------------ MFA: Backup Codes ------------------

@router.post("/mfa/backup-codes/generate", response_model=BackupCodesResponse)
def mfa_backup_generate(req: Request, resp: Response) -> BackupCodesResponse:
    sid = req.cookies.get(SESSION_COOKIE) or req.cookies.get(PREFLIGHT_COOKIE)
    # разрешаем генерацию при наличии pre-session (после пароля)
    user_id = None
    username = None
    if sid and sid in SESSIONS._sessions:
        rec = SESSIONS.get(sid)
        if not rec:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
        user_id, username = rec["user_id"], rec["username"]
    elif sid and sid in SESSIONS._pre:
        pre = SESSIONS.get_pre_session(sid)
        if not pre:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Pre-session expired")
        user_id, username = pre["user_id"], pre["username"]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No session")

    # генерируем 10 кодов по 10 символов
    codes = []
    hashes = []
    for _ in range(10):
        raw = _base64url(os.urandom(8))[:10]
        codes.append(raw)
        hashes.append(_base64url(_pbkdf2_sha256(raw, b"backup-pepper", iters=120_000, dklen=32)))
    USER_STORE.set_backup_codes(user_id, username, hashes)
    return BackupCodesResponse(codes=codes)

@router.post("/mfa/backup-codes/verify")
def mfa_backup_verify(req: Request, resp: Response, body: VerifyBackupCodeRequest) -> Dict[str, str]:
    psid = req.cookies.get(PREFLIGHT_COOKIE)
    if not psid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pre-session")
    pre = SESSIONS.get_pre_session(psid)
    if not pre:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Pre-session expired")
    if not USER_STORE.use_backup_code(pre["user_id"], pre["username"], body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or used backup code")

    sid, rid = SESSIONS.upgrade_to_full(psid)
    _del_cookie(resp, PREFLIGHT_COOKIE)
    _set_cookie(resp, SESSION_COOKIE, sid, ttl=ACCESS_TTL, http_only=True)
    _set_cookie(resp, REFRESH_COOKIE, rid, ttl=REFRESH_TTL, http_only=True)
    csrf = _issue_csrf(resp)
    return {"status": "ok"}

# ------------------ Интроспекция ------------------

@router.post("/introspect", response_model=IntrospectResponse)
def introspect(req: Request, body: IntrospectRequest) -> IntrospectResponse:
    # Если token не передан, читаем из sid cookie
    token = body.token or req.cookies.get(SESSION_COOKIE)
    if not token:
        return IntrospectResponse(active=False)

    rec = SESSIONS.get(token)
    if not rec:
        return IntrospectResponse(active=False)
    return IntrospectResponse(
        active=True,
        user_id=rec["user_id"],
        expires_at=datetime.fromtimestamp(rec["exp"], tz=timezone.utc),
        device_id=rec["device_id"],
    )

# ------------------ Middleware hints (под FastAPI app) ------------------
# Подключение:
#   from fastapi import FastAPI
#   from security_core.api.http.routers.v1.authn import router as authn_router
#   app = FastAPI()
#   app.include_router(authn_router)
#
# В продакшене:
# - замените InMemory* на Redis/SQL/KV, добавьте mTLS и внешнюю проверку пароля/учеток (IdP/LDAP/OIDC).
# - интегрируйте Risk Engine/Anti-Abuse провайдеры и SIEM аудит.
# - установите COOKIE_DOMAIN на боевой домен, включите SameSite=Strict для административных панелей.
