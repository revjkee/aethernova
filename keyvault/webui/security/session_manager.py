# TeslaAI Genesis — Secure Session Manager v2.0
# Защищает frontend-сессию через Zero Trust + context binding

import time
import jwt
import hashlib
import secrets
from fastapi import Request, Response, HTTPException
from fastapi.security import OAuth2PasswordBearer
from starlette.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from keyvault.config.vault_config import get_config
from keyvault.access.context_fingerprint import get_fingerprint_hash
from keyvault.audit.audit_logger import log_event

SECRET_KEY = get_config()["security"]["session_secret"]
ALGORITHM = "HS512"
TOKEN_EXPIRE_SECONDS = 900  # 15 минут

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# === GENERATE JWT TOKEN WITH FINGERPRINT BINDING ===
def generate_token(user_id: str, role: str, fingerprint_hash: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "fp": fingerprint_hash,
        "exp": time.time() + TOKEN_EXPIRE_SECONDS,
        "iat": time.time()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# === VERIFY JWT OR COOKIE SESSION ===
async def verify_session(request: Request):
    token = request.cookies.get("session_token") or request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=401, detail="Session token required")

    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        fingerprint_hash = await get_fingerprint_hash(request)

        if payload["fp"] != fingerprint_hash:
            raise HTTPException(status_code=403, detail="Fingerprint mismatch")

        request.state.user = {
            "sub": payload["sub"],
            "role": payload["role"],
            "session_start": payload["iat"]
        }

        return request.state.user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid session")

# === ISSUE COOKIE OR JWT BASED SESSION RESPONSE ===
def set_session_response(response: Response, user_id: str, role: str, fingerprint_hash: str, use_cookie=True):
    token = generate_token(user_id, role, fingerprint_hash)

    if use_cookie:
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=TOKEN_EXPIRE_SECONDS
        )
    else:
        response.headers["Authorization"] = f"Bearer {token}"

# === LOGOUT ===
def clear_session(response: Response):
    response.delete_cookie("session_token")

# === SESSION MIDDLEWARE FOR FastAPI ===
def attach_session_middleware(app):
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
