# TeslaAI Genesis — CSRF Protection Module v2.0
# Защита форм и API от CSRF через Double Submit Cookie + HMAC + Fingerprint

import hmac
import hashlib
import secrets
from fastapi import Request, Response, HTTPException
from keyvault.config.vault_config import get_config
from keyvault.access.context_fingerprint import get_fingerprint_hash

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

_SECRET = get_config()["security"]["csrf_secret"].encode()

# === Генерация нового CSRF-токена ===
async def generate_csrf_token(request: Request) -> str:
    nonce = secrets.token_urlsafe(24)
    fingerprint = await get_fingerprint_hash(request)
    message = f"{nonce}:{fingerprint}"
    signature = hmac.new(_SECRET, message.encode(), hashlib.sha256).hexdigest()
    token = f"{nonce}:{signature}"
    return token

# === Проверка CSRF-токена ===
async def verify_csrf_token(request: Request):
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)

    if not cookie_token or not header_token or cookie_token != header_token:
        raise HTTPException(status_code=403, detail="CSRF token mismatch or missing")

    try:
        nonce, signature = cookie_token.split(":")
        fingerprint = await get_fingerprint_hash(request)
        expected_message = f"{nonce}:{fingerprint}"
        expected_signature = hmac.new(_SECRET, expected_message.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            raise HTTPException(status_code=403, detail="CSRF token invalid or tampered")

    except Exception:
        raise HTTPException(status_code=403, detail="Invalid CSRF format")

# === Добавление CSRF-токена в ответ ===
async def attach_csrf_cookie(response: Response, request: Request):
    token = await generate_csrf_token(request)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=True,
        samesite="Strict",
        max_age=1800  # 30 минут
    )
