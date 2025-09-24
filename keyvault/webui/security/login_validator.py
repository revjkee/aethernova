# TeslaAI Genesis — Login Validator v3.0
# Проверка логинов с поддержкой BasicAuth, OAuth2, JWT, Fingerprint

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBasic, OAuth2AuthorizationCodeBearer
from starlette.status import HTTP_401_UNAUTHORIZED
from keyvault.config.vault_config import get_config
from keyvault.access.context_fingerprint import get_fingerprint_hash
from jose import JWTError, jwt
from typing import Optional
import secrets

basic_auth = HTTPBasic(auto_error=False)
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://auth.example.com/oauth/authorize",
    tokenUrl="https://auth.example.com/oauth/token"
)

SECRET_KEY = get_config()["security"]["jwt_secret"]
ALGORITHM = "HS256"

# === Проверка BasicAuth пользователя ===
def verify_basic_auth(credentials) -> Optional[str]:
    users = get_config()["security"]["basic_users"]  # {"admin": "hashed_pw"}
    if not credentials:
        return None
    username = credentials.username
    password = credentials.password
    if username in users and secrets.compare_digest(users[username], password):
        return username
    return None

# === Проверка JWT из OAuth ===
def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")  # subject: user ID/email
    except JWTError:
        return None

# === Универсальный валидатор входа ===
async def validate_login(request: Request, credentials=Depends(basic_auth), token=Depends(oauth2_scheme)) -> str:
    # Проверка Basic
    user = verify_basic_auth(credentials)
    if user:
        return user

    # Проверка JWT
    jwt_user = verify_jwt_token(token)
    if jwt_user:
        return jwt_user

    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Invalid login credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# === Проверка фингерпринта сессии ===
async def enforce_fingerprint(request: Request):
    token_fp = request.headers.get("X-Session-Fingerprint")
    current_fp = await get_fingerprint_hash(request)
    if not token_fp or not secrets.compare_digest(token_fp, current_fp):
        raise HTTPException(status_code=403, detail="Fingerprint mismatch")
