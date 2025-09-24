import jwt
import uuid
import time
from datetime import datetime, timedelta
from typing import Optional, Dict
from passlib.context import CryptContext
from fastapi import HTTPException, status
from hr_ai.db.models import User, AuditLog
from hr_ai.settings import settings
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# === CONFIG ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_ALG = "HS256"
ACCESS_EXP_MINUTES = 30
REFRESH_EXP_DAYS = 7

# === EXCEPTIONS ===
class AuthError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

# === TOKEN UTILS ===
def _create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=JWT_ALG)

def create_access_token(user_id: str, tenant_id: str, role: str) -> str:
    return _create_token(
        data={"sub": user_id, "tenant": tenant_id, "role": role},
        expires_delta=timedelta(minutes=ACCESS_EXP_MINUTES)
    )

def create_refresh_token(user_id: str) -> str:
    return _create_token(
        data={"sub": user_id, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_EXP_DAYS)
    )

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.JWTError:
        raise AuthError("Invalid token")

# === PASSWORD UTILS ===
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# === AUTH CORE ===
async def authenticate_user(session: AsyncSession, email: str, password: str, tenant_id: str) -> Dict[str, str]:
    stmt = select(User).where(User.email == email, User.tenant_id == tenant_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.hashed_password):
        raise AuthError("Invalid credentials")

    access_token = create_access_token(user.id, tenant_id, user.role)
    refresh_token = create_refresh_token(user.id)
    await _log_auth_event(session, user.id, tenant_id, "login_success")

    return {"access_token": access_token, "refresh_token": refresh_token}

async def refresh_tokens(refresh_token: str, session: AsyncSession) -> Dict[str, str]:
    payload = verify_token(refresh_token)
    if payload.get("type") != "refresh":
        raise AuthError("Invalid refresh token")

    stmt = select(User).where(User.id == payload["sub"])
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise AuthError("User not found")

    access_token = create_access_token(user.id, user.tenant_id, user.role)
    new_refresh_token = create_refresh_token(user.id)
    await _log_auth_event(session, user.id, user.tenant_id, "token_refresh")

    return {"access_token": access_token, "refresh_token": new_refresh_token}

# === XAI-AUDIT LOGGER ===
async def _log_auth_event(session: AsyncSession, user_id: str, tenant_id: str, action: str):
    log = AuditLog(
        id=str(uuid.uuid4()),
        user_id=user_id,
        action=action,
        target="auth_service",
        tenant_id=tenant_id,
        severity=1,
        timestamp=datetime.utcnow()
    )
    session.add(log)
    await session.flush()
