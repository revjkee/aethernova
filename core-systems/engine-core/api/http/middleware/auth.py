#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auth & RLS middleware for Engine-Core HTTP API (FastAPI)

Возможности:
- Bearer/JWT аутентификация (локальный HS256 ключ или удалённый JWKS с кэшированием)
- HMAC подпись запроса (X-Signature / X-Timestamp / X-Nonce / X-Key-Id)
- Анти-реплей защита (in-memory TTL nonce cache)
- Политики доступа: роли/скоупы, привязка к RLS-контексту (tenant/org/user)
- Каноникализация запроса для подписи (метод, путь, query, body-sha256, timestamp, nonce)
- Гладкая интеграция с FastAPI: зависимости `require_subject`, `require_scopes`, `require_roles`
- Аудит и структурное логирование

Зависимости: fastapi, pydantic, pydantic_settings, httpx, (опционально) PyJWT.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List, Literal, Optional, Tuple

import httpx
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("engine.auth")


# =============================================================================
# Конфигурация
# =============================================================================

class AuthSettings(BaseSettings):
    # Общие
    AUTH_ENABLED: bool = True
    AUTH_STRATEGY: Literal["bearer", "hmac", "hybrid"] = "hybrid"  # hybrid: принимаем и то, и другое

    # Bearer/JWT
    JWT_REQUIRED: bool = True
    JWT_ALG: Literal["HS256", "RS256", "ES256"] = "HS256"
    JWT_ISS: Optional[str] = None
    JWT_AUD: Optional[str] = None
    JWT_LEEWAY_SEC: int = 30
    JWT_HS_SECRET: Optional[str] = os.getenv("ENGINE_JWT_HS_SECRET")  # для HS256
    JWT_JWKS_URL: Optional[str] = None  # для RS/ES, если указан — берём ключи отсюда
    JWT_CACHE_TTL_SEC: int = 300

    # HMAC подписи
    SIG_REQUIRED: bool = False  # если True — подпись обязательна (в hybrid можно ослабить)
    SIG_HEADER: str = "x-signature"
    SIG_TS_HEADER: str = "x-timestamp"
    SIG_NONCE_HEADER: str = "x-nonce"
    SIG_KEYID_HEADER: str = "x-key-id"
    SIG_ALG: Literal["HMAC-SHA256"] = "HMAC-SHA256"
    SIG_MAX_SKEW_SEC: int = 120  # окно валидности timestamp

    # Хранение ключей HMAC (демо: словарь в конфиге). В проде — KMS/внешний стор.
    HMAC_KEYS: Dict[str, str] = Field(default_factory=dict)  # {"key-id": "base64-secret"}

    # Anti-replay nonce cache
    NONCE_TTL_SEC: int = 300
    NONCE_MAX_ITEMS: int = 200_000

    # RLS
    RLS_ENABLED: bool = True
    RLS_DEFAULT_TENANT: Optional[str] = None

    model_config = SettingsConfigDict(env_prefix="ENGINE_", case_sensitive=False)


settings = AuthSettings()


# =============================================================================
# Внутренние модели и кэш
# =============================================================================

class Subject(BaseModel):
    sub: str
    tenant: Optional[str] = None
    org: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    # исходный токен/метаданные
    raw_token: Optional[str] = None
    token_issuer: Optional[str] = None
    token_audience: Optional[str] = None
    token_exp: Optional[int] = None


class RLSContext(BaseModel):
    tenant: Optional[str] = None
    org: Optional[str] = None
    user: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)


class _JWKSCache:
    def __init__(self) -> None:
        self.data: Optional[Dict[str, Any]] = None
        self.expire_at: float = 0.0
        self.lock = asyncio.Lock()

    async def get(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        async with self.lock:
            now = time.time()
            if self.data and now < self.expire_at:
                return self.data
            r = await client.get(url, timeout=5.0)
            r.raise_for_status()
            self.data = r.json()
            self.expire_at = now + settings.JWT_CACHE_TTL_SEC
            return self.data


jwks_cache = _JWKSCache()


class _NonceCache:
    """In-memory TTL cache для анти-реплея."""
    def __init__(self, ttl: int, max_items: int) -> None:
        self.ttl = ttl
        self.max_items = max_items
        self.store: Dict[str, float] = {}
        self.lock = asyncio.Lock()

    async def add_if_absent(self, key: str) -> bool:
        now = time.time()
        async with self.lock:
            # очистка раз в N вставок — лёгкий best-effort, чтобы не расти бесконечно
            if len(self.store) > self.max_items:
                cutoff = now - self.ttl
                for k, ts in list(self.store.items())[: self.max_items // 10]:
                    if ts < cutoff:
                        self.store.pop(k, None)

            if key in self.store:
                # уже видели — реплей
                return False
            self.store[key] = now
            return True

nonce_cache = _NonceCache(settings.NONCE_TTL_SEC, settings.NONCE_MAX_ITEMS)


# =============================================================================
# JWT валидация (опционально через pyjwt)
# =============================================================================

def _import_pyjwt():
    try:
        import jwt  # type: ignore
        return jwt
    except Exception:  # pragma: no cover
        return None


async def _verify_jwt(token: str, request: Request) -> Dict[str, Any]:
    """
    Проверка JWT: HS256 (локальный секрет) или RS/ES (через JWKS).
    Возвращает пэйлоад при успехе, иначе HTTP 401.
    """
    if not settings.JWT_REQUIRED:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT not enabled")

    jwt_lib = _import_pyjwt()
    if not jwt_lib:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="PyJWT not installed")

    options = {"verify_signature": True, "verify_exp": True, "verify_aud": bool(settings.JWT_AUD), "verify_iss": bool(settings.JWT_ISS)}
    try:
        if settings.JWT_ALG == "HS256":
            if not settings.JWT_HS_SECRET:
                raise HTTPException(status_code=500, detail="HS secret not configured")
            payload = jwt_lib.decode(
                token,
                settings.JWT_HS_SECRET,
                algorithms=["HS256"],
                audience=settings.JWT_AUD,
                issuer=settings.JWT_ISS,
                leeway=settings.JWT_LEEWAY_SEC,
                options=options,
            )
            return payload  # type: ignore[return-value]

        # RS256/ES256 через JWKS
        if not settings.JWT_JWKS_URL:
            raise HTTPException(status_code=500, detail="JWKS URL not configured for asymmetric JWT")

        jwks = await jwks_cache.get(request.app.state.http, settings.JWT_JWKS_URL)
        header = jwt_lib.get_unverified_header(token)
        kid = header.get("kid")
        key = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key = jwt_lib.algorithms.get_default_algorithms()[settings.JWT_ALG].from_jwk(json.dumps(jwk))
                break
        if not key:
            raise HTTPException(status_code=401, detail="Unknown KID")

        payload = jwt_lib.decode(
            token,
            key,
            algorithms=[settings.JWT_ALG],
            audience=settings.JWT_AUD,
            issuer=settings.JWT_ISS,
            leeway=settings.JWT_LEEWAY_SEC,
            options=options,
        )
        return payload  # type: ignore[return-value]

    except HTTPException:
        raise
    except Exception as e:  # pragma: no cover
        logger.warning("jwt_verify_failed: %s", str(e))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token")


# =============================================================================
# Подписи (HMAC)
# =============================================================================

def _canonical_query(query_params: List[Tuple[str, str]]) -> str:
    # Стабильная сортировка по ключу/значению
    parts = [f"{k}={v}" for k, v in sorted(query_params, key=lambda x: (x[0], x[1]))]
    return "&".join(parts)


def _sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


async def _read_body_once(request: Request) -> bytes:
    # Считываем тело и возвращаем обратно в поток
    body = await request.body()
    async def receive_gen():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive_gen  # type: ignore[attr-defined]
    return body


async def _build_signing_string(request: Request, ts: str, nonce: str) -> str:
    # method\npath\nquery\nbody_sha256_b64url\nts\nnonce
    method = request.method.upper()
    path = request.url.path
    query = _canonical_query(list(request.query_params.multi_items()))
    body = await _read_body_once(request)
    body_hash = _b64url(_sha256_bytes(body))
    return "\n".join([method, path, query, body_hash, ts, nonce])


def _hmac_sign(key_b64: str, msg: str) -> str:
    key = base64.urlsafe_b64decode(key_b64 + "===") if key_b64 else b""
    mac = hmac.new(key, msg.encode(), hashlib.sha256).digest()
    return _b64url(mac)


async def verify_hmac_request(request: Request) -> Dict[str, str]:
    sig = request.headers.get(settings.SIG_HEADER)
    ts = request.headers.get(settings.SIG_TS_HEADER)
    nonce = request.headers.get(settings.SIG_NONCE_HEADER)
    key_id = request.headers.get(settings.SIG_KEYID_HEADER)

    if not (sig and ts and nonce and key_id):
        raise HTTPException(status_code=401, detail="missing_signature_headers")

    # окно валидности
    try:
        ts_int = int(ts)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_timestamp")

    skew = abs(int(time.time()) - ts_int)
    if skew > settings.SIG_MAX_SKEW_SEC:
        raise HTTPException(status_code=401, detail="timestamp_out_of_window")

    # анти-реплей
    nonce_key = f"{key_id}:{ts}:{nonce}"
    if not await nonce_cache.add_if_absent(nonce_key):
        raise HTTPException(status_code=401, detail="replay_detected")

    # ключ
    key_b64 = settings.HMAC_KEYS.get(key_id)
    if not key_b64:
        raise HTTPException(status_code=401, detail="unknown_key_id")

    signing_string = await _build_signing_string(request, ts, nonce)
    expected = _hmac_sign(key_b64, signing_string)

    # сравнение
    try:
        ok = hmac.compare_digest(expected, sig)
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(status_code=401, detail="bad_signature")

    return {"key_id": key_id, "nonce": nonce, "ts": ts}


# =============================================================================
# Основная зависимость аутентификации и построение RLS
# =============================================================================

async def authenticate(request: Request) -> Subject:
    """
    Возвращает аутентифицированного субъекта или поднимает 401.
    Поддерживает стратегии: bearer, hmac, hybrid.
    """
    if not settings.AUTH_ENABLED:
        # Аноним; RLS минимальный
        return Subject(sub="anonymous", tenant=settings.RLS_DEFAULT_TENANT, roles=["anon"], scopes=[])

    authz = request.headers.get("authorization", "")
    has_bearer = authz.lower().startswith("bearer ")

    # HMAC проверяем только если требуется или стратегия hybrid
    sig_ok = False
    sig_meta: Dict[str, str] = {}
    if settings.AUTH_STRATEGY in ("hmac", "hybrid"):
        try:
            sig_meta = await verify_hmac_request(request)
            sig_ok = True
        except HTTPException as e:
            if settings.SIG_REQUIRED or settings.AUTH_STRATEGY == "hmac":
                raise
            # иначе можно продолжать как bearer

    if settings.AUTH_STRATEGY in ("bearer", "hybrid"):
        if settings.JWT_REQUIRED:
            if not has_bearer:
                if settings.AUTH_STRATEGY == "bearer" or (settings.JWT_REQUIRED and not sig_ok):
                    raise HTTPException(status_code=401, detail="missing_bearer_token")
            if has_bearer:
                token = authz.split(" ", 1)[1].strip()
                payload = await _verify_jwt(token, request)
                # Mаппинг полей — настраивается по вашему стандарту токена
                sub = str(payload.get("sub") or payload.get("uid") or "unknown")
                tenant = payload.get("tenant") or payload.get("org_id") or settings.RLS_DEFAULT_TENANT
                roles = payload.get("roles") or []
                scopes = payload.get("scopes") or payload.get("scope", "").split() if payload.get("scope") else []
                return Subject(
                    sub=sub,
                    tenant=tenant,
                    org=payload.get("org"),
                    roles=list(roles),
                    scopes=list(scopes),
                    raw_token=token,
                    token_issuer=payload.get("iss"),
                    token_audience=payload.get("aud"),
                    token_exp=payload.get("exp"),
                )
        else:
            # Неподписанный Bearer (базовый токен без JWT) — НЕ рекомендуется в проде.
            if has_bearer:
                tok = authz.split(" ", 1)[1].strip()
                return Subject(sub=f"token:{tok[:8]}", tenant=settings.RLS_DEFAULT_TENANT, roles=["token"], scopes=[], raw_token=tok)

    if sig_ok:
        # Аутентификация только по HMAC‑подписи (машинный клиент)
        key_id = sig_meta.get("key_id", "hmac")
        return Subject(sub=f"hmac:{key_id}", tenant=settings.RLS_DEFAULT_TENANT, roles=["machine"], scopes=["api:write", "api:read"])

    # Если сюда дошли — не удалось аутентифицировать
    raise HTTPException(status_code=401, detail="unauthenticated")


def attach_rls(request: Request, subject: Subject) -> RLSContext:
    """
    Формирует и прикрепляет RLS-контекст к запросу.
    """
    if not settings.RLS_ENABLED:
        ctx = RLSContext()
        request.state.rls = ctx
        return ctx

    ctx = RLSContext(
        tenant=subject.tenant or settings.RLS_DEFAULT_TENANT,
        org=subject.org,
        user=subject.sub,
        roles=subject.roles[:],
        scopes=subject.scopes[:],
    )
    request.state.rls = ctx
    return ctx


# =============================================================================
# Зависимости для маршрутов
# =============================================================================

async def require_subject(request: Request) -> Subject:
    subj = await authenticate(request)
    attach_rls(request, subj)
    return subj


def require_scopes(*required: str):
    async def _dep(subject: Subject = Depends(require_subject)) -> Subject:
        missing = [s for s in required if s not in subject.scopes]
        if missing:
            raise HTTPException(status_code=403, detail=f"missing_scopes:{','.join(missing)}")
        return subject
    return _dep


def require_roles(*roles: str):
    async def _dep(subject: Subject = Depends(require_subject)) -> Subject:
        if not set(roles).intersection(subject.roles):
            raise HTTPException(status_code=403, detail=f"missing_roles:{','.join(roles)}")
        return subject
    return _dep


# =============================================================================
# Утилиты для серверных хендлеров/клиентов
# =============================================================================

def build_client_signature(
    method: str,
    path: str,
    query: List[Tuple[str, str]],
    body: bytes,
    ts: int,
    nonce: str,
    key_b64: str,
) -> str:
    """
    Клиентская утилита для формирования подписи (для тестов/скриптов).
    """
    query_str = "&".join([f"{k}={v}" for k, v in sorted(query, key=lambda x: (x[0], x[1]))])
    body_hash = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
    msg = "\n".join([method.upper(), path, query_str, body_hash, str(ts), nonce])
    mac = hmac.new(base64.urlsafe_b64decode(key_b64 + "==="), msg.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


# =============================================================================
# Пример подключения в приложении FastAPI:
#
# from fastapi import APIRouter
# from .middleware.auth import require_subject, require_scopes, require_roles
#
# router = APIRouter()
#
# @router.get("/v1/secure", dependencies=[Depends(require_scopes("api:read"))])
# async def secure_endpoint(subject = Depends(require_subject)):
#     rls = request.state.rls  # tenant/org/user/roles/scopes для
